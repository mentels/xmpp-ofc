-module(xmpp_ofc_ids).
-behaviour(gen_server).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([start_link/1,
         stop/1,
         handle_message/3]).

%% ------------------------------------------------------------------
%% gen_server Function Exports
%% ------------------------------------------------------------------

-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

%% ------------------------------------------------------------------
%% Includes & Type Definitions & Macros
%% ------------------------------------------------------------------

-include_lib("of_protocol/include/of_protocol.hrl").
-include_lib("of_protocol/include/ofp_v4.hrl").
-include("xmpp_ofc_v4.hrl").

-type fwd_table() :: #{MacAddr :: string() => SwitchPort :: integer()}.
-record(state, {datapath_id :: binary(),
                fwd_table :: fwd_table()}).

-define(SERVER, ?MODULE).
-define(OF_VER, 4).
-define(ENTRY_TIMEOUT, 30*100).
-define(FM_TIMEOUT_S(FmType, TimeoutType),
        case {FmType, TimeoutType} of
            {forward, idle} ->
                10;
            {forward, hard} ->
                30;
            {drop, _} ->
                10
        end).
-define(INIT_FM_COOKIE, <<0,0,0,0,0,0,0,150>>).
-define(CLIENT_FM_COOKIE(Type), case Type of
                                    forward ->
                                        <<0,0,0,0,0,0,0,200>>;
                                    drop ->
                                        <<0,0,0,0,0,0,0,300>>
                                end).
-define(FLOW_STAT_REQUEST_INTERVAL, 10 * 1000).
-define(MAX_PACKETS_PER_SECOND, 100).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec start_link(binary()) -> {ok, pid()} | ignore | {error, term()}.
start_link(DatapathId) ->
    {ok, Pid} = gen_server:start_link(?MODULE, [DatapathId], []),
    {ok, Pid, subscriptions(), [init_flow_mod()]}.

-spec stop(pid()) -> ok.
stop(Pid) ->
    gen_server:stop(Pid).

-spec handle_message(pid(),
                     {MsgType :: term(),
                      Xid :: term(),
                      MsgBody :: [tuple()]},
                     [ofp_message()]) -> [ofp_message()].
handle_message(Pid, Msg, OFMessages) ->
    gen_server:call(Pid, {handle_message, Msg, OFMessages}).

%% ------------------------------------------------------------------
%% gen_server Function Definitions
%% ------------------------------------------------------------------

init([DatapathId]) ->
    {ok, #state{datapath_id = DatapathId, fwd_table = #{}}}.


handle_call(
  {handle_message, {packet_in, _, MsgBody} = Msg, CurrOFMesssages},
  _From, #state{datapath_id = Dpid,
                fwd_table = FwdTable0} = State) ->
    case packet_in_extract(cookie, MsgBody) of
        ?INIT_FM_COOKIE ->
            {OFMessages, FwdTable1} = handle_init_fm_packet_in(
                                        Msg, Dpid, FwdTable0),
            {reply, OFMessages ++ CurrOFMesssages,
             State#state{fwd_table = FwdTable1}};
        _ ->
            {reply, CurrOFMesssages, State}
    end;
handle_call(
  {handle_message, {flow_stats_reply, _, []}, CurrOFMesssages},
  _From, State) ->
    {reply, CurrOFMesssages, State};
handle_call(
  {handle_message, {flow_stats_reply, _, [Reply]} = Msg,
   CurrOFMesssages}, _From, #state{datapath_id = Dpid,
                                   fwd_table = FwdTable0} = State) ->
    ClientFMCookie = ?CLIENT_FM_COOKIE(forward),
    case flow_stats_extract(cookie, Reply) of
        ClientFMCookie ->
            {OFMessages, FwdTable1} = handle_flow_stats_reply(
                                        Msg, Dpid, FwdTable0),
            {reply, OFMessages ++ CurrOFMesssages,
             State#state{fwd_table = FwdTable1}};
        _ ->
            {reply, CurrOFMesssages, State}
    end.


handle_cast(_Request, State) ->
    {noreply, State}.


handle_info({remove_entry, Dpid, SrcMac},
            #state{fwd_table = FwdTable} = State) ->
    lager:debug("Removed forwarding entry in ~p: ~p => ~p",
                [Dpid, format_mac(SrcMac), maps:get(SrcMac,
                                                    FwdTable)]),
    {noreply, State#state{fwd_table = maps:remove(SrcMac, FwdTable)}};
handle_info({send_flow_stats_request, Dpid, IpSrc, TCPSrc}, State) ->
    handle_flow_stats_request(Dpid, IpSrc, TCPSrc),
    {noreply, State}.


terminate(_Reason, _State) ->
    ok.


code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

subscriptions() ->
    [packet_in, flow_stats_reply].


handle_init_fm_packet_in({_, Xid, PacketIn}, DatapathId, FwdTable0) ->
    [IpSrc, TCPSrc] = packet_in_extract([ipv4_src, tcp_src], PacketIn),
    FM = client_flow_mod(IpSrc, TCPSrc),
    PO = packet_out(Xid, PacketIn, 1),
    %% TODO: Schedule remove entry
    schedule_stats_check(DatapathId, IpSrc, TCPSrc),
    {[FM, PO], maps:put({IpSrc, TCPSrc}, FM, FwdTable0)}.

handle_flow_stats_request(DatapathId, IpSrc, TCPSrc) ->
    FlowStats = flow_stats_request(?CLIENT_FM_COOKIE(forward),
                                   IpSrc, TCPSrc),
    ofs_handler:send(DatapathId, FlowStats).

handle_flow_stats_reply({_, FlowStatsReply}, _DatapathId, FwdTable0) ->
    [IpSrc, TCPSrc, PacketCount, DurationSec] =
        flow_stats_extract([ipv4_src,
                            tcp_src,
                            packet_count,
                            duration_sec], FlowStatsReply),
    case packets_threshold_exceeded(PacketCount, DurationSec) of
        true ->
            FM = client_drop_flow_mod(IpSrc, TCPSrc),
            {[FM], maps:put({IpSrc, TCPSrc}, FM, FwdTable0)};
        false ->
            {[], FwdTable0}
    end.

packets_threshold_exceeded(PacketCount, DurationSec) ->
    PacketCount div DurationSec > ?MAX_PACKETS_PER_SECOND.

schedule_stats_check(DatapathId, IpSrc, TCPSrc) ->
    timer:send_after(?FLOW_STAT_REQUEST_INTERVAL, 
                     {send_flow_stats_request,
                      DatapathId, IpSrc, TCPSrc}).

format_mac(MacBin) ->
    Mac0 = [":" ++ integer_to_list(X, 16) || <<X>> <= MacBin],
    tl(lists:flatten(Mac0)).

schedule_remove_entry(SrcMac, Dpid) ->
    {ok, _Tref} = timer:send_after(?ENTRY_TIMEOUT,
                                   {remove_entry, Dpid, SrcMac}).

%% ------------------------------------------------------------------
%% Internal Functions: OpenFlow related
%% ------------------------------------------------------------------

init_flow_mod() ->
    Matches = [{eth_type, 16#0800}, {ip_proto, <<6>>}, {tcp_dst, <<5222:16>>}],
    Instructions = [{apply_actions, [{output, controller, no_buffer}]}],
    FlowOpts = [{table_id, 0}, {priority, 150},
                {idle_timeout, 0},
                {idle_timeout, 0},
                {cookie, ?INIT_FM_COOKIE},
                {cookie_mask, <<0,0,0,0,0,0,0,0>>}],
    of_msg_lib:flow_add(?OF_VER, Matches, Instructions, FlowOpts).


client_drop_flow_mod(IpSrc, TCPSrc) ->
    Matches = client_flow_mod_matches(IpSrc, TCPSrc),
    Instructions = [{apply_actions, []}],
    FlowOpts = [{table_id, 0}, {priority, 150},
                {idle_timeout, 0},
                {idle_timeout, 0},
                {cookie, ?CLIENT_FM_COOKIE(drop)},
                {cookie_mask, <<0,0,0,0,0,0,0,0>>}],
    of_msg_lib:flow_add(?OF_VER, Matches, Instructions, FlowOpts).

client_flow_mod(IpSrc, TCPSrc) ->
    Matches = client_flow_mod_matches(IpSrc, TCPSrc),
    Instructions = [{apply_actions, [{output, 1, no_buffer}]}],
    FlowOpts = [{table_id, 0}, {priority, 150},
                {idle_timeout, ?FM_TIMEOUT_S(forward, idle)},
                {idle_timeout, ?FM_TIMEOUT_S(forward, hard)},
                {cookie, ?CLIENT_FM_COOKIE(forward)},
                {cookie_mask, <<0,0,0,0,0,0,0,0>>}],
    of_msg_lib:flow_add(?OF_VER, Matches, Instructions, FlowOpts).

client_flow_mod_matches(IpSrc, TCPSrc) ->
    [{eth_type, 16#0800},
     {ip_src, IpSrc},
     {ip_proto, <<6>>},
     {tcp_src, TCPSrc},
     {tcp_dst, <<5222:16>>}].

packet_out(Xid, PacketIn, OutPort) ->
    Actions = [{output, OutPort, no_buffer}],
    {InPort, BufferIdOrPacketPortion} =
        case packet_in_extract(buffer_id, PacketIn) of
            no_buffer ->
                packet_in_extract([in_port, data], PacketIn);
            BufferId when is_integer(BufferId) ->
                {packet_in_extract(in_port, PacketIn), BufferId}
        end,
    PacketOut =  of_msg_lib:send_packet(?OF_VER,
                                        BufferIdOrPacketPortion,
                                        InPort,
                                        Actions),
    PacketOut#ofp_message{xid = Xid}.

flow_stats_request(ClientFlowModCookie, IpSrc, TCPSrc) ->
    Matches = client_flow_mod_matches(IpSrc, TCPSrc),
    TableId = 0,
    Cookie = ClientFlowModCookie,
    of_msg_lib:get_flow_statistics(?OF_VER,
                                   TableId,
                                   Matches,
                                   [{cookie, Cookie},
                                    {cookie_mask, Cookie}]).

packet_in_extract(Elements, PacketIn) when is_list(Elements) ->
    [packet_in_extract(H, PacketIn) || H <- Elements];
packet_in_extract(src_mac, PacketIn) ->
    <<_:6/bytes, SrcMac:6/bytes, _/binary>> = proplists:get_value(data, PacketIn),
    SrcMac;
packet_in_extract(dst_mac, PacketIn) ->
    <<DstMac:6/bytes, _/binary>> = proplists:get_value(data, PacketIn),
    DstMac;
packet_in_extract(dst_mac, PacketIn) ->
    <<DstMac:6/bytes, _/binary>> = proplists:get_value(data, PacketIn),
    DstMac;
packet_in_extract(in_port, PacketIn) ->
    <<InPort:32>> = proplists:get_value(in_port, proplists:get_value(match, PacketIn)),
    InPort;
packet_in_extract(buffer_id, PacketIn) ->
    proplists:get_value(buffer_id, PacketIn);
packet_in_extract(data, PacketIn) ->
    proplists:get_value(data, PacketIn);
packet_in_extract(reason, PacketIn) ->
    proplists:get_value(reason, PacketIn);
packet_in_extract(cookie, PacketIn) ->
    proplists:get_value(cookie, PacketIn);
packet_in_extract(ipv4_src, PacketIn) ->
    proplists:get_value(ipv4_src, PacketIn);
packet_in_extract(tcp_src, PacketIn) ->
    proplists:get_value(tcp_src, PacketIn).


flow_stats_extract(Elements, FlowStats) when is_list(Elements) ->
    [packet_in_extract(H, FlowStats) || H <- Elements];
flow_stats_extract(duration, FlowStats) ->
    proplists:get_value(duration_sec, flow_stats_extract(flows, FlowStats));
flow_stats_extract(packet_count, FlowStats) ->
    proplists:get_value(packet_count, flow_stats_extract(flows, FlowStats));
flow_stats_extract(flows, FlowStats) ->
    hd(proplists:get_value(flows, FlowStats));
flow_stats_extract(match, FlowStats) ->
    proplists:get_value(match, flow_stats_extract(flows, FlowStats));
flow_stats_extract(ip_src, FlowStats) ->
    proplists:get_value(ipv4_src, flow_stats_extract(match, FlowStats));
flow_stats_extract(tcp_src, FlowStats) ->
    proplists:get_value(tcp_src, flow_stats_extract(match, FlowStats));
flow_stats_extract(cookie, FlowStats) ->
    proplists:get_value(cookie, flow_stats_extract(flows, FlowStats)).
