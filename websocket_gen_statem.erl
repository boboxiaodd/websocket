-module(websocket_gen_statem).
-behaviour(gen_statem).
-export([start_link/0, set_socket/2]).
-export([init/1, handle_event/4,terminate/3, code_change/4]).

-define(RECV_TIMEOUT,{timeout,60000,{recv_timeout}}).
-define(CONN_TIMEOUT,{timeout,5000,{conn_timeout}}).
-define(PACKET,0).
-define(PACKETTYPE,binary).
-define(MAGIC_STRING,"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").

start_link() ->
    gen_statem:start_link(?MODULE, [], []).

% from tcp_acceptor
set_socket(Pid, Socket) when is_pid(Pid), is_port(Socket) ->
    gen_statem:cast(Pid, {socket_ready, Socket }).


init([]) ->
    process_flag(trap_exit, true),
    State = #{},
    {handle_event_function, wait_for_socket , State}.

handle_event(cast,{socket_ready,Socket},wait_for_socket,_State) ->
    inet:setopts(Socket, [?PACKETTYPE, {packet, ?PACKET}, {active, once}]),
    {next_state,wait_for_data,#{socket => Socket,
                                  mode => hande,
                                   uid => 0
                                },?CONN_TIMEOUT};

handle_event(timeout,_,_,#{socket:=Socket} = State) ->
    gen_tcp:send(Socket, <<"CONNECT-TIMEOUT\r\n">>),
    {stop,normal,State};



handle_event(info,{tcp, Socket, Bin},wait_for_data,#{socket := Socket , mode := Mode} = State) ->
    inet:setopts(Socket, [{active, once}]),
    case Mode of
        hande ->  %the first request is hande
            case handshake(Socket, parse_header(Bin)) of
                true  ->
                    {keep_state,State#{mode=>connect}};
                false ->
                    {stop,normal,State}
            end;
        _ ->
            Result = get_packet_data(Bin),
            case is_binary_data(Result) of
                true -> Data = binary_to_list(Result);
                false -> Data = Result
            end,
            Ref    = pid_to_list(self()),
            send_packet(Socket, Ref++":"++Data),
            {keep_state,State}
    end;
    
handle_event(info,{tcp_error,_,_},_,State) ->
    {stop, normal, State};


handle_event(info,{tcp_closed,_,_},_,State) ->
    {stop, normal, State};

handle_event(info,_Event,_,State) ->  
    {stop, normal, State}.


terminate(_Reason, _StateName,   _State) ->
    ok.
    
code_change(_OldVsn, OldState, StateData, _Extra) ->
    {handle_event_function,OldState,StateData}.

%main function 
parse_header(Packet) ->
    _T = [string:tokens(X, ":") || X <-string:tokens(binary_to_list(Packet), "\r\n")],
    T  = [X || X <-_T, length(X) =:= 2],
    parse_header(T, maps:new()).


parse_header([H | T], Map) ->
    [K, V] = H,
    parse_header(T, maps:put(string:strip(K, both), string:strip(V, both), Map));
parse_header([], Map) ->
    Map.

handshake(Socket, Header)->
    case maps:find("Sec-WebSocket-Key", Header) of
        {ok, Key} ->
            Hash = gen_hash(string:concat(Key, ?MAGIC_STRING)),
            _X = ["HTTP/1.1 101 Switching Protocols", "Upgrade: websocket", "Connection: Upgrade\r\n"],
            _T = string:concat("Sec-WebSocket-Accept: ", string:concat(Hash, "\r\n\r\n")),
            _Y = string:join(_X, "\r\n"),
            Response = string:concat(_Y, _T),
            %io:format("~p~n", [Response]).
            case gen_tcp:send(Socket, Response) of
                ok ->
                    true;
                _ ->
                    false
            end;
        _ ->
            gen_tcp:send(Socket, <<"NOT-WEBSOCKET-PROTOCOL\r\n">>),
            false
    end.

get_packet_data(Packet) ->
    <<_FIN: 1, _RSV1: 1, _RSV2: 1, _RSV3: 1,
      _OPCODE: 4,
      _MASK: 1,
      PAYLOADLEN: 7,
      Rest/binary>> = Packet,

    if
        PAYLOADLEN =< 125 ->
            <<MASK_KEY1: 8, MASK_KEY2: 8, MASK_KEY3: 8, MASK_KEY4: 8, PAYLOAD/binary>> = Rest,
            MASK_KEY = [MASK_KEY1, MASK_KEY2, MASK_KEY3, MASK_KEY4],
            get_packet_data(binary_to_list(PAYLOAD), MASK_KEY, 0, []);
        PAYLOADLEN == 126 ->
            <<_LENGTH: 16, MASK_KEY1: 8, MASK_KEY2: 8, MASK_KEY3: 8, MASK_KEY4: 8,
              PAYLOAD/binary>> = Rest,
            MASK_KEY = [MASK_KEY1, MASK_KEY2, MASK_KEY3, MASK_KEY4],
            get_packet_data(binary_to_list(PAYLOAD), MASK_KEY, 0, []);
        PAYLOADLEN == 127 ->
            <<_LENGTH: 64, MASK_KEY1: 8, MASK_KEY2: 8, MASK_KEY3: 8, MASK_KEY4: 8,
              PAYLOAD/binary>> = Rest,
            MASK_KEY = [MASK_KEY1, MASK_KEY2, MASK_KEY3, MASK_KEY4],
            get_packet_data(binary_to_list(PAYLOAD), MASK_KEY, 0, [])
    end.

get_packet_data([H | T], Key, Counter, Result) ->
    get_packet_data(T, Key, Counter + 1, [H bxor lists:nth((Counter rem 4) + 1, Key) | Result]);
get_packet_data([], _, _, Result) ->
    lists:reverse(Result).


send_packet(Socket, Data) ->
    LIMIT = round(math:pow(2, 16)) - 1,
    case is_binary_data(Data) of
        true ->
            OPCODE = 2,
            PAYLOAD_LENGTH = lists:flatlength(binary_to_list(Data));
        false ->
            OPCODE = 1,
            PAYLOAD_LENGTH = lists:flatlength(Data)
    end,

    if
        PAYLOAD_LENGTH =< 125 ->
            Packet = build_packet(OPCODE, PAYLOAD_LENGTH, 0, 0, Data);
        PAYLOAD_LENGTH =< LIMIT ->
            Packet = build_packet(OPCODE, 126, PAYLOAD_LENGTH, 16, Data);
        true ->
            Packet = build_packet(OPCODE, 127, PAYLOAD_LENGTH, 32, Data)
    end,

    %io:format("~p~n", [Packet]),
    case gen_tcp:send(Socket, Packet) of
        ok ->
            true;
        _ ->
            false
    end.
build_packet(Opcode, PayloadLen, Extend, Length, Data) ->
    case Opcode of
        1 ->
            Packet = <<1: 1, 0: 3, Opcode: 4, PayloadLen: 8, Extend: Length>>,
            Binary = list_to_binary(Data),
            <<Packet/binary, Binary/binary>>;
        2 ->
            Packet = <<1: 1, 0: 3, Opcode: 4, 1: 1, PayloadLen: 7, Extend: Length>>,
            <<Packet/binary, Data/binary>>
    end.


is_binary_data(<<_Binary/binary>> = _Data) ->
    true;
is_binary_data(_) ->
    false.

gen_hash(Key) ->
    base64:encode_to_string(crypto:hash(sha, Key)).
