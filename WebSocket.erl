-module(websocket).
-export([start / 1]).

-define(MAGIC_STRING, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").


start(Port)->
    spawn(fun() -> start_server(Port) end).


start_server(Port) ->
    case gen_tcp:listen(Port, [binary, {packet, 0}, {active, false}]) of
        {ok, ListenSocket} ->
            server(ListenSocket);
        {error, Reason} ->
            {error, Reason}
    end.


server(ListenSocket)->
    %process_flag(trap_exit, true),
    case gen_tcp:accept(ListenSocket) of
        {ok, Socket} ->
            spawn(fun()-> loop(Socket, connecting) end),
            server(ListenSocket);
        {error, Reason} ->
            {error, Reason}
    end.


loop(Socket, Readystate)->
    case gen_tcp:recv(Socket, 0) of
        {ok, Packet} ->
            process_packet(Socket, Packet, Readystate),
            loop(Socket, open);
        {error, closed}->
            closed
    end.


process_packet(Socket, Packet, connecting) ->
    handshake(Socket, parse_header(Packet));
process_packet(Socket, Packet, open)->
    Result = get_packet_data(Packet),
    io:format("~p~n", [Result]),
    send_packet(Socket, Result).


parse_header(Packet) ->
    _T = [string:tokens(X, ":") || X <-string:tokens(binary_to_list(Packet), "\r\n")],
    T  = [X || X <-_T, length(X) =:= 2],
    parse_header(T, maps:new()).


parse_header([H | T], Map) ->
    [K, V] = H,
    parse_header(T, maps:put(string:strip(K, both), string:strip(V, both), Map));
parse_header([], Map) ->
    Map.


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


gen_hash(Key) ->
    crypto:start(),
    base64:encode_to_string(crypto:hash(sha, Key)).


handshake(Socket, Header)->
    {ok, Key} = maps:find("Sec-WebSocket-Key", Header),
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
    end.


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
