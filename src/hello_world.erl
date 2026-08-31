-module(hello_world).
-export([greet/1, encode_message/1]).

greet(Name) when is_binary(Name) ->
    Message = #{name => Name, status => <<"success">>},
    encode_message(Message);
greet(Name) when is_list(Name) ->
    Message = #{name => Name, status => <<"success">>},
    encode_message(Message).

encode_message(Map) ->
    jiffy:encode(Map).
