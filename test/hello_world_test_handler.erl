%% Cowboy handler used only by hello_world_http_tests: answers /greet/:name
%% with the JSON greeting from hello_world:greet/1.
-module(hello_world_test_handler).
-export([init/2]).

init(Req0, State) ->
    Name = cowboy_req:binding(name, Req0),
    Req = cowboy_req:reply(200,
                           #{<<"content-type">> => <<"application/json">>},
                           hello_world:greet(Name),
                           Req0),
    {ok, Req, State}.
