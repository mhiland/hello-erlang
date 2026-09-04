-module(hello_world_http_tests).
-include_lib("eunit/include/eunit.hrl").

-define(URL, <<"http://greetings.example/greet">>).

%% Unit tests: hackney is mocked with meck, so no socket is opened.
mocked_hackney_test_() ->
    {setup,
     fun() -> meck:new(hackney, [passthrough, no_link]) end,
     fun(_) -> meck:unload(hackney) end,
     [
      {"decodes the greeting on a 200",
       fun() ->
           expect_body(200, hello_world:greet(<<"Mocked">>)),
           ?assertMatch({ok, #{<<"name">> := <<"Mocked">>, <<"status">> := <<"success">>}},
                        hello_world_http:fetch_greeting(?URL)),
           ?assert(meck:validate(hackney))
       end},
      {"reports an unexpected status",
       fun() ->
           expect_body(404, <<"not here">>),
           ?assertEqual({error, {unexpected_status, 404}},
                        hello_world_http:fetch_greeting(?URL))
       end},
      {"reports a body that is not JSON",
       fun() ->
           expect_body(200, <<"<html>">>),
           ?assertEqual({error, invalid_json}, hello_world_http:fetch_greeting(?URL))
       end},
      {"reports JSON that is not a greeting",
       fun() ->
           expect_body(200, <<"{\"other\":1}">>),
           ?assertEqual({error, not_a_greeting}, hello_world_http:fetch_greeting(?URL))
       end},
      {"passes transport errors through",
       fun() ->
           meck:expect(hackney, request, fun(get, _, _, _, _) -> {error, econnrefused} end),
           ?assertEqual({error, econnrefused}, hello_world_http:fetch_greeting(?URL))
       end}
     ]}.

expect_body(Status, Body) ->
    meck:expect(hackney, request,
                fun(get, ?URL, [], <<>>, [with_body]) -> {ok, Status, [], Body} end).

%% Integration test: the real hackney client against a local cowboy server.
local_server_test_() ->
    {setup,
     fun start_server/0,
     fun stop_server/1,
     fun(BaseUrl) ->
         [
          {"fetches a greeting end to end",
           ?_assertMatch({ok, #{<<"name">> := <<"Ada">>}},
                         hello_world_http:fetch_greeting(<<BaseUrl/binary, "/greet/Ada">>))},
          {"surfaces a 404 from the server",
           ?_assertEqual({error, {unexpected_status, 404}},
                         hello_world_http:fetch_greeting(<<BaseUrl/binary, "/missing">>))}
         ]
     end}.

start_server() ->
    {ok, _} = application:ensure_all_started(cowboy),
    {ok, _} = application:ensure_all_started(hackney),
    Dispatch = cowboy_router:compile([{'_', [{"/greet/:name", hello_world_test_handler, []}]}]),
    {ok, _} = cowboy:start_clear(?MODULE, [{port, 0}], #{env => #{dispatch => Dispatch}}),
    Port = ranch:get_port(?MODULE),
    iolist_to_binary(io_lib:format("http://127.0.0.1:~b", [Port])).

stop_server(_BaseUrl) ->
    ok = cowboy:stop_listener(?MODULE).
