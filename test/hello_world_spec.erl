-module(hello_world_spec).
-include_lib("eunit/include/eunit.hrl").

hello_world_test_() ->
    {setup,
     fun() -> ok end,
     fun(_) -> ok end,
     [
      ?_test(begin
                Result = hello_world:greet(<<"Tester">>),
                Data = jiffy:decode(Result, [return_maps]),
                ?assertEqual(<<"Tester">>, maps:get(name, Data))
             end)
     ]}.
