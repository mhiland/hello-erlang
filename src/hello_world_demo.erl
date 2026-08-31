-module(hello_world_demo).
-export([run/0]).

run() ->
    logger:add_hdl_device(error_logger),
    lager:start_link(),

    Name = <<"Claude">> ,
    lager:info("Starting Hello World Demo...", []),

    Result = hello_world:greet(Name),

    io:format("Result: ~s~n", [Result]),
    
    lager:info("Demo finished successfully.", []).
