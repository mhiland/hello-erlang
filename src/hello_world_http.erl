%% Fetches a greeting document, as produced by hello_world:greet/1, over HTTP.
-module(hello_world_http).
-export([fetch_greeting/1]).

%% GETs Url with hackney and decodes the JSON greeting in the body.
-spec fetch_greeting(binary() | string()) -> {ok, map()} | {error, term()}.
fetch_greeting(Url) ->
    case hackney:request(get, Url, [], <<>>, [with_body]) of
        {ok, 200, _Headers, Body} -> decode(Body);
        {ok, Status, _Headers, _Body} -> {error, {unexpected_status, Status}};
        {error, Reason} -> {error, Reason}
    end.

decode(Body) ->
    try jsx:decode(Body, [return_maps]) of
        #{<<"name">> := _} = Greeting -> {ok, Greeting};
        _Other -> {error, not_a_greeting}
    catch
        error:badarg -> {error, invalid_json}
    end.
