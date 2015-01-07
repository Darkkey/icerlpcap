-module(icerlpcap).
-export([lookup/0, opendevice/1, capture/0, setfilter/1, close/0, test_loop/1]).

-on_load(init/0).

init() ->
    ok = erlang:load_nif("icerlpcap", 0).

lookup() ->
    exit(nif_library_not_loaded).

opendevice(_Device) ->
    exit(nif_library_not_loaded).

capture() ->
	exit(nif_library_not_loaded).

setfilter(_FilterString) ->
	exit(nif_library_not_loaded).

close() -> 
	exit(nif_library_not_loaded).

test_loop(0) ->  
    ok;  
test_loop(Count) ->  
    {ok, Pkt} = capture(),  
    io:format("~p~n", [Pkt]),  
    test_loop(Count-1).  