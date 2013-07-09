-module(erpcap).
-export([foo/1, bar/1, lookup/0, lookup_device_name/1, opendevice/1, capture/0, loop/1]).
-on_load(init/0).

init() ->
    ok = erlang:load_nif("x64/Debug/erpcap", 0).


foo(_X) ->
    exit(nif_library_not_loaded).
bar(_Y) ->
    exit(nif_library_not_loaded).

lookup() ->
    exit(nif_library_not_loaded).

lookup_device_name(_N) ->
    exit(nif_library_not_loaded).

opendevice(_Device) ->
    exit(nif_library_not_loaded).

capture() ->
	exit(nif_library_not_loaded).

loop(0) ->  
    ok;  
loop(Count) ->  
    Pkt = capture(),  
    io:format("~p~n", [Pkt]),  
    loop(Count-1).  