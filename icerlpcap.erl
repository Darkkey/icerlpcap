-module(icerlpcap).
-export([lookup/0, opendevice/1, capture/0, setfilter/1, close/0, test_loop/1]).

-type pcap_device_name() :: string().
-type pcap_device_desc() :: string().
-type pcap_device() :: tuple(pcap_device_name(), pcap_device_desc()).
-type pcap_filter() :: string().

-on_load(init/0).

init() ->
    ok = erlang:load_nif("icerlpcap", 0).

-spec init() -> [X :: pcap_device()].
%% @doc Returns a list of PCAP devices.
lookup() ->
    exit(nif_library_not_loaded).

-spec opendevice(pcap_device_name()) -> ok | {error, string()}.
%% @doc opens the device
opendevice(_Device) ->
    exit(nif_library_not_loaded).

-spec capture() -> {ok, binary()}.
%% @doc captures one packet (WARN: blocks the WHOLE erlang VM)
capture() ->
	exit(nif_library_not_loaded).

-spec setfilter(pcap_filter()) -> ok | {error, string()}.
%% @doc sets the PCAP filter on the opened interface
setfilter(_FilterString) ->
	exit(nif_library_not_loaded).

-spec close() -> ok.
% @doc closes the pcap device
close() -> 
	exit(nif_library_not_loaded).

test_loop(0) ->  
    ok;  
test_loop(Count) ->  
    {ok, Pkt} = capture(),  
    io:format("~p~n", [Pkt]),  
    test_loop(Count-1).  