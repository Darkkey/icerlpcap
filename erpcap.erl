%%% erlang sniffer
%%% original author: xumingyong (http://xumingyong.iteye.com/blog/586743)  
  
-module(erpcap).  
-on_load(on_load/0).  
  
-export([lookup/0, opendevice/1, capture/0, loop/1]).  
  
on_load() ->  
    ok = erlang:load_nif("./erpcap", 0),  
    true.  
  
lookup() ->  
    error.  
  
opendevice(_Interface) ->  
    error.  
  
capture() ->  
    error.  
  
loop(0) ->  
    ok;  
loop(Count) ->  
    Pkt = capture(),  
    io:format("~p~n", [Pkt]),  
    loop(Count-1).  