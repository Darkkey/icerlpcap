#include "erlpcap.h"

static const int max_intf = 32;
static const char _str_NULL[] = "NULL";
  
pcap_t *devHandler = NULL;  

#pragma comment(lib, "C:\\Tools\\WpdPack\\Lib\\x64\\wpcap.lib")

int foo(int x){
	return 1 - x;
}

int bar(int y){
	return y + 1;
}

static ERL_NIF_TERM lookup_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])  
{  
    int i = 0;  
    char errbuf[PCAP_ERRBUF_SIZE], str[256];  
    pcap_if_t *alldevs;  
    pcap_if_t *d; 
	ERL_NIF_TERM terms = enif_make_list(env, 0);
  
  
    if (pcap_findalldevs_ex("rpcap://", NULL /* auth is not needed */, &alldevs, errbuf) == -1)  
        return enif_make_string(env, errbuf, ERL_NIF_LATIN1);  
  

    for(d = alldevs; d != NULL && i < max_intf; d= d->next, i = i + 1)  
    {  
		memset(str, 0, sizeof(str));
		
		sprintf_s(str, sizeof(str), "%d. %s (%s)", i + 1, d->description, d->name);

		terms = enif_make_list_cell(env, enif_make_atom(env, str), terms);		
    }  
  
    pcap_freealldevs(alldevs);  
	return terms;
}  


static ERL_NIF_TERM lookup_device_name_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])  
{  
    int i = 1;  // shift + 1 (erlang lists starts from 1, but C from 0)
	int n = 1;

    char errbuf[PCAP_ERRBUF_SIZE];  
    pcap_if_t *alldevs;  
    pcap_if_t *d; 

	ERL_NIF_TERM _term = enif_make_string(env, "invalid interface index", ERL_NIF_LATIN1);  

	if (!enif_get_int(env, argv[0], &n)) {
		return enif_make_badarg(env);
    }
		
    if (pcap_findalldevs_ex("rpcap://", NULL /* auth is not needed */, &alldevs, errbuf) == -1)  
        return enif_make_string(env, errbuf, ERL_NIF_LATIN1);  
  

    for(d = alldevs; d != NULL && i < max_intf; d= d->next, i = i + 1)  
    {  
		if(i == n){
			_term = enif_make_string(env, d->name, ERL_NIF_LATIN1);
		}
    }  
  
    pcap_freealldevs(alldevs);  

	return _term;
} 

static ERL_NIF_TERM opendevice_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])  
{  
    char device[64];  
    char errbuf[PCAP_ERRBUF_SIZE];  

	if (!enif_get_string (env, argv[0], device, sizeof(device), ERL_NIF_LATIN1)) {
		return enif_make_badarg(env);
    }
	
  
    //memset(errbuf, 0, PCAP_ERRBUF_SIZE);  
    /* return enif_make_string(env, dev); */  
  
    /* Parms: dev,snaplen,promisc,timeout_ms,errbuf 
     * to_ms=0 means wait enough packet to arrive. 
     */  
    devHandler = pcap_open_live(device, 65535, 1, 0, errbuf);  
    if(devHandler != NULL)  
        return enif_make_atom(env, "ok");  
    else  
        return enif_make_string(env, errbuf, ERL_NIF_LATIN1);  
}  



static ERL_NIF_TERM foo_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    int x, ret;
    if (!enif_get_int(env, argv[0], &x)) {
	return enif_make_badarg(env);
    }
    ret = foo(x);
    return enif_make_int(env, ret);
}

static ERL_NIF_TERM bar_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    int y, ret;
    if (!enif_get_int(env, argv[0], &y)) {
	return enif_make_badarg(env);
    }
    ret = bar(y);
    return enif_make_int(env, ret);
}

static ERL_NIF_TERM capture_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])  
{  
    struct pcap_pkthdr pkthdr;  
    const u_char *packet = NULL;  
    ErlNifBinary bin;  
	
    packet = pcap_next(devHandler, &pkthdr);  
    if(packet != NULL)  
    {  
        enif_alloc_binary(pkthdr.len, &bin);  
		memcpy(bin.data, packet, pkthdr.len);
    }  
    else  
    {  
        bin.size = sizeof(_str_NULL);  
		enif_alloc_binary(bin.size, &bin);  
        memcpy(bin.data, _str_NULL, bin.size);  
    }  
    return enif_make_binary(env, &bin);  
}  


static ErlNifFunc nif_funcs[] = {
    {"foo", 1, foo_nif},
    {"bar", 1, bar_nif},
	{"lookup", 0, lookup_nif},
	{"lookup_device_name", 1, lookup_device_name_nif},
	{"opendevice", 1, opendevice_nif},
	{"capture", 0, capture_nif}
};

ERL_NIF_INIT(erpcap, nif_funcs, NULL, NULL, NULL, NULL)