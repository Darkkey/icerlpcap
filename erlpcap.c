#include "erlpcap.h"

static const int max_intf = 32;
static const char _str_NULL[] = "NULL";
  
pcap_t *devHandler = NULL;  
bpf_u_int32 mask;
bpf_u_int32 net;

#pragma comment(lib, "wpcap.lib")

static ERL_NIF_TERM lookup_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])  
{  
    int i = 0;  
    char errbuf[PCAP_ERRBUF_SIZE], str[256];  
    pcap_if_t *alldevs;  
    pcap_if_t *d; 
	ERL_NIF_TERM terms = enif_make_list(env, 0);
  
  
    if (pcap_findalldevs_ex("rpcap://", NULL /* auth is not needed */, &alldevs, errbuf) == -1)  
		return enif_make_tuple(env, 2, enif_make_atom(env, "error"), enif_make_string(env, errbuf, ERL_NIF_LATIN1));
  

    for(d = alldevs; d != NULL && i < max_intf; d= d->next, i = i + 1)  
    {  
		memset(str, 0, sizeof(str));
		
		sprintf_s(str, sizeof(str), "%d. %s (%s)", i + 1, d->description, d->name);

		terms = enif_make_list_cell(env, 
			enif_make_tuple(env, 2, 
				enif_make_string(env, d->name, ERL_NIF_LATIN1),
				enif_make_string(env, d->description, ERL_NIF_LATIN1))			
			, terms);
    }  
  
    pcap_freealldevs(alldevs);  
	return terms;
}  

static ERL_NIF_TERM opendevice_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])  
{  
    char device[64];  
    char errbuf[PCAP_ERRBUF_SIZE];  

	if (!enif_get_string (env, argv[0], device, sizeof(device), ERL_NIF_LATIN1)) {
		return enif_make_badarg(env);
    }

	if (pcap_lookupnet(device, &net, &mask, errbuf) == -1) {
		net = 0;
		mask = 0;
	}
  
    /* Parms: dev,snaplen,promisc,timeout_ms,errbuf 
     * to_ms=0 means wait enough packet to arrive. 
     */  
    devHandler = pcap_open_live(device, 65535, 1, 0, errbuf);  
    if(devHandler != NULL)  
        return enif_make_atom(env, "ok");  
    else  
		return enif_make_tuple(env, 2, enif_make_atom(env, "error"), enif_make_string(env, errbuf, ERL_NIF_LATIN1));
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
	return enif_make_tuple(env, 2, enif_make_atom(env, "ok"), enif_make_binary(env, &bin));
}  

static ERL_NIF_TERM setfilter_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
	char err_str[1024];
	char filter_exp[1024];
	struct bpf_program fp;

	if (!enif_get_string(env, argv[0], filter_exp, sizeof(filter_exp), ERL_NIF_LATIN1)) {
		return enif_make_badarg(env);
	}

	if (pcap_compile(devHandler, &fp, filter_exp, 0, net) == -1) {
		sprintf_s(err_str, sizeof(err_str), "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(devHandler));
		return enif_make_tuple(env, 2, enif_make_atom(env, "error"), enif_make_string(env, err_str, ERL_NIF_LATIN1));
	}

	if (pcap_setfilter(devHandler, &fp) == -1) {
		sprintf_s(err_str, sizeof(err_str), "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(devHandler));
		return enif_make_tuple(env, 2, enif_make_atom(env, "error"), enif_make_string(env, err_str, ERL_NIF_LATIN1));
	}

	return enif_make_atom(env, "ok");
}

static ERL_NIF_TERM close_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
	pcap_close(devHandler);
		
	return enif_make_atom(env, "ok");
}

static ErlNifFunc nif_funcs[] = {
	{"lookup", 0, lookup_nif},
	{"opendevice", 1, opendevice_nif},
	{"capture", 0, capture_nif},
	{"setfilter", 1, setfilter_nif },
	{"close", 0, close_nif}
};

ERL_NIF_INIT(icerlpcap, nif_funcs, NULL, NULL, NULL, NULL)