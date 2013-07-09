/* original author: xumingyong (http://xumingyong.iteye.com/blog/586743) */
#ifndef __ERLPCAP_H
#define __ERLPCAP_H

#include <stdio.h>  
#include <pcap.h>  
#include <string.h>  
#include <ctype.h>  

#include "erl_nif.h"

// WIN64 VS PCAP definitions
extern int pcap_findalldevs_ex(char *source, struct pcap_rmtauth *auth, pcap_if_t **alldevs, char *errbuf);

#endif  