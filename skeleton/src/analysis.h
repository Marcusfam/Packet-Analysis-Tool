#ifndef CS241_ANALYSIS_H
#define CS241_ANALYSIS_H
//#include "dispatch.h"
#include <pcap.h>

extern int flag;

//was void
void analyse(struct pcap_pkthdr *header,
              const unsigned char *packet,
              int verbose);

#endif
