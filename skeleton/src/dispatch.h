#ifndef CS241_DISPATCH_H
#define CS241_DISPATCH_H

#include <pcap.h>

//was void before
void dispatch(const struct pcap_pkthdr *header,
              const unsigned char *packet,
              int verbose);

#endif
