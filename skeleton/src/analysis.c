
#include "queue.h"
#include "analysis.h"
#include <stdio.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>


#define INITIALSIZE 10


/*
Flags/temporary counts are used to store information on packets which are added at the end 
to ensure changes are made at the end of execution to avoid having
to use too many mutex locks throughout code.
*/

extern struct queue *work_queue; //labeled extern so can be freed in handle_sigint here

int count=0;                      //total num of SYN packets
int countARP=0;                   //total num of arpPackets
int countBlack=0;                 //total num of blacklisted URLS
int countUnique=0;                //total num of Unique Syn packets (number of elements in array)
int countBlackG=0;                //total num of google URLs
int countBlackF=0;                //total num of facebook URLs
int checker=0;                    //remove

int firstTimeFlag=0;              //flag to check whether to allocate memory to build an array for the first time
struct in_addr *ip_addresses;     //Dynamic array holding distinct IPs encountered
int max_ip_addresses=INITIALSIZE; //size of array, starting at INITIALSIZE
int findDistinct(struct in_addr *ip_ads, int size);

pthread_mutex_t countMutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t memMutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t aMutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t kMutex = PTHREAD_MUTEX_INITIALIZER;

//print findings when program terminated
void handle_sigint(int sig)
{ 
  //int countUnique=findDistinct(ip_addresses,count);   //can be used(more accurate for 100k+ packets but slower)
  printf("Intrusion Detection Report: \n");
  printf("SYN packets detected from %d  different IPs \n",countUnique);
  printf("SYN packets sent: %d \n",count);//count extern
  printf("ARP responses: %d \n",countARP);
  printf("Blacklist Violations: %d  (%d google , %d facebook ) \n",countBlack, countBlackG ,countBlackF);
  free(ip_addresses);
  destroy_q(work_queue);
  exit(0);
}


void analyse(struct pcap_pkthdr *header,const unsigned char *packet,int verbose) {
              
  signal(SIGINT, handle_sigint);  
  //flags to check attributes of packets which are considered at the end of analyse together
  int countFlag=0;
  int countARPFlag=0;
  int countBlackFlag=0;
  int countBlackFlagF=0;
  int countBlackFlagG=0;
              
  struct ip *ip_header= (struct ip *)(packet+(ETH_HLEN)); //pointer to where ip header starts
  int ipLength=(ip_header->ip_hl);
  struct tcphdr *tcp_header= (struct tcphdr *) (packet+(ETH_HLEN)+(ipLength*4));  //pointer to where tcp header starts
  
  //create ip address array if doesnt exist and set size to INITIALSIZE
  if (firstTimeFlag==0){
    firstTimeFlag=firstTimeFlag+1;
    struct in_addr *temp_ip_addresses = malloc(sizeof(struct in_addr) * max_ip_addresses);  //starts with INITIALSIZE
    if (temp_ip_addresses){   //check for allocation errors
    ip_addresses=temp_ip_addresses;
    }else{
      printf("Out of memory \n");
    }
  }
  
  //Count number of SYN packets
  if (tcp_header->syn==1 && tcp_header->urg == 0 && tcp_header->rst == 0  && tcp_header->psh == 0  && tcp_header->ack == 0  && tcp_header->ack == 0 ){ 
    int found=0;  
    countFlag=1;    //stores number of syn packets sent in total
    
    //Add item to array if it is not found
    pthread_mutex_lock(&aMutex);
    for (int i = 0; i < countUnique; i++) {
      if ( ip_addresses[i].s_addr ==  ip_header->ip_src.s_addr  ) {
        found = 1;
        break;
    }
    }
    pthread_mutex_unlock(&aMutex);

    if (found==0){  
      pthread_mutex_lock(&memMutex);
      ip_addresses[countUnique] = (struct in_addr)ip_header->ip_src; //add item 
      countUnique=countUnique+1;
      pthread_mutex_unlock(&memMutex);
    }
  }


  //if array full, double size
  pthread_mutex_lock(&kMutex);
  if (max_ip_addresses  <=  (countUnique) ){
    max_ip_addresses = max_ip_addresses*2;
    struct in_addr *temp_ip_addresses = realloc(ip_addresses, sizeof(struct in_addr) * max_ip_addresses);//double size
    if (temp_ip_addresses){             //check for allocation errors
    ip_addresses=temp_ip_addresses;
    }else{
      printf("Out of memory \n");
    }
  }
  pthread_mutex_unlock(&kMutex);


  struct ether_header *eth_header= (struct ether_header *)(packet);
  if(ntohs(eth_header->ether_type) == ETHERTYPE_ARP){                   //If ARP packet
    struct arphdr *arp_Header = (struct arphdr *) (packet + ETH_HLEN);  //pointer to ARP header
    if(ntohs(arp_Header->ar_op) == ARPOP_REPLY){
      countARPFlag=1;
    }
  }

  //if IP packet, check if requesting blacklisted URL
  if(ntohs(eth_header->ether_type) == ETHERTYPE_IP){   
    const char *payload = (char *) ((char *)tcp_header+(4*tcp_header->doff));
    if((ntohs(tcp_header->th_dport) == 80)){            //if port 80
      char *src= inet_ntoa(ip_header->ip_src);          //get IP source
      char *dest = inet_ntoa(ip_header->ip_dst);        //get IP destinatoin
     if (strstr(payload, "www.facebook.com") ){         //if facebook is in http header
        countBlackFlag=countBlackFlag+1;
        countBlackFlagF=countBlackFlagF+1;
        printf("\n==============================\n");
        printf("Blacklist Intrusion Detected \n");
        printf("Source IP address: %s",src);
        printf("\nDestination IP address: %s",dest);
        printf("\n==============================\n");
      } 
        if (strstr(payload,"www.google.co.uk")){      //if google is in http header
        countBlackFlag=countBlackFlag+1;
        countBlackFlagG=countBlackFlagG+1;
        printf("\n==============================\n");
        printf("Blacklist Intrusion Detected \n");
        printf("Source IP address: %s",src);
        printf("\nDestination IP address: %s",dest);
        printf("\n==============================\n");
     }
    }
  }
  //lock variables when changing to avoid race conditions
  pthread_mutex_lock(&countMutex);
    count += countFlag;
    countARP += countARPFlag;
    countBlack += countBlackFlag;
    countBlackF += countBlackFlagF;
    countBlackG += countBlackFlagG;
  pthread_mutex_unlock(&countMutex);

}




