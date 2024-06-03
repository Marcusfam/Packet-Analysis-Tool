#ifndef CS241_QUEUE_H
#define CS241_QUEUE_H
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>

typedef struct params{
  int verbose;
  const unsigned char *packet;
  struct pcap_pkthdr *header;
} params;

struct node{ // data structure for each node
  struct params item;
  struct node *next;
};

struct queue{ // data structure for queue
  struct node *head;
  struct node *tail;
};

struct queue *create_q(void);

void enqueue(struct queue *q, struct params item);

int isempty(struct queue *q);

void dequeue(struct queue *q);


void destroy_q(struct queue *q);


#endif