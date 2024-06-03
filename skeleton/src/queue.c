#include <string.h>
#include <stdlib.h>
#include <stdio.h>

//#include "queue.h"

#include <stdio.h>
#include <stdlib.h>
#include "queue.h"


/* Queue inspired by CS241 labs*/

struct queue *create_q(void){ //creates a queue and returns its pointer
  struct queue *q=(struct queue *)malloc(sizeof(struct queue));
  q->head=NULL;
  q->tail=NULL;
  return(q);
}

void destroy_q(struct queue *q){  //destroys the queue and frees the memory
  while(!isempty(q)){
    dequeue(q);
  }
  free(q);
}


void enqueue(struct queue *q, struct params item){ //enqueues a node with an item
  struct node *new_node=(struct node *)malloc(sizeof(struct node));
  new_node->item=item;
  new_node->next=NULL;
  if(isempty(q)){
    q->head=new_node;
    q->tail=new_node;
  }
  else{
    q->tail->next=new_node;
    q->tail=new_node;
  }
}

int isempty(struct queue *q){ // checks if queue is empty
  return(q->head==NULL);
}


void dequeue(struct queue *q){ //dequeues a the head node
  struct node *head_node;
  if(isempty(q)){
    printf("Error: attempt to dequeue from an empty queue");
  }
  else{
    head_node=q->head;
    q->head=q->head->next;
    if(q->head==NULL)
      q->tail=NULL;
    free(head_node);
  }
}





