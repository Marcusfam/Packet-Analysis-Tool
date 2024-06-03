

#include <pcap.h>
#include "analysis.h"
#include "sniff.h"
#include "queue.h"
#include <pthread.h>
#include <signal.h>
#include <netinet/if_ether.h>

#define NUMTHREADS 12

int start=0;                  //flag used to create queue on first run only
struct queue *work_queue;     //queue holding all packets
pthread_mutex_t queue_mutex=PTHREAD_MUTEX_INITIALIZER; 
pthread_cond_t queue_cond=PTHREAD_COND_INITIALIZER;
pthread_t tid[NUMTHREADS];    //threadpool


/* Function used by threads to analyse packets from the queue*/
void *handle_pack(void *arg){
 while(1){
  	pthread_mutex_lock(&queue_mutex);
    while(isempty(work_queue)){         //waite while empty queue
			pthread_cond_wait(&queue_cond,&queue_mutex);
		}
		struct params elements=work_queue->head->item;    
		dequeue(work_queue);      
		pthread_mutex_unlock(&queue_mutex);
    analyse(elements.header, elements.packet, elements.verbose);  //analyse packed dequeued
  }
}

void dispatch(struct pcap_pkthdr *header,const unsigned char *packet,int verbose) {
  // This method should handle dispatching of work to threads. At present
  // it is a simple passthrough as this skeleton is single-threaded.
    params elements={verbose,packet,header} ;         //structure to pass parameters 
    if (start==0){                                    //ran only once
        work_queue=create_q();
        for(int i=0;i<NUMTHREADS;i++){                //create threads
          pthread_create(&tid[i],NULL,handle_pack,NULL);  //passes in method that threads carry out
       }
       start=start+1;
    }

    //add packets to queue for processing
    pthread_mutex_lock(&queue_mutex);
    enqueue(work_queue,elements);
    pthread_cond_broadcast(&queue_cond);
    pthread_mutex_unlock(&queue_mutex);
    //pthread_cond_signal(&queue_cond);       TODO -decide to keep or not
}

















