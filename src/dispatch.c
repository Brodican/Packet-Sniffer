#include "dispatch.h"
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <pthread.h>
#include "analysis.h"

struct param_pass { // Struct to hold all parameter to be passed to analyse.c. Struct is needed as thread_code function may only take one void pointer,
                    // and there are multiple variable to be passed.
  struct pcap_pkthdr *headerpass;
  const unsigned char *packetpass;
  int verbosepass;
};

void *thread_code(void *arg) { // Function passed to create thread, called on thread creation.
  struct param_pass * params = (struct param_pass *) arg; // Cast void pointer argument to a params struct pointer so variables may be accessed
  analyse(params->headerpass, params->packetpass, params->verbosepass); // Call analyse with variables in params
  free(arg); // Free memory allocated by malloc
  return NULL;
}

void dispatch(struct pcap_pkthdr *header,
              const unsigned char *packet,
              int verbose) { // Dispatch recieves packet and verbose option when called from sniff.

  struct param_pass * params = malloc(sizeof(struct param_pass)); // Allocate memory and variable for a params struct pointer

  // Store variables passed by sniff in the params struct
  params->headerpass = header;
  params->packetpass = packet;
  params->verbosepass = verbose;
  // Make a pthread_t to pass to pthread_create each time a thread is to be made
  pthread_t thread;
  pthread_create(&thread, NULL, &thread_code, (void *) params); // Cast params to void pointer before
                                                                // passing to thread code (since thread code only takes 1 void pointer)
  pthread_detach(thread); // Detach thread so resources allocated to thread are released upon thread completion
  return EXIT_SUCCESS; // Indicates successful exit
}
