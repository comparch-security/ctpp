#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <malloc.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sched.h>
#include <getopt.h>
#include <assert.h>
#define ASSERT(x) assert(x != -1)

#include "configuration.h"
#include "../utils/memory_utils.h"
#include "../utils/misc_utils.h"
#include "../list/list_struct.h"


int usehugepage;
int ctppp;
int disableflushp2;
int onecore;
int ppp;
int prime_pool_len;
int drain_pool_len;
int llc_miss_thres;
int help;
////////////////////////////////////////////////////////////////////////////////
// Memory Allocations

uint64_t *shared_mem;
volatile uint64_t *synchronization;
volatile uint64_t *synchronization_params;

volatile helpThread_t *ht_params[HPTHREADS];

////////////////////////////////////////////////////////////////////////////////
// Function declarations

void attacker(int test_option);
void victim();

////////////////////////////////////////////////////////////////////////////////

int main(int argc, char **argv)
{
  //////////////////////////////////////////////////////////////////////////////
  // Process command line arguments

  int option_index=0;
  usehugepage         = 0;
  ctppp               = 1;
  disableflushp2      = 0;
  onecore             = 0;
  ppp                 = 0;
  prime_pool_len      = 8000;
  drain_pool_len      = 20000;
  llc_miss_thres      = 0;
  help                = 0;
  int i;
  while (1) {

    static struct option long_options[] = {
      {"ctpp"                ,   no_argument,            0, 0  },
      {"occupyway"           ,   no_argument,            0, 0  },
      {"setblocktime"        ,   no_argument,            0, 0  },
      {"sbt"                 ,   no_argument,            0, 0  },
      {"rwevset"             ,   no_argument,            0, 0  },
      {"usehugepage"         ,   no_argument,            0, 0  },
      {"ctppp"               ,   no_argument,            0, 0  },
      {"disableflushp2"      ,   no_argument,            0, 0  },
      {"onecore"             ,   no_argument,            0, 0  },
      {"ppp"                 ,   no_argument,            0, 0  },
      {"prime_pool_len"      ,   required_argument,      0, 0  },
      {"drain_pool_len"      ,   required_argument,      0, 0  },
      {"llc_miss_thres"      ,   required_argument,      0, 0  },
      {"help"                ,   no_argument,            0, 0  },
      {0                     ,   0          ,            0, 0  }};

    if (getopt_long(argc, argv, "", long_options, &option_index) == -1)
      break;

    if(option_index ==   0)   ctppp                           = 0;
    if(option_index ==   5)   usehugepage                     = 1;
    if(option_index ==   6)   ctppp                           = 1;
    if(option_index ==   7)   disableflushp2                  = 1;
    if(option_index ==   8)   onecore                         = 1;
    if(option_index ==   9)   ppp                             = 1;
    if(option_index ==  10)   prime_pool_len                  = atoi(optarg);
    if(option_index ==  11)   drain_pool_len                  = atoi(optarg);
    if(option_index ==  12)   llc_miss_thres                  = atoi(optarg);
    if(option_index ==  13)   help                            = 1;
  }
  if(help) {
    printf("\texample:\n");
    printf("\txeon-4110:  ./app --llc_miss_thres=140 --prime_pool_len=7000 --drain_pool_len=10000\n");
    exit(0);
  }

  //////////////////////////////////////////////////////////////////////////////
  // Memory allocations

  // `shared_mem` is for addresses that the attacker and victim will share.
  // `synchronization*` are variables for communication between threads.

  ASSERT(mem_map_shared(&shared_mem, SHARED_MEM_SIZE, usehugepage));
  ASSERT(var_map_shared(&synchronization));
  
  for(i = 0; i<HPTHREADS; i++) {
    ASSERT(var_map_shared_bacheblocks((volatile uint64_t **)(&ht_params[i]), 4));
  }
  for(i = 0; i<HPTHREADS; i++)
    printf("ht_params[%d] %p\n", i, ht_params[i]);


  *shared_mem = 1;
  *synchronization = 0;

  //////////////////////////////////////////////////////////////////////////////
  // Start the threads

  /*if (fork() == 0) { //child process 
    set_core(VICTIM_CORE, "Victim");
    victim();
    return 0;
  }*/
  set_core(ATTACKER_CORE, "Attacker"); 
  attacker(option_index);


  //////////////////////////////////////////////////////////////////////////////
  // Memory de-allocations

  ASSERT(munmap(shared_mem, SHARED_MEM_SIZE));
  ASSERT(var_unmap(synchronization));
  for(i = 0; i<HPTHREADS; i++) {
    ASSERT(var_unmap_shared_bacheblocks((volatile uint64_t *)(ht_params[i]), 4));
  }

  return 0;
}
