#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#include "configuration.h"
#include "../utils/cache_utils.h"
#include "../utils/misc_utils.h"
#include "../list/list_struct.h"
#include "../evsets/ps_evset.h"

extern volatile uint64_t *shared_mem;
extern volatile uint64_t *synchronization;
extern volatile uint64_t *synchronization2;
extern volatile uint64_t *synchronization3;
extern volatile uint64_t *synchronization_params;

extern volatile helpThread_t* ht_params[HPTHREADS];

void attacker_helper() {

  //////////////////////////////////////////////////////////////////////////////
  // Prepare variables for test cache access times

  #define FENCE asm volatile ("mfence\n\t lfence\n\t");

  // Add a time limit to the helper process to prevent it from becoming a zombie process
  while(1) {  

    if (*synchronization == -1) {
      break;
    }
    if (*synchronization == 99) {
      // Implements the KILL_HELPER() macro
      *synchronization = 0;
      break;
    }
    if (*synchronization == 1) {
      /* Implements the HELPER_READ_ACCESS() macro */
      memread((void*)*synchronization_params); 
      FENCE
      *synchronization = 0;
    }
  }
  *synchronization = 0;
  printf("attacker_helper exit\n");
  exit(EXIT_SUCCESS);

}

void new_attacker_helper(int id) {

  //////////////////////////////////////////////////////////////////////////////
  // Prepare variables for test cache access times
  int i;

  volatile helpThread_t *myparams = ht_params[id];
  printf("new_attacker_helper id %d myparams  %p\n", id, myparams);
  //  printf("myparams id %d %p\n", id, ht_params[id]);
  //
  #define FENCE asm volatile ("mfence\n\t lfence\n\t");
  uint64_t drain, prime, time;
  // Add a time limit to the helper process to prevent it from becoming a zombie process
  while(1) {
    while(myparams->fun == HPT_FUN_IDLE);
    uint64_t fun         = myparams->fun;
    uint64_t victim      = (uint64_t)myparams->victim;
    uint64_t drain_index = myparams->idx;
    uint64_t drain_mem   = (uint64_t)myparams->drain_mem;
    uint64_t reqlen      = myparams->reqlen;
    uint64_t is_huge     = myparams->is_huge;
    uint64_t acc_index   = myparams->idx;
    uint64_t page        = myparams->page;
    uint64_t llcmissTh   = myparams->llcmissTh;
    uint64_t syn_addr    = (uint64_t)myparams->syn_addr;
    uint64_t offset      = (is_huge) ? LLC_PERIOD : SMALLPAGE_PERIOD;
    //drain
    if(fun == HPT_FUN_DRAIN) {
      drain = is_huge ?
            (drain_mem + (victim & (LLC_PERIOD-1      )) + (drain_index % MAX_POOL_SIZE_HUGE )*LLC_PERIOD      ):
            (drain_mem + (victim & (SMALLPAGE_PERIOD-1)) + (drain_index % MAX_POOL_SIZE_SMALL)*SMALLPAGE_PERIOD);
      drain -= offset;
      for(i=0; i<reqlen; i++) {
        drain += offset;
        maccess((void*)drain);
      }
    }

    //acc_syn
    if(fun == HPT_FUN_ACC_SYN) {
      memread((void*)syn_addr); 
      //FENCE;
    }

    //acc_asyn
    if(fun == HPT_FUN_ACC_ASYN) {
      prime = is_huge ?
            (page + (victim & (LLC_PERIOD-1      )) + (acc_index % MAX_POOL_SIZE_HUGE )*LLC_PERIOD      ):
            (page + (victim & (SMALLPAGE_PERIOD-1)) + (acc_index % MAX_POOL_SIZE_SMALL)*SMALLPAGE_PERIOD);
      prime -= offset;
      for(i=0; i<reqlen; i++) {
        prime += offset;
        maccess((void*)prime);
      }
    }

    //check
    if(fun == HPT_FUN_CHECK) {
      time  = time_mread_nofence((void*)victim);
      for(i =0; i<100; i++) time = time_mread_nofence((void*)victim);
      FENCE;
      time = time_mread_nofence((void*)victim);
      time = time_mread_nofence((void*)victim);
      while(time < llcmissTh) {
        time = time_mread_nofence((void*)victim);
        i++;
      }
    }

    if(fun == HPT_FUN_OCCUPY_WAY) {
      uint8_t  i = 0;
      uint64_t evset[32];
      for(i = 0; i < 32; i++) {
        evset[i] = myparams->evset[i];
      }
      while(1) {
        //reqlen = myparams->reqlen;
        for(i = 0; i < myparams->reqlen; i++) {
          maccess((void*)evset[i]);
        }
        if(myparams->fun == HPT_FUN_ABORT) break;
      }
    }

    if(fun == HPT_FUN_SCH_YIELD) {
      sched_yield();
    }
    if(fun == HPT_FUN_EXIT){
      printf("new_attacker_helper%d exit\n", id);
      break;
    }

    myparams->fun = HPT_FUN_IDLE;
    myparams->rv  = 1;
  }
  myparams->rv  = 1;
  exit(EXIT_SUCCESS);

}
/*
typedef struct helpThread
{
  uint64_t     fun;           //0:idle 1:drain 2:acc_syn 3:acc_asyn 4:check 
  uint8_t      *accaddr;
  uint64_t     offsetidx;
  uint64_t     acclen;
  uint64_t     rv;
  uint64_t     pad[3];
} __attribute__((aligned(128))) helpThread_t;*/