#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#include "../utils/cache_utils.h"
#include "../utils/misc_utils.h"

extern volatile uint64_t *shared_mem;
extern volatile uint64_t *synchronization;
extern volatile uint64_t *synchronization_params;

void victim() {

  //////////////////////////////////////////////////////////////////////////////
  // Prepare variables for test cache access times

  #define FENCE asm volatile ("mfence\n\t lfence\n\t");
  //////////////////////////////////////////////////////////////////////////////
  struct timespec tstart={0,0}, tend={0,0}; double timespan;
  clock_gettime(CLOCK_MONOTONIC, &tstart);
  while(timespan < 60) {

    if (*synchronization == -1) {
      break;
    }
    else if (*synchronization == 11) {
      /* Implements the VICTIM_READ_ACCESS() macro */
      memread((void*)*synchronization_params); 
      FENCE
      *synchronization = 0;
    }
    clock_gettime(CLOCK_MONOTONIC, &tend);
    timespan = (time_diff_ms(tstart,tend))/1000;
  }

  printf("victim exit\n");
  exit(EXIT_SUCCESS);
}