#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <time.h>
#include <errno.h>
#include <sys/mman.h>
#include <assert.h>
#define ASSERT(x) assert(x != -1)

// Consider this file only if the target machine has inclusive caches 
// according to configuration.h
#include "configuration.h"

#ifdef LLC_INCLUSIVE 


#include "prime.h"
#include "../utils/colors.h"
#include "../utils/cache_utils.h"
#include "../utils/memory_utils.h"
#include "../utils/misc_utils.h"

// Evset functions
#include "../evsets/list/list_traverse.h"
#include "../evsets/list/list_utils.h"
#include "../evsets/ps_evset.h"

////////////////////////////////////////////////////////////////////////////////
// Memory Allocations
extern volatile uint64_t *shared_mem;
extern volatile uint64_t *synchronization;
extern volatile uint64_t *synchronization_params;

extern volatile helpThread_t* ht_params[HPTHREADS];

static uint64_t lsfr = 0x01203891;

void init_seed(uint64_t seed) {
  lsfr = seed;
}

uint64_t random_fast() {
  return lsfr++;
  uint64_t b63 = 0x1 & (lsfr >> 62);
  uint64_t b62 = 0x1 & (lsfr >> 61);
  lsfr = ((lsfr << 2) >> 1) | (b63 ^ b62);
  return lsfr;
}

////////////////////////////////////////////////////////////////////////////////
// Function declarations

int  ctpp_ps_evset  (uint64_t *evset, char *victim, int len, uint64_t* page, int is_huge, int threshold, int* evset_len);
void test_ctpp();

void configure_thresholds(
  uint64_t target_addr, int* thrL1, int* thrLLC, int* thrRAM, int* thrDET);

////////////////////////////////////////////////////////////////////////////////

uint64_t *evict_mem;
uint64_t *drain_mem;
void new_attacker_helper();

void attacker(int test_option) {

  ASSERT(mem_map_shared(&evict_mem, (uint64_t)EVICT_LLC_SIZE, usehugepage));
  ASSERT(mem_map_shared(&drain_mem, (uint64_t)EVICT_LLC_SIZE, usehugepage));
  int i,j;
  //for(i = 0; i<HPTHREADS; i++)
  //  printf("ht_params[%d] %p\n", i, ht_params[i]);
  for(i=0; i<HPTHREADS; i++) {
    ht_params[i]->fun = HPT_FUN_IDLE;
    ht_params[i]->rv  = 1;
    for(j = 0; j<32; j++) {
      ht_params[i]->evset[j]  = 0;
    }
  }
  //for(i = 0; i<HPTHREADS; i++)
  //  printf("ht_params[%d] %p\n", i, ht_params[i]);

  for(i = 0; i<HPTHREADS; i++) {
    if (fork() == 0) {
      set_core(HELPER_CORE + 2*i, "new Attacker Helper");
      new_attacker_helper(i);
      return;
    }
    usleep(1000);
  }

  //while(1);
  /*if (fork() == 0) {
    set_core(HELPER3_CORE, "Attacker Helper3");
    attacker_helper3();
    return;
  }*/
  test_ctpp();
  /*if (test_option == 0)      test_ctpp();
  else if (test_option == 1) test_occupy_way();
  else if (test_option == 2) time_set_block();
  else if (test_option == 3) test_sbt();
  else if (test_option == 4) test_rwevset();
  else                  test_eviction_set_creation();*/

  ASSERT(munmap(evict_mem,  EVICT_LLC_SIZE));

  // Shut Down,Control the victim core
  *synchronization = -1;
  sleep(1);
}

////////////////////////////////////////////////////////////////////////////////

void test_ctpp(){

  //////////////////////////////////////////////////////////////////////////////
  // Include the function macros
  #include "macros.h"
  #define TIMERECORD 1000

  //////////////////////////////////////////////////////////////////////////////
  // Eviction Set Construction

  printf("\nTesting Eviction Set Construction Performance BY CT+Probe+Probe");
  if(ctppp) printf("+Probe");
  printf("\n\n");

  struct timespec tstart={0,0}, tend={0,0}; double timespan , timeall; timeall = 0;
  int seed = time(NULL); srand(seed);
  float timeLo = 0, timeMedi = 0, timeHi = 0, timerecord[TIMERECORD];
  uint64_t target_addr;
  uint64_t target_index = (random_fast()%1000)*8;
  clock_gettime(CLOCK_MONOTONIC, &tstart);
  init_seed((uint64_t)tstart.tv_sec * 1000 + (uint64_t)tstart.tv_nsec);
  target_index    = (random_fast()%1000)*8;
  target_addr     = (uint64_t)&shared_mem[target_index];

  ////////////////////////////////////////////////////////////////////////////
  // Cache Access Thresholds
  uint64_t succ = 0 ;
  int thrLLC, thrRAM, thrDET, thrL1;

  printf("\nThresholds Configured\n\n");
  if(llc_miss_thres == 0) {
    configure_thresholds(target_addr, &thrL1, &thrLLC, &thrRAM, &thrDET);
    printf("\tL1/L2    : %u\n", thrL1   );
    printf("\tLLC      : %u\n", thrLLC  );
    printf("\tRAM      : %u\n", thrRAM  );
  } else {
    thrDET  = llc_miss_thres;
  }
  printf("\tTHRESHOLD: %u\n", thrDET  );

  // Only need helper for clean threshold calibration
  //KILL_HELPER(); 

  #if PREMAP_PAGES == 1
    ps_evset_premap(evict_mem);
  #endif

  for (uint64_t t=0; t<TEST_LEN; t++) {

    ////////////////////////////////////////////////////////////////////////////
    // Pick a new random target_addr from shared_mem

    target_index    = (random_fast()%100000)*8;
    target_addr     = (uint64_t)&shared_mem[target_index];

    ////////////////////////////////////////////////////////////////////////////
    // Eviction Set Construction
    #define EV_LLC LLC_WAYS


    Elem  *evsetList;
    Elem **evsetList_ptr = &evsetList;
    uint64_t  evsetArray[32];
    for(uint8_t i = 0; i<32; i++) evsetArray[i] = 0;

    *evsetList_ptr = NULL;
    int evset_len = 0 ;
    clock_gettime(CLOCK_MONOTONIC, &tstart);
    int rv = ctpp_ps_evset(&evsetArray[0],
                          (char*)target_addr,
                          EV_LLC,
                          evict_mem,
                          0,
                          thrDET,&evset_len);
    clock_gettime(CLOCK_MONOTONIC, &tend);
    timespan = time_diff_ms(tstart, tend);
    timeall += timespan;
    timerecord[t%TIMERECORD] = timespan;
    if(t%TIMERECORD == TIMERECORD - 1) {
      qsort(timerecord, TIMERECORD, sizeof(float), comp);
      timeLo    = timerecord[0];
      timeMedi  = timerecord[TIMERECORD>>1];
      timeHi    = timerecord[TIMERECORD-1];
    }
    if (rv) {
      succ++;
      char disp = 0;
      if(succ == 1) disp = 1;
      else if(10      <= succ && succ <     100) { if(succ % 10    == 0) disp = 1; }
      else if(100     <= succ && succ <    1000) { if(succ % 100   == 0) disp = 1; }
      else if(1000    <= succ && succ <   10000) { if(succ % 1000  == 0) disp = 1; }
      else if(10000   <= succ                  ) { if(succ % 10000 == 0) disp = 1; }


      if(disp)
        printf(GREEN"\tSuccess. traget %p Constucted succrate %ld/%ld=%3.2f%%, %3.3f[%3.3f-%3.3f-%3.3f]ms\n"NC,
               (void*)target_addr, succ, t+1, (float)(100*succ)/(t+1), timeall/(t+1), timeLo, timeMedi, timeHi);
    }
    //else
      //printf(RED"\tFail. Could not construct  succrate %d/%d=%f \n"NC, succ, t+1,  (float)(succ)/(t+1));
  }
  printf("ctpp"); if(ctppp) printf("p" );
  printf(" finish succrate %ld/%ld=%f%% avertime= %f ms midtime= %f ms totaltime %f s\n",
          succ, (uint64_t)TEST_LEN,  (float)(100*succ)/TEST_LEN, timeall/TEST_LEN, timeMedi, (float)clock()/CLOCKS_PER_SEC);
  KILL_HELPER();
}

int ctpp_ps_evset  (uint64_t *evset, char *victim, int len, uint64_t* page, int is_huge, int threshold, int* evset_len){

  #define CHECKS         10
  #define TRYMAX         1
  #define PAGAINS        0
  #define EVSET_LEN_MAX  32

  int i,j,k;
  int time;
  int try = 0;
  uint8_t pass[2];
  uint64_t mask;
  uint64_t offset;
  int timerecord[CHECKS];

  static uint64_t prime_index  = 0;
  static uint64_t drain_index  = 0;

  static uint32_t try_accumulated         = 0;
  static uint32_t succ_accumulated[2]     = {0, 0}; //dual core / single core

  static uint32_t prime_len_accumulated[2]   = {0, 0};
  static uint32_t p1_pool_len_accumulated[2] = {0, 0};
  static uint32_t p2_pool_len_accumulated[2] = {0, 0};
  static uint32_t p3_pool_len_accumulated[2] = {0, 0};
  static uint32_t p4_pool_len_accumulated[2] = {0, 0};

  uint64_t drain;
  uint64_t prime, prime_len;
  uint64_t probe;
  uint64_t *p1_mask=NULL, p1_pool_len=0;
  uint64_t *p2_pool=NULL, p2_pool_len=0;
  uint64_t *p3_pool=NULL, p3_pool_len=0;
  uint64_t *p4_pool=NULL, p4_pool_len=0;
  uint64_t evset_array[EVSET_LEN_MAX];
  uint64_t pagain;
  uint64_t max_pool_size = (is_huge) ? MAX_POOL_SIZE_HUGE : MAX_POOL_SIZE_SMALL;
  offset = (is_huge) ? LLC_PERIOD : SMALLPAGE_PERIOD;
  *evset_len = 0;

  do {
    try_accumulated ++;
    if(p1_mask != NULL) { free(p1_mask); p1_mask = NULL; }
    if(p2_pool != NULL) { free(p2_pool); p2_pool = NULL; }
    //if(p3_pool != NULL) { free(p3_pool); p3_pool = NULL; }
    //if(p4_pool != NULL) { free(p4_pool); p4_pool = NULL; }
    prime_len      = 0;
    p1_pool_len    = 0;
    p2_pool_len    = 0;
    p3_pool_len    = 0;
    p4_pool_len    = 0;
    if(prime_index + prime_pool_len > max_pool_size-10) prime_index = 0;
    if(drain_index + drain_pool_len > max_pool_size-10) drain_index = 0;
    for(i = 0; i<CHECKS; i++) timerecord[i] = 0;

    p1_mask  = (uint64_t*)malloc(sizeof(uint64_t)*(prime_pool_len/64+10));
    p2_pool  = (uint64_t*)malloc(sizeof(uint64_t)*(prime_pool_len+10));
    for(i = 0; i < prime_pool_len; i = i+8) {
      p1_mask[i/64] = 0;
      p2_pool[i]    = 0;
    }


    for(i=0; i<HPTHREADS && onecore == 0; i++) {
      while(ht_params[i]->rv == 0);
      ht_params[i]->is_huge      = is_huge;
      ht_params[i]->idx          = drain_index;
      ht_params[i]->reqlen       = drain_pool_len;
      ht_params[i]->victim       = (uint8_t*)victim;
      ht_params[i]->page         = (uint64_t)page;
      ht_params[i]->drain_mem    = (uint8_t*)drain_mem;
      ht_params[i]->llcmissTh    = threshold;
    }

    //CTPP STEP 0: drain out (and force LRU?)
    if(onecore == 0) {
      ht_params[0]->rv           = 0;
      ht_params[0]->fun          = HPT_FUN_DRAIN;
    }
    drain = (is_huge) ?
          ((uint64_t)drain_mem + ((uint64_t)victim & (LLC_PERIOD-1      )) + (drain_index % MAX_POOL_SIZE_HUGE )*LLC_PERIOD      ):
          ((uint64_t)drain_mem + ((uint64_t)victim & (SMALLPAGE_PERIOD-1)) + (drain_index % MAX_POOL_SIZE_SMALL)*SMALLPAGE_PERIOD);
    drain -= offset;
    for(i = 0; i < drain_pool_len; i++) {
      drain += offset;
      maccess((void*)drain);
    }
    drain_index += drain_pool_len;
    if((random_fast() & 0x07) == 0 && onecore == 0) {
      for(i=0; i<HPTHREADS; i++){
        while(ht_params[i]->rv == 0);
        ht_params[i]->rv  = 0;
        ht_params[i]->fun = HPT_FUN_SCH_YIELD;
      }
      sched_yield();
    }
    for(i=0; i<HPTHREADS; i++) {
      while(ht_params[i]->rv == 0);
    }

    if(onecore == 0) TOGHTER_READ_ACCESS((void*)victim);
    else             maccess((void*)victim);
    // CTPP STEP 1: prime until evict the victim
    i =0;j=1;
    int evicted = 0;
    int reqlen  = 20;
    int prime_index_start = prime_index;
    prime = (is_huge) ?
          ((uint64_t)page + ((uint64_t)victim & (LLC_PERIOD-1      )) + (prime_index % MAX_POOL_SIZE_HUGE )*LLC_PERIOD      ):
          ((uint64_t)page + ((uint64_t)victim & (SMALLPAGE_PERIOD-1)) + (prime_index % MAX_POOL_SIZE_SMALL)*SMALLPAGE_PERIOD);
    prime -= offset;
    while(1){
      prime += offset;
      maccess((void*)prime);
      if(onecore == 0) {
        if(is_huge) {
          HELPER_READ_ACCESS_NOBLK((void*)prime);
        } else {
          if(i % reqlen == 0 && is_huge == 0) {
            while(ht_params[0]->rv == 0);
            ht_params[0]->rv      = 0;
            ht_params[0]->reqlen  = reqlen;
            ht_params[0]->idx     = prime_index;
            ht_params[0]->fun     = HPT_FUN_ACC_ASYN;
          }
        }
      }
      i++; j++; prime_index++; prime_len++;
      time = time_mread_nofence((void*)victim);
      if(evicted == 1 && (j % reqlen == 0)) break;
      if(evicted == 0) {
        if (time > threshold) evicted = 1;
      }
      if(evicted && is_huge) break;
      if(prime_len > prime_pool_len) { prime_len = 0; break; }
    }
    if(onecore == 0) {
      while(ht_params[0]->rv == 0);
      HELPER_READ_ACCESS((void*)victim);
    }

    // CTPP STEP2: remove hit
    reqlen = 10;
    int ht_index  = prime_index_start;
    probe = (is_huge) ?
        ((uint64_t)page + ((uint64_t)victim & (LLC_PERIOD-1      )) + (prime_index_start % MAX_POOL_SIZE_HUGE )*LLC_PERIOD      ):
        ((uint64_t)page + ((uint64_t)victim & (SMALLPAGE_PERIOD-1)) + (prime_index_start % MAX_POOL_SIZE_SMALL)*SMALLPAGE_PERIOD);
    probe -= offset;
    for(i = 0, j = 1; i < prime_len; i++, j++) {
      probe += offset;
      time = time_mread_nofence((void*)probe);
      if(is_huge && onecore == 0) HELPER_READ_ACCESS_NOBLK((void*)probe);
      if((i & 0x3f) == 0) mask = 0;
      if (time>threshold) {
        p1_pool_len ++;
        mask |= ((uint64_t)1 << (i & 0x3f));
      }
      p1_mask[i>>6]  = mask;
      if(is_huge == 0 && onecore == 0) {
        if(j >= reqlen && (j % reqlen == 0 || j == prime_len)) {
          while(ht_params[0]->rv == 0);
          ht_params[0]->rv      = 0;
          ht_params[0]->reqlen  = reqlen;
          ht_params[0]->idx     = ht_index;
          ht_params[0]->fun     = HPT_FUN_ACC_ASYN;
          ht_index             += reqlen;
        }
      }
    }
    if(onecore == 0) while(ht_params[0]->rv == 0);

    // CTPP STEP3: remove miss
    probe = (is_huge) ?
          ((uint64_t)page + ((uint64_t)victim & (LLC_PERIOD-1      )) + (prime_index_start % MAX_POOL_SIZE_HUGE )*LLC_PERIOD      ):
          ((uint64_t)page + ((uint64_t)victim & (SMALLPAGE_PERIOD-1)) + (prime_index_start % MAX_POOL_SIZE_SMALL)*SMALLPAGE_PERIOD);
    probe -= offset;
    for(i = 0, mask = 0; ; ) {
      do {
        mask = mask >> 1;
        if((i & 0x3f) == 0) mask = p1_mask[i>>6];
        probe += offset;
        i++;
      } while((mask & 0x01) == 0 && i < prime_len);
      if((mask & 0x01) == 0) break;
      time = time_mread_nofence((void*)probe);
      if(time<threshold) {
        p2_pool[p2_pool_len++] = probe;
      }
      if(onecore == 0) HELPER_READ_ACCESS_NOBLK(probe);
    }
    free(p1_mask); p1_mask = NULL;

    // CTPP STEP4: remove hit
    if(ctppp && disableflushp2 == 0) {
      FLUSH(victim);
      for(i = 0; i < p2_pool_len; i++){
        FLUSH(p2_pool[i]);
      }
      for(i = 0; i < p2_pool_len; i++){
        if(onecore == 0) TOGHTER_READ_ACCESS((void*)p2_pool[i]);
        else             maccess            ((void*)p2_pool[i]);
        asm volatile("lfence");
      }
    }
    if(onecore == 0) TOGHTER_READ_ACCESS((void*)victim);
    else             maccess            ((void*)victim);
    for(i = 0; i < p2_pool_len; i++){
      if(ctppp) {
        time = time_mread_nofence((void*)p2_pool[i]);
        if (time>threshold) {
          p2_pool[p3_pool_len++] = p2_pool[i];
        }
        if(onecore == 0) HELPER_READ_ACCESS((void*)p2_pool[i]);
        asm volatile("lfence");
      } else {
        p2_pool[p3_pool_len++] = p2_pool[i];
      }
    }

    p4_pool_len = p3_pool_len;
    // CTPP STEP5: remove miss
    /*for(i = 0; i < p3_pool_len ; i++) {
      p2_pool[p4_pool_len++] = p2_pool[i];
      if(ctppp) {
        time = time_mread_nofence((void*)p3_pool[i]);
        if(time<threshold) {
          p4_pool[p4_pool_len++] = p3_pool[i];
        }
        HELPER_READ_ACCESS((void*)p3_pool[i]);
      } else {
        p4_pool[p4_pool_len++] = p3_pool[i];
      }
    }*/

    // CTPP STEP5: loop
    /*for(i = 0; i < PAGAINS && p4_pool_len > len; i++) {
      uint64_t p4_pool_len_latch = p4_pool_len;
      p4_pool_len = 0;
      if(i % 2 == 0) {
        TOGHTER_READ_ACCESS((void*)victim);
        for(j = 0; j < p4_pool_len_latch ; j++) {
          time = time_mread_nofence((void*)p4_pool[j]);
          if(time>threshold) {
            p4_pool[p4_pool_len++] = p4_pool[j];
          }
        HELPER_READ_ACCESS((void*)p4_pool[j]);
        }
      } else {
        for(j = 0; j < p4_pool_len_latch ; j++) {
          time = time_mread_nofence((void*)p4_pool[j]);
          if(time<threshold) {
            p4_pool[p4_pool_len++] = p4_pool[j];
          }
        HELPER_READ_ACCESS((void*)p4_pool[j]);
        }
      }
    }*/

    //check
    pass[0] = 0;
    pass[1] = 0;
    if(1) {
      //dual_core_check
      for(i =0 ; i <1; i++) {
        TOGHTER_READ_ACCESS_NOBLK((void*)victim);
        for(j = 0; j<p4_pool_len; j++) {
          TOGHTER_READ_ACCESS_NOBLK((void*)p2_pool[j]);
        }
      }
      for(i =0 ; i <CHECKS; i++) {
        TOGHTER_READ_ACCESS_NOBLK((void*)victim);
        for(j=0; j<4; j++) {
          for(k = 0; k<p4_pool_len; k++) {
            TOGHTER_READ_ACCESS_NOBLK((void*)p2_pool[k]);
          }
        }
        //while(ht_params[0]->rv == 0);
        time = time_mread_nofence((void*)victim);
        if(time > threshold) pass[0]++;
        else break;
        //timerecord[i] = time;
      }
      if(pass[0] == CHECKS) {
        for(j = 0; j<p4_pool_len && *evset_len < EVSET_LEN_MAX; j++) {
          evset_array[*evset_len] = p2_pool[j];
          *evset_len = *evset_len + 1;
          if(*evset_len >= EVSET_LEN_MAX) break;
        }
        //single_core_check
        for(i =0 ; i <CHECKS; i++) {
          maccess((void*)victim);
          for(j=0; j<10; j++) {
            for(k = 0; k< *evset_len; k++) {
              maccess((void*)evset_array[k]);
            }
          }
          time = time_mread_nofence((void*)victim);
          if(time > threshold) pass[1]++;
          else break;
          //timerecord[i] = time;
        }
      }
      if(onecore == 1) {
        pass[1] = 0;
        for(i =0 ; i <CHECKS; i++) {
          maccess((void*)victim);
          for(j=0; j<10; j++) {
            for(k = 0; k< p4_pool_len; k++) {
              maccess((void*)p2_pool[k]);
            }
          }
          time = time_mread_nofence((void*)victim);
          if(time > threshold) pass[1]++;
          else break;
          //timerecord[i] = time;
        }
      }

      //minimize_evset
      /*if(pass == CHECKS) {
        for(uint8_t rmsel = 0; rmsel < *evset_len; ) {
          for(i = 0; i<CHECKS; i++) {
            for(j = 0; j<10; j++) {
              for(k = 0; k< *evset_len; k++) {
                if(k != rmsel) maccess((void*)evset_array[k]);
              }
            }
            time = time_mread_nofence((void*)victim);
            if(time < threshold) break;
          }
          if(i == CHECKS) {
            for(j = rmsel; j < *evset_len-1; j++) evset_array[j]=evset_array[j+1];
            *evset_len = *evset_len-1;
          } else {
            rmsel++;
          }
        }
      }*/


      free(p2_pool); p2_pool = NULL;
      //qsort(timerecord, CHECKS, sizeof(int), comp);
      prime_len_accumulated[0]   += prime_len;
      p1_pool_len_accumulated[0] += p1_pool_len;
      p2_pool_len_accumulated[0] += p2_pool_len;
      p3_pool_len_accumulated[0] += p3_pool_len;
      p4_pool_len_accumulated[0] += p4_pool_len;
      if((onecore == 0 && pass[0] == CHECKS) || (onecore !=0 && pass[1] == CHECKS)) {
        /*if(p4_pool_len == 0) {
          if(0) printf(CYAN"\tvictim %p try:%d pagain:%d pass:%d time:[%d-%d-%d] pool_size: [%d->%d->%d->%d->%d] evsize %d\n"NC,
                 (void*)victim, (int)try, (int)pagain, pass[0], timerecord[0], timerecord[CHECKS>>1], timerecord[CHECKS-1],
                 (int)prime_len, (int)p1_pool_len, (int)p2_pool_len, (int)p3_pool_len, (int)p4_pool_len, *evset_len);
        } else if(p4_pool_len < 16) {
          if(0) printf(BLUE"\tvictim %p try:%d pagain:%d pass:%d time:[%d-%d-%d] pool_size: [%d->%d->%d->%d->%d] evsize %d\n"NC,
                 (void*)victim, (int)try, (int)pagain, pass[0], timerecord[0], timerecord[CHECKS>>1], timerecord[CHECKS-1],
                 (int)prime_len, (int)p1_pool_len, (int)p2_pool_len, (int)p3_pool_len, (int)p4_pool_len, *evset_len);
        } else if(p4_pool_len > 20) {
          if(0) printf(YELLOW"\tvictim %p try:%d pagain:%d pass:%d time:[%d-%d-%d] pool_size: [%d->%d->%d->%d->%d] evsize %d\n"NC,
                 (void*)victim, (int)try, (int)pagain, pass[0], timerecord[0], timerecord[CHECKS>>1], timerecord[CHECKS-1],
                 (int)prime_len, (int)p1_pool_len, (int)p2_pool_len, (int)p3_pool_len, (int)p4_pool_len, *evset_len);
        } else {
          if(0) printf(WHITE"\tvictim %p try:%d pagain:%d pass:%d time:[%d-%d-%d] pool_size: [%d->%d->%d->%d->%d] evsize %d\n"NC,
                 (void*)victim, (int)try, (int)pagain, pass[0], timerecord[0], timerecord[CHECKS>>1], timerecord[CHECKS-1],
                 (int)prime_len, (int)p1_pool_len, (int)p2_pool_len, (int)p3_pool_len, (int)p4_pool_len, *evset_len);
        }*/
        if(0) printf(WHITE"\tvictim %p try:%d pagain:%d pass:%d time:[%d-%d-%d] pool_size: [%d->%d->%d->%d->%d] evsize %d\n"NC,
               (void*)victim, (int)try, (int)pagain, pass[0], timerecord[0], timerecord[CHECKS>>1], timerecord[CHECKS-1],
               (int)prime_len, (int)p1_pool_len, (int)p2_pool_len, (int)p3_pool_len, (int)p4_pool_len, *evset_len);
        // return evset
        for(i = 0; i < *evset_len; i++) {
          *(evset+i) = evset_array[i];
        }
        prime_len_accumulated[1]   += prime_len;
        p1_pool_len_accumulated[1] += p1_pool_len;
        p2_pool_len_accumulated[1] += p2_pool_len;
        p3_pool_len_accumulated[1] += p3_pool_len;
        p4_pool_len_accumulated[1] += p4_pool_len;

        if((succ_accumulated[0] != 0) && (succ_accumulated[0] % 1000 == 0)) {
          printf(RED"\tsucc_accumulated %d %d pool_size: [%d->%d->%d->%d->%d]\n"NC,
                 succ_accumulated[0], succ_accumulated[1],
                 prime_len_accumulated[1]   / succ_accumulated[0],
                 p1_pool_len_accumulated[1] / succ_accumulated[0],
                 p2_pool_len_accumulated[1] / succ_accumulated[0],
                 p3_pool_len_accumulated[1] / succ_accumulated[0],
                 p4_pool_len_accumulated[1] / succ_accumulated[0]);
            printf(RED"\ttry_accumulated %d pool_size: [%d->%d->%d->%d->%d]\n"NC,
                 try_accumulated,
                 prime_len_accumulated[0]   / try_accumulated,
                 p1_pool_len_accumulated[0] / try_accumulated,
                 p2_pool_len_accumulated[0] / try_accumulated,
                 p3_pool_len_accumulated[0] / try_accumulated,
                 p4_pool_len_accumulated[0] / try_accumulated);

        }

        succ_accumulated[0] ++;
        if((onecore == 0 && pass[0] == CHECKS) || (onecore !=0 && pass[1] == CHECKS)) succ_accumulated[1] ++;
        return 1;
      } else if(0) {
        printf("\tvictim %p try:%d pagain:%d pass:%d time:[%d-%d-%d] pool_size: [%d->%d->%d->%d->%d] evsize %d\n",
                 (void*)victim, (int)try, (int)pagain, pass[0], timerecord[0], timerecord[CHECKS>>1], timerecord[CHECKS-1],
                 (int)prime_len, (int)p1_pool_len, (int)p2_pool_len, (int)p3_pool_len, (int)p4_pool_len, *evset_len);
      }
    }
  } while(++try < TRYMAX);
  if(p1_mask != NULL) { free(p1_mask); p1_mask = NULL; }
  if(p2_pool != NULL) { free(p2_pool); p2_pool = NULL; }
  if(p3_pool != NULL) { free(p3_pool); p3_pool = NULL; }
  if(p4_pool != NULL) { free(p4_pool); p4_pool = NULL; }
  if(0) printf(RED"\tvictim %p try:%d pagain:%d pass:%d time:[%d-%d-%d] pool_size: [%d->%d->%d->%d->%d]\n"NC,
        (void*)victim, (int)try, (int)pagain, pass[0], timerecord[0], timerecord[CHECKS>>1], timerecord[CHECKS-1],
        (int)prime_len, (int)p1_pool_len, (int)p2_pool_len, (int)p3_pool_len, (int)p4_pool_len);
  return 0;
}


void configure_thresholds(
  uint64_t target_addr, int* thrL1, int* thrLLC, int* thrRAM, int* thrDET) {

  #define THRESHOLD_TEST_COUNT 2000
  #define RAND_IDX 10000

  uint  timing[3][THRESHOLD_TEST_COUNT];
  uint  timing2[3][RAND_IDX];
  uint  timingLo[3] = {(uint)(-1), (uint)(-1), (uint)(-1)};
  uint  timingHi[3] = {0, 0, 0};
  uint  timingCnt[3][1000];
  uint  access_time;
  for(int i =0; i<3; i++) {
    for(int j = 0; j<1000; j++) {
      timingCnt[i][j] = 0;
    }
  }
  *thrLLC = 0;  *thrRAM = 0; *thrL1=0;
  #include "macros.h"
  for(int i=0; i<RAND_IDX; i++) {
    sched_yield();
    uint64_t index = (random_fast()%100000)*8;
    uint64_t addr  = (uint64_t)&shared_mem[index];
    maccess((void*)addr); HELPER_READ_ACCESS((void*)addr);
    for (int t=0; t<THRESHOLD_TEST_COUNT; t++) {
      FLUSH                   (addr);
      FLUSH                   (addr);
      HELPER_READ_ACCESS      (addr);
      TIME_READ_ACCESS_NOFENCE(addr); timing[0][t] = access_time; // time0: LLC
      FLUSH                   (addr);
      TIME_READ_ACCESS_NOFENCE(addr); timing[1][t] = access_time; // time1: DRAM
      TIME_READ_ACCESS_NOFENCE(addr); timing[2][t] = access_time; // time2: L1/L2
      if(timing[0][t] < 1000) timingCnt[0][timing[0][t]]++;
      if(timing[1][t] < 1000) timingCnt[1][timing[1][t]]++;
      if(timing[2][t] < 1000) timingCnt[2][timing[2][t]]++;
    }
    qsort(timing[0], THRESHOLD_TEST_COUNT, sizeof(int), comp);
    qsort(timing[1], THRESHOLD_TEST_COUNT, sizeof(int), comp);
    qsort(timing[2], THRESHOLD_TEST_COUNT, sizeof(int), comp);

    timing2[0][i] = timing[0][(int)(0.50*THRESHOLD_TEST_COUNT)];
    timing2[1][i] = timing[1][(int)(0.50*THRESHOLD_TEST_COUNT)];
    timing2[2][i] = timing[2][(int)(0.50*THRESHOLD_TEST_COUNT)];

    if(timingLo[0] > timing[0][0]) timingLo[0] = timing[0][0];
    if(timingLo[1] > timing[1][0]) timingLo[1] = timing[1][0];
    if(timingLo[2] > timing[2][0]) timingLo[2] = timing[2][0];
    if(i>(RAND_IDX>>1)) {
      int sel = (int)(0.99*THRESHOLD_TEST_COUNT);
      if(timingHi[0] < timing[0][sel] && timing[0][THRESHOLD_TEST_COUNT-1] < timingLo[1]) timingHi[0] = timing[0][sel];  //TimeLLCHi
      if(timingHi[2] < timing[2][sel] && timing[2][THRESHOLD_TEST_COUNT-1] < timingLo[0]) timingHi[2] = timing[2][sel];  //TimeL1L2Hi
    }
  }

  qsort(timing2[0], RAND_IDX, sizeof(int), comp);
  qsort(timing2[1], RAND_IDX, sizeof(int), comp);
  qsort(timing2[2], RAND_IDX, sizeof(int), comp);
  *thrLLC  = timing2[0][(int)(0.50*RAND_IDX)];
  *thrRAM  = timing2[1][(int)(0.50*RAND_IDX)];
  *thrL1   = timing2[2][(int)(0.50*RAND_IDX)];

  printf("timeL1L2 : [%3d|%3d-%3d-%3d-%3d-%3d|%3d-%3d-%3d-%3d-%3d|-%3d-%3d-%3d-%3d-%3d|-%3d-%3d-%3d-%3d-%3d|-%3d-%3d-%3d-%3d|-%3d-%3d-%3d-%3d-%3d|%3d]\n",
    timingLo[2],
    timing2[2][(int)(0.00*RAND_IDX)], timing2[2][(int)(0.01*RAND_IDX)], timing2[2][(int)(0.02*RAND_IDX)], timing2[2][(int)(0.03*RAND_IDX)], timing2[2][(int)(0.04*RAND_IDX)],
    timing2[2][(int)(0.05*RAND_IDX)], timing2[2][(int)(0.10*RAND_IDX)], timing2[2][(int)(0.15*RAND_IDX)], timing2[2][(int)(0.20*RAND_IDX)], timing2[2][(int)(0.25*RAND_IDX)],
    timing2[2][(int)(0.30*RAND_IDX)], timing2[2][(int)(0.35*RAND_IDX)], timing2[2][(int)(0.40*RAND_IDX)], timing2[2][(int)(0.45*RAND_IDX)], timing2[2][(int)(0.50*RAND_IDX)],
    timing2[2][(int)(0.55*RAND_IDX)], timing2[2][(int)(0.60*RAND_IDX)], timing2[2][(int)(0.65*RAND_IDX)], timing2[2][(int)(0.70*RAND_IDX)], timing2[2][(int)(0.75*RAND_IDX)],
    timing2[2][(int)(0.80*RAND_IDX)], timing2[2][(int)(0.85*RAND_IDX)], timing2[2][(int)(0.90*RAND_IDX)], timing2[2][(int)(0.95*RAND_IDX)],
    timing2[2][(int)(0.96*RAND_IDX)], timing2[2][(int)(0.97*RAND_IDX)], timing2[2][(int)(0.98*RAND_IDX)], timing2[2][(int)(0.99*RAND_IDX)], timing2[2][RAND_IDX-1]          ,
    timingHi[2]);
  printf("timeLLC  : [%3d|%3d-%3d-%3d-%3d-%3d|%3d-%3d-%3d-%3d-%3d|-%3d-%3d-%3d-%3d-%3d|-%3d-%3d-%3d-%3d-%3d|-%3d-%3d-%3d-%3d|-%3d-%3d-%3d-%3d-%3d|%3d]\n",
    timingLo[0],
    timing2[0][(int)(0.00*RAND_IDX)], timing2[0][(int)(0.01*RAND_IDX)], timing2[0][(int)(0.02*RAND_IDX)], timing2[0][(int)(0.03*RAND_IDX)], timing2[0][(int)(0.04*RAND_IDX)],
    timing2[0][(int)(0.05*RAND_IDX)], timing2[0][(int)(0.10*RAND_IDX)], timing2[0][(int)(0.15*RAND_IDX)], timing2[0][(int)(0.20*RAND_IDX)], timing2[0][(int)(0.25*RAND_IDX)],
    timing2[0][(int)(0.30*RAND_IDX)], timing2[0][(int)(0.35*RAND_IDX)], timing2[0][(int)(0.40*RAND_IDX)], timing2[0][(int)(0.45*RAND_IDX)], timing2[0][(int)(0.50*RAND_IDX)],
    timing2[0][(int)(0.55*RAND_IDX)], timing2[0][(int)(0.60*RAND_IDX)], timing2[0][(int)(0.65*RAND_IDX)], timing2[0][(int)(0.70*RAND_IDX)], timing2[0][(int)(0.75*RAND_IDX)],
    timing2[0][(int)(0.80*RAND_IDX)], timing2[0][(int)(0.85*RAND_IDX)], timing2[0][(int)(0.90*RAND_IDX)], timing2[0][(int)(0.95*RAND_IDX)],
    timing2[0][(int)(0.96*RAND_IDX)], timing2[0][(int)(0.97*RAND_IDX)], timing2[0][(int)(0.98*RAND_IDX)], timing2[0][(int)(0.99*RAND_IDX)], timing2[0][RAND_IDX-1]          ,
    timingHi[0]);
  printf("timeRAM  : [%3d|%3d-%3d-%3d-%3d-%3d|%3d-%3d-%3d-%3d-%3d|-%3d-%3d-%3d-%3d-%3d|-%3d-%3d-%3d-%3d-%3d|-%3d-%3d-%3d-%3d|-%3d-%3d-%3d-%3d-%3d|%3d]\n",
    timingLo[1],
    timing2[1][(int)(0.00*RAND_IDX)], timing2[1][(int)(0.01*RAND_IDX)], timing2[1][(int)(0.02*RAND_IDX)], timing2[1][(int)(0.03*RAND_IDX)], timing2[1][(int)(0.04*RAND_IDX)],
    timing2[1][(int)(0.05*RAND_IDX)], timing2[1][(int)(0.10*RAND_IDX)], timing2[1][(int)(0.15*RAND_IDX)], timing2[1][(int)(0.20*RAND_IDX)], timing2[1][(int)(0.25*RAND_IDX)],
    timing2[1][(int)(0.30*RAND_IDX)], timing2[1][(int)(0.35*RAND_IDX)], timing2[1][(int)(0.40*RAND_IDX)], timing2[1][(int)(0.45*RAND_IDX)], timing2[1][(int)(0.50*RAND_IDX)],
    timing2[1][(int)(0.55*RAND_IDX)], timing2[1][(int)(0.60*RAND_IDX)], timing2[1][(int)(0.65*RAND_IDX)], timing2[1][(int)(0.70*RAND_IDX)], timing2[1][(int)(0.75*RAND_IDX)],
    timing2[1][(int)(0.80*RAND_IDX)], timing2[1][(int)(0.85*RAND_IDX)], timing2[1][(int)(0.90*RAND_IDX)], timing2[1][(int)(0.95*RAND_IDX)],
    timing2[1][(int)(0.96*RAND_IDX)], timing2[1][(int)(0.97*RAND_IDX)], timing2[1][(int)(0.98*RAND_IDX)], timing2[1][(int)(0.99*RAND_IDX)], timing2[1][RAND_IDX-1]          ,
    timingHi[1]);
  for(int i =0; i < 300; i++) {
    //                        L1L2             LLC              RAM
    //printf("%d %d %d %d\n",i, timingCnt[2][i], timingCnt[0][i], timingCnt[1][i]);
  }

  // *thrDET = (2*timingHi[0]+timingLo[1])/3;
  *thrDET =  timingLo[1] - 1;

  uint64_t index = (random_fast()%100000)*8;
  uint64_t addr  = (uint64_t)&shared_mem[index];
  maccess((void*)addr); HELPER_READ_ACCESS((void*)addr);
  *(char*)addr = 0;

  #define FLUSHTESTS 1000
  uint timeflushhit[FLUSHTESTS], timeflushmiss[FLUSHTESTS];
  for(int i=0; i<FLUSHTESTS; i++) {
   maccess((void*)addr);
   timeflushhit[i]  = time_flush((void*)addr);
   timeflushmiss[i] = time_flush((void*)addr);
  }
  qsort(timeflushhit,  FLUSHTESTS, sizeof(int), comp);
  qsort(timeflushmiss, FLUSHTESTS, sizeof(int), comp);


  printf("Time flush hit   [%d-%d-%d-%d-%d-%d-%d-%d-%d-%d-%d]\n",
          timeflushhit[(int)(0.00*FLUSHTESTS)],   timeflushhit[(int)(0.10*FLUSHTESTS)],   timeflushhit[(int)(0.20*FLUSHTESTS)],
          timeflushhit[(int)(0.30*FLUSHTESTS)],   timeflushhit[(int)(0.40*FLUSHTESTS)],   timeflushhit[(int)(0.50*FLUSHTESTS)],
          timeflushhit[(int)(0.60*FLUSHTESTS)],   timeflushhit[(int)(0.70*FLUSHTESTS)],   timeflushhit[(int)(0.80*FLUSHTESTS)],
          timeflushhit[(int)(0.90*FLUSHTESTS)],   timeflushhit[(int)(FLUSHTESTS-1)]);
  printf("Time flush miss  [%d-%d-%d-%d-%d-%d-%d-%d-%d-%d-%d]\n",
          timeflushmiss[(int)(0.00*FLUSHTESTS)],  timeflushmiss[(int)(0.10*FLUSHTESTS)],  timeflushmiss[(int)(0.20*FLUSHTESTS)],
          timeflushmiss[(int)(0.30*FLUSHTESTS)],  timeflushmiss[(int)(0.40*FLUSHTESTS)],  timeflushmiss[(int)(0.50*FLUSHTESTS)],
          timeflushmiss[(int)(0.60*FLUSHTESTS)],  timeflushmiss[(int)(0.70*FLUSHTESTS)],  timeflushmiss[(int)(0.80*FLUSHTESTS)],
          timeflushmiss[(int)(0.90*FLUSHTESTS)],  timeflushmiss[(int)(FLUSHTESTS-1)]);

}

#endif
