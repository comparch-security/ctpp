////////////////////////////////////////////////////////////////////////////////
// Basic Memory Operations

#define READ_ACCESS(x)  ({                                        \
  maccess((void*)x);                                              })

#define TIME_READ_ACCESS(x)  ({                                   \
  access_time = time_mread((void*)x);                             })

#define TIME_READ_ACCESS_NOFENCE(x)  ({                            \
  access_time = time_mread_nofence((void*)x);                     })

#define WRITE_ACCESS(x)  ({                                       \
  memwrite((void*)x);                                             })

#define FLUSH(x)  ({                                              \
  flush((void*)x);                                                })

#define TIME_FLUSH(x)  ({                                         \
  access_time = time_flush((void*)x);                             })
                                     

////////////////////////////////////////////////////////////////////////////////
// Memory Operations to be executed by the helper thread
/*
#define HELPER_READ_ACCESS(x)   ({                                \
  *synchronization_params = (volatile uint64_t)x;                  \
  *synchronization  = 1;                                           \
  while(*synchronization==1);                                      })
*/

#define HELPER_READ_ACCESS(x)   ({                                \
  while(ht_params[0]->rv == 0);                                   \
  ht_params[0]->rv           = 0;                                 \
  ht_params[0]->syn_addr     = (uint8_t*)(x);                     \
  ht_params[0]->fun          = HPT_FUN_ACC_SYN;                   \
  while(ht_params[0]->rv == 0);                                   })

#define HELPER_READ_ACCESS_NOBLK(x)   ({                          \
  while(ht_params[0]->rv == 0);                                   \
  ht_params[0]->rv           = 0;                                 \
  ht_params[0]->syn_addr     = (uint8_t*)(x);                     \
  ht_params[0]->fun          = HPT_FUN_ACC_SYN;                  })

#define HELPER_CHECK_ACCESS_START(x)   ({                         \
  while(ht_params[0]->rv == 0);                                   \
  *synchronization           = 0;                                 \
  ht_params[1]->rv           = 0;                                 \
  ht_params[1]->victim       = (uint8_t*)(x);                     \
  ht_params[1]->fun          = HPT_FUN_CHECK;                     })

#define TOGHTER_READ_ACCESS(x)   ({                                \
  while(ht_params[0]->rv == 0);                                    \
  ht_params[0]->rv           = 0;                                  \
  ht_params[0]->syn_addr     = (uint8_t*)(x);                      \
  ht_params[0]->fun          = HPT_FUN_ACC_SYN;                    \
  maccess((void*)x);                                               \
  while(ht_params[0]->rv == 0);                                    })

#define TOGHTER_READ_ACCESS_NOBLK(x)   ({                          \
  while(ht_params[0]->rv == 0);                                    \
  ht_params[0]->rv           = 0;                                  \
  ht_params[0]->syn_addr     = (uint8_t*)(x);                      \
  ht_params[0]->fun          = HPT_FUN_ACC_SYN;                    \
  maccess((void*)x);                                               })

/*
#define HELPER_READ_ACCESS_NONBLOCK(x)   ({                        \
  while(*synchronization==1);                                      \
  *synchronization_params = (volatile uint64_t)x;                  \
  *synchronization  = 1;                                           })

#define TOGHTER_READ_ACCESS(x)   ({                                \
  *synchronization_params = (volatile uint64_t)x;                  \
  *synchronization  = 1;                                           \
  maccess((void*)x);                                               \
  while(*synchronization==1);                                      })
*/


#define KILL_HELPER()   ({                                          \
    for(int i = 0;i <HPTHREADS;i++)   ht_params[i]->fun = HPT_FUN_EXIT;                                   })

#define HELPER_TIME_ACCESS(x)   ({                                 \
  *synchronization_params = (volatile uint64_t)x;                  \
  *synchronization = 3;                                            \
  while(*synchronization==3);                                      \
  access_time = *synchronization_params;                           })

////////////////////////////////////////////////////////////////////////////////
// Memory Operations to be executed by the victim thread

#define VICTIM_READ_ACCESS(x)   ({                                \
  *synchronization_params = (volatile uint64_t)x;                  \
  *synchronization = 11;                                           \
  while(*synchronization==11);                                     })

////////////////////////////////////////////////////////////////////////////////
// Extras

#define BUSY_WAIT() ({                                            \
  for (i = 30000; i>0; i--)                                       \
    asm volatile("nop;");                                         })
