#pragma once

#include <stddef.h> // For size_t
#include <stdint.h>

#define HPTHREADS 1

typedef struct elem
{
  struct elem *next;
  struct elem *prev;
  int          set;
  size_t       delta;
  char         pad[32]; // up to 64B
} Elem;

#define HPT_FUN_IDLE        0
#define HPT_FUN_DRAIN       1
#define HPT_FUN_ACC_SYN     2
#define HPT_FUN_ACC_ASYN    3
#define HPT_FUN_CHECK       4
#define HPT_FUN_SCH_YIELD   5
#define HPT_FUN_OCCUPY_WAY  6
#define HPT_FUN_ABORT       7
#define HPT_FUN_EXIT        8

typedef struct helpThread
{
  uint64_t     fun;           //0:idle 1:check 2:maccess
  uint64_t     is_huge;
  uint8_t      *victim;
  uint8_t      *drain_mem;
  uint8_t      *shared_mem;
  uint64_t     page;
  uint8_t      syn;
  uint8_t      *syn_addr;
  uint64_t     idx;
  uint64_t     reqlen;
  uint64_t     acclen;
  uint64_t     rv;
  uint64_t     llcmissTh;
  uint64_t     evset[32];
} __attribute__((aligned(512))) helpThread_t;