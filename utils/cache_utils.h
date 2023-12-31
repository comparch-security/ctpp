#pragma once

void     clflush            (void *p);
void     clflush_f          (void *p);

uint64_t rdtsc              (void);
uint64_t rdtscp64           (void);

void     maccess            (void *p);
void     mwrite             (void *v);
int      mread              (void *v);
int      time_mread         (void *adrs);
int      time_mread_nofence (void *adrs);
int      time_mread_nofence2 (void *adrs0, void *adrs1);
int      time_mread_nofence3 (void *adrs0, void *adrs1, void *adrs2);
int      time_flush         (void *adrs);

#define  flush(x)            clflush_f(x)
#define  flush_nofence(x)    clflush(x)
#define  memwrite(x)         mwrite(x)
#define  memread(x)          mread(x)