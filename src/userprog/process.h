#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"

struct wait_status
  {
    tid_t tid;                      /* Child thread id. */
    int exit_code;                  /* Exit status reported to parent. */
    bool loaded;                    /* True if load succeeded. */
    bool exited;                    /* True once child has exited. */
    int ref_cnt;                    /* Reference count (parent + child). */
    struct semaphore wait_sema;     /* For parent waiting on exit. */
    struct semaphore load_sema;     /* For parent waiting on load. */
    struct lock lock;               /* Protects mutable fields. */
    struct list_elem elem;          /* Element in parent's child list. */
  };

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */
