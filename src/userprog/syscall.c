#include "userprog/syscall.h"
#include <stdio.h>
#include <stdlib.h>
#include <syscall-nr.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

static struct lock fs_lock;

static void syscall_handler (struct intr_frame *);
static void check_ptr (const void *ptr);
static void check_buf (const void *buf, unsigned size);
static void check_str (const char *str);
static int get_fd (void);
static struct file *get_file (int fd);

void
syscall_init (void) 
{
  lock_init (&fs_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
check_ptr (const void *ptr)
{
  if (ptr == NULL || !is_user_vaddr (ptr) ||
      pagedir_get_page (thread_current ()->pagedir, ptr) == NULL)
    {
      thread_current ()->exit_status = -1;
      thread_exit ();
    }
}

static void
check_buf (const void *buf, unsigned size)
{
  unsigned i;
  for (i = 0; i < size; i++)
    check_ptr ((uint8_t *) buf + i);
}

static void
check_str (const char *str)
{
  check_ptr (str);
  while (*str != '\0')
    {
      str++;
      check_ptr (str);
    }
}

static int
get_fd (void)
{
  struct thread *cur = thread_current ();
  int fd;
  
  if (cur->fd_tbl == NULL)
    {
      cur->fd_tbl = calloc (16, sizeof (struct file *));
      if (cur->fd_tbl == NULL)
        return -1;
      cur->fd_max = 16;
    }
  
  for (fd = 2; fd < cur->fd_max; fd++)
    {
      if (cur->fd_tbl[fd] == NULL)
        return fd;
    }
  
  /* Need to expand table. */
  int new_max = cur->fd_max * 2;
  struct file **new_tbl = realloc (cur->fd_tbl, new_max * sizeof (struct file *));
  if (new_tbl == NULL)
    return -1;
  
  memset (new_tbl + cur->fd_max, 0, cur->fd_max * sizeof (struct file *));
  cur->fd_tbl = new_tbl;
  fd = cur->fd_max;
  cur->fd_max = new_max;
  return fd;
}

static struct file *
get_file (int fd)
{
  struct thread *cur = thread_current ();
  if (fd < 2 || fd >= cur->fd_max || cur->fd_tbl == NULL)
    return NULL;
  return cur->fd_tbl[fd];
}

static void
syscall_handler (struct intr_frame *f) 
{
  uint32_t *args = (uint32_t *) f->esp;
  struct thread *cur = thread_current ();
  
  check_ptr (args);
  
  switch (args[0])
    {
    case SYS_HALT:
      shutdown_power_off ();
      break;
      
    case SYS_EXIT:
      check_ptr (&args[1]);
      cur->exit_status = (int) args[1];
      thread_exit ();
      break;
      
    case SYS_EXEC:
      check_ptr (&args[1]);
      check_str ((char *) args[1]);
      lock_acquire (&fs_lock);
      f->eax = process_execute ((char *) args[1]);
      lock_release (&fs_lock);
      break;
      
    case SYS_WAIT:
      check_ptr (&args[1]);
      f->eax = process_wait ((tid_t) args[1]);
      break;
      
    case SYS_CREATE:
      check_ptr (&args[1]);
      check_ptr (&args[2]);
      check_str ((char *) args[1]);
      lock_acquire (&fs_lock);
      f->eax = filesys_create ((char *) args[1], (unsigned) args[2]);
      lock_release (&fs_lock);
      break;
      
    case SYS_REMOVE:
      check_ptr (&args[1]);
      check_str ((char *) args[1]);
      lock_acquire (&fs_lock);
      f->eax = filesys_remove ((char *) args[1]);
      lock_release (&fs_lock);
      break;
      
    case SYS_OPEN:
      {
        check_ptr (&args[1]);
        check_str ((char *) args[1]);
        lock_acquire (&fs_lock);
        struct file *file = filesys_open ((char *) args[1]);
        if (file == NULL)
          {
            lock_release (&fs_lock);
            f->eax = -1;
          }
        else
          {
            int fd = get_fd ();
            if (fd == -1)
              {
                file_close (file);
                lock_release (&fs_lock);
                f->eax = -1;
              }
            else
              {
                cur->fd_tbl[fd] = file;
                lock_release (&fs_lock);
                f->eax = fd;
              }
          }
      }
      break;
      
    case SYS_FILESIZE:
      {
        check_ptr (&args[1]);
        lock_acquire (&fs_lock);
        struct file *file = get_file ((int) args[1]);
        if (file == NULL)
          {
            lock_release (&fs_lock);
            f->eax = -1;
          }
        else
          {
            f->eax = file_length (file);
            lock_release (&fs_lock);
          }
      }
      break;
      
    case SYS_READ:
      {
        check_ptr (&args[1]);
        check_ptr (&args[2]);
        check_ptr (&args[3]);
        check_buf ((void *) args[2], (unsigned) args[3]);
        
        int fd = (int) args[1];
        void *buf = (void *) args[2];
        unsigned size = (unsigned) args[3];
        
        if (fd == 0)
          {
            /* Read from stdin. */
            unsigned i;
            uint8_t *b = (uint8_t *) buf;
            for (i = 0; i < size; i++)
              b[i] = input_getc ();
            f->eax = size;
          }
        else if (fd == 1)
          {
            f->eax = -1;
          }
        else
          {
            lock_acquire (&fs_lock);
            struct file *file = get_file (fd);
            if (file == NULL)
              {
                lock_release (&fs_lock);
                f->eax = -1;
              }
            else
              {
                f->eax = file_read (file, buf, size);
                lock_release (&fs_lock);
              }
          }
      }
      break;
      
    case SYS_WRITE:
      {
        check_ptr (&args[1]);
        check_ptr (&args[2]);
        check_ptr (&args[3]);
        check_buf ((void *) args[2], (unsigned) args[3]);
        
        int fd = (int) args[1];
        const void *buf = (const void *) args[2];
        unsigned size = (unsigned) args[3];
        
        if (fd == 1)
          {
            /* Write to stdout. */
            putbuf (buf, size);
            f->eax = size;
          }
        else if (fd == 0)
          {
            f->eax = -1;
          }
        else
          {
            lock_acquire (&fs_lock);
            struct file *file = get_file (fd);
            if (file == NULL)
              {
                lock_release (&fs_lock);
                f->eax = -1;
              }
            else
              {
                f->eax = file_write (file, buf, size);
                lock_release (&fs_lock);
              }
          }
      }
      break;
      
    case SYS_SEEK:
      {
        check_ptr (&args[1]);
        check_ptr (&args[2]);
        lock_acquire (&fs_lock);
        struct file *file = get_file ((int) args[1]);
        if (file != NULL)
          file_seek (file, (unsigned) args[2]);
        lock_release (&fs_lock);
      }
      break;
      
    case SYS_TELL:
      {
        check_ptr (&args[1]);
        lock_acquire (&fs_lock);
        struct file *file = get_file ((int) args[1]);
        if (file == NULL)
          {
            lock_release (&fs_lock);
            f->eax = -1;
          }
        else
          {
            f->eax = file_tell (file);
            lock_release (&fs_lock);
          }
      }
      break;
      
    case SYS_CLOSE:
      {
        check_ptr (&args[1]);
        int fd = (int) args[1];
        lock_acquire (&fs_lock);
        struct file *file = get_file (fd);
        if (file != NULL)
          {
            file_close (file);
            cur->fd_tbl[fd] = NULL;
          }
        lock_release (&fs_lock);
      }
      break;
      
    default:
      cur->exit_status = -1;
      thread_exit ();
      break;
    }
}
