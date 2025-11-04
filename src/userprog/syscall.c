#include "userprog/syscall.h"
#include <stdint.h>
#include <stddef.h>
#include <syscall-nr.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "lib/kernel/stdio.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"

struct file_descriptor
  {
    int fd;
    struct file *file;
    struct list_elem elem;
  };

static struct lock filesys_lock;

static void syscall_handler (struct intr_frame *);
static void syscall_exit (int status) NO_RETURN;
static int32_t get_user_arg (const void *esp, int index);
static void validate_user_ptr (const void *uaddr);
static void validate_user_buffer (const void *uaddr, unsigned size);
static void copy_in (void *dst, const void *usrc, size_t size);
static char *copy_in_string (const char *us);
static struct file_descriptor *find_fd (int fd);

void
syscall_init (void)
{
  lock_init (&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f)
{
  int32_t syscall_nr;

  validate_user_ptr (f->esp);
  syscall_nr = get_user_arg (f->esp, 0);

  switch (syscall_nr)
    {
    case SYS_HALT:
      shutdown_power_off ();
      break;

    case SYS_EXIT:
      syscall_exit (get_user_arg (f->esp, 1));
      break;

    case SYS_EXEC:
      {
        const char *cmd = (const char *) get_user_arg (f->esp, 1);
        char *kcmd = copy_in_string (cmd);
        tid_t tid = process_execute (kcmd);
        palloc_free_page (kcmd);
        f->eax = tid == TID_ERROR ? -1 : tid;
        break;
      }

    case SYS_WAIT:
      f->eax = process_wait ((tid_t) get_user_arg (f->esp, 1));
      break;

    case SYS_CREATE:
      {
        const char *fname = (const char *) get_user_arg (f->esp, 1);
        unsigned size = (unsigned) get_user_arg (f->esp, 2);
        char *kname = copy_in_string (fname);
        lock_acquire (&filesys_lock);
        bool ok = filesys_create (kname, size);
        lock_release (&filesys_lock);
        palloc_free_page (kname);
        f->eax = ok;
        break;
      }

    case SYS_REMOVE:
      {
        const char *fname = (const char *) get_user_arg (f->esp, 1);
        char *kname = copy_in_string (fname);
        lock_acquire (&filesys_lock);
        bool ok = filesys_remove (kname);
        lock_release (&filesys_lock);
        palloc_free_page (kname);
        f->eax = ok;
        break;
      }

    case SYS_OPEN:
      {
        const char *fname = (const char *) get_user_arg (f->esp, 1);
        char *kname = copy_in_string (fname);
        lock_acquire (&filesys_lock);
        struct file *file = filesys_open (kname);
        lock_release (&filesys_lock);
        palloc_free_page (kname);
        if (file == NULL)
          {
            f->eax = -1;
            break;
          }
        struct file_descriptor *fd = malloc (sizeof *fd);
        if (fd == NULL)
          {
            lock_acquire (&filesys_lock);
            file_close (file);
            lock_release (&filesys_lock);
            f->eax = -1;
            break;
          }
        struct thread *cur = thread_current ();
        fd->fd = cur->next_fd++;
        fd->file = file;
        list_push_back (&cur->file_list, &fd->elem);
        f->eax = fd->fd;
        break;
      }

    case SYS_FILESIZE:
      {
        int fd_val = get_user_arg (f->esp, 1);
        struct file_descriptor *fd = find_fd (fd_val);
        if (fd == NULL)
          {
            f->eax = -1;
            break;
          }
        lock_acquire (&filesys_lock);
        int size = file_length (fd->file);
        lock_release (&filesys_lock);
        f->eax = size;
        break;
      }

    case SYS_READ:
      {
        int fd_val = get_user_arg (f->esp, 1);
        void *buffer = (void *) get_user_arg (f->esp, 2);
        unsigned size = (unsigned) get_user_arg (f->esp, 3);
        if (size == 0)
          {
            f->eax = 0;
            break;
          }
        validate_user_buffer (buffer, size);
        if (fd_val == 0)
          {
            unsigned i;
            uint8_t *buf = buffer;
            for (i = 0; i < size; i++)
              buf[i] = input_getc ();
            f->eax = size;
            break;
          }
        struct file_descriptor *fd = find_fd (fd_val);
        if (fd == NULL)
          {
            f->eax = -1;
            break;
          }
        lock_acquire (&filesys_lock);
        int bytes_read = file_read (fd->file, buffer, size);
        lock_release (&filesys_lock);
        f->eax = bytes_read;
        break;
      }

    case SYS_WRITE:
      {
        int fd_val = get_user_arg (f->esp, 1);
        const void *buffer = (const void *) get_user_arg (f->esp, 2);
        unsigned size = (unsigned) get_user_arg (f->esp, 3);
        if (size == 0)
          {
            f->eax = 0;
            break;
          }
        validate_user_buffer (buffer, size);
        if (fd_val == 1)
          {
            putbuf (buffer, size);
            f->eax = size;
            break;
          }
        struct file_descriptor *fd = find_fd (fd_val);
        if (fd == NULL)
          {
            f->eax = -1;
            break;
          }
        lock_acquire (&filesys_lock);
        int bytes_written = file_write (fd->file, buffer, size);
        lock_release (&filesys_lock);
        f->eax = bytes_written;
        break;
      }

    case SYS_SEEK:
      {
        int fd_val = get_user_arg (f->esp, 1);
        unsigned position = (unsigned) get_user_arg (f->esp, 2);
        struct file_descriptor *fd = find_fd (fd_val);
        if (fd != NULL)
          {
            lock_acquire (&filesys_lock);
            file_seek (fd->file, position);
            lock_release (&filesys_lock);
          }
        break;
      }

    case SYS_TELL:
      {
        int fd_val = get_user_arg (f->esp, 1);
        struct file_descriptor *fd = find_fd (fd_val);
        if (fd == NULL)
          {
            f->eax = -1;
            break;
          }
        lock_acquire (&filesys_lock);
        off_t pos = file_tell (fd->file);
        lock_release (&filesys_lock);
        f->eax = pos;
        break;
      }

    case SYS_CLOSE:
      {
        int fd_val = get_user_arg (f->esp, 1);
        struct file_descriptor *fd = find_fd (fd_val);
        if (fd != NULL)
          {
            list_remove (&fd->elem);
            lock_acquire (&filesys_lock);
            file_close (fd->file);
            lock_release (&filesys_lock);
            free (fd);
          }
        break;
      }

    default:
      syscall_exit (-1);
      break;
    }
}

void
syscall_cleanup (void)
{
  struct thread *cur = thread_current ();
  while (!list_empty (&cur->file_list))
    {
      struct list_elem *e = list_pop_front (&cur->file_list);
      struct file_descriptor *fd = list_entry (e, struct file_descriptor, elem);
      lock_acquire (&filesys_lock);
      file_close (fd->file);
      lock_release (&filesys_lock);
      free (fd);
    }
}

static void
syscall_exit (int status)
{
  struct thread *cur = thread_current ();
  cur->exit_status = status;
  thread_exit ();
  NOT_REACHED ();
}

static int32_t
get_user_arg (const void *esp, int index)
{
  int32_t value;
  copy_in (&value, (const uint8_t *) esp + sizeof (int32_t) * index,
           sizeof value);
  return value;
}

static void
validate_user_ptr (const void *uaddr)
{
  if (uaddr == NULL || !is_user_vaddr (uaddr)
      || pagedir_get_page (thread_current ()->pagedir, uaddr) == NULL)
    syscall_exit (-1);
}

static void
validate_user_buffer (const void *uaddr, unsigned size)
{
  unsigned i;
  const uint8_t *addr = uaddr;
  for (i = 0; i < size; i++)
    validate_user_ptr (addr + i);
}

static void
copy_in (void *dst_, const void *usrc_, size_t size)
{
  uint8_t *dst = dst_;
  const uint8_t *src = usrc_;
  size_t i;

  for (i = 0; i < size; i++)
    {
      validate_user_ptr (src);
      dst[i] = *src++;
    }
}

static char *
copy_in_string (const char *us)
{
  char *ks = palloc_get_page (0);
  if (ks == NULL)
    syscall_exit (-1);

  size_t length = 0;
  for (;;)
    {
      validate_user_ptr (us + length);
      ks[length] = us[length];
      if (ks[length] == '\0')
        return ks;
      length++;
      if (length >= PGSIZE)
        syscall_exit (-1);
    }
}

static struct file_descriptor *
find_fd (int fd)
{
  struct thread *cur = thread_current ();
  struct list_elem *e;

  for (e = list_begin (&cur->file_list); e != list_end (&cur->file_list);
       e = list_next (e))
    {
      struct file_descriptor *f = list_entry (e, struct file_descriptor, elem);
      if (f->fd == fd)
        return f;
    }
  return NULL;
}
