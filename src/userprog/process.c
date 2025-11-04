#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "userprog/syscall.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
static bool setup_arguments (void **esp, char **argv, int argc);
static void release_wait_status (struct wait_status *ws);

struct exec_info
  {
    char *cmdline;                 /* Command line to execute. */
    struct wait_status *wait_status; /* Parent-child synchronization state. */
  };

static void
release_wait_status (struct wait_status *ws)
{
  if (ws == NULL)
    return;

  lock_acquire (&ws->lock);
  ws->ref_cnt--;
  int ref_cnt = ws->ref_cnt;
  lock_release (&ws->lock);

  if (ref_cnt == 0)
    free (ws);
}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name)
{
  struct thread *cur = thread_current ();
  struct exec_info *info = NULL;
  struct wait_status *ws = NULL;
  char *cmdline = NULL;
  char *name_copy = NULL;
  char *program_name = NULL;
  tid_t tid = TID_ERROR;

  if (file_name == NULL)
    return TID_ERROR;

  cmdline = palloc_get_page (0);
  if (cmdline == NULL)
    goto done;
  strlcpy (cmdline, file_name, PGSIZE);

  name_copy = palloc_get_page (0);
  if (name_copy == NULL)
    goto done;
  strlcpy (name_copy, file_name, PGSIZE);
  char *save_ptr;
  program_name = strtok_r (name_copy, " ", &save_ptr);
  if (program_name == NULL)
    goto done;

  ws = malloc (sizeof *ws);
  if (ws == NULL)
    goto done;
  ws->tid = TID_ERROR;
  ws->exit_code = -1;
  ws->loaded = false;
  ws->exited = false;
  ws->ref_cnt = 2;
  sema_init (&ws->wait_sema, 0);
  sema_init (&ws->load_sema, 0);
  lock_init (&ws->lock);
  list_push_back (&cur->children, &ws->elem);

  info = malloc (sizeof *info);
  if (info == NULL)
    goto done;
  info->cmdline = cmdline;
  info->wait_status = ws;

  tid = thread_create (program_name, PRI_DEFAULT, start_process, info);
  if (tid == TID_ERROR)
    goto done;
  ws->tid = tid;
  info = NULL;
  cmdline = NULL;

  /* Wait for the child to finish loading. */
  sema_down (&ws->load_sema);
  if (!ws->loaded)
    {
      list_remove (&ws->elem);
      release_wait_status (ws);
      tid = TID_ERROR;
      ws = NULL;
    }

done:
  if (tid == TID_ERROR)
    {
      if (info != NULL)
        free (info);
      if (ws != NULL && ws->tid == TID_ERROR)
        {
          list_remove (&ws->elem);
          release_wait_status (ws);
        }
      if (cmdline != NULL)
        palloc_free_page (cmdline);
    }
  if (name_copy != NULL)
    palloc_free_page (name_copy);
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *exec_info_)
{
  struct exec_info *info = exec_info_;
  struct wait_status *ws = info->wait_status;
  char *cmdline = info->cmdline;
  struct intr_frame if_;
  bool success;
  struct thread *cur = thread_current ();

  cur->wait_status = ws;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (cmdline, &if_.eip, &if_.esp);

  lock_acquire (&ws->lock);
  ws->loaded = success;
  lock_release (&ws->lock);
  sema_up (&ws->load_sema);

  /* If load failed, quit. */
  palloc_free_page (cmdline);
  free (info);
  if (!success)
    {
      cur->exit_status = -1;
      thread_exit ();
    }

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid)
{
  struct thread *cur = thread_current ();
  struct list_elem *e;
  struct wait_status *ws = NULL;

  for (e = list_begin (&cur->children); e != list_end (&cur->children); e = list_next (e))
    {
      struct wait_status *candidate = list_entry (e, struct wait_status, elem);
      if (candidate->tid == child_tid)
        {
          ws = candidate;
          list_remove (e);
          break;
        }
    }

  if (ws == NULL)
    return -1;

  sema_down (&ws->wait_sema);
  lock_acquire (&ws->lock);
  int status = ws->exit_code;
  lock_release (&ws->lock);
  release_wait_status (ws);
  return status;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  if (cur->pagedir != NULL)
    printf ("%s: exit(%d)\n", cur->name, cur->exit_status);

  /* Notify parent if waiting. */
  if (cur->wait_status != NULL)
    {
      lock_acquire (&cur->wait_status->lock);
      cur->wait_status->exit_code = cur->exit_status;
      cur->wait_status->exited = true;
      lock_release (&cur->wait_status->lock);
      sema_up (&cur->wait_status->wait_sema);
      release_wait_status (cur->wait_status);
      cur->wait_status = NULL;
    }

  /* Release all remaining references to children. */
  while (!list_empty (&cur->children))
    {
      struct list_elem *e = list_pop_front (&cur->children);
      struct wait_status *child_ws = list_entry (e, struct wait_status, elem);
      release_wait_status (child_ws);
    }

  syscall_cleanup ();
  if (cur->executable != NULL)
    {
      file_allow_write (cur->executable);
      file_close (cur->executable);
      cur->executable = NULL;
    }

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

load (const char *cmdline, void (**eip) (void), void **esp)
  char *cmdline_copy = NULL;
  char **argv = NULL;
  int argc = 0;
  if (t->pagedir == NULL)
  argv = palloc_get_page (PAL_ZERO);
  if (argv == NULL)
    goto done;

  cmdline_copy = palloc_get_page (0);
  if (cmdline_copy == NULL)
    goto done;
  strlcpy (cmdline_copy, cmdline, PGSIZE);
  char *token, *save_ptr;
  size_t max_args = PGSIZE / sizeof *argv;
  for (token = strtok_r (cmdline_copy, " ", &save_ptr); token != NULL;
       token = strtok_r (NULL, " ", &save_ptr))
    {
      argv[argc++] = token;
      if ((size_t) argc >= max_args)
        goto done;
    }

  if (argc == 0)
    goto done;

  file = filesys_open (argv[0]);
  if (file == NULL)
      printf ("load: %s: open failed\n", argv[0]);
      goto done;
  t->executable = file;
  file_deny_write (file);
      printf ("load: %s: error loading executable\n", cmdline);
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open executable file. */
  file = filesys_open (file_name);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
  if (!setup_arguments (esp, argv, argc))
    goto done;
  if (!success && file != NULL)
    {
      file_close (file);
      t->executable = NULL;
    }
  if (cmdline_copy != NULL)
    palloc_free_page (cmdline_copy);
  if (argv != NULL)
    palloc_free_page (argv);

static bool
setup_arguments (void **esp, char **argv, int argc)
{
  int i;

  for (i = argc - 1; i >= 0; i--)
    {
      size_t len = strlen (argv[i]) + 1;
      *esp -= len;
      memcpy (*esp, argv[i], len);
      argv[i] = *esp;
    }

  uintptr_t esp_val = (uintptr_t) *esp;
  esp_val &= 0xfffffffc;
  *esp = (void *) esp_val;

  *esp -= sizeof (char *);
  char **stack_ptr = *esp;
  *stack_ptr = NULL;

  for (i = argc - 1; i >= 0; i--)
    {
      *esp -= sizeof (char *);
      stack_ptr = *esp;
      *stack_ptr = argv[i];
    }

  char **argv_start = *esp;
  *esp -= sizeof (char **);
  char ***argv_ptr = *esp;
  *argv_ptr = argv_start;

  *esp -= sizeof (int);
  int *argc_ptr = *esp;
  *argc_ptr = argc;

  *esp -= sizeof (void *);
  void **ret_addr = *esp;
  *ret_addr = NULL;

  return true;
}

                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  file_close (file);
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        palloc_free_page (kpage);
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
