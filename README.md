# Pintos
Labs for undergraduate OS class (600.318) at Johns Hopkins. [Pintos](http://pintos-os.org) 
is a teaching operating system for x86, challenging but not overwhelming, small
but realistic enough to understand OS in depth (it can run x86 machine and simulators 
including QEMU, Bochs and VMWare Player!). The main source code, documentation and assignments 
are developed by Ben Pfaff and others from Stanford (refer to its [LICENSE](src/LICENSE)).

The course instructor ([Ryan Huang](mailto:huang@cs.jhu.edu)) made some changes to the original
Pintos labs to tailor for his class. The upstream for this branch comes from 
[https://github.com/ryanphuang/PintosM](https://github.com/ryanphuang/PintosM). For students in the class, please
download the release version for this branch at https://github.com/jhu-cs318/pintos.git


----------------------------------------------------------------------------------------

Pintos is a teaching operating system for x86 used in the Johns Hopkins 600.318
undergraduate operating systems course. The upstream for this branch is based
on Ryan Huang's PintosM fork of the original Stanford Pintos project. The
release version for the class is distributed at
<https://github.com/jhu-cs318/pintos.git>.

This README explains how the repository is organized so you can quickly locate
code, understand build infrastructure, and start extending Pintos. Each section
below maps the file system layout to the subsystem it implements.

## Top-Level Layout

| Path | Purpose |
| --- | --- |
| `README.md` | High-level overview of the project and file system (this file). |
| `src/` | All source code, build scripts, tests, utilities, and lab material. |

Within `src/` you will find both the kernel implementation and the supporting
user programs, tests, and tools that ship with Pintos.

## Build System and Common Files (`src/`)

| File/Directory | Role |
| --- | --- |
| `LICENSE` | Pintos license from the original Stanford project. |
| `Make.config` | Common compiler, assembler, and linker configuration; detects the `i386-elf-*` toolchain and centralizes build flags. |
| `Makefile` | Entry point that dispatches builds to kernel subdirectories (`threads`, `userprog`, `vm`, `filesys`) and aggregates clean/tag targets. |
| `Makefile.build` | Shared build logic (rules, patterns) used by the component-specific makefiles. |
| `Makefile.kernel` | Rules for building kernel binaries and disk images used in kernel mode labs. |
| `Makefile.userprog` | Additional rules for building user programs and integrating them into file system images. |
| `examples/` | Source for sample user programs that can be loaded into Pintos. |
| `lib/` | C library code shared between kernel and user space (details below). |
| `tests/` | Automated test suites for each lab (details below). |
| `utils/` | Host-side utilities for building disks, launching QEMU/Bochs, and grading. |
| `misc/` | Toolchain helper scripts, Bochs patches, and documentation for building the cross-compilation environment. |

## Kernel Subsystems

### `threads/`
Core kernel that boots Pintos, manages threads, and implements basic
synchronization primitives. Key files include:

* `init.c` / `init.h` – Kernel entry once hardware setup is complete; orchestrates subsystem initialization.
* `start.S`, `loader.S`, `loader.h`, and `kernel.lds.S` – Assembly stubs and linker script that load the kernel.
* `thread.c` / `thread.h` – Core thread scheduler, thread data structures, and thread lifecycle management.
* `synch.c` / `synch.h` – Semaphores, locks, condition variables.
* `palloc.c` / `palloc.h` – Page allocator for kernel memory.
* `malloc.c` / `malloc.h` – General-purpose dynamic allocator built on top of the page allocator.
* `interrupt.c` / `interrupt.h`, `intr-stubs.S`, `intr-stubs.h`, `io.h` – Interrupt and handler dispatch infrastructure.
* `switch.S` / `switch.h` – Context-switch routine between kernel threads.
* `flags.h`, `pte.h`, `vaddr.h` – Hardware constants for flags registers, page tables, and virtual address helpers.

### `userprog/`
Optional user program support that adds process management and system calls.

* `process.c` / `process.h` – Loading ELF binaries, setting up user processes, and tracking child processes.
* `syscall.c` / `syscall.h` – System call dispatch table and handlers.
* `exception.c` / `exception.h` – User-mode exception and page fault handling.
* `gdt.c` / `gdt.h`, `tss.c` / `tss.h` – Global Descriptor Table and Task State Segment setup for user-mode transitions.
* `pagedir.c` / `pagedir.h` – Abstractions over hardware page directories.

### `filesys/`
Reference file system for later labs.

* `filesys.c` / `filesys.h` – File system initialization, mounting, and top-level operations.
* `inode.c` / `inode.h` – On-disk inode management, including block allocation and metadata.
* `directory.c` / `directory.h` – Directory hierarchy management.
* `file.c` / `file.h` – File descriptor layer exposed to user programs.
* `free-map.c` / `free-map.h` – Persistent free-space bitmap management.
* `fsutil.c` / `fsutil.h` – Command-line utilities used by host tools to inspect Pintos file systems.
* `off_t.h` – File offset type definition shared with userland.

### `devices/`
Device drivers and emulated hardware interfaces.

* Block devices (`block.c`, `ide.c`, `partition.c`).
* Character devices and input queues (`input.c`, `kbd.c`, `serial.c`).
* Timers and clocks (`timer.c`, `pit.c`, `rtc.c`).
* Power and console interfaces (`shutdown.c`, `speaker.c`, `vga.c`).
* `intq.c` / `intq.h` – Interrupt-driven circular buffers used by drivers.

### `vm/`
Virtual memory lab starter directory. Initially only contains makefiles; you
will populate this folder when implementing demand paging and swapping.

## Shared Libraries (`src/lib/`)

Split into kernel-only and user-only subsets that replace a standard C library.

* Root-level library files (`string.c`, `stdlib.c`, `stdio.c`, `debug.c`, `random.c`, `arithmetic.c`) implement fundamental routines used across Pintos.
* Headers (`stddef.h`, `stdint.h`, `stdbool.h`, etc.) provide type definitions compatible with the compiler toolchain.
* `syscall-nr.h` defines syscall numbers shared with user programs.
* `kernel/` holds data structures meant only for kernel builds (e.g., `list.c`, `hash.c`, `bitmap.c`, `console.c`).
* `user/` contains user-mode runtime support (`syscall.c`, `console.c`, `entry.c`, linker script `user.lds`).

## User Programs and Examples (`src/examples/`)

Sample user applications that can be compiled into file system images for
testing. Each `.c` file is a standalone program (e.g., `halt.c`, `shell.c`,
`matmult.c`). The `lib/user/` subdirectory mirrors the user-space runtime
support required to build the examples.

## Test Suites (`src/tests/`)

Automated regression tests organized by lab.

* `threads/`, `userprog/`, `filesys/`, and `vm/` – Lab-specific tests that exercise scheduling, user processes, file systems, and virtual memory respectively.
* `Algorithm/` – Reference algorithm implementations used by certain tests.
* `internal/`, `lib.*`, and `main.*` – Testing harness infrastructure shared by all suites.
* `make-grade` – Script that runs the appropriate tests and summarizes scores.
* `tests.pm`, `arc4.pm`, `cksum.pm`, etc. – Perl modules used by grading tools.

## Utilities (`src/utils/`)

Host-side tools that help build disk images and launch Pintos.

* `pintos` – Front-end script that boots Pintos under QEMU or Bochs.
* `pintos-mkdisk`, `pintos-set-cmdline` – Disk image helpers.
* `pintos-gdb`, `Pintos.pm` – GDB integration and shared Perl code.
* `backtrace`, `squish-pty.c`, `squish-unix.c`, `setitimer-helper.c` – Support binaries used by the test harness.

## Toolchain and Miscellaneous (`src/misc/`)

Patches and scripts for building the cross-compiler and simulator environment.
This includes Bochs patches, GCC/GDB build instructions, and helper scripts such
as `toolchain-build.sh`. The `stale/` directory contains outdated resources kept
for reference.

## How to Get Started

1. Install the `i386-elf-*` toolchain or configure `GCCPREFIX` in `Make.config`.
2. Change into `src/threads`, `src/userprog`, `src/filesys`, or `src/vm` and run
   `make` to build the kernel for the corresponding lab.
3. Use `utils/pintos` to launch the resulting kernel image under QEMU or Bochs.
4. Run `tests/<lab>/make check` or `tests/make-grade` to execute automated
   grading scripts once your features are implemented.

Refer to the Stanford Pintos documentation for lab specifications and detailed
assignment write-ups. This repository provides the code scaffold, tools, and
reference tests required to complete each lab.
