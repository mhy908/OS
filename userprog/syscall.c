#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/init.h"
#include "threads/mmu.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "lib/string.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

//mhy908 - lock for filesystem
struct lock file_lock;

// wooyechan start
void halt() {
	power_off();
}

void exit(int status) {
	struct thread * curr = thread_current();
	curr -> exit = status;
	printf ("%s: exit(%d)\n", curr -> name, status);
	thread_exit();
}

pid_t fork (const char *thread_name); {
	
}

int exec (const char *file) {

}

int wait (int pid) {}

bool create (const char *file, unsigned initial_size) {
	/* MUST CHECK validity of file */
	
	lock_acquire(&file_lock);
	bool ret=filesys_create(file, initial_size);
	lock_release(&file_lock);
	return ret;
}

bool remove (const char *file) {
	/* MUST CHECK validity of file */

	lock_acquire(&file_lock);
	bool ret=filesys_remove(file);
	lock_release(&file_lock);
	return ret;
}
int open (const char *file) {}
int filesize (int fd) {}
int read (int fd, void *buffer, unsigned length) {}

int write (int fd, const void *buffer, unsigned length) {

}

void seek (int fd, unsigned position) {}
unsigned tell (int fd) {}
void close (int fd) {}
// wooyechan end

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

	//mhy908
	lock_init(&file_lock);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f) {
	// TODO: Your implementation goes here.
	// wooyechan start
	/* 
	Thus, when the system call handler syscall_handler() gets control,
	the system call number is in the rax, and arguments are passed with 
	the order %rdi, %rsi, %rdx, %r10, %r8, and %r9. 
	*/
	uint64_t syscall_number = f->R.rax;
	uint64_t first_arg = f->R.rdi;
	int pid;
	printf ("syscall_number : %d\n", syscall_number);
	switch (syscall_number)
	{
	case SYS_HALT:
		halt();
	case SYS_EXIT:
		exit(first_arg);
	case SYS_FORK:
		fork(first_arg);		
	case SYS_EXEC:
		exec(first_arg);
	case SYS_WAIT:
		wait(first_arg);
	case SYS_CREATE:
		create(first_arg, f->R.rsi);		
	case SYS_REMOVE:
		remove(first_arg);		
	case SYS_OPEN:
		open(first_arg);		
	case SYS_FILESIZE:
		filesize(first_arg);
	case SYS_READ:
		read(first_arg, f->R.rsi, f->R.rdx);
	case SYS_WRITE:
		write(first_arg, f->R.rsi, f->R.rdx);		
	case SYS_SEEK:
		seek(first_arg, f->R.rsi);		
	case SYS_TELL:
		tell(first_arg);		
	case SYS_CLOSE:
		close(first_arg);
	}
	// wooyechan end
}
