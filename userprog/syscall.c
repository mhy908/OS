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

#include <string.h>
#include <stdlib.h>

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

//wooyechan - max size of fd_table
#define MAX_FD 128
//mhy908 - lock for filesystem
struct lock file_lock;

// wooyechan start
char * get_first_word (char *name) {
	char * token, save;
	token = strtok_r(name, " ", &save);
	return token;
}

int push_fd (struct file *file) {
	struct thread * curr = thread_current();
	
	// curr -> index < MAX_PAGE_SIZE
	// note that fd_index start from 2
	/*
	File descriptors numbered 0 and 1 are reserved for the console: fd 0 (STDIN_FILENO)
	is standard input, fd 1 (STDOUT_FILENO) is standard output.
	*/
	int fd = 2;
	lock_acquire(&file_lock);
	while (fd < MAX_FD && curr->fd_table[fd] != NULL) {
		fd++;
	}

	if (fd >= MAX_FD) {
		lock_release(&file_lock);
		return -1;
	}

	curr->fd_table[fd] = file;
	lock_release(&file_lock);
	return fd;
}	

void halt() {
	power_off();
}

void exit(int status) {
	struct thread * curr = thread_current();
	curr -> exit = status;
	char * name = get_first_word (curr -> name);
    printf("%s: exit(%d)\n", name, status);
	thread_exit();
}

int fork (const char *thread_name) {
	
}

int exec (const char *file) {

}

int wait (int pid) {
	return 0;
}

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

int open (const char *file) {
	// validity (file);
	struct file * f = filesys_open(file);
	//if (f == NULL) return -1;

	int fd = push_fd(f);
	
	printf("FD : %d \n", fd);

	if (fd <= 1) return -1;
	return fd;
}

int filesize (int fd) {
	if (fd < 0) return -1;

	struct thread * curr = thread_current();
	struct file * file = curr -> fd_table[fd];
	if (file == NULL) return -1;
	return file_length(file);
}

int read (int fd, void *buffer, unsigned length) {


}

int write (int fd, const void *buffer, unsigned length) {
	if (fd == STDOUT_FILENO)
		putbuf(buffer, length);
	return length;
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

	The x86-64 convention for function return values is to place them in
	the RAX register. System calls that return a value can do so by modifying
	the rax member of struct intr_frame
	*/
	uint64_t syscall_number = f->R.rax;
	uint64_t first_arg = f->R.rdi;
	int pid;
	//printf ("syscall_number : %d\n", syscall_number);
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
		f->R.rax = wait(first_arg);
	case SYS_CREATE:
		f->R.rax = create(first_arg, f->R.rsi);		
	case SYS_REMOVE:
		f->R.rax = remove(first_arg);		
	case SYS_OPEN:
		f->R.rax = open(first_arg);		
	case SYS_FILESIZE:
		f->R.rax = filesize(first_arg);
	case SYS_READ:
		read(first_arg, f->R.rsi, f->R.rdx);
	case SYS_WRITE:
		f->R.rax = write(first_arg, f->R.rsi, f->R.rdx);		
	case SYS_SEEK:
		seek(first_arg, f->R.rsi);		
	case SYS_TELL:
		tell(first_arg);		
	case SYS_CLOSE:
		close(first_arg);
	}
	// wooyechan end
}
