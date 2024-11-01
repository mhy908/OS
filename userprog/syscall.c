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
#include "filesys/inode.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "lib/string.h"
#include "devices/input.h"

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

//mhy908 - lock for filesystem
struct lock file_lock;

//mhy908 - validation mechanism
bool validate_pointer(void *p, size_t size, bool writable){
	if(p==NULL||!is_user_vaddr(p))return false;
	struct thread *th=thread_current();
	void *ptr1=pg_round_down(p);
	void *ptr2=pg_round_down(p+size);
	bool ret=true;
	for(; ptr1<=ptr2; ptr1+=PGSIZE){
		uint64_t *pte=pml4e_walk(th->pml4, (uint64_t)ptr1, 0);
		if(pte==NULL||is_kern_pte(pte)||(writable&&!is_writable(pte))){
			ret=false;
			break;
		}
	}
	return ret;
}
bool validate_string(void *p){
	if(p==NULL||!is_user_vaddr(p))return false;
	struct thread *th=thread_current();
	void *ptr=NULL;
	uint64_t *pte=NULL;
	bool ret=true;
	for(char *i=p; ; i++){
		if(ptr!=pg_round_down(i)){
			ptr=pg_round_down(i);
			pte=pml4e_walk(th->pml4, (uint64_t)ptr, 0);
			if(pte==NULL||is_kern_pte(pte)){
				ret=false;
				break;
			}
		}
		if(*i==0)break;
	}
	return ret;
}
void error_exit(){
	struct thread * curr = thread_current();
	curr -> exit = -1;
	thread_exit();
}

struct file_box* get_filebox(int fd){
	struct list *file_list=&thread_current()->file_list;
	struct list_elem *e;
	for(e=list_begin(file_list); e!=list_end(file_list); e=list_next(e)){
		struct file_box* file_box=list_entry(e, struct file_box, file_elem);
		if(file_box->fd==fd)return file_box;
	}
	return NULL;
}

void halt() {
	power_off();
}

void exit(int status) {
	struct thread * curr = thread_current();
	curr -> exit = status;
	thread_exit();
}

tid_t fork (const char *name, struct intr_frame *f) {
	// wooyechan
	if (!validate_string(name))error_exit ();

	lock_acquire(&file_lock);

	tid_t tid = process_fork (name, f);

	lock_release(&file_lock);

	return tid;
}

int exec (const char *file) {
	if(!validate_string(file))error_exit();

	char *file_copy=palloc_get_page(0);
	if(!file_copy)error_exit();
	strlcpy(file_copy, file, PGSIZE);
	process_exec(file_copy);
	NOT_REACHED();
	return -1;
}

int wait (int pid) {
	process_wait(pid);
}

bool create (const char *file, unsigned initial_size) {
	if(!validate_string(file)||!strcmp(file, ""))error_exit();
	lock_acquire(&file_lock);

	bool ret=filesys_create(file, initial_size);

	lock_release(&file_lock);
	return ret;
}

bool remove (const char *file) {
	if(!validate_string(file))error_exit();
	lock_acquire(&file_lock);

	bool ret=filesys_remove(file);

	lock_release(&file_lock);
	return ret;
}

int open (const char *file_name) {
	if(!validate_string(file_name))error_exit();

	struct thread *t=thread_current();
	int ret=-1;
	lock_acquire(&file_lock);

	struct file *file=filesys_open(file_name);
	if(file){
		struct file_box *file_box=malloc(sizeof(struct file_box));
		file_box->fd=t->fd_index++;
		ret=file_box->fd;
		struct file_ref *file_ref=malloc(sizeof(struct file_ref));
		file_ref->file=file;
		file_ref->ref_cnt=1;
		file_box->file_ref=file_ref;
		file_box->type=FILE;
		list_push_back(&t->file_list, &file_box->file_elem);
	}

	lock_release(&file_lock);
	return ret;
}

int filesize (int fd){
	int ret=-1;
	lock_acquire(&file_lock);

	struct file_box *file_box=get_filebox(fd);
	if(file_box)ret=file_length(file_box->file_ref->file);

	lock_release(&file_lock);
	return ret;
}

int read (int fd, void *buffer, unsigned length) {

	int ret=-1;
	if(!validate_pointer(buffer, length, true))error_exit();
	lock_acquire(&file_lock);
	
	char *buf=(char*)buffer;
	struct file_box *file_box=get_filebox(fd);
	if(file_box){
		switch(file_box->type){
			case STDIN:
				for(unsigned i=0; i<length; i++)buf[i]=input_getc();
				break;
			case FILE:
				ret=file_read(file_box->file_ref->file, buffer, length);
				break;
		}
	}

	lock_release(&file_lock);
	return ret;
}

int write (int fd, void *buffer, unsigned length) {
	int ret=-1;
	if(!validate_pointer(buffer, length, false))error_exit();
	lock_acquire(&file_lock);

	struct file_box *file_box=get_filebox(fd);
	if(file_box){
		switch(file_box->type){
			case STDOUT:
				putbuf(buffer, length);
				break;
			case FILE:
				ret=file_write(file_box->file_ref->file, buffer, length);
				break;
		}
	}

	lock_release(&file_lock);
	return ret;
}

void seek (int fd, unsigned position) {
	lock_acquire(&file_lock);
	struct file_box* file_box=get_filebox(fd);
	if(file_box&&file_box->type==FILE){
		file_seek(file_box->file_ref->file, position);
	}
	lock_release(&file_lock);
}

int tell (int fd) {
	int ret=-1;
	lock_acquire(&file_lock);
	struct file_box* file_box=get_filebox(fd);
	if(file_box&&file_box->type==FILE){
		ret=file_tell(file_box->file_ref->file);
	}
	lock_release(&file_lock);
	return ret;
}

void close (int fd) {
	lock_acquire(&file_lock);
	struct file_box *file_box=get_filebox(fd);
	if(file_box){
		list_remove(&(file_box->file_elem));
		if(file_box->type==FILE){
			if(--file_box->file_ref->ref_cnt==0){
				file_close(file_box->file_ref->file);
				free(file_box->file_ref);
			}
		}
		free(file_box);
	}
	lock_release(&file_lock);
}

int dup2(int oldfd, int newfd){
	int ret=-1;
	if(newfd<0)return ret;

	lock_acquire(&file_lock);

	struct file_box *old_file_box=get_filebox(oldfd);
	struct file_box *new_file_box=get_filebox(newfd);
	if(!old_file_box){
		//do nothing
	}
	else if(oldfd==newfd){
		ret=oldfd;
	}
	else{
		if(new_file_box){
			if(new_file_box->type==FILE){
				if(--new_file_box->file_ref->ref_cnt==0){
					file_close(new_file_box->file_ref->file);
					free(new_file_box->file_ref);
				}
			}
			list_remove(&new_file_box->file_elem);
			free(new_file_box);
		}
		new_file_box=(struct file_box*)malloc(sizeof(struct file_box));
		new_file_box->fd=newfd;
		new_file_box->type=old_file_box->type;
		if(new_file_box->type==FILE){
			new_file_box->file_ref=old_file_box->file_ref;
			new_file_box->file_ref->ref_cnt++;
		}
		list_push_back(&thread_current()->file_list, &new_file_box->file_elem);
		ret=newfd;
	}
	lock_release(&file_lock);

	return ret;
}

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
	uint64_t rdi=f->R.rdi, rsi=f->R.rsi, rdx=f->R.rdx;
	int pid;
	//printf ("BEFORE (syscall_handler) syscall_number : %d, thread : %d, opened_file : %d\n", syscall_number, thread_current()->tid, list_size(&thread_current()->file_list));
	switch (syscall_number){
	case SYS_HALT:
		halt();
		break;	
	case SYS_EXIT:
		exit(rdi);
		break;	
	case SYS_FORK:
		f->R.rax = fork(rdi, f);
		break;			
	case SYS_EXEC:
		f->R.rax = exec(rdi);
		break;	
	case SYS_WAIT:
		f->R.rax = wait(rdi);
		break;	
	case SYS_CREATE:
		f->R.rax = create(rdi, rsi);		
		break;	
	case SYS_REMOVE:
		f->R.rax = remove(rdi);		
		break;	
	case SYS_OPEN:
		f->R.rax = open(rdi);
		break;		
	case SYS_FILESIZE:
		f->R.rax = filesize(rdi);
		break;	
	case SYS_READ:
		f->R.rax = read(rdi, rsi, rdx);
		break;	
	case SYS_WRITE:
		f->R.rax = write(rdi, rsi, rdx);
		break;			
	case SYS_SEEK:
		seek(rdi, rsi);		
		break;	
	case SYS_TELL:
		f->R.rax = tell(rdi);
		break;			
	case SYS_CLOSE:
		close(rdi);
		break;
	case SYS_DUP2:
		f->R.rax = dup2(rdi, rsi);
		break;	
	}
	//printf ("AFTER (syscall_handler) syscall_number : %d, thread : %d, opened_file : %d\n", syscall_number, thread_current()->tid, list_size(&thread_current()->file_list));
	// wooyechan end
}
