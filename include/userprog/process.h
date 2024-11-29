#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

//wooyechan
// to allow two argument at once
struct load_arg{
	struct file* file;
	off_t ofs;
	uint32_t read_bytes;
	uint32_t zero_bytes;
};
struct fork_arg {
    struct thread *parent;
    struct intr_frame if_;
    struct semaphore fork_sema;
    bool succ;
};

struct init_arg {
    struct thread * parent;
    char * file_name;
    struct semaphore sema;
};

void try_close (struct file_box *file_box);

tid_t process_create_initd (const char *file_name);
tid_t process_fork (const char *name, struct intr_frame *if_);
int process_exec (void *f_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (struct thread *next);

#endif /* userprog/process.h */
