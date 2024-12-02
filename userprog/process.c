#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h" 
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#ifdef VM
#include "vm/vm.h"
#endif

static void process_cleanup (void);
static bool load (const char *file_name, struct intr_frame *if_);
static void initd (void *f_name);
static void __do_fork (void *);
struct lock file_lock;

/* General process initializer for initd and other process. */
static void
process_init (void) {
	struct thread *current = thread_current ();
	sema_init (&current->wait_sema, 0);
	sema_init (&current->cleanup_sema, 0);
	current->exit = -1;
}

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
tid_t
process_create_initd (const char *file_name) {
	char *fn_copy;
	tid_t tid;

	/* Make a copy of FILE_NAME.
	 * Otherwise there's a race between the caller and load(). */

	//wooyechan
	struct init_arg * init_arg = malloc (sizeof (struct init_arg));

	fn_copy = palloc_get_page (0);
	if (fn_copy == NULL)
		return TID_ERROR;
	strlcpy (fn_copy, file_name, PGSIZE);

	init_arg->file_name = fn_copy;
	init_arg->parent = thread_current();
	sema_init(&init_arg->sema, 0);

	/* Create a new thread to execute FILE_NAME. */
	tid = thread_create (file_name, PRI_DEFAULT, initd, init_arg);

	if (tid == TID_ERROR) palloc_free_page (fn_copy);
	else sema_down(&init_arg->sema);

	free(init_arg);

	return tid;
}

/* A thread function that launches first user process. */
static void
initd (void *init_arg_) {
#ifdef VM
	supplemental_page_table_init (&thread_current ()->spt);
#endif
	struct init_arg *init_arg = (struct init_arg *)init_arg_;
	char *f_name = init_arg -> file_name;
	struct thread * parent = init_arg -> parent;

	struct thread *t=thread_current();
	struct file_box *file_box_stdin=malloc(sizeof(struct file_box));
	struct file_box *file_box_stdout=malloc(sizeof(struct file_box));

	file_box_stdin->fd=t->fd_index++;
	file_box_stdin->type=STDIN;
	list_push_back(&t->file_list, &file_box_stdin->file_elem);

	file_box_stdout->fd=t->fd_index++;
	file_box_stdout->type=STDOUT;
	list_push_back(&t->file_list, &file_box_stdout->file_elem);

	t -> wait_on_exit = true;

	process_init ();

	lock_acquire (&parent->child_lock);
	list_push_back(&parent->children, &t->child_elem);
	lock_release (&parent->child_lock);

	sema_up(&init_arg->sema);

	if (process_exec (f_name) < 0)
		PANIC("Fail to launch initd\n");
	NOT_REACHED ();
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
tid_t
process_fork (const char *name, struct intr_frame *if_) {
	/* Clone current thread to new thread.*/
	//wooyechan
	struct thread *curr = thread_current();
	struct fork_arg *fork_arg = (struct fork_arg *) malloc (sizeof (struct fork_arg));
	int priority = curr->priority;
	
	if (!fork_arg) return TID_ERROR;

	fork_arg->parent = curr;
	memcpy (&fork_arg->if_, if_, sizeof(struct intr_frame));
	sema_init (&fork_arg->fork_sema, 0);
	fork_arg->succ = false;

	tid_t tid = thread_create (name, priority, __do_fork, fork_arg);

	if (tid != TID_ERROR) sema_down(&fork_arg->fork_sema);

	if(!fork_arg->succ) tid=TID_ERROR;

	free(fork_arg);

	return tid;
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
static bool
duplicate_pte (uint64_t *pte, void *va, void *aux) {
	struct thread *current = thread_current ();
	struct thread *parent = (struct thread *) aux;
	void *parent_page;
	void *newpage;
	bool writable;

	//wooyechan
	/* 1. TODO: If the parent_page is kernel page, then return immediately. */
	if (is_kernel_vaddr(va)) return true;
	/* 2. Resolve VA from the parent's page map level 4. */
	parent_page = pml4_get_page (parent->pml4, va);

	/* 3. TODO: Allocate new PAL_USER page for the child and set result to
	 *    TODO: NEWPAGE. */
	newpage = palloc_get_page(PAL_USER);
	if (newpage == NULL) return false;
	/* 4. TODO: Duplicate parent's page to the new page and
	 *    TODO: check whether parent's page is writable or not (set WRITABLE
	 *    TODO: according to the result). */
	memcpy(newpage, parent_page, PGSIZE);
	writable = is_writable(pte);
	/* 5. Add new page to child's page table at address VA with WRITABLE
	 *    permission. */
	if (!pml4_set_page (current->pml4, va, newpage, writable)) {
		/* 6. TODO: if fail to insert page, do error handling. */
		palloc_free_page (newpage);
		return false;
	}
	return true;
}
#endif

/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
static void
__do_fork (void *_aux) {
	struct fork_arg *aux=(struct fork_arg *)_aux;
	struct intr_frame if_;
	struct thread *parent = ((struct fork_arg *)aux) -> parent;
	struct thread *current = thread_current ();
	/* TODO: somehow pass the parent_if. (i.e. process_fork()'s if_) */
	struct intr_frame *parent_if = &aux -> if_;

	/* 1. Read the cpu context to local stack. */
	memcpy (&if_, parent_if, sizeof (struct intr_frame));

	/* 2. Duplicate PT */
	current->exit = 0;
	current->pml4 = pml4_create();
	if (current->pml4 == NULL)
		goto error;
	process_activate (current);
#ifdef VM
	supplemental_page_table_init (&current->spt);
	if (!supplemental_page_table_copy (&current->spt, &parent->spt))
		goto error;
#else
	if (!pml4_for_each (parent->pml4, duplicate_pte, parent))
		goto error;
#endif

	/* TODO: Your code goes here.
	 * TODO: Hint) To duplicate the file object, use `file_duplicate`
	 * TODO:       in include/filesys/file.h. Note that parent should not return
	 * TODO:       from the fork() until this function successfully duplicates
	 * TODO:       the resources of parent.*/

	//wooyechan
	//printf ("(__do_fork) thread %d is running with sema %d, parent %d\n", current->tid , &((struct fork_arg *)aux) -> fork_sema, parent->tid);
	if_.R.rax = 0;
	current -> fd_index = parent -> fd_index;

    struct list *file_list = &parent->file_list;
    struct list_elem *e = list_begin(file_list);
    
    while (e != list_end(file_list))
    {   
        struct file_box *file_box = list_entry(e, struct file_box, file_elem);

		// Allocation
        struct file_box *new_file_box = (struct file_box *)malloc(sizeof(struct file_box));
        if (new_file_box == NULL) goto error;

		if(file_box->type==FILE){
			struct file * new_file=file_duplicate(file_box->file_ref->file);
			new_file_box->type=FILE;
			struct file_ref *new_file_ref=(struct file_ref*)malloc(sizeof(struct file_ref));
			new_file_ref->file=new_file;
			new_file_ref->ref_cnt=1;
       	 	new_file_box->file_ref = new_file_ref;
			new_file_box->fd=file_box->fd;
		}
		else{
			new_file_box->type=file_box->type;
			new_file_box->fd=file_box->fd;
		}
		list_push_back(&current->file_list, &new_file_box->file_elem);
        e=list_next(e);
    }

	process_init ();
	lock_acquire (&parent->child_lock);
	list_push_back (&parent->children, &current->child_elem);
	lock_release (&parent->child_lock);

	aux->succ= true;
	/* Finally, switch to the newly created process. */
error:
	current -> wait_on_exit = aux->succ;
	sema_up (&aux -> fork_sema);
	if (aux->succ) do_iret (&if_);
	thread_exit ();
}

/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */
int
process_exec (void *f_name) {

	char *file_name = f_name;
	//wooyechan
	char *argv[64];
	char *save_ptr;
	int argc = 0;
	bool success;

	//wooyechan
	//save tokens in argument list
    for (char *token = strtok_r(f_name, " ", &save_ptr); token != NULL; token = strtok_r(NULL, " ", &save_ptr)) {
        argv[argc] = token;
        argc++;
    }
    argv[argc] = NULL;

	/* We cannot use the intr_frame in the thread structure.
	 * This is because when current thread rescheduled,
	 * it stores the execution information to the member. */
	struct intr_frame _if;
	_if.ds = _if.es = _if.ss = SEL_UDSEG;
	_if.cs = SEL_UCSEG;
	_if.eflags = FLAG_IF | FLAG_MBS;

	/* We first kill the current context */
	process_cleanup ();

	/* And then load the binary */
	//wooyechan
	//filename to argv[0]
	success = load (argv[0], &_if);

	/* If load failed, quit. */
	if (!success) {
		// for safety?
		palloc_free_page (argv[0]);
		thread_current()->exit=-1;
		thread_exit();
	}
	
	//wooyechan
	uintptr_t arg_addr[64]; 
    for (int i = argc - 1; i >= 0; i--) {
        int arg_len = strlen(argv[i]) + 1;
        _if.rsp -= arg_len;
        memcpy(_if.rsp, argv[i], arg_len);
        arg_addr[i] = _if.rsp;
    }

    // Word-align
    _if.rsp -= ((uintptr_t)_if.rsp % 8);

    // null pointer argv[argc]
    _if.rsp -= 8;
    memset(_if.rsp, 0, 8);

    // argv addresses
    for (int i = argc - 1; i >= 0; i--) {
        _if.rsp -= 8;
        memcpy(_if.rsp, &arg_addr[i], 8);
    }

    // return address
    _if.rsp -= 8;
    memset(_if.rsp, 0, 8);

    _if.R.rdi = argc;
    _if.R.rsi = _if.rsp + 8; 

	// for debug
	/*
	hex_dump(_if.rsp, _if.rsp, USER_STACK - (uint64_t)*(&_if.rsp), true);
    printf("Registers setup: RDI = %d, RSI = %p\n", _if.R.rdi, (void *)_if.R.rsi);
	*/
	/* Start switched process. */
	palloc_free_page (argv[0]);
	
	do_iret (&_if);

	NOT_REACHED ();
}

struct thread* get_child(tid_t child_tid){
	struct thread * curr = thread_current();

	lock_acquire (&curr->child_lock);
	struct list * children = &(curr->children);
	struct list_elem *e = list_begin(children);

	while (e != list_end(children)) {
        struct thread *child = list_entry(e, struct thread, child_elem);
        if (child->tid == child_tid) {
			lock_release (&curr->child_lock);
			return child;
		}
        e = list_next(e);
    }
	lock_release (&curr->child_lock);

    return NULL;
}

/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */
int
process_wait (tid_t child_tid) {
	/* XXX: Hint) The pintos exit if process_wait (initd), we recommend you
	 * XXX:       to add infinite loop here before
	 * XXX:       implementing the process_wait. */
	// wooyechan
	struct thread * child = get_child(child_tid);
	if (child == NULL) return -1;

	sema_down(&child->wait_sema);
	list_remove(&child->child_elem);
	int status = child->exit;
	sema_up(&child->cleanup_sema);

	return status;
}

//wooyechan
char *get_first_word (char *name) {
	char * token, save;
	token = strtok_r(name, " ", &save);
	return token;
}

void try_close (struct file_box *file_box) {
	if (file_box->type != FILE) return;
	if(--file_box->file_ref->ref_cnt==0){
		file_close(file_box->file_ref->file);
		free(file_box->file_ref);
	}
}

/* Exit the process. This function is called by thread_exit (). */
void
process_exit (void) {
	struct thread *t = thread_current ();
	/* TODO: Your code goes here.
	 * TODO: Implement process termination message (see
	 * TODO: project2/process_termination.html).
	 * TODO: We recommend you to implement process resource cleanup here. */
	
	while(!list_empty(&t->file_list)){
		struct list_elem *elem=list_pop_front(&t->file_list);
		struct file_box *file_box=list_entry(elem, struct file_box, file_elem);
		try_close (file_box);
		free(file_box);
	}

	// wooyechan
	while (!list_empty (&t->children)) {
		struct list_elem *e = list_pop_front (&t->children);
		struct thread *th = list_entry (e, struct thread, child_elem);
		th->wait_on_exit = false;
		sema_up (&th->cleanup_sema);
	}

	process_cleanup ();

	file_close(t->executable);

	if (t->wait_on_exit) {
	  	printf ("%s: exit(%d)\n", get_first_word(t->name), t->exit);
	  	sema_up (&t->wait_sema);
	  	sema_down (&t->cleanup_sema);
	}
}

/* Free the current process's resources. */
static void
process_cleanup (void) {
	struct thread *curr = thread_current ();

#ifdef VM
	supplemental_page_table_kill (&curr->spt);
#endif

	uint64_t *pml4;
	/* Destroy the current process's page directory and switch back
	 * to the kernel-only page directory. */
	pml4 = curr->pml4;
	if (pml4 != NULL) {
		/* Correct ordering here is crucial.  We must set
		 * cur->pagedir to NULL before switching page directories,
		 * so that a timer interrupt can't switch back to the
		 * process page directory.  We must activate the base page
		 * directory before destroying the process's page
		 * directory, or our active page directory will be one
		 * that's been freed (and cleared). */
		curr->pml4 = NULL;
		pml4_activate (NULL);
		pml4_destroy (pml4);
	}
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void
process_activate (struct thread *next) {
	/* Activate thread's page tables. */
	pml4_activate (next->pml4);

	/* Set thread's kernel stack for use in processing interrupts. */
	tss_update (next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct ELF64_PHDR {
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack (struct intr_frame *if_);
static bool validate_segment (const struct Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes,
		bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
static bool
load (const char *file_name, struct intr_frame *if_) {
	struct thread *t = thread_current ();
	struct ELF ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;

	/* Allocate and activate page directory. */
	t->pml4 = pml4_create ();
	if (t->pml4 == NULL)
		goto done;
	process_activate (thread_current ());

	/* Open executable file. */
	lock_acquire(&file_lock);
	file = filesys_open (file_name);
	if (file == NULL) {
		printf ("load: %s: open failed\n", file_name);
		goto done;
	}

	/* Read and verify executable header. */
	if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
			|| memcmp (ehdr.e_ident, "\177ELF\2\1\1", 7)
			|| ehdr.e_type != 2
			|| ehdr.e_machine != 0x3E // amd64
			|| ehdr.e_version != 1
			|| ehdr.e_phentsize != sizeof (struct Phdr)
			|| ehdr.e_phnum > 1024) {
		printf ("load: %s: error loading executable\n", file_name);
		goto done;
	}

	/* Read program headers. */
	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++) {
		struct Phdr phdr;

		if (file_ofs < 0 || file_ofs > file_length (file))
			goto done;
		file_seek (file, file_ofs);

		if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
		file_ofs += sizeof phdr;
		switch (phdr.p_type) {
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
				if (validate_segment (&phdr, file)) {
					bool writable = (phdr.p_flags & PF_W) != 0;
					uint64_t file_page = phdr.p_offset & ~PGMASK;
					uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
					uint64_t page_offset = phdr.p_vaddr & PGMASK;
					uint32_t read_bytes, zero_bytes;
					if (phdr.p_filesz > 0) {
						/* Normal segment.
						 * Read initial part from disk and zero the rest. */
						read_bytes = page_offset + phdr.p_filesz;
						zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
								- read_bytes);
					} else {
						/* Entirely zero.
						 * Don't read anything from disk. */
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
	if (!setup_stack (if_))
		goto done;

	/* Start address. */
	if_->rip = ehdr.e_entry;

	/* TODO: Your code goes here.
	 * TODO: Implement argument passing (see project2/argument_passing.html). */

	success = true;

done:
	/* We arrive here whether the load is successful or not. */
	
	if(success){
		file_deny_write(file);
		t->executable=file;
	}
	else{
		file_close(file);
		t->executable=NULL;
	}
	lock_release(&file_lock);
	return success;
}


/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Phdr *phdr, struct file *file) {
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (uint64_t) file_length (file))
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

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page (void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	file_seek (file, ofs);
	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page (PAL_USER);
		if (kpage == NULL)
			return false;

		/* Load this page. */
		if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes) {
			palloc_free_page (kpage);
			return false;
		}
		memset (kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page (upage, kpage, writable)) {
			printf("fail\n");
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

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool
setup_stack (struct intr_frame *if_) {

	uint8_t *kpage;
	bool success = false;

	kpage = palloc_get_page (PAL_USER | PAL_ZERO);
	if (kpage != NULL) {
		success = install_page (((uint8_t *) USER_STACK) - PGSIZE, kpage, true);
		if (success)
			if_->rsp = USER_STACK;
		else
			palloc_free_page (kpage);
	}
	return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable) {
	struct thread *t = thread_current ();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page (t->pml4, upage) == NULL
			&& pml4_set_page (t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */



bool
lazy_load_segment (struct page *page, void *aux) {
	/* TODO: Load the segment from the file */
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */
	uint8_t *paddr=page->frame->kva;
	struct load_arg* load_arg=aux;

	file_read_at(load_arg->file, paddr, load_arg->read_bytes, load_arg->offset);
	memset(paddr+load_arg->read_bytes, 0, load_arg->zero_bytes);

	return true;
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	//printf("call load segment read = %d zero = %d writable = %d\n", read_bytes, zero_bytes, writable);

	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: Set up aux to pass information to the lazy_load_segment. */

		//printf("! read = %d zero = %d curread = %d curzero = %d\n", read_bytes, zero_bytes, page_read_bytes, page_zero_bytes);

		struct load_arg* aux=(struct load_arg*)malloc(sizeof(struct load_arg));
		aux->file=file;
		aux->offset=ofs;
		aux->read_bytes=page_read_bytes;
		aux->zero_bytes=page_zero_bytes;
		if (!vm_alloc_page_with_initializer (VM_ANON, upage, writable, lazy_load_segment, aux))
			return false;

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
		ofs += page_read_bytes;
	}
	return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool
setup_stack (struct intr_frame *if_) {
	bool success = false;
	void *stack_bottom = (void *) (((uint8_t *) USER_STACK) - PGSIZE);

	/* TODO: Map the stack on stack_bottom and claim the page immediately.
	 * TODO: If success, set the rsp accordingly.
	 * TODO: You should mark the page is stack. */
	/* TODO: Your code goes here */

	if (vm_alloc_page(VM_ANON, stack_bottom, true) && vm_claim_page(stack_bottom)) {
		if_->rsp = USER_STACK;
		return true;
	}
	return false;
}
#endif /* VM */
