/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include <list.h>

#define MEGA_BYTE 0x100000

//mhy908
uint64_t derive_key(void *va){
	//need to round????
	uint64_t x=pg_round_down(va);
	x*=998244353;
	x^=(x>>32);
	x*=1000000007;
	x^=(x>>32);
	return x;
}

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */

struct list frame_queue;

void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
	list_init(&frame_queue);
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt=&thread_current()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
		
		struct page *page=(struct page*)malloc(sizeof(struct page));
		//printf("key = %llu\n", page->key);
		
		bool (*initializer) (struct page*, enum vm_type, void *);
		if(type==VM_ANON)initializer=anon_initializer;
		if(type==VM_FILE)initializer=file_backed_initializer;
		uninit_new(page, upage, init, type, aux, initializer);

		/* TODO: Insert the page into the spt. */
		//printf("Insert\n");
		
		page->dead=0;
		page->key=derive_key(upage);
		page->writable=writable;
		page->type=type;
		page->th=thread_current();

		return spt_insert_page(spt, page);
	}
err:
	return false;
}

//mhy908
/* Find VA from spt and return page. On error, return NULL. */
struct page* spt_find_page_help(struct page* nw, uint64_t tar){
	//printf("nw = %llu tar = %llu\n", nw->key, tar);
	if(nw->key==tar) {
		//printf ("(spt_find_page_help) nw : %d\n", nw);
		return nw->dead?NULL:nw;
	}
	if(nw->key<tar){
		if(nw->r)return spt_find_page_help(nw->r, tar);
		return NULL;
	}
	if(nw->key>tar){
		if(nw->l)return spt_find_page_help(nw->l, tar);
		return NULL;
	}
}
struct page *spt_find_page(struct supplemental_page_table *spt, void *va) {
	/* TODO: Fill this function. */
	if(!spt->root)return NULL;
	return spt_find_page_help(spt->root, derive_key(va));
}
/* Insert PAGE into spt with validation. */
bool spt_insert_page_help(struct page *nw, struct page *par, int dir, struct page *page){
	if(nw->key==page->key){
		if(!nw->dead)return false;
		page->l=nw->l;
		page->r=nw->r;
		if(par){
			if(dir==0)par->l=page;
			else par->r=page;
		}
		free(nw);
		return true;
	}
	if(nw->key<page->key){
		if(nw->r)return spt_insert_page_help(nw->r, nw, 0, page);
		nw->r=page;
		return true;
	}
	if(nw->key>page->key){
		if(nw->l)return spt_insert_page_help(nw->l, nw, 1, page);
		nw->l=page;
		return true;
	}
}
bool spt_insert_page(struct supplemental_page_table *spt, struct page *page){
	page->key=derive_key(page->va);
	// printf("INSERT %llu\n", page->key);
	if(!spt->root){
		spt->root=page;
		return true;
	}
	if(spt->root->dead&&spt->root->key==page->key){
		page->l=spt->root->l;
		page->r=spt->root->r;
		free(spt->root);
		spt->root=page;
		return true;
	}
	return spt_insert_page_help(spt->root, NULL, 0, page);
}

void
spt_remove_page(struct supplemental_page_table *spt UNUSED, struct page *page) {
	if(page->frame)list_remove(&page->frame->list_elem);
	destroy(page);
	page->dead=true;
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct list_elem* victem_elem=list_pop_front(&frame_queue);
	struct frame *victim = list_entry(victem_elem, struct frame, list_elem);
	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim = vm_get_victim ();
	return swap_out(victim->page)?victim:NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	/* TODO: Fill this function. */
	void *page=palloc_get_page(PAL_USER);
	if(page){
		struct frame* frame=(struct frame*)malloc(sizeof(struct frame));
		frame->page=NULL;
		frame->kva=page;
		return frame;
	}
	return vm_evict_frame();
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr_) {
	void *addr = pg_round_down(addr_);
	void *rsp = thread_current()->rsp;
	for (; addr < rsp; addr += PGSIZE) {
		if (vm_alloc_page(VM_ANON, addr, true) && vm_claim_page(addr)) memset(addr, 0, PGSIZE);
		else break;
	}
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f, void *addr, bool user, bool write, bool not_present) {
	struct supplemental_page_table *spt = &thread_current ()->spt;
	struct page *page = spt_find_page(spt, addr);
	void *rsp;

	if (user && is_kernel_vaddr(addr)){
		return false;
	}

	/* TODO: Validate the fault */
	/* TODO: Your code goes here */
	if (!not_present) return false;
	if (user) rsp = f->rsp;
	else rsp = thread_current()->rsp;
	if (!page && (USER_STACK - MEGA_BYTE) <= addr && addr <= USER_STACK && rsp - 8 <= addr) {
		vm_stack_growth(addr);
		return true;
	}
	if (write && !page->writable) return false;
	return vm_do_claim_page(page);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool vm_claim_page (void *va) {
	/* TODO: Fill this function */
	struct page* page=spt_find_page(&thread_current()->spt, va);
	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool vm_do_claim_page (struct page *page) {
	if (!page) return false;

	struct frame* frame = vm_get_frame ();

	if (!frame) return false;
	/* Set links */
	frame->page=page;
	page->frame=frame;
	list_push_back(&frame_queue, &frame->list_elem);

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	if (!pml4_set_page(thread_current()->pml4, page->va, frame->kva, page->writable))
		return false;

	return swap_in (page, frame->kva);
}

/* Initialize new supplemental page table */
void supplemental_page_table_init (struct supplemental_page_table *spt) {
	spt->root=NULL;
}

/* Copy supplemental page table from src to dst */

bool page_copy_helper(struct page *p, struct supplemental_page_table *dst){
	if(p->dead)return true;
	if(p->operations->type==VM_UNINIT){
		struct load_arg* load_arg=(struct load_arg*)malloc(sizeof(struct load_arg));
		if(!load_arg)return false;
		load_arg->file = ((struct load_arg*)(p->uninit.aux))->file;
    	load_arg->offset = ((struct load_arg*)(p->uninit.aux))->offset;
    	load_arg->read_bytes = ((struct load_arg*)(p->uninit.aux))->read_bytes;
    	load_arg->zero_bytes = ((struct load_arg*)(p->uninit.aux))->zero_bytes;
		return vm_alloc_page_with_initializer(p->type, p->va, p->writable, lazy_load_segment, load_arg);
	}
	if(p->operations->type==VM_ANON){
		if(!vm_alloc_page_with_initializer(VM_ANON, p->va, p->writable, NULL, NULL))return false;
		if(!vm_claim_page(p->va))return false;
		struct page *cur=spt_find_page(dst, p->va);
		memcpy(cur->va, p->frame->kva, PGSIZE);
		return true;
	}
	if(p->operations->type==VM_FILE){
		struct load_arg* load_arg=(struct load_arg*)malloc(sizeof(struct load_arg));
		if(!load_arg)return false;
		load_arg->file = p->file.file;
    	load_arg->offset = p->file.offset;
    	load_arg->read_bytes = p->file.read_bytes;
    	load_arg->zero_bytes = p->file.zero_bytes;
		return vm_alloc_page_with_initializer(VM_FILE, p->va, p->writable, lazy_load_segment, load_arg);
	}
}
bool page_table_copy_helper(struct page *p, struct supplemental_page_table *dst){
	if(!page_copy_helper(p, dst))return false;
	if(p->l&&!page_table_copy_helper(p->l, dst))return false;
	if(p->r&&!page_table_copy_helper(p->r, dst))return false;
	return true;
}
bool supplemental_page_table_copy (struct supplemental_page_table *dst,
		struct supplemental_page_table *src) {
	if(!src->root){
		dst->root=NULL;
		return true;
	}
	return page_table_copy_helper(src->root, dst);
}

/* Free the resource hold by the supplemental page table */
void page_table_kill_helper(struct page *p){
	if(p->l)page_table_kill_helper(p->l);
	if(p->r)page_table_kill_helper(p->r);
	if(!p->dead){
		if(p->frame)list_remove(&p->frame->list_elem);
		vm_dealloc_page(p);
	}
	else free(p);
}
void supplemental_page_table_kill (struct supplemental_page_table *spt) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	if(!spt->root)return;
	page_table_kill_helper(spt->root);
	spt->root=NULL;
}
