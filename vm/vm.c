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
		
		bool (*initializer) (struct page*, enum vm_type, void *);
		if(type==VM_ANON)initializer=anon_initializer;
		if(type==VM_FILE)initializer=file_backed_initializer;
		uninit_new(page, upage, init, type, aux, initializer);

		/* Initialize new fields */
		list_init(&page->box_list);
		lock_init(&page->box_lock);
		page->writable=writable;
		page->is_cow=false;
		page->type=type;

		/* TODO: Insert the page into the spt. */
		
		return spt_insert_page(spt, page);
	}
err:
	return false;
}

//mhy908
/* Find VA from spt and return page_box. On error, return NULL. */
struct page_box* spt_find_page_box_help(struct page_box* nw, uint64_t tar){
	if(nw->key==tar) {
		return nw->dead?NULL:nw;
	}
	if(nw->key<tar){
		if(nw->r)return spt_find_page_box_help(nw->r, tar);
		return NULL;
	}
	if(nw->key>tar){
		if(nw->l)return spt_find_page_box_help(nw->l, tar);
		return NULL;
	}
}

struct page_box* spt_find_page_box(struct supplemental_page_table *spt, void *va) {
	if(!spt->root)return NULL;
	return spt_find_page_box_help(spt->root, derive_key(va));
}

struct page *spt_find_page(struct supplemental_page_table *spt, void *va) {
	struct page_box *box = spt_find_page_box(spt, va);
	return box ? box->page : NULL;
}

/* Insert PAGE into spt with validation. */
bool spt_insert_page_help(struct page_box *nw, struct page_box *par, int dir, struct page_box *page_box){
	if(nw->key==page_box->key){
		if(!nw->dead)return false;
		page_box->l=nw->l;
		page_box->r=nw->r;
		if(par){
			if(dir==1)par->l=page_box;
			else par->r=page_box;
		}
		free(nw);
		return true;
	}
	if(nw->key<page_box->key){
		if(nw->r)return spt_insert_page_help(nw->r, nw, 0, page_box);
		nw->r=page_box;
		return true;
	}
	if(nw->key>page_box->key){
		if(nw->l)return spt_insert_page_help(nw->l, nw, 1, page_box);
		nw->l=page_box;
		return true;
	}
}

bool spt_insert_page(struct supplemental_page_table *spt, struct page *page){
	struct page_box *page_box = (struct page_box*)malloc(sizeof(struct page_box));
	page_box->key=derive_key(page->va);
	page_box->l = NULL;
	page_box->r = NULL;
	page_box->page = page;
	page_box->th = thread_current();
	page_box->dead = false;
	lock_acquire(&page->box_lock);
	list_push_back(&page->box_list, &page_box->box_elem);
	lock_release(&page->box_lock);

	if(!spt->root){
		spt->root=page_box;
		return true;
	}
	if(spt->root->dead&&spt->root->key==page_box->key){
		page_box->l=spt->root->l;
		page_box->r=spt->root->r;
		free(spt->root);
		spt->root=page_box;
		return true;
	}
	return spt_insert_page_help(spt->root, NULL, 0, page_box);
}

void
spt_remove_page(struct supplemental_page_table *spt, struct page *page) {
	struct page_box *box = spt_find_page_box(spt, page->va);
	if (box){
		lock_acquire(&page->box_lock);
		list_remove(&box->box_elem);
		if(list_size(&page->box_list)==0){
			if(page->frame)list_remove(&page->frame->list_elem);
			lock_release(&page->box_lock);
			vm_dealloc_page(page);
		}
		else lock_release(&page->box_lock);
		box->dead=true;
	}
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
		if (vm_alloc_page_with_initializer(VM_ANON, addr, true, NULL, NULL) && vm_claim_page(addr)) memset(addr, 0, PGSIZE);
		else break;
	}
}

/* Handle the fault on write_protected page */

static bool
vm_handle_wp (struct page_box *page_box) {
	if(!page_box->page->is_cow)return false;
	if(!page_box->page->frame){
		if(!vm_do_claim_page(page_box->page))return false;
	}
    ASSERT(page_box->page->type!=VM_UNINIT);
    if(page_box->page->type==VM_FILE)return true;
    if(list_size(&page_box->page->box_list)==1){
		page_box->page->writable=true;
		page_box->page->is_cow=false;
		return true;
	}

	struct page* page=page_box->page;

    list_remove(&page_box->box_elem);
    page_box->dead=true;
    if(!vm_alloc_page_with_initializer(VM_ANON, page->va, true, NULL, NULL))return false;
    if(!vm_claim_page(page->va))return false;
	memcpy(page->va, page->frame->kva, PGSIZE);

    return true;
}

bool vm_try_handle_fault_help(struct intr_frame *f, void *addr, bool user, bool write, bool not_present){

	//printf("addr = %lld user = %d write = %d not_present = %d kern = %d\n", addr, user, write, not_present, is_kernel_vaddr(addr));

	struct supplemental_page_table *spt = &thread_current ()->spt;
	void *rsp;

	if (user && is_kernel_vaddr(addr)){
		return false;
	}

	struct page_box *page_box = spt_find_page_box(spt, addr);

	/* TODO: Validate the fault */
	/* TODO: Your code goes here */
	if (write&&page_box&&!page_box->page->writable){
		return vm_handle_wp(page_box);
	}
	/*
	if (!not_present) {
		printf("wtf\n");
		return false;
	}
	*/
	if (user) rsp = f->rsp;
	else rsp = thread_current()->rsp;
	if (!page_box && (USER_STACK - MEGA_BYTE) <= addr && addr <= USER_STACK && rsp - 8 <= addr) {
		vm_stack_growth(addr);
		return true;
	}
	if(!page_box)return false;
	if(page_box->page->frame){
		//if(page_box->page->type==VM_ANON)printf("ANON??? %llu\n", page_box->page);
		pml4_set_page(page_box->th->pml4, page_box->page->va, page_box->page->frame->kva, page_box->page->writable);
		return true;
	}
	//printf("page_box->page = %d frame = %d\n", page_box->page, page_box->page->frame);
	return vm_do_claim_page(page_box->page);
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f, void *addr, bool user, bool write, bool not_present) {
	bool ret=vm_try_handle_fault_help(f, addr, user, write, not_present);
	//printf("?? %d\n", ret);
	return ret;
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

	struct list_elem *box_elem=list_begin(&page->box_list);
	bool ret=true;
	for(; box_elem!=list_end(&page->box_list); box_elem=list_next(box_elem)){
		struct thread *th=list_entry(box_elem, struct page_box, box_elem)->th;
		if(!pml4_set_page(th->pml4, page->va, frame->kva, page->writable))ret=false;
	}
	if(!ret)return false;
	return swap_in (page, frame->kva);
}

/* Initialize new supplemental page table */
void supplemental_page_table_init (struct supplemental_page_table *spt) {
	spt->root=NULL;
}

/* Copy supplemental page table from src to dst */

bool page_copy_helper(struct page_box *p, struct supplemental_page_table *dst){
	if(p->dead)return true;
	if(!p->page->is_cow){
		p->page->is_cow=p->page->writable;
		p->page->writable=false;
	}
	if(p->page->frame){
		ASSERT(&thread_current()->spt==dst);
		pml4_set_page(thread_current()->pml4, p->page->va, p->page->frame->kva, p->page->writable);
	}
	spt_insert_page(dst, p->page);
	//printf("?? %d %d %d\n", list_size(&p->page->box_list), p->page->is_cow, p->page->writable);
	return true;
}

bool page_table_copy_helper(struct page_box *p, struct supplemental_page_table *dst){
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
void page_table_kill_helper(struct page_box *p){
	if(p->l)page_table_kill_helper(p->l);
	if(p->r)page_table_kill_helper(p->r);
	if(!p->dead){
		lock_acquire(&p->page->box_lock);
		list_remove(&p->box_elem);
		if(list_size(&p->page->box_list)==0){
			if(p->page->frame)list_remove(&p->page->frame->list_elem);
			lock_release(&p->page->box_lock);
			vm_dealloc_page(p->page);
		}
		else lock_release(&p->page->box_lock);
	}
	free(p);
}

void supplemental_page_table_kill (struct supplemental_page_table *spt) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	if(!spt->root)return;
	page_table_kill_helper(spt->root);
	spt->root=NULL;
}
