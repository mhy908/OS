/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include "devices/disk.h"
#include <bitmap.h>

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
struct bitmap *swap_table;
static bool anon_swap_in (struct page *page, void *kva);
static bool anon_swap_out (struct page *page);
static void anon_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

/* Initialize the data for anonymous pages */
void
vm_anon_init (void) {
	/* TODO: Set up the swap_disk. */
	swap_disk=disk_get(1, 1);
	swap_table=bitmap_create(disk_size(swap_disk)/8);
}

/* Initialize the file mapping */
bool anon_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &anon_ops;
	return true;
}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in (struct page *page, void *kva) {
	struct anon_page *anon_page = &page->anon;
	int index=anon_page->swap_index;
	for(int i=0; i<8; i++){
		disk_read(swap_disk, 8*index+i, page->frame->kva+512*i);
	}
	bitmap_set(swap_table, index, false);
	return true;
}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out (struct page *page) {
	struct anon_page *anon_page = &page->anon;
	int index=bitmap_scan_and_flip(swap_table, 0, 1, false);
	if(index==BITMAP_ERROR)return false;
	anon_page->swap_index=index;
	for(int i=0; i<8; i++){
		disk_write(swap_disk, 8*index+i, page->frame->kva+512*i);
	}
	struct thread *t = list_entry(list_begin(&page->box_list), struct page_box, box_elem)->th;
	pml4_clear_page(t->pml4, page->va);
	page->frame=NULL;
	return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {
	struct anon_page *anon_page = &page->anon;
	if(page->frame){
		free(page->frame);
		page->frame=NULL;
	}
}
