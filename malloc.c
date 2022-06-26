/**********************************************************************
 * Copyright (c) 2020
 *  Jinwoo Jeong <jjw8967@ajou.ac.kr>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTIABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 **********************************************************************/

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdint.h>

#include "malloc.h"
#include "types.h"
#include "list_head.h"

#define ALIGNMENT 32
#define HDRSIZE sizeof(header_t)

static LIST_HEAD(free_list); // Don't modify this line
static algo_t g_algo;        // Don't modify this line
static void *bp;             // Don't modify thie line

#define IS_LOGGING 1
#define ALIGN(target, size) ((target - 1) / size * size + size)

header_t *new_alloc(size_t size) {
  header_t *p = sbrk(0); // get end of current heap
  if(IS_LOGGING) fprintf(stderr, "Allocate %zu new bytes on %p\n", size, p);

  // allocate new heap
  // TODO: print error reason
  if(sbrk(size+HDRSIZE)==(void*)-1) {
      fprintf(stderr, "sbrk failed\n");
      return NULL;
  }

  p->size = size;
  p->free = false;

  // add to the free_list
  if (list_empty(&free_list))
    INIT_LIST_HEAD(&free_list);
  list_add_tail(&p->list, &free_list);

  return p;
}

header_t *split_free(header_t *p, size_t size){
  header_t *new_p = (header_t*)((char *)p + size);
  new_p->size = p->size - size - HDRSIZE;
  new_p->free = true;
  list_add(&new_p->list, &p->list);
  p->size = size;
  return p;
}

void merge_prev(header_t *p){
    if (list_is_last(&p->list, &free_list) ||
        p == list_first_entry(&free_list, header_t, list))
        return;

    header_t *cur = list_prev_entry(p, list);
    if (cur->free) {
        if (IS_LOGGING) fprintf(stderr, "Merge %p with %p(prev)\n", p, cur);
        p->size += cur->size + HDRSIZE;
        list_del(&cur->list);
    }
  // merge_prev(p);
}

void merge_next(header_t *p){
  if (list_is_last(&p->list, &free_list) ||
        p == list_last_entry(&free_list, header_t, list))
    return;

  header_t *cur = list_next_entry(p, list);
  if(cur->free) {
      if (IS_LOGGING) fprintf(stderr, "Merge %p with %p(next)\n", p, cur);
      p->size += cur->size + HDRSIZE;
      list_del(&cur->list);
  }
  // merge_next(p);
}

void merge_free(header_t *p) {
  merge_prev(p);
  merge_next(p);
}

/***********************************************************************
 * my_malloc()
 *
 * DESCRIPTION
 *   allocate size of bytes of memory and returns a pointer to the
 *   allocated memory.
 *
 * RETURN VALUE
 *   Return a pointer to the allocated memory.
 */
void *my_malloc(size_t size)
{
  /* Implement this function */

  // if(리스트가 비었을 경우): 새로 할당
  // else if(리스트 돌았는데 빈 게 없을 경우): 새로 할당
  // else:
  //  if(FIRST_FIT): 찾자마자 break
  //  else if(BEST_FIT): 저장해 놓고 계속 탐색
  // 찾은 주소 or 할당한 주소 반환

  char *new_p;
  header_t *target = NULL;
  size_t act_size = ALIGN(size, ALIGNMENT); 

  if (list_empty(&free_list)) {
      target = new_alloc(act_size);
      if (!target) return NULL;
  } else {
      header_t *cur;
      list_for_each_entry(cur, &free_list, list) {
          if (cur->free && cur->size >= act_size) {
              if (g_algo == FIRST_FIT) {
                  target = cur;
                  break;
                }
              else {  //BEST_FIT: continue iter
                    if (!target || cur->size < target->size)
                      target = cur;
                }
          }
      }
      if(!target){
        target = new_alloc(act_size);
        if (!target) return NULL;
      } else {
          target->free = false;
      }
  }

  // split block if it is too big
  if (target->size > act_size + HDRSIZE) {
      target = split_free(target, act_size);
  }

  new_p = (char *)target + HDRSIZE;
  return new_p;
}

/***********************************************************************
 * my_realloc()
 *
 * DESCRIPTION
 *   tries to change the size of the allocation pointed to by ptr to
 *   size, and returns ptr. If there is not enough memory block,
 *   my_realloc() creates a new allocation, copies as much of the old
 *   data pointed to by ptr as will fit to the new allocation, frees
 *   the old allocation.
 *
 * RETURN VALUE
 *   Return a pointer to the reallocated memory
 */
void *my_realloc(void *ptr, size_t size)
{
  /* Implement this function */

  // header_t *p;
  // // add to the free_list
  // if (list_empty(&free_list))
  //   INIT_LIST_HEAD(&free_list);
  // list_add_tail(&p->list, &free_list);

  return NULL;
}

/***********************************************************************
 * my_free()
 *
 * DESCRIPTION
 *   deallocates the memory allocation pointed to by ptr.
 */
void my_free(void *ptr)
{
  /* Implement this function */
  // TODO: check if *ptr is in the heap
  // TODO: increase size if last block is free
  // TODO: merge free blocks recursively
  header_t *p = (header_t *)((char *)ptr - HDRSIZE);
  p->free = true;
  if(IS_LOGGING) fprintf(stderr, "Free block(size: %lu) on %p\n", p->size, p);
  merge_free(p);

  return;
}

/*====================================================================*/
/*          ****** DO NOT MODIFY ANYTHING BELOW THIS LINE ******      */
/*          ****** BUT YOU MAY CALL SOME IF YOU WANT TO.. ******      */
/*          ****** EXCEPT TO mem_init() AND mem_deinit(). ******      */
void mem_init(const algo_t algo)
{
  g_algo = algo;
  bp = sbrk(0);
}

void mem_deinit()
{
  header_t *header;
  size_t size = 0;
  list_for_each_entry(header, &free_list, list) {
    size += HDRSIZE + header->size;
  }
  sbrk(-size);

  if (bp != sbrk(0)) {
    fprintf(stderr, "[Error] There is memory leak\n");
  }
}

void print_memory_layout()
{
  header_t *header;
  int cnt = 0;

  printf("===========================\n");
  list_for_each_entry(header, &free_list, list) {
    cnt++;
    printf("%c %ld\n", (header->free) ? 'F' : 'M', header->size);
  }

  printf("Number of block: %d\n", cnt);
  printf("===========================\n");
  return;
}
