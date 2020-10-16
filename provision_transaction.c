#include <stdlib.h>
#include <string.h>
#include "bg_types.h"
#include <stdio.h>

struct segment {
  uint8 len;
  uint8 data[64];
};

struct transactions {
  struct transactions *next;
  uint16 length, total;
  uint8 seg_count;
  uint8 number;
  struct segment *segments;
};

struct links {
  struct links *next;
  struct transactions *transactions;
  uint32 id;
} *links = NULL;

struct links *find_link(uint32 id) {
  struct links *p;
  for (p = links; p; p = p->next) if(id == p->id) return p;
  p = links;
  links = malloc(sizeof(struct links));
  links->next = p;
  links->id = id;
  links->transactions = NULL;
  return links;
}

struct transactions *find_transaction(struct links *p, uint8 number) {
  struct transactions *tp;
  for(tp = p->transactions; tp; tp = tp->next) if(number == tp->number) return tp;
  tp = p->transactions;
  p->transactions = malloc(sizeof(struct transactions));
  p->transactions->number = number;
  p->transactions->next = tp;
  return p->transactions;
}

void transaction_start(uint32 link_id,uint8 transaction_number,uint16 total_length,uint8 segn,uint8 len,uint8 *data) {
  struct links *p = find_link(link_id);
  struct transactions *tp = find_transaction(p,transaction_number);
  tp->length = total_length;
  tp->seg_count = segn+1;
  tp->segments = malloc(tp->seg_count*sizeof(struct segment));
  memset(tp->segments,0,tp->seg_count*sizeof(struct segment));
  tp->segments[0].len = len;
  memcpy(tp->segments[0].data,data,len);
  tp->total = len;
}

void add_transaction(uint32 link_id,uint8 transaction_number,uint8 index, uint8 len, uint8 *data) {
  struct links *p = find_link(link_id);
  struct transactions *tp = find_transaction(p,transaction_number);
  tp->segments[index].len = len;
  memcpy(tp->segments[index].data,data,len);
  tp->total += len;
  if(tp->total == tp->length) printf("Link ID:%08x Transaction %d completed\n",link_id,transaction_number);
}
