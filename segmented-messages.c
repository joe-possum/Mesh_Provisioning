#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "utility.h"
#include "segmented-messages.h"

#ifdef TEST_SEGMENTED_MESSAGES
#include <unistd.h>

#ifndef VERBOSE_SEGMENTED_MESSAGES
#  define VERBOSE_SEGMENTED_MESSAGES 1
#endif

struct messages {
  int length, quanta, seg_count;
  uint8_t *data;
  uint32_t queued;
  uint16_t src;
  uint32_t seq;
  uint8_t complete;
} *messages = NULL;

void dump_message(struct messages *p) {
  printf("src: %x, seq: %x, seg_count: %x, queued: %x\n",p->src,p->seq,p->seg_count,p->queued);
}

int send_next(struct messages *p) {
  for(int i = 0; i < p->seg_count; i++) {
    uint32_t bit = 1 << i;
    if(p->queued & bit) {
      int len = p->length - i * p->quanta;
      if(len > p->quanta) len = p->quanta;
      struct segment_data data = { .len = len,
				   .data = p->data+i*p->quanta,
				   .offset = i,
				   .src = p->src,
				   .seq = p->seq,
				   .size = p->quanta,
				   .last = p->seg_count-1,
      };
      struct segmented *rc = new_segment(&data);
      p->queued ^= bit;
      if(rc) {
	dump_message(p);
	assert(rc->len == p->length);
	assert(0 == memcmp(rc->data,p->data,p->length));
	rc->clear(rc);
      }
      return 0;
    }
  }
  return 0;
}

int main(int argc, char *argv[]) {
  int message_count = 10;
  messages = malloc(message_count*sizeof(struct messages));
  for(int i = 0; i < message_count; i++) {
    messages[i].quanta = 12;
    messages[i].length = 13+rand()%(30*messages[i].quanta);
    messages[i].data = malloc(messages[i].length);
    for(int j = 0; j < messages[i].length; j++) messages[i].data[j] = rand();
    int partial = messages[i].length % messages[i].quanta;
    messages[i].seg_count = messages[i].length / messages[i].quanta;
    if(partial) messages[i].seg_count++;
    messages[i].queued = 0;
    for(int j = 0; j < messages[i].seg_count; j++) {
      messages[i].queued <<= 1;
      messages[i].queued |= 1;
    }
    messages[i].src = rand() & ((1<<16)-1);
    messages[i].seq = rand() & ((1<<24)-1);
    messages[i].complete = 0;
    dump_message(&messages[i]);
  }
  int done;
  do {
    done = 1;
    for(int i = 0; i < message_count; i++) {
      if(messages[i].queued) {
	send_next(&messages[i]);
	done = 0;
      }
    }
  } while(!done);
  return 0;
}
#else
#ifndef VERBOSE_SEGMENTED_MESSAGES
#  define VERBOSE_SEGMENTED_MESSAGES 0
#endif
#endif

struct segments {
  struct segmented rc;
  uint8_t *received;
  uint16_t src;
  uint32_t seq;
  struct segments *next;
} *segments = NULL;

struct segments *find_segments(uint16_t src, uint32_t seq) {
  for(struct segments *p = segments; p; p = p->next) {
    assert(p->next != p);
    if((src == p->src)&&(seq == p->seq)) return p;
  }
  return NULL;
}

static void clear(struct segmented *self) {
  free(self->data);
  for(struct segments **p = &segments; *p; p = &(*p)->next) {
    if(&(*p)->rc == self) {
      struct segments *tp = *p;
      *p = tp->next;
      free(tp->received);
      free(tp);
      return;
    }
  }
  assert(NULL == self);
}

struct segmented *new_segment(struct segment_data *data) {
  assert((data->offset == data->last) || ((data->offset < data->last) && (data->len == data->size)));
  struct segments *p = find_segments(data->src,data->seq);
  if(!p) {
    p = malloc(sizeof(struct segments));
    p->next = segments;
    segments = p;
    assert(p->next != p);
    p->rc.data = malloc(data->size*(data->last+1));
    p->rc.clear = clear;
    p->received = malloc(data->last+1);
    memset(p->received,0,data->last+1);
    p->src = data->src;
    p->seq = data->seq;
  }
  printf("src:%x,seq:%x,offset:%x,last%x,data:%s\n",data->src,data->seq,data->offset,data->last,hex(data->len,data->data));
  p->received[data->offset] = data->len;
  memcpy(&p->rc.data[data->offset*data->size],data->data,data->len);
  p->rc.len = 0;
  for(int i = 0; i <= data->last; i++) {
    if(!p->received[i]) return NULL;
    p->rc.len += p->received[i];
  }
  return &p->rc;
}
