struct segmented {
  uint8_t *data;
  uint16_t len;
  void (*clear)(struct segmented*);
};

struct segment_data {
  uint8_t len;
  uint8_t *data;
  uint8_t offset;
  uint8_t last;
  uint16_t src;
  uint32_t seq;
  uint8_t size;
};

struct segmented *new_segment(struct segment_data *data);
  
