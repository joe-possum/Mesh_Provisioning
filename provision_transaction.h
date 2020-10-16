/* provision_transaction.c */
struct links *find_link(uint32 id);
struct transactions *find_transaction(struct links *p, uint8 number);
void transaction_start(uint32 link_id, uint8 transaction_number, uint16 total_length, uint8 segn, uint8 len, uint8 *data);
void add_transaction(uint32 link_id, uint8 transaction_number, uint8 index, uint8 len, uint8 *data);
