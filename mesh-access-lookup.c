#include <stdint.h>

const char *mesh_access_lookup(uint16_t opcode) {
  switch(opcode) {
  case 0x0: return "Config AppKey Add";
  case 0x1: return "Config AppKey Update";
  case 0x2: return "Config Composition Data Status";
  case 0x3: return "Config Config Model Publication Set";
  case 0x4: return "Health Current Status";
  case 0x5: return "Health Fault Status";
  case 0x6: return "Config Heartbeat Publication Status";
  case 0x8000: return "Config AppKey Delete";
  case 0x8001: return "Config AppKey Get";
  case 0x8002: return "Config AppKey List";
  case 0x8003: return "Config AppKey Status";
  case 0x8004: return "Health Attention Get";
  case 0x8005: return "Health Attention Set";
  case 0x8006: return "Health Attention Set Unacknowledged";
  case 0x8007: return "Health Attention Status";
  case 0x8008: return "Config Composition Data Get";
  case 0x8009: return "Config Beacon Get";
  case 0x800a: return "Config Beacon Set";
  case 0x800b: return "Config Beacon Status";
  case 0x800c: return "Config Default TTL Get";
  case 0x800d: return "Config Default TTL Set";
  case 0x800e: return "Config Default TTL Status";
  case 0x800f: return "Config Friend Get";
  case 0x8010: return "Config Friend Set";
  case 0x8011: return "Config Friend Status";
  case 0x8012: return "Config GATT Proxy Get";
  case 0x8013: return "Config GATT Proxy Set";
  case 0x8014: return "Config GATT Proxy Status";
  case 0x8015: return "Config Key Refresh Phase Get";
  case 0x8016: return "Config Key Refresh Phase Set";
  case 0x8017: return "Config Key Refresh Phase Status";
  case 0x8018: return "Config Model Publication Get";
  case 0x8019: return "Config Model Publication Status";
  case 0x801a: return "Config Model Publication Virtual Address Set";
  case 0x801b: return "Config Model Subscription Add";
  case 0x801c: return "Config Model Subscription Delete";
  case 0x801d: return "Config Model Subscription Delete All";
  case 0x801e: return "Config Model Subscription Overwrite";
  case 0x801f: return "Config Model Subscription Status";
  case 0x8020: return "Config Model Subscription Virtual Address Add";
  case 0x8021: return "Config Model Subscription Virtual Address Delete";
  case 0x8022: return "Config Model Subscription Virtual Address Overwrite";
  case 0x8023: return "Config Network Transmit Get";
  case 0x8024: return "Config Network Transmit Set";
  case 0x8025: return "Config Network Transmit Status";
  case 0x8026: return "Config Relay Get";
  case 0x8027: return "Config Relay Set";
  case 0x8028: return "Config Relay Status";
  case 0x8029: return "Config SIG Model Subscription Get";
  case 0x802a: return "Config SIG Model Subscription List";
  case 0x802b: return "Config Vendor Model Subscription Get";
  case 0x802c: return "Config Vendor Model Subscription List";
  case 0x802d: return "Config Low Power Node PollTimeout Get";
  case 0x802e: return "Config Low Power Node PollTimeout Status";
  case 0x802f: return "Health Fault Clear";
  case 0x8030: return "Health Fault Clear Unacknowledged";
  case 0x8031: return "Health Fault Get";
  case 0x8032: return "Health Fault Test";
  case 0x8033: return "Health Fault Test Unacknowledged";
  case 0x8034: return "Health Period Get";
  case 0x8035: return "Health Period Set";
  case 0x8036: return "Health Period Set Unacknowledged";
  case 0x8037: return "Health Period Status";
  case 0x8038: return "Config Heartbeat Publication Get";
  case 0x8039: return "Config Heartbeat Publication Set";
  case 0x803a: return "Config Heartbeat Subscription Get";
  case 0x803b: return "Config Heartbeat Subscription Set";
  case 0x803c: return "Config Heartbeat Subscription Status";
  case 0x803d: return "Config Model App Bind";
  case 0x803e: return "Config Model App Status";
  case 0x803f: return "Config Model App Unbind";
  case 0x8040: return "Config NetKey Add";
  case 0x8041: return "Config NetKey Delete";
  case 0x8042: return "Config NetKey Get";
  case 0x8043: return "Config NetKey List";
  case 0x8044: return "Config NetKey Status";
  case 0x8045: return "Config NetKey Update";
  case 0x8046: return "Config Node Identity Get";
  case 0x8047: return "Config Node Identity Set";
  case 0x8048: return "Config Node Identity Status";
  case 0x8049: return "Config Node Reset";
  case 0x804a: return "Config Node Reset Status";
  case 0x804b: return "Config SIG Model App Get";
  case 0x804c: return "Config SIG Model App List";
  case 0x804d: return "Config Vendor Model App Get";
  case 0x804e: return "Config Vendor Model App List";
  default: return (void*)0;
  }
}
