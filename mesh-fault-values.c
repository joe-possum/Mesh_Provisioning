#include <stdint.h>
const char *lookup_fault_value(uint8_t value) {
  switch(value) {
  case 0x00: return "No Fault";
  case 0x01: return "Battery Low Warning";
  case 0x02: return "Battery Low Error";
  case 0x03: return "Supply Voltage Too Low Warning";
  case 0x04: return "Supply Voltage Too Low Error";
  case 0x05: return "Supply Voltage Too High Warning";
  case 0x06: return "Supply Voltage Too High Error";
  case 0x07: return "Power Supply Interrupted Warning";
  case 0x08: return "Power Supply Interrupted Error";
  case 0x09: return "No Load Warning";
  case 0x0a: return "No Load Error";
  case 0x0b: return "Overload Warning";
  case 0x0c: return "Overload Error";
  case 0x0d: return "Overheat Warning";
  case 0x0e: return "Overheat Error";
  case 0x0f: return "Condensation Warning";
  case 0x10: return "Condensation Error";
  case 0x11: return "Vibration Warning";
  case 0x12: return "Vibration Error";
  case 0x13: return "Configuration Warning";
  case 0x14: return "Configuration Error";
  case 0x15: return "Element Not Calibrated Warning";
  case 0x16: return "Element Not Calibrated Error";
  case 0x17: return "Memory Warning";
  case 0x18: return "Memory Error";
  case 0x19: return "Self-Test Warning";
  case 0x1a: return "Self-Test Error";
  case 0x1b: return "Input Too Low Warning";
  case 0x1c: return "Input Too Low Error";
  case 0x1d: return "Input Too High Warning";
  case 0x1e: return "Input Too High Error";
  case 0x1f: return "Input No Change Warning";
  case 0x20: return "Input No Change Error";
  case 0x21: return "Actuator Blocked Warning";
  case 0x22: return "Actuator Blocked Error";
  case 0x23: return "Housing Opened Warning";
  case 0x24: return "Housing Opened Error";
  case 0x25: return "Tamper Warning";
  case 0x26: return "Tamper Error";
  case 0x27: return "Device Moved Warning";
  case 0x28: return "Device Moved Error";
  case 0x29: return "Device Dropped Warning";
  case 0x2a: return "Device Dropped Error";
  case 0x2b: return "Overflow Warning";
  case 0x2c: return "Overflow Error";
  case 0x2d: return "Empty Warning";
  case 0x2e: return "Empty Error";
  case 0x2f: return "Internal Bus Warning";
  case 0x30: return "Internal Bus Error";
  case 0x31: return "Mechanism Jammed Warning";
  case 0x32: return "Mechanism Jammed Error";
  default:
    if(value < 0x80) return "<Reserved For Future Use>";
    return "<vendor-defined>";
  }
}
