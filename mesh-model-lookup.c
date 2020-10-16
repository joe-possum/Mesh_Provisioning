#include <stdint.h>

const char *mesh_model_lookup(uint16_t opcode) {
  switch(opcode) {
  case 0x8201:
  case 0x8202:
  case 0x8203:
  case 0x8204:
  case 0x8205:
    return "Generic OnOff";
  case 0x8206:
  case 0x8207:
  case 0x8208:
  case 0x8209:
  case 0x820a:
  case 0x820b:
  case 0x820c:
  case 0x820d:
    return "Generic Level";
  case 0x820e:
  case 0x820f:
  case 0x8210:
  case 0x8211:
    return "Generic Default Transition Time";
  case 0x8212:
  case 0x8213:
    return "Generic Power OnOff";
  case 0x8214:
  case 0x8215:
    return "Generic Power OnOff Setup";
  case 0x8216:
  case 0x8217:
  case 0x8218:
  case 0x8219:
  case 0x821a:
  case 0x821b:
  case 0x821c:
  case 0x821d:
  case 0x821e:
  case 0x821f:
    return "Generic Power Level";
  case 0x8220:
  case 0x8221:
  case 0x8222:
  case 0x8223:
    return "Generic Power Level Setup";
  case 0x8224:
  case 0x8225:
    return "Generic Battery";
  case 0x40:
  case 0x8226:
  case 0x8227:
  case 0x41:
    return "Generic Location";
  case 0x42:
  case 0x8228:
  case 0x8229:
  case 0x822a:
    return "Generic Location Setup";
  case 0x43:
  case 0x822b:
  case 0x44:
  case 0x45:
  case 0x46:
  case 0x822c:
    return "Generic Manufacturer Property";
  case 0x47:
  case 0x822d:
  case 0x48:
  case 0x49:
  case 0x4a:
  case 0x822e:
    return "Generic Admin Property";
  case 0x4b:
  case 0x822f:
  case 0x4c:
  case 0x4d:
  case 0x4e:
  case 0x4f:
    return "Generic User Property";
  case 0x50:
  case 0x8230:
    return "Generic Client Property";
  case 0x51:
  case 0x8231:
  case 0x52:
  case 0x8232:
  case 0x53:
  case 0x8233:
  case 0x54:
  case 0x8234:
  case 0x55:
  case 0x56:
  case 0x57:
  case 0x8235:
  case 0x58:
  case 0x8236:
  case 0x59:
  case 0x5a:
  case 0x5b:
  case 0x8237:
    return "Sensor";
  case 0x5c:
  case 0x5d:
  case 0x8238:
  case 0x8239:
  case 0x823a:
  case 0x823b:
  case 0x823c:
  case 0x823d:
  case 0x823e:
  case 0x823f:
  case 0x8240:
  case 0x8241:
    return "Time";
  case 0x8242:
  case 0x8243:
  case 0x5e:
  case 0x8244:
  case 0x8245:
  case 0x8246:
    return "Scene";
  case 0x8247:
  case 0x829e:
  case 0x829f:
  case 0x8248:
    return "Scene Setup";
  case 0x5f:
  case 0x8249:
  case 0x824a:
  case 0x60:
    return "Scheduler";
  case 0x61:
  case 0x824b:
    return "Scheduler Setup";
  case 0x824c:
  case 0x824d:
  case 0x824e:
  case 0x824f:
  case 0x8250:
  case 0x8251:
  case 0x8252:
  case 0x8253:
  case 0x8254:
  case 0x8255:
  case 0x8256:
  case 0x8257:
  case 0x8258:
  case 0x8259:
    return "Light Lightness";
  case 0x825a:
  case 0x825b:
  case 0x825c:
  case 0x825d:
    return "Light Lightness Setup";
  case 0x825e:
  case 0x825f:
  case 0x8260:
  case 0x8261:
  case 0x8262:
  case 0x8263:
  case 0x8264:
  case 0x8265:
  case 0x8266:
  case 0x8267:
  case 0x8268:
  case 0x8269:
    return "Light CTL";
  case 0x826a:
  case 0x826b:
  case 0x826c:
  case 0x826d:
    return "Light CTL Setup";
  case 0x826e:
  case 0x826f:
  case 0x8270:
  case 0x8271:
  case 0x8272:
  case 0x8273:
  case 0x8274:
  case 0x8275:
  case 0x8276:
  case 0x8277:
  case 0x8278:
  case 0x8279:
  case 0x827a:
  case 0x827b:
  case 0x827c:
  case 0x827d:
  case 0x827e:
  case 0x827f:
    return "Light HSL";
  case 0x8280:
  case 0x8281:
  case 0x82:
  case 0x8283:
    return "Light HSL Setup";
  case 0x8284:
  case 0x8285:
  case 0x8286:
  case 0x8287:
  case 0x8288:
  case 0x8289:
  case 0x828a:
  case 0x828b:
  case 0x828c:
  case 0x828d:
    return "Light xyL";
  case 0x828e:
  case 0x828f:
  case 0x8290:
    return "";
  default: return (void*)0;
  }
}

const char *mesh_message_lookup(uint16_t opcode) {
  switch(opcode) {
  case 0x8201: return "Generic OnOff Get";
  case 0x8202: return "Generic OnOff Set";
  case 0x8203: return "Generic OnOff Set Unacknowledged";
  case 0x8204: return "Generic OnOff Status";
  case 0x8205: return "Generic Level Get";
  case 0x8206: return "Generic Level Set";
  case 0x8207: return "Generic Level Set Unacknowledged";
  case 0x8208: return "Generic Level Status";
  case 0x8209: return "Generic Delta Set";
  case 0x820a: return "Generic Delta Set Unacknowledged";
  case 0x820b: return "Generic Move Set";
  case 0x820c: return "Generic Move Set Unacknowledged";
  case 0x820d: return "Generic Default Transition Time Get";
  case 0x820e: return "Generic Default Transition Time Set";
  case 0x820f: return "Generic Default Transition Time Set Unacknowledged";
  case 0x8210: return "Generic Default Transition Time Status";
  case 0x8211: return "Generic OnPowerUp Get";
  case 0x8212: return "Generic OnPowerUp Status";
  case 0x8213: return "Generic OnPowerUp Set";
  case 0x8214: return "Generic OnPowerUp Set Unacknowledged";
  case 0x8215: return "Generic Power Level Get";
  case 0x8216: return "Generic Power Level Set";
  case 0x8217: return "Generic Power Level Set Unacknowledged";
  case 0x8218: return "Generic Power Level Status";
  case 0x8219: return "Generic Power Last Get";
  case 0x821a: return "Generic Power Last Status";
  case 0x821b: return "Generic Power Default Get";
  case 0x821c: return "Generic Power Default Status";
  case 0x821d: return "Generic Power Range Get";
  case 0x821e: return "Generic Power Range Status";
  case 0x821f: return "Generic Power Default Set";
  case 0x8220: return "Generic Power Default Set Unacknowledged";
  case 0x8221: return "Generic Power Range Set";
  case 0x8222: return "Generic Power Range Set Unacknowledged";
  case 0x8223: return "Generic Battery Get";
  case 0x8224: return "Generic Battery Status";
  case 0x8225: return "Generic Location Global Get";
  case 0x40: return "Generic Location Global Status";
  case 0x8226: return "Generic Location Local Get";
  case 0x8227: return "Generic Location Local Status";
  case 0x41: return "Generic Location Global Set";
  case 0x42: return "Generic Location Global Set Unacknowledged";
  case 0x8228: return "Generic Location Local Set";
  case 0x8229: return "Generic Location Local Set Unacknowledged";
  case 0x822a: return "Generic Manufacturer Properties Get";
  case 0x43: return "Generic Manufacturer Properties Status";
  case 0x822b: return "Generic Manufacturer Property Get";
  case 0x44: return "Generic Manufacturer Property Set";
  case 0x45: return "Generic Manufacturer Property Set Unacknowledged";
  case 0x46: return "Generic Manufacturer Property Status";
  case 0x822c: return "Generic Admin Properties Get";
  case 0x47: return "Generic Admin Properties Status";
  case 0x822d: return "Generic Admin Property Get";
  case 0x48: return "Generic Admin Property Set";
  case 0x49: return "Generic Admin Property Set Unacknowledged";
  case 0x4a: return "Generic Admin Property Status";
  case 0x822e: return "Generic User Properties Get";
  case 0x4b: return "Generic User Properties Status";
  case 0x822f: return "Generic User Property Get";
  case 0x4c: return "Generic User Property Set";
  case 0x4d: return "Generic User Property Set Unacknowledged";
  case 0x4e: return "Generic User Property Status";
  case 0x4f: return "Generic Client Properties Get";
  case 0x50: return "Generic Client Properties Status";
  case 0x8230: return "Sensor Descriptor Get";
  case 0x51: return "Sensor Descriptor Status";
  case 0x8231: return "Sensor Get";
  case 0x52: return "Sensor Status";
  case 0x8232: return "Sensor Column Get";
  case 0x53: return "Sensor Column Status";
  case 0x8233: return "Sensor Series Get";
  case 0x54: return "Sensor Series Status";
  case 0x8234: return "Sensor Cadence Get";
  case 0x55: return "Sensor Cadence Set";
  case 0x56: return "Sensor Cadence Set Unacknowledged";
  case 0x57: return "Sensor Cadence Status";
  case 0x8235: return "Sensor Settings Get";
  case 0x58: return "Sensor Settings Status";
  case 0x8236: return "Sensor Setting Get";
  case 0x59: return "Sensor Setting Set";
  case 0x5a: return "Sensor Setting Set Unacknowledged";
  case 0x5b: return "Sensor Setting Status";
  case 0x8237: return "Time Get";
  case 0x5c: return "Time Set";
  case 0x5d: return "Time Status";
  case 0x8238: return "Time Role Get";
  case 0x8239: return "Time Role Set";
  case 0x823a: return "Time Role Status";
  case 0x823b: return "Time Zone Get";
  case 0x823c: return "Time Zone Set";
  case 0x823d: return "Time Zone Status";
  case 0x823e: return "TAI-UTC Delta Get";
  case 0x823f: return "TAI-UTC Delta Set";
  case 0x8240: return "TAI-UTC Delta Status";
  case 0x8241: return "Scene Get";
  case 0x8242: return "Scene Recall";
  case 0x8243: return "Scene Recall Unacknowledged";
  case 0x5e: return "Scene Status";
  case 0x8244: return "Scene Register Get";
  case 0x8245: return "Scene Register Status";
  case 0x8246: return "Scene Store";
  case 0x8247: return "Scene Store Unacknowledged";
  case 0x829e: return "Scene Delete";
  case 0x829f: return "Scene Delete Unacknowledged";
  case 0x8248: return "Scheduler Action Get";
  case 0x5f: return "Scheduler Action Status";
  case 0x8249: return "Scheduler Get";
  case 0x824a: return "Scheduler Status";
  case 0x60: return "Scheduler Action Set";
  case 0x61: return "Scheduler Action Set Unacknowledged";
  case 0x824b: return "Light Lightness Get";
  case 0x824c: return "Light Lightness Set";
  case 0x824d: return "Light Lightness Set Unacknowledged";
  case 0x824e: return "Light Lightness Status";
  case 0x824f: return "Light Lightness Linear Get";
  case 0x8250: return "Light Lightness Linear Set";
  case 0x8251: return "Light Lightness Linear Set Unacknowledged";
  case 0x8252: return "Light Lightness Linear Status";
  case 0x8253: return "Light Lightness Last Get";
  case 0x8254: return "Light Lightness Last Status";
  case 0x8255: return "Light Lightness Default Get";
  case 0x8256: return "Light Lightness Default Status";
  case 0x8257: return "Light Lightness Range Get";
  case 0x8258: return "Light Lightness Range Status";
  case 0x8259: return "Light Lightness Default Set";
  case 0x825a: return "Light Lightness Default Set Unacknowledged";
  case 0x825b: return "Light Lightness Range Set";
  case 0x825c: return "Light Lightness Range Set Unacknowledged";
  case 0x825d: return "Light CTL Get";
  case 0x825e: return "Light CTL Set";
  case 0x825f: return "Light CTL Set Unacknowledged";
  case 0x8260: return "Light CTL Status";
  case 0x8261: return "Light CTL Temperature Get";
  case 0x8262: return "Light CTL Temperature Range Get";
  case 0x8263: return "Light CTL Temperature Range Status";
  case 0x8264: return "Light CTL Temperature Set";
  case 0x8265: return "Light CTL Temperature Set Unacknowledged";
  case 0x8266: return "Light CTL Temperature Status";
  case 0x8267: return "Light CTL Default Get";
  case 0x8268: return "Light CTL Default Status";
  case 0x8269: return "Light CTL Default Set";
  case 0x826a: return "Light CTL Default Set Unacknowledged";
  case 0x826b: return "Light CTL Temperature Range Set";
  case 0x826c: return "Light CTL Temperature Range Set Unacknowledged";
  case 0x826d: return "Light HSL Get";
  case 0x826e: return "Light HSL Hue Get";
  case 0x826f: return "Light HSL Hue Set";
  case 0x8270: return "Light HSL Hue Set Unacknowledged";
  case 0x8271: return "Light HSL Hue Status";
  case 0x8272: return "Light HSL Saturation Get";
  case 0x8273: return "Light HSL Saturation Set";
  case 0x8274: return "Light HSL Saturation Set Unacknowledged";
  case 0x8275: return "Light HSL Saturation Status";
  case 0x8276: return "Light HSL Set";
  case 0x8277: return "Light HSL Set Unacknowledged";
  case 0x8278: return "Light HSL Status";
  case 0x8279: return "Light HSL Target Get";
  case 0x827a: return "Light HSL Target Status";
  case 0x827b: return "Light HSL Default Get";
  case 0x827c: return "Light HSL Default Status";
  case 0x827d: return "Light HSL Range Get";
  case 0x827e: return "Light HSL Range Status";
  case 0x827f: return "Light HSL Default Set";
  case 0x8280: return "Light HSL Default Set Unacknowledged";
  case 0x8281: return "Light HSL Range Set";
  case 0x82: return "Light HSL Range Set Unacknowledged";
  case 0x8283: return "Light xyL Get";
  case 0x8284: return "Light xyL Set";
  case 0x8285: return "Light xyL Set Unacknowledged";
  case 0x8286: return "Light xyL Status";
  case 0x8287: return "Light xyL Target Get";
  case 0x8288: return "Light xyL Target Status";
  case 0x8289: return "Light xyL Default Get";
  case 0x828a: return "Light xyL Default Status";
  case 0x828b: return "Light xyL Range Get";
  case 0x828c: return "Light xyL Range Status";
  case 0x828d: return "Light xyL Default Set";
  case 0x828e: return "Light xyL Default Set Unacknowledged";
  case 0x828f: return "Light xyL Range Set";
  case 0x8290: return "Light xyL Range Set Unacknowledged";
  default: return (void*)0;
  }
}

