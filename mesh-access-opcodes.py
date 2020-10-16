fh = open('mesh-access-opcodes.txt','r')
text = fh.read()
fh.close()

def process_model(name,opcodes) :
    out = ''
    for opcode in opcodes :
        out += '  case 0x%x:\n'%(opcode)
    out += '    return "%s";\n'%(name)
    return out

access_lookup = ''
opcodes = []
stack = []
model = None
lines = text.split('\n')
for line in lines :
    if line.find('0x') < 0 :
        stack.append(line)
        continue
    bytes = line.split()
    opcode = 0
    for byte in bytes :
        opcode <<= 8
        opcode |= int(byte,16)
    opcodes.append(opcode)
    access_lookup += '  case 0x%x: return "%s";\n'%(opcode,stack[-1])
    stack = []
    
#access_lookup += process_model(stack[0],opcodes)

access_sig = 'const char *mesh_access_lookup(uint16_t opcode)'

fh = open('mesh-access-lookup.c','w')
fh.write('#include <stdint.h>\n\n')
fh.write('%s {\n  switch(opcode) {\n'%(access_sig))
fh.write(access_lookup)
fh.write('  default: return (void*)0;\n  }\n}\n\n')

fh = open('mesh-access-lookup.h','w')
fh.write('#include <stdint.h>\n\n')
fh.write('%s;\n'%(access_sig))
fh.close()
