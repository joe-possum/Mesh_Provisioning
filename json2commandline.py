import json
import sys

fileName = ""
if 2 == len(sys.argv) :
    fileName = sys.argv[1]

fh = open(fileName,"r")
content = json.load(fh)
fh.close()

out = ""
for nk in content['netKeys'] :
    out += " -k n:%s:0"%(nk["value"].lower())

for dk in content["devKeys"] :
    out += " -k d:%s:0x%04x" % (dk["value"].lower(),int(dk["primaryAddress"]))

for ak in content["appKeys"] :
    out += " -k a:%s" % (ak["value"].lower())
    
print(out)
