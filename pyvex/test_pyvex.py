import pyvex
import archinfo
import sys
filename = sys.argv[1]
f = open(filename, "rb");
inst_flow = f.read();
print "len(inst_flow) = ", len(inst_flow);
irsb = pyvex.IRSB(inst_flow, 0x400400, archinfo.ArchAMD64())


# translate an AMD64 basic block (of nops) at 0x400400 into VEX
#irsb = pyvex.IRSB("\x90\x90\x90\x90\x90", 0x400400, archinfo.ArchAMD64())

# pretty-print the basic block
irsb.pp()


