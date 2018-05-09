#include <stdio.h>
#include <libvex.h>
#include <pyvex.h>
#include <main_globals.h>
#include <stdint.h>
#define MAX_INST_BYTES  16
static VexArchInfo         vai_guest;
static VexArch 			   arch_guest;

void init_bin2vex(VexArch arch) {
	vex_init();
	LibVEX_default_VexArchInfo(&vai_guest);
	vai_guest.endness = 0x601;
	vta.archinfo_host.hwcaps = 4064;
	arch_guest = arch;
}

IRSB* bin2vex(uint8_t* inst_data, uint64_t inst_addr) {
	//IRSB* irsb = vex_lift(arch_guest, vai_guest, inst_data, inst_addr, 1, MAX_INST_BYTES, 1, VEX_TRACE_FE|VEX_TRACE_OPT1|VEX_TRACE_INST|VEX_TRACE_OPT2|VEX_TRACE_ASM/*255 to trace all*/, 0);
	IRSB* irsb = vex_lift(arch_guest, vai_guest, inst_data, inst_addr, 1, MAX_INST_BYTES, 1, 0, 0);

	if(irsb == NULL){
		fprintf(stderr, "vex_lift error.\n");
		exit(-1);
	}
	return irsb;
}
