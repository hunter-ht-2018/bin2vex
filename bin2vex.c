#include <stdio.h>
#include <libvex.h>
#include <pyvex.h>
#include <main_globals.h>
#include <stdint.h>
#include <capstone/capstone.h>
#include <stdlib.h>

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

char* disassemble_inst(const uint8_t* code, uint32_t code_size, uint64_t base_address){
    static char dis_str[1024];
    char* ret = NULL;
	csh handle;
	cs_insn *insn = NULL;

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return false;

	int count = cs_disasm(handle, code, code_size, base_address, 1, &insn);
	if (count > 0) {
        sprintf(dis_str, "%lx \t%s\t%s\t\t\n", insn->address, insn->mnemonic, insn->op_str);
        ret = dis_str;
	    cs_free(insn, 1);
	}
    else {
        printf("ERROR: Failed to disassemble given code!\n");
    }
	cs_close(&handle);
    return ret;
}
