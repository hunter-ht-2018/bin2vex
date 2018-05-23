#include <stdio.h>
//#include <malloc.h>
#include <libvex.h>
#include <pyvex.h>

#include <main_globals.h>
#include <setjmp.h>
#include <string.h>
#include <stdlib.h>
#include "bin2vex.h"
#include "utils.h"

#define MAX_INST_BYTES  16
int BUFF_AREA;
VexArchInfo         vai_guest;
VexGuestExtents     vge;
VexTranslateArgs    vta;
VexTranslateResult  vtr;
VexAbiInfo	        vbi;
VexArch             arch;

/*static*/
/*void log_bytes ( const HChar* bytes, SizeT nbytes )*/
/*{*/
   /*fwrite ( bytes, 1, nbytes, stdout );*/
/*}*/

char *msg_buffer = NULL;
size_t msg_capacity = 0, msg_current_size = 0;

jmp_buf jumpout;
VexControl vc;

void dump_arch_info(VexArchInfo vai) {
    printf("hwcaps = %d\n", vai.hwcaps);
}

int main(int argc, char** argv){

    void (*init)();
    IRSB (*lift)(VexArch guest,
        VexArchInfo archinfo,
        unsigned char *insn_start,
        unsigned long long insn_addr,
        unsigned int max_insns,
        unsigned int max_bytes,
        int opt_level,
        int traceflags,
        int allow_lookback);

    IRSB *irsb;
    uint32_t inst_num = 0;
    if(argc <= 1) {
        printf("usage: %s <inst_binary_file> [inst_num]\n", argv[0]);
        exit(0);
    }
    if(argc >= 3) {
        inst_num = atoi(argv[2]);
        printf("decode first %d instructions.\n", inst_num);
     }
    //import bin_flow to data
    char* bin_file = argv[1];
    printf("load binary file: %s\n", bin_file);
    size_t file_size;
    uint8_t* inst_data = load_file_data(bin_file, &file_size);
    if(inst_data != NULL) {
        printf("Load binary file OK, file size = %d\n", file_size);
    }
    else {
        printf("load binary file failed.\n");
        exit(-1);
    }

    init_bin2vex(VexArchAMD64);
    int64_t code_size = file_size;
    uint64_t inst_addr = 0x400400;
    int i = 0;
    while(1) {
        if(inst_num != 0 && i >= inst_num) break;
        if(code_size <= 0) {
            printf("all code decoded, break.\n");
            break;
        }
    	printf("\nInstruction %d: \n", i);
    	irsb = bin2vex(inst_data, inst_addr);
    	char* dis = disassemble_inst(inst_data, code_size, inst_addr);
        if(dis != NULL) printf(dis);
        ppIRSB(irsb);

    	for(int j = 0; j < irsb->stmts_used; j ++) {
    		IRStmt* stmt = irsb->stmts[j];
    		if(stmt->tag == Ist_IMark) {
    			inst_data += stmt->Ist.IMark.len;
    			inst_addr += stmt->Ist.IMark.len;
                code_size -= stmt->Ist.IMark.len;
    		}
    		//ppIRStmt(stmt);
    		//printf("\n");
    	}
    	printf("next instruction addr = %x\n", inst_addr);
        i ++;
    }

    return 0;
}


void array_merge(unsigned char des[] , unsigned char src[] , int inx)
{
    int i = 0;
    for (;i<512;i++)
    {
        des[i+inx]=src[i];
    }
}
