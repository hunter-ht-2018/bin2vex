#include <stdio.h>
//#include <malloc.h>
#include <libvex.h>
#include <pyvex.h>

#include <main_globals.h>
#include <setjmp.h>
#include <string.h>
#include <stdlib.h>
#include "utils.h"

char* BIN_FLOW_PATH = "log_ls.out";
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
    if(argc <= 1) {
        printf("usage: %s <inst_binary_file>\n", argv[0]);
        exit(0);
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

    //init and lift
    printf("before vex init.\n");
    vex_init();
    printf("before vex_lift.\n");
    LibVEX_default_VexArchInfo(&vai_guest);
    vai_guest.endness = 0x601;
    vta.archinfo_host.hwcaps = 4064;
    irsb = vex_lift(VexArchAMD64, vai_guest, inst_data, 0x400400, 1, MAX_INST_BYTES, 1, VEX_TRACE_FE|VEX_TRACE_OPT1|VEX_TRACE_INST|VEX_TRACE_OPT2|VEX_TRACE_ASM/*255 to trace all*/, 0);
    if(irsb == NULL){
        fprintf(stderr, "vex_lift error.\n");
        exit(-1);
    }

    ppIRSB(irsb);
/*    int i;*/
    /*for(i=0;i<strlen(msg_buffer);i++)*/
    /*{*/
        /*putchar(msg_buffer[i]);*/
    /*}*/
    /*printf("finished.\n");*/
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
