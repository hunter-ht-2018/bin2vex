#include <stdio.h>
#include <malloc.h>
#include <libvex.h>
#include <pyvex.h>
#include <setjmp.h>
#include <string.h>

char* BIN_FLOW_PATH = "log_ls.out";
int BUFF_AREA;
VexArchInfo         vai_host;
VexGuestExtents     vge;
VexTranslateArgs    vta;
VexTranslateResult  vtr;
VexAbiInfo	        vbi;
VexArch             arch;

char *msg_buffer = NULL;
size_t msg_capacity = 0, msg_current_size = 0;

jmp_buf jumpout;
VexControl vc;
int main(){
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

    //import bin_flow to data
    FILE *in ;
    unsigned char buf_array[65536]={'\0'};
    unsigned char buf_temp[512]={'\0'};
    int inx=0;

    printf("try to open binary file: \n");

    in = fopen(BIN_FLOW_PATH,"r");

    while(!feof(in)&&inx<=65536)
    {


        fread(buf_temp,512,1,in);

        array_merge(buf_array,buf_temp,inx);
        inx+=512;
    }


    //init and lift
    printf("before vex init.\n");
    vex_init();
    printf("before vex_lift.\n");
    irsb = vex_lift(VexArchAMD64, vai_host, buf_array, 0, 99, 5000, 1, 0, 0);
    ppIRSB(irsb);
    printf("finished.\n");
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
