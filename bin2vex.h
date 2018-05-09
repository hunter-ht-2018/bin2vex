#ifndef BIN_2_VEX_H_
#define BIN_2_VEX_H_
#include <libvex.h>
#include <pyvex.h>
#include <stdint.h>

void init_bin2vex(VexArch arch);

IRSB* bin2vex(uint8_t* inst_data, uint64_t inst_addr) ;

#endif
