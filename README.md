# bin2vex
convert binary to VEX IR using the C interface provided by pyvex.

## Compile
1. build pyvex_c and vex
```
    ./build_pyvex.sh
``` 
2. build bin2vex

```
    mkdir build
    
    cd build
    
    cmake ../
    
    make
```
It will create library *libbin2vex.a* and executable *disbin2vex* 

## Usage
```
./disbin2vex <raw_binary> [num]
```
This will disassemble the first *num* of instructions, and show both the disassembled code and VEX code. If *num* is not set, it will *disassemble* all the codes in *raw_binary*.

*NOTE: raw_binary means the pure binary machine code.*
