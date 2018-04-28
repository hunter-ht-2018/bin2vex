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
