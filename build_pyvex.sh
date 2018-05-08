export VEX_INCLUDE_PATH=../../vex/pub
export VEX_LIB_PATH=../../vex
export MULTIARCH=1
export DEBUG=1
myfile="./Makefile"
CWD=`pwd`
cd ${CWD}/vex
if [ ! -f "$myfile" ]; then
    cp Makefile-gcc makefile
fi
make clean && make

cd ${CWD}/pyvex/pyvex_c && make clean && make

