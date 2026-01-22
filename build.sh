set -xe
GCC=x86_64-w64-mingw32-gcc
$GCC -g -fPIC -c main.c -o main.o -O0
$GCC -g -static -shared -o fc5_no_aim_sway.asi main.o
