#!/bin/bash

make
mkdir build
cd build
mkdir -p usr/bin/ && mkdir -p usr/share/aliwe
install -m755 ../Release/aliwe usr/bin/
cp ../models  usr/share/aliwe/

