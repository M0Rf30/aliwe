#!/bin/bash

PREFIX=usr
make
mkdir build
cd build
mkdir -p $PREFIX/bin/ && mkdir -p $PREFIX/share/aliwe
install -m755 ../Release/aliwe $PREFIX/bin/
cp ../{models,README,COPYING,INSTALL,AUTHORS}  $PREFIX/share/aliwe/

