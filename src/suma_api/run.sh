#!/bin/bash
rm -r build
mkdir build
cp database/user_data.db build/
cd build 
cmake ..
make
sudo ./suma-api 
