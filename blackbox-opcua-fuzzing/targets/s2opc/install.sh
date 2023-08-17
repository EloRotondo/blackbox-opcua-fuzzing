#!/usr/bin/env bash

set -o errexit                                                                                          
set -o nounset                                                                                          
set -o pipefail 

apt-get update
apt-get install -y wget build-essential clang-9 gcc g++ doxygen graphviz

pip install cmake paho-mqtt

 ##MbedTLS
wget https://github.com/ARMmbed/mbedtls/archive/v2.28.3.tar.gz
tar xzvf v2.28.3.tar.gz
cd mbedtls-2.28.3
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DUSE_SHARED_MBEDTLS_LIBRARY=OFF ..
make -j`nproc`
make install

## Expat
wget https://github.com/libexpat/libexpat/releases/download/R_2_5_0/expat-2.5.0.tar.gz
tar xzvf expat-2.5.0.tar.gz
cd expat-2.5.0
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DEXPAT_SHARED_LIBS=OFF ..
make -j`nproc`
make install

##Check
git clone https://github.com/libcheck/check.git
cd check
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DEXPAT_SHARED_LIBS=OFF ..
make -j`nproc`
make install

cd /opt/app
git clone https://gitlab.com/systerel/S2OPC.git
(
cd /opt/app/S2OPC/src/ClientServer/configuration
sed -i "49s/150/5400/g" sopc_toolkit_config_constants.h 
sed -i "130s/20/4100/g" sopc_toolkit_config_constants.h 
sed -i "77s/21/4200/g" sopc_toolkit_config_constants.h 

cd /opt/app/S2OPC
export CC="gcc" CXX="g++"
./build.sh

cd /opt/app/S2OPC/build/bin/server_private
echo "password" > secret.txt
openssl rsa -in encrypted_server_4k_key.pem -passin file:secret.txt -out server_4k_key.pem

cd ..
sed -i "s/4841/4840/g" S2OPC_Server_Demo_Config.xml
sed -i "s/encrypted_server_4k_key.pem/server_4k_key.pem/g" S2OPC_Server_Demo_Config.xml
sed -i "13s/true/false/g" S2OPC_Server_Demo_Config.xml
sed -i -e '26a <ApplicationType type="DiscoveryServer"/>' S2OPC_Server_Demo_Config.xml

mv /opt/app/targets/s2opc/nonePolicy.txt .
linenumber=32
while read line; do 
sed -i -e "${linenumber}a $line" S2OPC_Server_Demo_Config.xml;
linenumber=$((linenumber+1))
done < nonePolicy.txt


)
cd /opt/app
cp targets/s2opc/target target

exit 0

