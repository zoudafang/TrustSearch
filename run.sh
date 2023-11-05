#!/bin/bash

# myArray=(32 64 128 256 512 1024)
# myArray=(4 8 16 )

for i in {4..4}
do
echo "+++++++++++dist $((6+2*i))+++++++++++++\n" >> res.txt
for t in {1..3}
do
# for j in {0..2}
# do

# new_value=${myArray[j]}   #$((10+10*j))  # 替换为你想要的新值
# file_path="./include/constVar.h"
# sed -i "s/const uint32_t PAGE_SIZE = [0-9]\+;/const uint32_t PAGE_SIZE = $new_value;/" "$file_path"

# for j in {1..5}
# do

# new_value=$((2+2*j))  # 替换为你想要的新值
# file_path="./include/constVar.h"
# sed -i "s/const uint32_t SUBINDEX_NUM = [0-9]\+;/const uint32_t SUBINDEX_NUM = $new_value;/" "$file_path"

 echo "data $((t)) PAGE_SIZE $((new_value)) " >> res.txt  #subindex $((new_value))

# make clean
# make SGX_DEBUG=0
# /opt/intel/sgxsdk/bin/x64/sgx_sign sign -key Enclave/Enclave_private_test.pem -enclave enclave.so -out enclave.signed.so -config Enclave/Enclave.config.xml
# echo "-------------------------"
# ./app  -h $((4+4*i)) -s 5000000 -d 4 -t $((t-1)) -l 50000 -c 50 >> res.txt #no -l 30
# make clean
# echo "naive----"  >> res.txt
# make clean
# make SGX_DEBUG=0
# /opt/intel/sgxsdk/bin/x64/sgx_sign sign -key Enclave/Enclave_private_test.pem -enclave enclave.so -out enclave.signed.so -config Enclave/Enclave.config.xml
# echo "-------------------------"
# ./app  -h $((4+4*i)) -s 5000000 -d 4 -t $((t-1)) -l 50 -c 50 >> res.txt #no -l 30
# make clean
# echo "naive----"  >> res.txt


# make clean
# make SGX_DEBUG=0
# /opt/intel/sgxsdk/bin/x64/sgx_sign sign -key Enclave/Enclave_private_test.pem -enclave enclave.so -out enclave.signed.so -config Enclave/Enclave.config.xml
# echo "-------------------------"
# ./app  -h $((4+4*i)) -s 5000000 -d 4 -t $((t-1)) -l 50000 -c 40 >> res.txt
# make clean
# echo "naive----" >> res.txt
# make clean
# make SGX_DEBUG=0
# /opt/intel/sgxsdk/bin/x64/sgx_sign sign -key Enclave/Enclave_private_test.pem -enclave enclave.so -out enclave.signed.so -config Enclave/Enclave.config.xml
# echo "-------------------------"
# ./app  -h $((4+4*i)) -s 5000000 -d 5 -t $((t-1)) -l 150 -c 50 >> res.txt
# make clean
# echo "max 3 ----" >> res.txt

# make clean
# make SGX_DEBUG=0
# /opt/intel/sgxsdk/bin/x64/sgx_sign sign -key Enclave/Enclave_private_test.pem -enclave enclave.so -out enclave.signed.so -config Enclave/Enclave.config.xml
# echo "-------------------------"
# ./app  -h $((4+4*i)) -s 150 -d 4 -t $((t-1)) -l 5000000 -c 0 >> res.txt #3 4
# make clean

# make clean
# make SGX_DEBUG=0
# /opt/intel/sgxsdk/bin/x64/sgx_sign sign -key Enclave/Enclave_private_test.pem -enclave enclave.so -out enclave.signed.so -config Enclave/Enclave.config.xml
# echo "-------------------------"
# ./app  -h $((4+4*i)) -s 50000000 -d 4 -t $((t-1)) -l 500000 -c 40 >> res.txt
# make clean

make clean
make SGX_DEBUG=0
/opt/intel/sgxsdk/bin/x64/sgx_sign sign -key Enclave/Enclave_private_test.pem -enclave enclave.so -out enclave.signed.so -config Enclave/Enclave.config.xml
echo "-------------------------"
./app  -h $((4+4*i)) -s 50 -d 4 -t $((t-1)) -l 30 -c 40 >> res.txt #3 4
make clean

# make clean
# make SGX_DEBUG=0
# /opt/intel/sgxsdk/bin/x64/sgx_sign sign -key Enclave/Enclave_private_test.pem -enclave enclave.so -out enclave.signed.so -config Enclave/Enclave.config.xml
# echo "-------------------------"
# ./app  -h $((4+4*i)) -s 50 -d 4 -t $((t-1)) -l 50000 -c 40 >> res.txt
# make clean

# make clean
# make SGX_DEBUG=0
# /opt/intel/sgxsdk/bin/x64/sgx_sign sign -key Enclave/Enclave_private_test.pem -enclave enclave.so -out enclave.signed.so -config Enclave/Enclave.config.xml
# echo "-------------------------"
# ./app  -h $((4+4*i)) -s 150 -d 6 -t $((t-1)) -l 50000 -c 0 >> res.txt
# make clean

# done
done
done



# make clean
# make SGX_DEBUG=0
# /opt/intel/sgxsdk/bin/x64/sgx_sign sign -key Enclave/Enclave_private_test.pem -enclave enclave.so -out enclave.signed.so -config Enclave/Enclave.config.xml
# echo "-------------------------"
# ./app  -h $((4+4*i)) -s 1500000 -d 4 -t 1 -l 500000 -c 30 >> res.txt #3 4
# make clean