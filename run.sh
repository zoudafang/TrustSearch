#!/bin/bash


myArray=(4 6 8 10 12)

# echo "+++++++++++dist $((6+2*i))+++++++++++++\n" >> res.txt
for t in {1..1}
do
for j in {1..1}
do
for i in {1..1}
do
file_path="./include/constVar.h"
# new_value=${myArray[j]}   #$((10+10*j))  # 替换为你想要的新值
# sed -i "s/const uint32_t PAGE_SIZE = [0-9]\+;/const uint32_t PAGE_SIZE = $new_value;/" "$file_path"

# for j in {1..5}
# do

new_value=$((4+2*j))  # 替换为你想要的新值
# file_path="./include/constVar.h"
# sed -i "s/const uint32_t SUBINDEX_NUM = [0-9]\+;/const uint32_t SUBINDEX_NUM = $new_value;/" "$file_path"

sed -i "s/const uint32_t SUBINDEX_NUM = [0-9]\+;/const uint32_t SUBINDEX_NUM = 8;/" "$file_path"
sed -i "s/const uint32_t PAGE_SIZE = [0-9]\+;/const uint32_t PAGE_SIZE = 64;/" "$file_path"

# testLen=$((j*50000000))
# sed -i "s/const uint32_t SIFT_LEN = [0-9]\+;/const uint32_t SIFT_LEN = $testLen;/" "$file_path"
# sed -i "s/const uint32_t PAGE_SIZE = [0-9]\+;/const uint32_t PAGE_SIZE = 1;/" "$file_path"

echo "data $((t)) SUBINDEX_NUM $((new_value)) " >> res.txt  #subindex $((new_value))  0xdffff0000

# make clean        #    $cautious for testCS
# make SGX_DEBUG=0
# /opt/intel/sgxsdk/bin/x64/sgx_sign sign -key Enclave/Enclave_private_test.pem -enclave enclave.so -out enclave.signed.so -config Enclave/Enclave.config.xml
# echo "-------------------------"
# ./app  -h $((4+4*i)) -s 500000000 -d 4 -t $((t-1)) -l 3000000 -c 50 -v 50 -b 20 -n 1 -m 0.4 >> res.txt #3 4
# make clean



# make clean        #    $cautious for testCS
# make SGX_DEBUG=0 > /dev/null 2>&1
# /opt/intel/sgxsdk/bin/x64/sgx_sign sign -key Enclave/Enclave_private_test.pem -enclave enclave.so -out enclave.signed.so -config Enclave/Enclave.config.xml
# echo "-------------------------"
# sudo  ./app  -h $((4+4*i)) -s 1500000000 -d 4 -t $((t-1)) -l 3000000 -c 50 -v 100 -b 10 -n 1 -m 0.4 >> res2.txt #3 4
# make clean



sed -i "s/const uint32_t SUBINDEX_NUM = [0-9]\+;/const uint32_t SUBINDEX_NUM = 6;/" "$file_path"
make clean        #    $cautious for testCS
make SGX_DEBUG=0 > /dev/null 2>&1
/opt/intel/sgxsdk/bin/x64/sgx_sign sign -key Enclave/Enclave_private_test.pem -enclave enclave.so -out enclave.signed.so -config Enclave/Enclave.config.xml
echo "-------------------------"
sudo  ./app  -h $((4+4*i)) -s 150 -d 4 -t $((t-1)) -l 3000000 -c 50 -v 100 -b 10 -n 1 -m 0.4 >> resCnd2.txt #3 4
make clean

#./app  -h 8 -s 150 -d 4 -t 1 -l 3000000 -c 50 -v 200 -b 20 -n 1 -m 0.4
# make clean        #    $cautious for testCS
# make SGX_DEBUG=0
# /opt/intel/sgxsdk/bin/x64/sgx_sign sign -key Enclave/Enclave_private_test.pem -enclave enclave.so -out enclave.signed.so -config Enclave/Enclave.config.xml
# echo "-------------------------"
# ./app  -h $((4+4*i)) -s 50 -d 4 -t $((t-1)) -l 3000000 -c 50 -v 25 -b 10 -n 1 -m 0.8 >> res.txt #3 4
# make clean



# sed -i "s/const uint32_t PAGE_SIZE = [0-9]\+;/const uint32_t PAGE_SIZE = 1;/" "$file_path"

# make clean        #    $cautious for testCS
# make SGX_DEBUG=0
# /opt/intel/sgxsdk/bin/x64/sgx_sign sign -key Enclave/Enclave_private_test.pem -enclave enclave.so -out enclave.signed.so -config Enclave/Enclave.config.xml
# echo "-------------------------"
# ./app  -h $((4+4*i)) -s 50 -d 4 -t $((t-1)) -l 3000000 -c 50 -v 25 -b 10 -n 1 -m 0.4 >> res.txt #3 4
# make clean



done
done
done