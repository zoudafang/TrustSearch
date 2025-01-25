#!/bin/bash


myArray=(4 6 8 10 12)

# echo "+++++++++++dist $((6+2*i))+++++++++++++\n" >> res.txt
for t in {2..3} # 1-3:img, gist, sift
do
for j in {1..1}
do
for i in {1..2} # repeat times
do
file_path="./include/constVar.h"
# new_value=${myArray[j]}   #$((10+10*j))  # 替换为你想要的新值
# sed -i "s/const uint32_t PAGE_SIZE = [0-9]\+;/const uint32_t PAGE_SIZE = $new_value;/" "$file_path"

# for j in {1..5}
# do

# new_value=$((3+2*j))  # 替换为你想要的新值
# file_path="./include/constVar.h"
# sed -i "s/const uint32_t SUBINDEX_NUM = [0-9]\+;/const uint32_t SUBINDEX_NUM = $new_value;/" "$file_path"

sed -i "s/const uint32_t SUBINDEX_NUM = [0-9]\+;/const uint32_t SUBINDEX_NUM = 6;/" "$file_path"
sed -i "s/const uint32_t PAGE_SIZE = [0-9]\+;/const uint32_t PAGE_SIZE = 64;/" "$file_path"

echo "data $((t)) SUBINDEX_NUM $((new_value)) " >> res.txt  #subindex $((new_value))



# make clean        #    $cautious for testCS
# make SGX_DEBUG=0
# /opt/intel/sgxsdk/bin/x64/sgx_sign sign -key Enclave/Enclave_private_test.pem -enclave enclave.so -out enclave.signed.so -config Enclave/Enclave.config.xml
# echo "-------------------------"
# ./app  -h $((4+4*i)) -s 50 -d 4 -t $((t-1)) -l 3000000 -c 50 -v 25 -b 10 -n 1 -m 0.8 >> res.txt #3 4
# make clean

# make clean        #    $cautious for testCS
# make SGX_DEBUG=0
# /opt/intel/sgxsdk/bin/x64/sgx_sign sign -key Enclave/Enclave_private_test.pem -enclave enclave.so -out enclave.signed.so -config Enclave/Enclave.config.xml
# echo "-------------------------"
# ./app  -h $((4+4*i)) -s 50 -d 4 -t $((t-1)) -l 3000000 -c 50 -v 25 -b 10 -n 1 -m 0.6 >> res.txt #3 4
# make clean

make clean        #    $cautious for testCS
make SGX_DEBUG=0
/opt/intel/sgxsdk/bin/x64/sgx_sign sign -key Enclave/Enclave_private_test.pem -enclave enclave.so -out enclave.signed.so -config Enclave/Enclave.config.xml
echo "-------------------------"
./app  -h $((4+4*i)) -s 50 -d 4 -t $((t-1)) -l 3000000 -c 50 -v 25 -b 10 -n 1 -m 0.4 #>> res.txt #3 4
make clean

# make clean        #    $cautious for testCS
# make SGX_DEBUG=0
# /opt/intel/sgxsdk/bin/x64/sgx_sign sign -key Enclave/Enclave_private_test.pem -enclave enclave.so -out enclave.signed.so -config Enclave/Enclave.config.xml
# echo "-------------------------"
# ./app  -h $((4+4*i)) -s 50 -d 4 -t $((t-1)) -l 3000000 -c 50 -v 25 -b 10 -n 1 -m 0.2 >> res.txt #3 4
# make clean

done
done
done



# for i in {4..4}
# do
# echo "+++++++++++dist $((6+2*i))+++++++++++++\n" >> res.txt
# for t in {1..3}
# do
# for j in {0..0}
# do

# file_path="./include/constVar.h"
# new_value=${myArray[j]}   #$((10+10*j))  # 替换为你想要的新值
# # sed -i "s/const uint32_t PAGE_SIZE = [0-9]\+;/const uint32_t PAGE_SIZE = $new_value;/" "$file_path"

# # for j in {1..5}
# # do

# # new_value=$((3+2*j))  # 替换为你想要的新值
# # file_path="./include/constVar.h"
# sed -i "s/const uint32_t SUBINDEX_NUM = [0-9]\+;/const uint32_t SUBINDEX_NUM = $new_value;/" "$file_path"

# sed -i "s/const uint32_t PAGE_SIZE = [0-9]\+;/const uint32_t PAGE_SIZE = 64;/" "$file_path"

# echo "data $((t)) SUBINDEX_NUM $((new_value)) " >> res.txt  #subindex $((new_value))



# make clean        #    $cautious for testCS
# make SGX_DEBUG=0
# /opt/intel/sgxsdk/bin/x64/sgx_sign sign -key Enclave/Enclave_private_test.pem -enclave enclave.so -out enclave.signed.so -config Enclave/Enclave.config.xml
# echo "-------------------------"
# ./app  -h $((4+4*i)) -s 50 -d 4 -t $((t-1)) -l 3000000 -c 50 -v 25 -b 10 -n 1 -m 0.4 >> res.txt #3 4
# make clean


# done
# done
# done

# pages=(16 32 64 128 256 512 1024 2048 4096)

# for i in {4..4}
# do
# echo "+++++++++++dist $((6+2*i))+++++++++++++\n" >> res.txt
# for t in {1..3}
# do
# for j in {0..7}
# do

# new_value=${pages[j]}   #$((10+10*j))  # 替换为你想要的新值
# file_path="./include/constVar.h"
# sed -i "s/const uint32_t PAGE_SIZE = [0-9]\+;/const uint32_t PAGE_SIZE = $new_value;/" "$file_path"

# # for j in {1..5}
# # do

# # new_value=$((3+2*j))  # 替换为你想要的新值
# # file_path="./include/constVar.h"
# sed -i "s/const uint32_t SUBINDEX_NUM = [0-9]\+;/const uint32_t SUBINDEX_NUM = 6;/" "$file_path"

# # sed -i "s/const uint32_t PAGE_SIZE = [0-9]\+;/const uint32_t PAGE_SIZE = 64;/" "$file_path"

#  echo "data $((t)) SUBINDEX_NUM $((new_value)) " >> res.txt  #subindex $((new_value))



# make clean        #    $cautious for testCS
# make SGX_DEBUG=0
# /opt/intel/sgxsdk/bin/x64/sgx_sign sign -key Enclave/Enclave_private_test.pem -enclave enclave.so -out enclave.signed.so -config Enclave/Enclave.config.xml
# echo "-------------------------"
# ./app  -h $((4+4*i)) -s 50 -d 4 -t $((t-1)) -l 3000000 -c 50 -v 25 -b 10 -n 1 -m 0.4 >> res.txt #3 4
# make clean


# done
# done
# done

