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
./app  -h $((4+4*i)) -s 50 -d 4 -t $((t-1)) -l 3000000 -c 50 -v 25 -b 10 -n 1 -m 0.4 >> res.txt #3 4
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

# # myArray=(32 64 128 256 512 1024)
# myArray=(4 6 8 10 12)

# for i in {4..4}
# do
# echo "+++++++++++dist $((6+2*i))+++++++++++++\n" >> res.txt
# for t in {3..3}
# do
# for j in {1..1}
# do

# new_value=${myArray[j]}   #$((10+10*j))  # 替换为你想要的新值
# file_path="./include/constVar.h"
# # sed -i "s/const uint32_t PAGE_SIZE = [0-9]\+;/const uint32_t PAGE_SIZE = $new_value;/" "$file_path"

# # for j in {1..5}
# # do

# # new_value=$((3+2*j))  # 替换为你想要的新值
# # file_path="./include/constVar.h"
# sed -i "s/const uint32_t SUBINDEX_NUM = [0-9]\+;/const uint32_t SUBINDEX_NUM = $new_value;/" "$file_path"

#  echo "data $((t)) SUBINDEX_NUM $((new_value)) " >> res.txt  #subindex $((new_value))


# # sed -i "s/const uint32_t PAGE_SIZE = [0-9]\+;/const uint32_t PAGE_SIZE = 64;/" "$file_path"

# make clean        #    $cautious for testCS
# make SGX_DEBUG=0
# /opt/intel/sgxsdk/bin/x64/sgx_sign sign -key Enclave/Enclave_private_test.pem -enclave enclave.so -out enclave.signed.so -config Enclave/Enclave.config.xml
# echo "-------------------------"
# ./app  -h $((4+4*i)) -s 50 -d 4 -t $((t-1)) -l 3000000 -c 50 -v 25 -b 10 -n 1 -m 0.4 >> res.txt #3 4
# make clean

# # make clean        #    $cautious for testCS
# # make SGX_DEBUG=0
# # /opt/intel/sgxsdk/bin/x64/sgx_sign sign -key Enclave/Enclave_private_test.pem -enclave enclave.so -out enclave.signed.so -config Enclave/Enclave.config.xml
# # echo "-------------------------"
# # ./app  -h $((4+4*i)) -s 50 -d 4 -t $((t-1)) -l 3000000 -c 50 -v 25 -b 10 -n 1 -m 0.3 >> res.txt #3 4
# # make clean

# # make clean        #    $cautious for testCS
# # make SGX_DEBUG=0
# # /opt/intel/sgxsdk/bin/x64/sgx_sign sign -key Enclave/Enclave_private_test.pem -enclave enclave.so -out enclave.signed.so -config Enclave/Enclave.config.xml
# # echo "-------------------------"
# # ./app  -h $((4+4*i)) -s 50 -d 4 -t $((t-1)) -l 3000000 -c 50 -v 25 -b 10 -n 1 -m 0.5 >> res.txt #3 4
# # make clean

# # make clean        #    $cautious for testCS
# # make SGX_DEBUG=0
# # /opt/intel/sgxsdk/bin/x64/sgx_sign sign -key Enclave/Enclave_private_test.pem -enclave enclave.so -out enclave.signed.so -config Enclave/Enclave.config.xml
# # echo "-------------------------"
# # ./app  -h $((4+4*i)) -s 50 -d 3 -t $((t-1)) -l 3000000 -c 50 -v 25 -b 10 -n 1 -m 0.4 >> res.txt #3 4
# # make clean

# # make clean        #    $cautious for testCS
# # make SGX_DEBUG=0
# # /opt/intel/sgxsdk/bin/x64/sgx_sign sign -key Enclave/Enclave_private_test.pem -enclave enclave.so -out enclave.signed.so -config Enclave/Enclave.config.xml
# # echo "-------------------------"
# # ./app  -h $((4+4*i)) -s 50 -d 5 -t $((t-1)) -l 3000000 -c 50 -v 25 -b 10 -n 1 -m 0.4 >> res.txt #3 4
# # make clean


# #  echo "data $((t)) SUBINDEX_NUM $((new_value))----------------cautious PAGE==1 " >> res.txt  #subindex $((new_value))


# # sed -i "s/const uint32_t PAGE_SIZE = [0-9]\+;/const uint32_t PAGE_SIZE = 1;/" "$file_path"

# # make clean        #    $cautious for testCS
# # make SGX_DEBUG=0
# # /opt/intel/sgxsdk/bin/x64/sgx_sign sign -key Enclave/Enclave_private_test.pem -enclave enclave.so -out enclave.signed.so -config Enclave/Enclave.config.xml
# # echo "-------------------------"
# # ./app  -h $((4+4*i)) -s 50 -d 4 -t $((t-1)) -l 3000000 -c 50 -v 25 -b 10 -n 1 -m 0.2 >> res.txt #3 4
# # make clean

# # make clean        #    $cautious for testCS
# # make SGX_DEBUG=0
# # /opt/intel/sgxsdk/bin/x64/sgx_sign sign -key Enclave/Enclave_private_test.pem -enclave enclave.so -out enclave.signed.so -config Enclave/Enclave.config.xml
# # echo "-------------------------"
# # ./app  -h $((4+4*i)) -s 50 -d 4 -t $((t-1)) -l 3000000 -c 50 -v 25 -b 10 -n 1 -m 0.3 >> res.txt #3 4
# # make clean

# # make clean        #    $cautious for testCS
# # make SGX_DEBUG=0
# # /opt/intel/sgxsdk/bin/x64/sgx_sign sign -key Enclave/Enclave_private_test.pem -enclave enclave.so -out enclave.signed.so -config Enclave/Enclave.config.xml
# # echo "-------------------------"
# # ./app  -h $((4+4*i)) -s 50 -d 4 -t $((t-1)) -l 3000000 -c 50 -v 25 -b 10 -n 1 -m 0.5 >> res.txt #3 4
# # make clean

# # make clean        #    $cautious for testCS
# # make SGX_DEBUG=0
# # /opt/intel/sgxsdk/bin/x64/sgx_sign sign -key Enclave/Enclave_private_test.pem -enclave enclave.so -out enclave.signed.so -config Enclave/Enclave.config.xml
# # echo "-------------------------"
# # ./app  -h $((4+4*i)) -s 50 -d 3 -t $((t-1)) -l 3000000 -c 50 -v 25 -b 10 -n 1 -m 0.4 >> res.txt #3 4
# # make clean

# # make clean        #    $cautious for testCS
# # make SGX_DEBUG=0
# # /opt/intel/sgxsdk/bin/x64/sgx_sign sign -key Enclave/Enclave_private_test.pem -enclave enclave.so -out enclave.signed.so -config Enclave/Enclave.config.xml
# # echo "-------------------------"
# # ./app  -h $((4+4*i)) -s 50 -d 5 -t $((t-1)) -l 3000000 -c 50 -v 25 -b 10 -n 1 -m 0.4 >> res.txt #3 4
# # make clean

# # make clean        #    $cautious for testCS
# # make SGX_DEBUG=0
# # /opt/intel/sgxsdk/bin/x64/sgx_sign sign -key Enclave/Enclave_private_test.pem -enclave enclave.so -out enclave.signed.so -config Enclave/Enclave.config.xml
# # echo "-------------------------"
# # ./app  -h $((4+4*i)) -s 500000 -d 4 -t $((t-1)) -l 3000000 -c 40 -v 50 -b 10 -n 1 -m 0.5 >> res.txt #3 4
# # make clean

# # sed -i "s/const uint32_t PAGE_SIZE = [0-9]\+;/const uint32_t PAGE_SIZE = 1;/" "$file_path"

# # make clean        #    $cautious for testCS
# # make SGX_DEBUG=0
# # /opt/intel/sgxsdk/bin/x64/sgx_sign sign -key Enclave/Enclave_private_test.pem -enclave enclave.so -out enclave.signed.so -config Enclave/Enclave.config.xml
# # echo "-------------------------"
# # ./app  -h $((4+4*i)) -s 50 -d 4 -t $((t-1)) -l 3000000 -c 40 -v 10 -b 10 -n 1 -m 0.5 >> res.txt #3 4
# # make clean

# # # make clean        #    $cautious for testCS
# # # make SGX_DEBUG=0
# # # /opt/intel/sgxsdk/bin/x64/sgx_sign sign -key Enclave/Enclave_private_test.pem -enclave enclave.so -out enclave.signed.so -config Enclave/Enclave.config.xml
# # # echo "-------------------------"
# # # ./app  -h $((4+4*i)) -s 500000 -d 4 -t $((t-1)) -l 3000000 -c 40 -v 50 -b 10 -n 1 -m 0.5 >> res.txt #3 4
# # # make clean

# # make clean        #    $cautious for testCS
# # make SGX_DEBUG=0
# # /opt/intel/sgxsdk/bin/x64/sgx_sign sign -key Enclave/Enclave_private_test.pem -enclave enclave.so -out enclave.signed.so -config Enclave/Enclave.config.xml
# # echo "-------------------------"
# # ./app  -h $((4+4*i)) -s 50000000000 -d 4 -t $((t-1)) -l 3000000 -c 40 -v 10 -b 20 -n 1 -m 0.8 >> res.txt #3 4
# # make clean


# # make SGX_DEBUG=0
# # /opt/intel/sgxsdk/bin/x64/sgx_sign sign -key Enclave/Enclave_private_test.pem -enclave enclave.so -out enclave.signed.so -config Enclave/Enclave.config.xml
# # echo "-------------------------"
# # ./app  -h $((4+4*i)) -s 50 -d 4 -t $((t-1)) -l 3000000 -c 40 -v 10 -b 20 -n 1 -m 0.2 >> res.txt #3 4
# # make clean
# #--------------------------------------h 18 -s 50 -t 1 -l 300000 -c 40 -v 50 -b 20 -n 1 -m 0.5

# # make clean
# # make SGX_DEBUG=0
# # /opt/intel/sgxsdk/bin/x64/sgx_sign sign -key Enclave/Enclave_private_test.pem -enclave enclave.so -out enclave.signed.so -config Enclave/Enclave.config.xml
# # echo "-------------------------"
# # ./app  -h $((4+4*i)) -s 50 -d 4 -t $((t-1)) -l 50000 -c 40 >> res.txt
# # make clean

# # make clean
# # make SGX_DEBUG=0
# # /opt/intel/sgxsdk/bin/x64/sgx_sign sign -key Enclave/Enclave_private_test.pem -enclave enclave.so -out enclave.signed.so -config Enclave/Enclave.config.xml
# # echo "-------------------------"
# # ./app  -h $((4+4*i)) -s 150 -d 6 -t $((t-1)) -l 50000 -c 0 >> res.txt
# # make clean

# # make clean        #    $cautious for testCS
# # make SGX_DEBUG=0
# # /opt/intel/sgxsdk/bin/x64/sgx_sign sign -key Enclave/Enclave_private_test.pem -enclave enclave.so -out enclave.signed.so -config Enclave/Enclave.config.xml
# # echo "-------------------------"
# # ./app  -h $((4+4*i)) -s 50 -d 3 -t $((t-1)) -l 3000000 -c 40 -v 10 -b 10 -n 1 -m 0.5 >> res.txt #3 4
# # make clean

# # make clean        #    $cautious for testCS
# # make SGX_DEBUG=0
# # /opt/intel/sgxsdk/bin/x64/sgx_sign sign -key Enclave/Enclave_private_test.pem -enclave enclave.so -out enclave.signed.so -config Enclave/Enclave.config.xml
# # echo "-------------------------"
# # ./app  -h $((4+4*i)) -s 50 -d 3 -t $((t-1)) -l 3000000 -c 40 -v 10 -b 20 -n 1 -m 0.7 >> res.txt #3 4
# # make clean


# # make SGX_DEBUG=0
# # /opt/intel/sgxsdk/bin/x64/sgx_sign sign -key Enclave/Enclave_private_test.pem -enclave enclave.so -out enclave.signed.so -config Enclave/Enclave.config.xml
# # echo "-------------------------"
# # ./app  -h $((4+4*i)) -s 50 -d 3 -t $((t-1)) -l 3000000 -c 40 -v 10 -b 20 -n 1 -m 0.3 >> res.txt #3 4
# # make clean

# # make clean        #    $cautious for testCS
# # make SGX_DEBUG=0
# # /opt/intel/sgxsdk/bin/x64/sgx_sign sign -key Enclave/Enclave_private_test.pem -enclave enclave.so -out enclave.signed.so -config Enclave/Enclave.config.xml
# # echo "-------------------------"
# # ./app  -h $((4+4*i)) -s 50 -d 5 -t $((t-1)) -l 3000000 -c 40 -v 10 -b 10 -n 1 -m 0.5 >> res.txt #3 4
# # make clean


# # make clean        #    $cautious for testCS
# # make SGX_DEBUG=0
# # /opt/intel/sgxsdk/bin/x64/sgx_sign sign -key Enclave/Enclave_private_test.pem -enclave enclave.so -out enclave.signed.so -config Enclave/Enclave.config.xml
# # echo "-------------------------"
# # ./app  -h $((4+4*i)) -s 50 -d 5 -t $((t-1)) -l 3000000 -c 40 -v 10 -b 20 -n 1 -m 0.7 >> res.txt #3 4
# # make clean


# # make SGX_DEBUG=0
# # /opt/intel/sgxsdk/bin/x64/sgx_sign sign -key Enclave/Enclave_private_test.pem -enclave enclave.so -out enclave.signed.so -config Enclave/Enclave.config.xml
# # echo "-------------------------"
# # ./app  -h $((4+4*i)) -s 50 -d 5 -t $((t-1)) -l 3000000 -c 40 -v 10 -b 20 -n 1 -m 0.3 >> res.txt #3 4
# # make clean

# done
# done
# done

