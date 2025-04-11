#!/bin/bash



while getopts "t:" opt; do
  case $opt in
    t)
      # 获取 -t 参数的值
      value=$OPTARG
      ;;
    *)
      echo "Usage: $0 -t <value>"
      exit 1
      ;;
  esac
done


for j in {1..1}
do
for i in {1..1}
do

make clean   
make SGX_DEBUG=0 > /dev/null 2>&1
/opt/intel/sgxsdk/bin/x64/sgx_sign sign -key Enclave/Enclave_private_test.pem -enclave enclave.so -out enclave.signed.so -config Enclave/Enclave.config.xml
echo "-------------------------"
sudo  ./app  -d 4 -t $value -m 0.4
make clean

done
done