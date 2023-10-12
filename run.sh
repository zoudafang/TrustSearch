#test query time
#!/bin/bash
a=10000
for i in {1..12}
do
# cd ~/ZJ/SGX-Search-2q1-back
    a=$((i * 500000))
make clean
make SGX_DEBUG=0
/opt/intel/sgxsdk/bin/x64/sgx_sign sign -key Enclave/Enclave_private_test.pem -enclave enclave.so -out enclave.signed.so -config Enclave/Enclave.config.xml > /dev/null 2>&1    
echo "-------------------------"
# rm -f app.log
pkill app
sleep 1
rm -f app.log
./app -l $a -i 3 &
server_started=0
touch app.log
while [[ $server_started -eq 0 ]]; do
    sleep 5
    if grep -q "start server successful" app.log; then
        server_started=1
    fi
done
# sleep 10 
cd Client/build
make
echo "Value of test_len: $a" >> res.txt
./client -l $a -i 3 >> res.txt
cd ../../
# sleep 10
done
# make clean

# test invalid
#!/bin/bash
# a=640000
for i in {1..10}
do
cd ~/ZJ/SGX-Search-2q1-back
    a=$((i * 100000+200000))
make clean
make SGX_DEBUG=0
/opt/intel/sgxsdk/bin/x64/sgx_sign sign -key Enclave/Enclave_private_test.pem -enclave enclave.so -out enclave.signed.so -config Enclave/Enclave.config.xml > /dev/null 2>&1    
echo "-------------------------"
# rm -f app.log
pkill app
sleep 1
rm -f app.log
./app -l $a -i 1 &
server_started=0
touch app.log
while [[ $server_started -eq 0 ]]; do
    sleep 5
    if grep -q "start server successful" app.log; then
        server_started=1
    fi
done
# sleep 10 
cd Client/build
make
echo "Value of test_len: $a   is_invalid 1" >> res.txt
./client -l $a -i 1 >> res.txt
# sleep 10
done
# make clean

#test valid
# #!/bin/bash
# # a=640000
# for i in {1..20}
# do
#     a=$((i * 50000))
# make clean
# make SGX_DEBUG=0
# /opt/intel/sgxsdk/bin/x64/sgx_sign sign -key Enclave/Enclave_private_test.pem -enclave enclave.so -out enclave.signed.so -config Enclave/Enclave.config.xml > /dev/null 2>&1    
# echo "-------------------------"
# # rm -f app.log
# pkill app
# sleep 1
# rm -f app.log
# ./app -l $a -i 0 &
# server_started=0
# touch app.log
# while [[ $server_started -eq 0 ]]; do
#     sleep 5
#     if grep -q "start server successful" app.log; then
#         server_started=1
#     fi
# done
# # sleep 10 
# cd Client/build
# make
# echo "Value of test_len: $a is_invalid 0" >> res.txt
# ./client -l $a -i 0 >> res.txt
# cd ../../
# # sleep 10
# done
# # make clean

