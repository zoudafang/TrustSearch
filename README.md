## TrustSearch


## Introduction

## Dependencies

## Build & Usage

## Traces、dataset





## Getting Started Instructions



## 

## Example
## Configuration

```
./include/constVar


#define CACHE_SIZE 500000 //NUM in SGX1(=5000) differ from SGX2 

static const char SERVER_IP[] = "172.22.7.61";   //ip of server

static const int SERVER_PORT = 9030 (default); //port of TrustSearch

static const uint32_t SUBINDEX_NUM = 8 (default); //number of partition
```

## Server

```
make SGX_DEBUG=0
sgx_sign sign -key Enclave/Enclave_private_test.pem -enclave enclave.so -out enclave.signed.so -config Enclave/Enclave.config.xml

./app  -d [radius] -t [dataset] -m [alpha]

make clean
```

```
// parameters
// [radius]: cluster's max radius {val: 3 4 5}
// [dataset]: 0-imgNet 1-gist 2-sift  4-wabface(webface: fetch from github,run "cat part_* > faceData_5_23.bin" to combine all parts of webface)
// [alpha]: the ratio of vectors from all vectors that not be clustered {val:0.4 0.6 0.8}
```

## Client

```
mkdir build

cd build && make ..

./client -t  [dataset]  -h [threshold]

// parameters
// [threshold]: the threshold of each query 4, 8, 16 ...
// [dataset]: 0-imgNet 1-gist 2-sift  4-wabface
```



## Experiment

// start SGX
```
    sudo /sbin/modprobe intel_sgx 
```

Server Side:
```
    ./run.sh -t [dataset]
```

Client Side: (./Client/build)
```
    ./run_client_exp2.sh -t [dataset] -n [numOfClients]
    ./run_client_exp3.sh -t [dataset]
```