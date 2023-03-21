#include "Enclave_t.h"
#include "../Enclave.h"

//这个函数用于定义Ecall可信函数
void ecall_helloworld(){
    printf("this is a message from Enclave");
}


