#include "../App.h"
#include "Enclave_u.h"

void call_helloworld_from_enclave(void){
    ecall_helloworld(global_eid);
}

//change!!
void run_code_from_enclave(void){
    run_code(global_eid);
}