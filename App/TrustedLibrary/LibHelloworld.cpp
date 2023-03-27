#include "../App.h"
#include "Enclave_u.h"

//change!!
void init_from_enclave(void){
    init(global_eid);
}
void test_from_enclave(void){
    test_run(global_eid);
}