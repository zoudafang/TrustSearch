#include "../App.h"
#include "Enclave_u.h"
#include <fstream>
#include "../include/constVar.h"

//change!!
void init_from_enclave(void){
    init(global_eid);
}
void test_from_enclave(void){
    test_run(global_eid);
}

void read_data(std::string file_name,std::vector<std::pair<uint64_t,uint64_t>> &full_key,std::vector<uint32_t> &targets){
    std::ifstream input(file_name, std::ios::binary);
    uint64_t high, low;uint32_t target;
    while (full_key.size()<test_data_len&&input.read(reinterpret_cast<char*>(&high), sizeof(high)) && input.read(reinterpret_cast<char*>(&low), sizeof(low))) {
        full_key.emplace_back(high,low);
	    input.read(reinterpret_cast<char*>(&target),sizeof(target));
	    input.read(reinterpret_cast<char*>(&target),sizeof(target));
	    targets.emplace_back(target);
    }
    input.close();
}
void send_data(std::vector<std::pair<uint64_t,uint64_t>> &full_key,std::vector<uint32_t> &targets,int f){
    //send 128 full_key to Enclave
    const size_t count=sendKey_batch_size;
    uint32_t remain_size=full_key.size();
    std::pair<uint64_t,uint64_t>* data_ptr=full_key.data();

    while(remain_size>0){
        size_t send_size=remain_size>count?count:remain_size;
        for(int i=0;i<send_size;i++){
            data_ptr[i].first^=f;
            data_ptr[i].second^=f;
        }
        encall_send_data(global_eid,data_ptr,send_size);
        remain_size-=send_size;
        data_ptr+=send_size;
    }
    //send targets to enclave
    remain_size=targets.size();
    uint32_t* data_ptr2=targets.data();

    while(remain_size>0){
        size_t send_size=remain_size>count?count:remain_size;
        // encall_send_targets(global_eid,data_ptr2,send_size);
        remain_size-=send_size;
        data_ptr2+=send_size;
    }
}