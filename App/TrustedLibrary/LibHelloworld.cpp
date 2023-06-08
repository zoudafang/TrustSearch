#include "../App.h"
#include "Enclave_u.h"
#include <fstream>

//change!!
void init_from_enclave(void){
    init(global_eid);
}
void test_from_enclave(void){
    test_run(global_eid);
}

void read_data(std::string file_name,std::vector<std::pair<uint64_t,uint64_t>> &data,std::vector<uint32_t> &data2){
    std::ifstream input(file_name, std::ios::binary);
    uint64_t high, low;uint32_t target;
    while (data.size()<1000000&&input.read(reinterpret_cast<char*>(&high), sizeof(high)) && input.read(reinterpret_cast<char*>(&low), sizeof(low))) {
        data.emplace_back(high,low);
	    input.read(reinterpret_cast<char*>(&target),sizeof(target));
	    data2.emplace_back(target);
    }
    input.close();
}
void send_data(std::vector<std::pair<uint64_t,uint64_t>> &data,std::vector<uint32_t> &data2){
    //send 128code to Enclave
    const size_t count=512;
    uint32_t remain_size=data.size();
    std::pair<uint64_t,uint64_t>* data_ptr=data.data();

    while(remain_size>0){
        size_t send_size=remain_size>count?count:remain_size;
        encall_send_data(global_eid,data_ptr,send_size);
        remain_size-=send_size;
        data_ptr+=send_size;
    }
    //send targets to enclave
    remain_size=data2.size();
    uint32_t* data_ptr2=data2.data();

    while(remain_size>0){
        size_t send_size=remain_size>count?count:remain_size;
        encall_send_targets(global_eid,data_ptr2,send_size);
        remain_size-=send_size;
        data_ptr2+=send_size;
    }
}