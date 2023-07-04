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
void init_after_send_data(void){
    init_after_send(global_eid);
}
void read_data(std::string file_name,std::vector<std::pair<uint64_t,uint64_t>> &data,std::vector<uint32_t> &data_target){
    std::ifstream input(file_name, std::ios::binary);
    uint64_t high, low;
    uint32_t target;
    while (data.size()<DATA_LEN&&input.read(reinterpret_cast<char*>(&high), sizeof(high)) && input.read(reinterpret_cast<char*>(&low), sizeof(low))) {
        data.emplace_back(high,low);//1281167
	    input.read(reinterpret_cast<char*>(&target),sizeof(target));
	    input.read(reinterpret_cast<char*>(&target),sizeof(target));//the 512w dataSet's target is 64 bit
	    data_target.emplace_back(target);
    }
    input.close();
}
void send_data(std::vector<std::pair<uint64_t,uint64_t>> &data,std::vector<uint32_t> &data_target){
    const size_t count=SEND_BATCH_LEN;
    uint32_t remain_size=data.size();
    std::pair<uint64_t,uint64_t>* data_ptr=data.data();

    while(remain_size>0){
        size_t send_size=remain_size>count?count:remain_size;
        encall_send_data(global_eid,data_ptr,send_size);
        remain_size-=send_size;
        data_ptr+=send_size;
    }
    //send targets to enclave
    remain_size=data_target.size();
    uint32_t* data_ptr2=data_target.data();

    while(remain_size>0){
        size_t send_size=remain_size>count?count:remain_size;
        encall_send_targets(global_eid,data_ptr2,send_size);
        remain_size-=send_size;
        data_ptr2+=send_size;
    }
}