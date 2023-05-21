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
void read_data(std::string file_name,std::vector<std::pair<uint64_t,uint64_t>> &data){
    std::ifstream input(file_name, std::ios::binary);
    uint64_t high, low;
    while (input.read(reinterpret_cast<char*>(&high), sizeof(high)) && input.read(reinterpret_cast<char*>(&low), sizeof(low))) {
        data.emplace_back(high,low);
    }
    input.close();
}
void send_data(std::vector<std::pair<uint64_t,uint64_t>> &data){
    const size_t count=512;
    uint32_t remain_size=data.size();
    std::pair<uint64_t,uint64_t>* data_ptr=data.data();

    while(remain_size>0){
        size_t send_size=remain_size>count?count:remain_size;
        encall_send_data(global_eid,data_ptr,send_size);
        remain_size-=send_size;
        data_ptr+=send_size;
    }
}