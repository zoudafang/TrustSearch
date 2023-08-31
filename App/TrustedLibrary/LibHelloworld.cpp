#include "../App.h"
#include "Enclave_u.h"
#include <fstream>
#include "../include/constVar.h"

// change!!
void init_from_enclave(void)
{
    init(global_eid);
}
void test_from_enclave(void)
{
    test_run(global_eid);
}
void init_after_send_data(void)
{
    init_after_send(global_eid);
}
void read_data(std::string file_name, std::vector<std::pair<uint64_t, uint64_t>> &data, std::vector<uint32_t> &data_target, int flag)
{
    if (flag == 2) // 读取test_data
    {
        std::ifstream input(file_name, std::ios::binary);
        uint64_t high, low;
        uint32_t target;
        uint32_t data_len = 1000000;//siftM和gistM中，前100w个数据是特征值数据集，后面的是才测试特征值集合
        {
            uint32_t read_len = 0;
            while (read_len < data_len && input.read(reinterpret_cast<char *>(&high), sizeof(high)) && input.read(reinterpret_cast<char *>(&low), sizeof(low)))
            {
                read_len++;
            }
            while (data.size() < DATA_LEN && input.read(reinterpret_cast<char *>(&high), sizeof(high)) && input.read(reinterpret_cast<char *>(&low), sizeof(low)))
            {
                data.push_back({high, low});
            }
        }
        input.close();
        return;
    }
    std::ifstream input(file_name, std::ios::binary);
    uint64_t high, low;
    uint32_t target;
    while (data.size() < DATA_LEN && input.read(reinterpret_cast<char *>(&high), sizeof(high)) && input.read(reinterpret_cast<char *>(&low), sizeof(low)))
    {
        data.emplace_back(high, low); // 1281167
        // gist和siftM不存在target数据，不能进行读取
        if (!flag)
        {
            input.read(reinterpret_cast<char *>(&target), sizeof(target));
            data_target.emplace_back(target);
            input.read(reinterpret_cast<char *>(&target), sizeof(target)); // the 512w dataSet's target is 64 bit,target虽然是64bit，但是值从0-1000，所以高位都是0
        }
    }
    input.close();
}
void send_data(std::vector<std::pair<uint64_t, uint64_t>> &data, std::vector<uint32_t> &data_target, int is_query)
{
    const size_t count = SEND_BATCH_LEN;
    uint32_t remain_size = data.size();
    std::pair<uint64_t, uint64_t> *data_ptr = data.data();

    while (remain_size > 0)
    {
        size_t send_size = remain_size > count ? count : remain_size;
        if (!is_query)
            ecall_send_data(global_eid, data_ptr, send_size);
        else
            ecall_send_query(global_eid, data_ptr, send_size);
        remain_size -= send_size;
        data_ptr += send_size;
    }
    // send targets to enclave
    remain_size = data_target.size();
    uint32_t *data_ptr2 = data_target.data();

    while (remain_size > 0)
    {
        size_t send_size = remain_size > count ? count : remain_size;
        if (!is_query)
            ecall_send_targets(global_eid, data_ptr2, send_size);
        else
            ecall_send_qtargets(global_eid, data_ptr2, send_size);
        remain_size -= send_size;
        data_ptr2 += send_size;
    }
}