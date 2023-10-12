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

void read_data(std::string file_name, std::vector<std::pair<uint64_t, uint64_t>> &data, std::vector<uint32_t> &data_target, int isQuery)
{
    // //test and printf 100 full-keys
    // std::ifstream input(file_name, std::ios::binary);
    // uint8_t tmp;
    // for (int k = 0; k < 100; k++)
    // {
    //     for (int i = 0; i < 16; i++)
    //     {
    //         input.read(reinterpret_cast<char *>(&tmp), sizeof(tmp));
    //         printf("%u ", tmp);
    //     }
    //     printf("\n");
    // }
    // std::vector<std::pair<uint64_t, uint64_t>> reservoir(test_data_len);
    srand(time(NULL));
    // for (int i = 0; i < 1000000; ++i)
    // {
    //     int j = rand() % (i + 1);
    //     if (j < test_data_len)
    //         reservoir[j] = i;
    // }
    // sort(reservoir.begin(), reservoir);
    std::ifstream input(file_name, std::ios::binary);
    uint64_t high, low;
    uint32_t target;
    uint32_t index = 0;
    uint32_t max_num = UINT32_MAX;
    if (isQuery)
        max_num = 1000000;
    // data.resize(test_data_len);
    printf("lib test_data_len: %d\n", test_data_len);
    while (index < max_num && input.read(reinterpret_cast<char *>(&high), sizeof(high)) && input.read(reinterpret_cast<char *>(&low), sizeof(low)))
    { // data.size() < test_data_len &&
        // data.emplace_back(high, low); // 1281167
        std::pair<uint64_t, uint64_t> tmp = {high, low};
        // gist和siftM不存在target数据，不能进行读取
        if (!isQuery)
        {
            input.read(reinterpret_cast<char *>(&target), sizeof(target));
            data_target.emplace_back(target);
            input.read(reinterpret_cast<char *>(&target), sizeof(target)); // the 512w dataSet's target is 64 bit,target虽然是64bit，但是值从0-1000，所以高位都是0
        }
        if (index < test_data_len)
        {
            data.push_back(tmp); // data[index];
        }
        else
        {
            int j = rand() % (index + 1);
            if (j < test_data_len)
            {
                data[j] = tmp; // data[index];
            }
        }
        index++;
    }
    input.close();
}
void send_data(std::vector<std::pair<uint64_t, uint64_t>> &data, std::vector<uint32_t> &data_target, int isQuery)
{
    const size_t count = sendKey_batch_size;
    uint32_t remain_size = data.size();
    std::pair<uint64_t, uint64_t> *data_ptr = data.data();

    while (remain_size > 0)
    {
        size_t send_size = remain_size > count ? count : remain_size;
        if (!isQuery)
            encall_send_data(global_eid, data_ptr, send_size);
        else
            encall_send_query(global_eid, data_ptr, send_size);
        remain_size -= send_size;
        data_ptr += send_size;
    }
    // send targets to enclave
    remain_size = data_target.size();
    uint32_t *data_ptr2 = data_target.data();

    while (remain_size > 0)
    {
        size_t send_size = remain_size > count ? count : remain_size;
        if (!isQuery)
            encall_send_targets(global_eid, data_ptr2, send_size);
        else
            encall_send_qtargets(global_eid, data_ptr2, send_size);
        remain_size -= send_size;
        data_ptr2 += send_size;
    }
}
void read_data_query(std::string file_name, std::vector<std::pair<uint64_t, uint64_t>> &query, int is_img_code)
{
    std::ifstream input(file_name, std::ios::binary);
    uint64_t high, low;
    uint32_t target;
    uint32_t data_len = 1000000;
    if (is_img_code)
    {
        while (input.read(reinterpret_cast<char *>(&high), sizeof(high)) && input.read(reinterpret_cast<char *>(&low), sizeof(low)))
        {
            query.emplace_back(high, low);
        }
    }
    else
    {
        uint32_t read_len = 0;
        while (read_len < data_len && input.read(reinterpret_cast<char *>(&high), sizeof(high)) && input.read(reinterpret_cast<char *>(&low), sizeof(low)))
        {
            read_len++;
        }
        while (query.size() < test_data_len && input.read(reinterpret_cast<char *>(&high), sizeof(high)) && input.read(reinterpret_cast<char *>(&low), sizeof(low)))
        {
            query.push_back({high, low});
        }
    }
    input.close();
}

void change_data_len(int val)
{
    test_data_len = val;
}
