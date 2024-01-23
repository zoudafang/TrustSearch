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
        uint32_t data_len = 1000000; // siftM和gistM中，前100w个数据是特征值数据集，后面的是才测试特征值集合
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
    srand(time(NULL));
    std::ifstream input(file_name, std::ios::binary);
    uint64_t high, low;
    uint32_t target, index = 0;
    uint32_t max_sift = (flag == 0) ? DATA_LEN : 1000000; // gist, sift is 100w 128bit feature
    while (index < max_sift && input.read(reinterpret_cast<char *>(&high), sizeof(high)) && input.read(reinterpret_cast<char *>(&low), sizeof(low)))
    {
        std::pair<uint64_t, uint64_t> tmp = {high, low}; // 1281167
        // gist和siftM不存在target数据，不能进行读取
        if (!flag)
        {
            input.read(reinterpret_cast<char *>(&target), sizeof(target));
            data_target.emplace_back(target);
            input.read(reinterpret_cast<char *>(&target), sizeof(target)); // the 512w dataSet's target is 64 bit,target虽然是64bit，但是值从0-1000，所以高位都是0
        }
        if (index < DATA_LEN)
        {
            data.push_back(tmp); // data[index];
        }
        else
        {
            int j = rand() % (index + 1);
            if (j < DATA_LEN)
            {
                data[j] = tmp; // data[index];
            }
        }
        index++;
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

void read_enc_dataset(std::string file_name, int is_query)
{
    int is_img512_dataset = 0, sift_len = 1000000;
    if (file_name.find("img") != std::string::npos)
    {
        is_img512_dataset = 1;
    }
    std::ifstream input(file_name, std::ios::binary);
    std::vector<uint8_t> read_data;
    uint8_t *enc_data;
    uint8_t tmp, tmp1 = 0;
    uint32_t batch_size = (is_img512_dataset == 1) ? (ENC_BATCH_SIZE_IMG) : (ENC_BATCH_SIZE_SIFT);

    int i, tmp_size, skip_len = 0;
    if (is_query && !is_img512_dataset)
    {
        skip_len = SIFT_LEN * sizeof(uint64_t) * 2;
    }

    while (1)
    {
        for (i = 1; i <= batch_size; i++)
        {
            if (input.read(reinterpret_cast<char *>(&tmp), sizeof(tmp)))
                read_data.push_back(tmp);
            else
                break;
        }
        tmp_size = (i >= batch_size) ? (batch_size) : (i - 1);
        skip_len -= tmp_size;
        if (tmp_size == 0)
            break;
        if (!is_query)
        {
            tmp1 += batch_size;
            ecall_send_data_enc(global_eid, read_data.data(), tmp_size, is_img512_dataset);
        }
        else if (skip_len < 0)
        {
            ecall_send_query_enc(global_eid, read_data.data(), tmp_size, is_img512_dataset);
        }
        if (!is_img512_dataset && tmp1 > ((sift_len) * 16 - batch_size))
        {
            break;
        }
        if (tmp_size < batch_size)
            break;
        read_data.clear();
    }
    input.close();
}

// img512's file struct is different with GIST, SIFT
void enc_data_set(std::string file_name)
{
    int is_img512_dataset = 0;
    if (file_name.find("img") != std::string::npos)
    {
        is_img512_dataset = 1;
    }
    std::ifstream input(file_name, std::ios::binary);
    uint64_t high, low;
    uint32_t target, index = 0;
    std::vector<uint8_t> read_data;
    uint8_t *enc_data;
    uint8_t tmp;
    uint32_t batch_size = (is_img512_dataset == 1) ? (ENC_BATCH_SIZE_IMG) : (ENC_BATCH_SIZE_SIFT);

    size_t dotPosition = file_name.find_last_of('.');
    // encode file is  "_enc"
    std::string enc_file_name = file_name;
    enc_file_name.insert(dotPosition, "_enc");
    std::ofstream output(enc_file_name, std::ios::binary);

    int i, tmp_size;
    while (1)
    {
        for (i = 1; i <= batch_size; i++)
        {
            if (input.read(reinterpret_cast<char *>(&tmp), sizeof(tmp)))
                read_data.push_back(tmp);
            else
                break;
        }
        tmp_size = (i >= batch_size) ? (batch_size) : (i - 1);
        ecall_enc_dataset(global_eid, read_data.data(), tmp_size);
        for (i = 0; i < tmp_size; i++)
        {
            output.write(reinterpret_cast<const char *>(&read_data[i]), sizeof(read_data[i]));
        }
        if (tmp_size < batch_size)
            break;
        read_data.clear();
    }
    output.close();
    input.close();
};