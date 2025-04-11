#include "../App.h"
#include <fstream>

void init_after_send_data(std::vector<dataItem> &db, int dataset_flag)
{
    Con::cont.init_index(db, dataset_flag);
}
void init_test_query(std::vector<uint8_t> &queries)
{
    Con::cont.init_query(queries);
}

void Dec_data(void *dataptr, size_t batch_size, int is_img_dataset);
void Dec_data_query(void *dataptr, size_t batch_size, int is_img_dataset);
void read_data(std::string file_name, std::vector<std::pair<uint64_t, uint64_t>> &data, std::vector<uint32_t> &data_target, int flag)
{
    srand(time(NULL));
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
    std::ifstream input(file_name, std::ios::binary);
    uint64_t high, low;
    uint32_t target, index = 0;
    while (input.read(reinterpret_cast<char *>(&high), sizeof(high)) && input.read(reinterpret_cast<char *>(&low), sizeof(low)))
    { // data.size() < DATA_LEN &&
        std::pair<uint64_t, uint64_t> tmp = {high, low};
        // data.emplace_back(high, low); // 1281167
        if (!flag)
        {
            input.read(reinterpret_cast<char *>(&target), sizeof(target));
            // data_target.emplace_back(target);
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

void read_enc_dataset(std::string file_name,
                      std::vector<uint8_t> &read_data, int is_query)
{
    int is_img512_dataset = 0, sift_len = 100000;
    if (file_name.find("img") != std::string::npos)
    {
        is_img512_dataset = 1;
    }
    std::ifstream input(file_name, std::ios::binary);
    uint8_t *enc_data;
    uint8_t tmp;
    uint32_t batch_size = (is_img512_dataset == 1) ? (ENC_BATCH_SIZE_IMG) : (ENC_BATCH_SIZE_SIFT);
    uint32_t tmp1 = 0, read_len = 0;

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
            tmp1 += tmp_size;
            Dec_data(read_data.data() + read_len, tmp_size, is_img512_dataset);
        }
        else if (skip_len < 0)
        {
            Dec_data(read_data.data() + read_len, tmp_size, is_img512_dataset);
        }
        else
        {
            read_data.clear();
            read_len = -tmp_size;
        }
        read_len += tmp_size;

        if (!is_img512_dataset && tmp1 > ((sift_len) * 16 - batch_size))
        {
            break;
        }
        if (tmp_size < batch_size)
            break;
        // read_data.clear();
    }
    input.close();
}

void Dec_data(void *dataptr, size_t batch_size, int is_img_dataset)
{
    CryptoPrimitive *cryptoObj = new CryptoPrimitive(CIPHER_TYPE, HASH_TYPE);
    EVP_MD_CTX *mdCtx = EVP_MD_CTX_new();
    EVP_CIPHER_CTX *cipherCtx_ = EVP_CIPHER_CTX_new();
    uint8_t *sessionKey_ = const_sessionKey;

    uint8_t *dataE = reinterpret_cast<uint8_t *>(dataptr);
    cryptoObj->SessionKeyDec(cipherCtx_, dataE,
                             batch_size, sessionKey_,
                             dataE);
    EVP_MD_CTX_free(mdCtx);
    EVP_CIPHER_CTX_free(cipherCtx_);
}

vector<dataItem> partEncData(std::vector<uint8_t> &read_data, int dataSet)
{
    CryptoPrimitive *cryptoObj = new CryptoPrimitive(CIPHER_TYPE, HASH_TYPE);
    EVP_MD_CTX *mdCtx = EVP_MD_CTX_new();
    EVP_CIPHER_CTX *cipherCtx_ = EVP_CIPHER_CTX_new();
    uint8_t *encKey = feature_key;
    vector<uint8_t> tmp_fullkey;
    int tmp_size = 0, is_img_dataset = 0;

    if (!dataSet)
        is_img_dataset = 1;
    uint8_t *dataE = read_data.data();
    vector<dataItem> partEncData;
    dataItem dtm;
    static int id = 0;
    // VECTOR_LEN:{ENC, PLAIN} enc:{a,...,0bx0...0};plain:{0b0...0x,..d,e}可能不是8的倍数，多余的bit用一个uint8
    for (int i = 0; i < read_data.size();)
    {
        tmp_fullkey.clear();
        for (int j = 0; j < VECTOR_LEN; j++)
        {
            tmp_fullkey.push_back(read_data[i]);
            i++;
        }
        if (is_img_dataset)
            i += sizeof(uint64_t);
        // if (PLAIN_BIT < VECTOR_BIT)
        // {
        //     memcpy(dtm.fullkey, tmp_fullkey.data(), ENC_LEN);
        //     dtm.fullkey[ENC_LEN - 1] &= MASK_8[ENC_BIT & 7];
        //     cryptoObj->SessionKeyEnc(cipherCtx_, dtm.fullkey,
        //                              ENC_LEN, encKey,
        //                              dtm.fullkey);
        // }
        // if (ENC_BIT & 7)
        // {
        //     memcpy(dtm.fullkey + ENC_LEN, tmp_fullkey.data() + ENC_LEN - 1, PLAIN_LEN);
        //     dtm.fullkey[ENC_LEN] &= (~MASK_8[8 - ENC_BIT & 7]);
        // }
        // else
        {
            memcpy(dtm.fullkey + ENC_LEN, tmp_fullkey.data() + ENC_LEN, PLAIN_LEN);
        }
        dtm.id = id++;
        partEncData.push_back(dtm);
    }
    return std::move(partEncData);
}