#include "../App.h"
#include "Enclave_u.h"
#include <fstream>
#include "../include/constVar.h"
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <time.h>
#include <math.h>

using namespace std;
static int nn = 0;
void random_32(uint32_t *tmp)
{
    *tmp = rand();
    // *tmp = *tmp << 16;
    // *tmp = *tmp + nn;
    // nn++;
    // sgx_read_rand(reinterpret_cast<unsigned char *>(tmp), sizeof(uint32_t));
}
static uint32_t ll = 0;
void random_128(uint64_t *temp_key)
{
    unsigned char rands[16] = {0};
    // sgx_read_rand(rand, 16);
    for (int i = 0; i < 16; i++)
    {
        rands[i] = rand() % 256;
        ll++;
    }
    temp_key[0] = (uint64_t)rands[0];
    for (int i = 1; i < 8; i++)
    {
        temp_key[0] = temp_key[0] << 8;
        temp_key[0] = temp_key[0] + (uint64_t)rands[i];
    }
    temp_key[1] = (uint64_t)rands[8];
    for (int j = 1; j < 8; j++)
    {
        temp_key[1] = temp_key[1] << 8;
        temp_key[1] = temp_key[1] + (uint64_t)rands[j + 8];
    }
}
void get_sub_fingerprint(uint32_t *sub_fingerprint, uint64_t *fingerprint)
{
    sub_fingerprint[0] = fingerprint[0] & 0xffffffff;
    fingerprint[0] = fingerprint[0] >> 32;
    sub_fingerprint[1] = fingerprint[0] & 0xffffffff;

    sub_fingerprint[2] = fingerprint[1] & 0xffffffff;
    fingerprint[1] = fingerprint[1] >> 32;
    sub_fingerprint[3] = fingerprint[1] & 0xffffffff;
}
void prepare(uint32_t tmp_sub_hammdist, vector<uint32_t> &C_0_TO_subhammdis)
{
    // LOGGER("Prepare");
    int sub_keybit = 32;
    int tmp1, tmp2, tmp3, tmp4 = 1;
    int tmp = 0;
    uint32_t tmpx = 0;
    switch (tmp_sub_hammdist) // sub_hammdist
    {
    case 4:
        for (int a = 0; a < sub_keybit - 3; a++)
        {
            tmp1 = 0x0000000000000001 << a;
            for (int b = 1 + a; b < sub_keybit - 2; b++)
            {
                tmp2 = 0x0000000000000001 << b;
                for (int c = 1 + b; c < sub_keybit - 1; c++)
                {
                    tmp3 = 0x0000000000000001 << c;
                    for (int d = 1 + c; d < sub_keybit; d++)
                    {
                        tmp4 = 0x0000000000000001 << d;
                        tmp = tmp1 + tmp2 + tmp3 + tmp4;
                        tmpx = (uint32_t)tmp;
                        C_0_TO_subhammdis.push_back(tmpx);
                    }
                }
            }
        }
    case 3:
        for (int e = 0; e < sub_keybit - 2; e++)
        {
            tmp1 = 0x0000000000000001 << e;
            for (int f = 1 + e; f < sub_keybit - 1; f++)
            {
                tmp2 = 0x0000000000000001 << f;
                for (int g = 1 + f; g < sub_keybit; g++)
                {
                    tmp3 = 0x0000000000000001 << g;
                    tmp = tmp1 + tmp2 + tmp3;
                    tmpx = (uint32_t)tmp;
                    C_0_TO_subhammdis.push_back(tmpx);
                }
            }
        }
    case 2:
        for (int i = 0; i < sub_keybit - 1; i++)
        {
            tmp1 = 0x0000000000000001 << i;
            for (int j = 1 + i; j < sub_keybit; j++)
            {
                tmp2 = 0x0000000000000001 << j;
                tmp = tmp1 + tmp2;
                tmpx = (uint32_t)tmp;
                C_0_TO_subhammdis.push_back(tmpx);
            }
        }
    case 1:
        for (int x = 0; x < sub_keybit; x++)
        {
            tmp = 0x0000000000000001 << x;
            tmpx = (uint32_t)tmp;
            C_0_TO_subhammdis.push_back(tmpx);
        }
    case 0:
    {
        C_0_TO_subhammdis.push_back(0);
        break;
    }
    default:
        break;
    }
}
void get_rand_keys(vector<uint32_t> &C_0_TO_subhammdis, vector<pair<uint64_t, uint64_t>> &full_index, vector<pair<uint64_t, uint64_t>> &test_pool, int is_invalid_q)
{
    srand(time(NULL));
    uint64_t tmp_key[2] = {0}, tmp_key2[2] = {0};
    uint32_t tmp_subkey;
    full_index.clear();
    int j = 0, batch_size = 530, nums = floor(1.0 * test_data_len / batch_size);
    pair<uint64_t, uint64_t> tmp;
    if (!is_invalid_q)
    {
        nums = (nums < 1000 ? nums : 1000);
        for (int t = 0; t < nums; t++)
        {
            random_128(tmp_key);
            tmp.first = tmp_key[0];
            tmp.second = tmp_key[1];
            full_index.push_back(tmp);
            test_pool.push_back(tmp);
            // full_index[j].fullkey[0] = tmp_key[0];
            // full_index[j].fullkey[1] = tmp_key[1];
            // test_pool.push_back({tmp_key[0], tmp_key[1]});
            // full_index[j].identifier = j;
            j++;
        }
        for (int i = 0, j = test_pool.size(); i < j; i++)
        {
            tmp_key[0] = test_pool[i].first;
            tmp_key[1] = test_pool[i].second;
            uint64_t mask;
            for (auto &val : C_0_TO_subhammdis)
            {
                tmp_key2[0] = 0;
                tmp_key2[1] = 0;
                // full_index[j].fullkey[0] = 0;
                // full_index[j].fullkey[1] = 0;
                for (int i = 0; i < 4; i++)
                {
                    mask = 0xffffffffULL;
                    tmp_key2[i & 1] |= ((mask << 32 * (i >> 1)) & (tmp_key[i & 1] ^ ((uint64_t)val << 32 * (i >> 1)))); // ((uint32_t)(tmp_key[i & 2] >> (32 * (i >> 1))) ^ val) << (32 * (i >> 1)); //
                    // full_index[j].fullkey[i & 1] |= ((mask << 32 * (i >> 1)) & (tmp_key[i & 1] ^ ((uint64_t)val << 32 * (i >> 1)))); // ((uint32_t)(tmp_key[i & 2] >> (32 * (i >> 1))) ^ val) << (32 * (i >> 1)); //
                }
                tmp.first = tmp_key2[0];
                tmp.second = tmp_key2[1];
                full_index.push_back(tmp);
                // j++;
            }
            tmp_key[0] = 0;
            tmp_key[1] = 0;
        }

        for (int t = full_index.size(); t < test_data_len; t++)
        {
            tmp_key[0] = 0;
            tmp_key[1] = 0;
            for (int i = 0; i < 4; i++)
            {
                random_32(&tmp_subkey);
                tmp_key[(i & 2) >> 1] |= ((uint64_t)tmp_subkey) << (32 * (i & 1));
            }
            tmp.first = tmp_key[0];
            tmp.second = tmp_key[1];
            full_index.push_back(tmp);
            // tmp_key[0] = (((uint64_t)t << 32) | (uint64_t)t);
            // tmp_key[1] = (((uint64_t)t << 32) | (uint64_t)t);
            // // random_128(tmp_key);
            // full_index[j].fullkey[0] = tmp_key[0];
            // full_index[j].fullkey[1] = tmp_key[1];
            // // full_index[j].identifier = j;
            // j++;
        }
        printf("full_index.size(): %d test %d\n", full_index.size(), test_data_len);
    }
    else
    {
        j = 0;
        unordered_set<uint32_t> is_exist[4];
        uint32_t sub[4];
        for (int i = 0; i < 1000; i++)
        {
            random_128(tmp_key);
            test_pool.push_back({tmp_key[0], tmp_key[1]});
            get_sub_fingerprint(sub, tmp_key);
            for (auto &val : C_0_TO_subhammdis)
            {
                for (int t = 0; t < 4; t++)
                {
                    tmp_subkey = sub[t] ^ val;
                    is_exist[t].insert(tmp_subkey);
                }
            }
        }
        full_index.clear();
        while (full_index.size() < test_data_len)
        {
            tmp_key[0] = 0;
            tmp_key[1] = 0;
            for (int i = 0; i < 4; i++)
            {
                do
                {
                    random_32(&tmp_subkey);
                } while (is_exist[i].find(tmp_subkey) != is_exist[i].end());
                tmp_key[(i & 2) >> 1] |= (((uint64_t)tmp_subkey) << (32 * (i & 1)));
            }
            tmp.first = tmp_key[0];
            tmp.second = tmp_key[1];
            full_index.push_back(tmp);
        }
        printf("full_index.size(): %d test %d\n", full_index.size(), test_data_len);
    }

    // uint32_t sub[4];
    // for (int i = 0; i < test_pool.size(); i++)
    // {
    //     tmp_key[0] = test_pool[i].first;
    //     tmp_key[1] = test_pool[i].second;
    //     get_sub_fingerprint(sub, tmp_key);
    //     printf("full_index[%d]: %x %x %x %x\n", i, sub[0], sub[1], sub[2], sub[3]);
    // }
}