

#include "../include/PartEncIndex.h"

void PartEncIndex::initPartIndex(std::vector<dataItem> &db, uint32_t dataSet)
{
    printf("init index\n");
    uint32_t sub[SUBINDEX_NUM];
    uint8_t *plain_data;
    for (int i = 0; i < db.size(); i++)
    {
        auto &val = db[i];
        plain_data = val.fullkey + ENC_LEN;
        split(sub, plain_data, sub_index_num, sub_index_plus, sub_keybit);
        for (int j = 0; j < SUBINDEX_NUM; j++)
        {
            this->sub_index[j][sub[j]].push_back(i);
        }
    }
    for (int i = 0; i < SUBINDEX_NUM; i++)
        printf("sub_index: %d \n", this->sub_index[i].size());
    this->fullIndex = std::move(db);
    printf("total_len: %d \n", this->fullIndex.size());
};

PartEncIndex::PartEncIndex()
{
    hammdist.resize(MAX_CLIENT_NUM);
    sub_hamm.resize(MAX_CLIENT_NUM);

    hammdist[0] = 8;
    sub_index_num = SUBINDEX_NUM;
    sub_keybit = ceil((double)PLAIN_BIT / sub_index_num);
    sub_index_plus = PLAIN_BIT - sub_index_num * (sub_keybit - 1);

    // for (int j = 0; j < sub_index_num; j++)
    sub_hamm[0] = floor((double)hammdist[0] / sub_index_num);
};

void PartEncIndex::changeHammingDist(int hammdist, int client_id)
{
    if (this->hammdist.size() <= client_id)
    {
        this->hammdist.resize(client_id + 100);
        this->sub_hamm.resize(client_id + 100);
    }

    this->hammdist[client_id] = hammdist;
    sub_hamm[client_id] = floor((double)hammdist / sub_index_num);
};

unordered_set<uint32_t> PartEncIndex::rangeQuery(int client, uint8_t query[PLAIN_LEN])
{
    unordered_set<uint32_t> candidate;
    int curb = 0;
    int power[100];
    int query_mask;
    uint32_t sub[SUBINDEX_NUM];
    split(sub, query, sub_index_num, sub_index_plus, sub_keybit);

    for (int i = 0; i < SUBINDEX_NUM; i++)
    {
        if (i < sub_index_plus)
            curb = sub_keybit;
        else
            curb = sub_keybit - 1;

        {
            query_mask = sub[i];
            auto fg = sub_index[i].find(query_mask);
            if (fg != sub_index[i].end())
            {
                for (auto &val : fg->second)
                {
                    candidate.emplace_hint(candidate.end(), val);
                }
            }
        }
        for (int h = 1; h <= sub_hamm[client]; h++)
        {
            int s = h;
            uint32_t bitstr = 0; // the bit-string with s number of 1s
            for (int i = 0; i < s; i++)
                power[i] = i;    // power[i] stores the location of the i'th 1
            power[s] = curb + 1; // used for stopping criterion (location of (s+1)th 1)

            int bit = s - 1; // bit determines the 1 that should be moving to the left

            while (true)
            { // the loop for changing bitstr
                if (bit != -1)
                {
                    bitstr ^= (power[bit] == bit) ? (uint32_t)1 << power[bit] : (uint32_t)3 << (power[bit] - 1);
                    power[bit]++;
                    bit--;
                }
                else
                {
                    // printf("%x ,", bitstr);
                    query_mask = sub[i] ^ bitstr;
                    auto fg = sub_index[i].find(query_mask);
                    if (fg != sub_index[i].end())
                    {
                        for (auto &val : fg->second)
                        {
                            candidate.emplace_hint(candidate.end(), val);
                        }
                    }
                    while (++bit < s && power[bit] == power[bit + 1] - 1)
                    {
                        bitstr ^= (uint32_t)1 << (power[bit] - 1);
                        power[bit] = bit;
                    }
                    if (bit == s)
                        break;
                }
            }
        }
    }
    return std::move(candidate);
};
static uint32_t candi = 0, resN = 0;
// vector<triRes> PartEncIndex::verifyCand(int client_id, uint8_t *query, unordered_set<uint32_t> &cand)
// {
//     vector<triRes> res;
//     uint32_t hamm = hammdist[client_id], tmp_dis;
//     dataItem dtm;
//     uint8_t encPart[ENC_LEN];
//     triRes tmp;
//     for (auto &val : cand)
//     {
//         dtm = fullIndex[val];
//         tmp_dis = calDistance(dtm.fullkey + ENC_LEN, query, PLAIN_LEN);
//         if (tmp_dis <= hamm)
//         {
//             printf("%d %d \n", dtm.id, tmp_dis);
//             // #if PLAIN_BIT < 128
//             memcpy(tmp.res + ID_DIS_LEN, dtm.fullkey, ENC_LEN);
//             // #endif
//             *((uint32_t *)tmp.res) = dtm.id;
//             *(uint32_t *)(tmp.res + ID_LEN) = tmp_dis;
//             res.emplace_back(tmp);
//         }
//     }
//     candi += cand.size(), resN += res.size();
//     printf("size sc %d res %d\n", candi, resN);
//     return std::move(res);
// };

vector<triRes> PartEncIndex::verifyCand(int client_id, uint8_t *query, vector<uint32_t> &cand)
{
    vector<triRes> res;
    uint32_t hamm = hammdist[client_id], tmp_dis;
    dataItem dtm;
    uint8_t encPart[ENC_LEN];
    triRes tmp;
    res.push_back(tmp);
    for (auto &val : cand)
    {
        dtm = fullIndex[val];
        tmp_dis = calDistance(dtm.fullkey + ENC_LEN, query, PLAIN_LEN);
        if (tmp_dis <= hamm)
        {
            // printf("%d %d \n", dtm.id, tmp_dis);
            // #if PLAIN_BIT < 128
            memcpy(tmp.res + ID_DIS_LEN, dtm.fullkey, ENC_LEN);
            // #endif
            *((uint32_t *)tmp.res) = dtm.id;
            *(uint32_t *)(tmp.res + ID_LEN) = tmp_dis;
            res.emplace_back(tmp);
        }
    }
    *(uint32_t *)res.front().res = (res.size() - 1); // 在第一个位置存储res的个数，主要是为了记录ssl传输的数组有效长度，ssl每次传递N大小的数据
    candi += cand.size(), resN += res.size();
    printf("size sc %d res %d\n", candi, resN);
    return std::move(res);
};