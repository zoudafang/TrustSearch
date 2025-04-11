#ifndef PARTINDEX
#define PARTINDEX

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <vector>
#include <iostream>
#include <unistd.h>
#include <pwd.h>
#include <unordered_map>
#include <unordered_set>
#include <forward_list>
#include <algorithm>
#include <random>
#include <chrono>
#include "constVar.h"
#include "util.h"
#include <NTL/ZZ.h>
#include "PaillierEnc.h"
#include "crypto.h"
#include <typeinfo>
#include "emp-tool/emp-tool.h"
#include "emp-ot/emp-ot.h"
#include "emp-sh2pc/emp-sh2pc.h"
#include "emp-sh2pc/semihonest.h"
#include "emp-sh2pc/sh_party.h"

using namespace emp;
using namespace std;
using namespace NTL;

class PartEncIndex
{
private:
    int sub_index_num, sub_index_plus, sub_keybit;
    vector<int> hammdist, sub_hamm;
    vector<uint8_t> queries;

    ZZ pkN, pkG, skL, skU;
    RandKey rks[3];

    vector<dataItem> fullIndex;
    unordered_map<uint32_t, vector<int>> sub_index[SUBINDEX_NUM];
    unordered_map<uint32_t, forward_list<int>> sub_index_list[SUBINDEX_NUM];

    NetIO *io = nullptr;
    vector<vector<uint8_t>> A_s[SUBINDEX_NUM];
    unordered_map<std::array<uint8_t, RAND_PARAM_LEN>, vector<uint8_t>, ArrayHasher, ArrayEqual> T_s[SUBINDEX_NUM];
    unordered_map<uint32_t, uint32_t> D_j[SUBINDEX_NUM]; // D is for update index; useless for query

public:
    PartEncIndex();
    ~PartEncIndex();

    std::bitset<DATA_LEN> cand_set;
    void initPartIndex(std::vector<dataItem> &db, uint32_t dataSet);
    unordered_set<uint32_t> rangeQuery(int client, uint8_t query[ENC_LEN]);
    vector<triRes> verifyCand(int client_id, uint8_t *query, unordered_set<uint32_t> &cand);
    void changeHammingDist(int hammdist, int client_id);
    void initCryptoIndex(int sub_i);
    vector<uint32_t> query(int client, QueryBuffer qbf, int sub_i, int &is_fetched);
    void test_query();
    vector<uint8_t> getMsgQuery(const uint8_t *fullkey, int sub_i, uint32_t subkey);
    void EncMaskQ(ZZ &fullkeyMask, ZZ &rand, ZZ &randEnc);
    void EncMask(ZZ &fullkeyMask_q, ZZ &rand_cand, ZZ &rand_candEnc);
    void SendHamMsg(ZZ &fullkey);

    void fullkeyRndMask(ZZ &fullkeyMask, ZZ &fullkeyMask_q, ZZ &rand, ZZ &rand_cand, ZZ &randEnc, ZZ &rand_candEnc);

    void init_homo_param(int port, int party);
    void init_query(vector<uint8_t> &queries);
    // calculate the hamming distance of full-feature
    int SHAM(ZZ &fullkeyEnc, ZZ &fullkey_qEnc, ZZ &rand, ZZ &rand_cand, ZZ &randEnc, ZZ &rand_candEnc);
    void getHomo(uint8_t *res);
    void changeHammingDist(uint64_t hammdist, int client_id);
};

#endif