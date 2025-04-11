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
#include "constVar.h"
#include "util.h"
using namespace std;

class PartEncIndex
{
private:
    int sub_index_num, sub_index_plus, sub_keybit;
    vector<int> hammdist, sub_hamm;

public:
    PartEncIndex();
    vector<dataItem> fullIndex;
    unordered_map<uint32_t, vector<int>> sub_index[SUBINDEX_NUM];

    void initPartIndex(std::vector<dataItem> &db, uint32_t dataSet);
    unordered_set<uint32_t> rangeQuery(int client, uint8_t query[ENC_LEN]);
    vector<triRes> verifyCand(int client_id, uint8_t *query, unordered_set<uint32_t> &cand);
    void changeHammingDist(int hammdist, int client_id);
};

#endif