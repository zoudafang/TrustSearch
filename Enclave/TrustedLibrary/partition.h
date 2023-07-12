#include<set>
#include<vector>
#include<iostream>
#include<unordered_map>
#include<unordered_set>
#include "Enclave_t.h"
#include "../Enclave.h"
#include <queue>
#include <cstdint>

using namespace std;

struct information
{
	// uint32_t identifier;
	uint64_t fullkey[2];
	uint16_t location=111;
};


class  skewed_partition{
public:
	vector<information> full_index;
	uint32_t dimension[128];
	void set_skewed_partition(unordered_map<uint32_t,information> &skewed_partition);
    void make_partition(vector<uint32_t> &dims);
	uint32_t get_dimension(information info,uint32_t dim);
};