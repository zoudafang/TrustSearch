#ifndef CONTAINER
#define CONTAINER

#include <set>
#include <vector>
#include <iostream>
#include <unordered_map>
#include <unordered_set>
#include <NTL/ZZ.h>
#include "../../include/constVar.h"
#include <utility>
#include "../../include/murmurHash.h"
#include "../../include/PartEncIndex.h"
#include "../../include/cryptoPrimitive.h"
using namespace std;

typedef uint64_t UINT64;
typedef uint8_t UINT8;
#define UINT32_1 ((uint32_t)0x01)

struct information
{
	// uint32_t identifier;
	uint64_t fullkey[2];
	uint16_t location = 111;
};

struct sub_information
{
	uint32_t identifiers;
	uint32_t sub_key;
};

class containers
{
private:
	static uint64_t keybit;
	uint32_t fullkey_len;
	uint64_t hammdist;
	uint64_t sub_index_num;
	uint32_t sub_index_plus;
	uint32_t sub_keybit;
	uint64_t sub_hammdist;
	static uint32_t initialize_size;
	static uint32_t test_size;
	PartEncIndex db_index;

public:
	int successful_num = 0;
	containers();
	~containers();

	CryptoPrimitive *cryptoObj;
	uint32_t bloom_hash_times, uint_size = sizeof(uint32_t);

	void init_index(std::vector<dataItem> &db, int dataset_flag);
	void partQuery(uint8_t *queryPart, vector<triRes> &result, int dataLen, int hammdist, int client_id);
	void init_query(std::vector<uint8_t> &queries);

	void getHomoParam(uint8_t *data);
	void maskQuery(uint8_t *queryItem, uint8_t *result, int query_len, uint64_t hammdist, uint32_t client_id);
};

namespace Con
{
	extern containers cont;
	extern std::vector<std::pair<uint64_t, uint64_t>> sign_data;
	extern std::vector<uint32_t> targets_data;
}

#endif