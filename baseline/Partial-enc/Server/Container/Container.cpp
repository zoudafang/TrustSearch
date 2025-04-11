#include "Container.h"
#include <cstdarg>
#define KNRM "\x1B[0m"
#define KRED "\x1B[31m"
#define KGRN "\x1B[32m"
#define KYEL "\x1B[33m"
#define KBLU "\x1B[34m"
#define KMAG "\x1B[35m"
#define KCYN "\x1B[36m"
#define KWHT "\x1B[37m"
// change!!!
// #include "Enclave_t.h"
// #include "../Enclave.h"
#include "stdio.h"
#include <cstdio>
#include <bitset>

uint64_t containers::keybit = 128;
// uint64_t containers::hammdist = 8;
// uint64_t containers::sub_index_num = 4;
uint32_t containers::test_size = 1000;
uint32_t containers::initialize_size = 0;
uint32_t hash_seed[4]{0x12345678, 0x23456789, 0x34567890, 0x45678901};

namespace Con
{
	containers cont;
	std::vector<std::pair<uint64_t, uint64_t>> sign_data;
	std::vector<uint32_t> targets_data;
}

containers::containers()
{
	hammdist = 12;
	sub_index_num = SUBINDEX_NUM;
	sub_keybit = ceil((double)keybit / sub_index_num);
	sub_index_plus = keybit - sub_index_num * (sub_keybit - 1);
	fullkey_len = keybit / 32;
	cryptoObj = new CryptoPrimitive(CIPHER_TYPE, HASH_TYPE);

	sub_hammdist = floor((double)hammdist / sub_index_num);
}
void containers::init_index(std::vector<dataItem> &db, int dataset_flag)
{
	Con::cont.db_index.initPartIndex(db, dataset_flag);
};
void containers::partQuery(uint8_t *queryPart, vector<triRes> &result, int dataLen, int hammdist, int client_id)
{
	int dataSize = dataLen;
	EVP_MD_CTX *mdCtx = EVP_MD_CTX_new();
	EVP_CIPHER_CTX *cipherCtx_ = EVP_CIPHER_CTX_new();
	uint8_t *fkey = const_sessionKey;

	uint8_t *PlainPartQuery = reinterpret_cast<uint8_t *>(queryPart);
	cryptoObj->SessionKeyDec(cipherCtx_, PlainPartQuery,
							 dataSize, fkey,
							 PlainPartQuery);

	db_index.changeHammingDist(hammdist, client_id);
	auto candidate = Con::cont.db_index.rangeQuery(client_id,
												   PlainPartQuery);
	printf("server_candi %d\n", candidate.size());
	auto ref_res = Con::cont.db_index.verifyCand(client_id,
												 PlainPartQuery, candidate);
	result = std::move(ref_res);
	printf("server_candi %d\n", result.size());
};

containers::~containers()
{
	delete cryptoObj;
}