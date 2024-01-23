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
#include "Enclave_t.h"
#include "../Enclave.h"
#include <bitset>
#include "sgx_trts.h"
#include "stdio.h"
#include <cstdio>
#include <bitset>

uint64_t containers::keybit = 128;
// uint64_t containers::hammdist = 16;
// uint64_t containers::sub_index_num = 4;
uint32_t containers::test_size = 1000;
uint32_t containers::initialize_size = 450000;
uint32_t containers::sub_map_size = 4500;

// void log(const char *file_name, const char *function_name, size_t line, const char *fmt, ...) {
// #ifdef DEBUG
//     va_list args;
//     va_start(args, fmt);
//     fprintf(stdout, KGRN "[%s:%zu @ %s]: %s", file_name, line, function_name, KWHT);
//     vfprintf(stdout, fmt, args);
//     fprintf(stdout, "\n");
//     fflush(stdout);
// #endif
// }

// void error_msg(const char *file_name, const char *function_name, size_t line, const char *fmt, ...) {
//     va_list args;
//     va_start(args, fmt);
//     fprintf(stdout, KRED "[ERROR] [%s:%zu @ %s]: %s", file_name, line, function_name, KWHT);
//     vfprintf(stdout, fmt, args);
//     fprintf(stdout, "\n");
//     fflush(stdout);
// }
// void M_Assert(const char *expr_str, bool expr, const char *file, int line, const char *msg, ...) {
//     if (!expr) {
//         fprintf(stderr, KRED "Assert failed:\t");
//         va_list args;
//         va_start(args, msg);
//         vfprintf(stderr, msg, args);
//         fprintf(stderr, "\nExpected: %s\n", expr_str);
//         fprintf(stderr, "At Source: %s:%d\n", file, line);
//         abort();
//     }
// }

namespace
{
	containers cont;
	std::vector<std::pair<uint64_t, uint64_t>> sign_data;
	std::vector<uint32_t> targets_data;
	static long long total_time = 0;
	static long long find_time = 0;
	static long long insert_time = 0;
	static long long verify_time = 0;

	long long bd_time[6];
	uint64_t *times = new uint64_t[2];
	uint32_t resize_times = 0;
	uint64_t resize_size = 0, candi_num = 0;
	uint32_t hash_seed[4]{0x12345678, 0x23456789, 0x34567890, 0x45678901};

	long long times_[5] = {0};
}

void get_times(int begin, int i)
{
	if (begin)
	{
		// ocall_get_timeNow(times);
	}
	else
	{
		// ocall_get_timeNow(times + 1);
		bd_time[i] += times[1] - times[0];
		*times = *(times + 1);
	}
}
containers::containers()
{
	hammdist.resize(MAX_CLIENT_NUM);
	sub_hammdist.resize(MAX_CLIENT_NUM);

	hammdist[0] = 8;
	sub_index_num = SUBINDEX_NUM;
	sub_keybit = ceil((double)keybit / sub_index_num);
	sub_index_plus = keybit - sub_index_num * (sub_keybit - 1);
	// sub_hammdist=hammdist/sub_index_num;
	fullkey_len = keybit / 32;

	// for (int j = 0; j < sub_index_num; j++)
	sub_hammdist[0] = floor((double)hammdist[0] / sub_index_num);

	// the sum of sub_hammdist is hammdist - sub_index_num + 1
	// for (int j = hammdist; j > 0;)
	// {
	// 	for (int i = 0; i < sub_index_num; i++)
	// 	{
	// 		if (j <= 0)
	// 			break;
	// 		sub_hammdist[i]++; // if hammdist=8,sub_hammdist={2,1,1,1}
	// 		j--;
	// 	}
	// }
}
bool customCompare_fullkey(const info_uncomp &p1, const info_uncomp &p2)
{
	if (p1.fullkey[0] < p2.fullkey[0])
	{
		return true;
	}
	else if (p1.fullkey[0] == p2.fullkey[0])
	{
		if (p1.fullkey[1] < p2.fullkey[1])
			return true;
		else if (p1.fullkey[1] == p2.fullkey[1])
		{
			return p1.identify < p2.identify;
		}
		else
			return false;
	}
	return false;
}
bool compareFirst_fullkey(const info_uncomp &p, info_uncomp &x)
{
	if (p.fullkey[0] < x.fullkey[0])
		return true;
	else if (p.fullkey[0] == x.fullkey[0])
		return p.fullkey[1] < x.fullkey[1];
}
uint32_t mask = 0xffffffff;
bool customCompare(const sub_information &p1, const sub_information &p2)
{
	if ((p1.sub_key) != (p2.sub_key))
	{
		return (p1.sub_key) < (p2.sub_key);
	}
	// std::hash<uint32_t> ishash;
	// if (ishash(p1.sub_key) != ishash(p2.sub_key))
	// {
	// 	return ishash(p1.sub_key) < ishash(p2.sub_key);
	// }
	if (p1.sub_key < p2.sub_key)
	{
		return true;
	}
	else if (p1.sub_key == p2.sub_key)
	{
		return p1.identifiers < p2.identifiers;
	}
	return false;
}
bool compareFirst(const sub_information &p, uint32_t x)
{
	if ((p.sub_key) != (x))
	{
		return (p.sub_key) < (x);
	}
	// std::hash<uint32_t> ishash;
	// if (ishash(p.sub_key) != ishash(x))
	// {
	// 	return ishash(p.sub_key) < ishash(x);
	// }
	return p.sub_key < x;
}
bool customCompare_comp(const sub_info_comp &p1, const sub_info_comp &p2)
{
	if (p1.sub_key != p2.sub_key)
	{
		return p1.sub_key < p2.sub_key;
	}
	else if (p1.sub_key == p2.sub_key)
	{
		return p1.skiplen < p2.skiplen;
	}
	return false;
}
bool compareFirst_comp(const sub_info_comp &p, uint32_t x)
{
	if ((p.sub_key) != (x))
	{
		return (p.sub_key) < (x);
	}
	// std::hash<uint32_t> ishash;
	// if (ishash(p.sub_key) != ishash(x))
	// {
	// 	return ishash(p.sub_key) < ishash(x);
	// }
	return p.sub_key < x;
}
void containers::random_128(uint64_t *temp_key)
{
	unsigned char rand[16] = {0};
	sgx_read_rand(rand, 16);
	temp_key[0] = (uint64_t)rand[0];
	for (int i = 1; i < 8; i++)
	{
		temp_key[0] = temp_key[0] << 8;
		temp_key[0] = temp_key[0] + (uint64_t)rand[i];
	}
	temp_key[1] = (uint64_t)rand[8];
	for (int j = 1; j < 8; j++)
	{
		temp_key[1] = temp_key[1] << 8;
		temp_key[1] = temp_key[1] + (uint64_t)rand[j + 8];
	}
}
void containers::get_sub_fingerprint32(uint32_t *sub_fingerprint, uint64_t *fingerprint)
{
	sub_fingerprint[0] = fingerprint[0] & 0xffffffff;
	fingerprint[0] = fingerprint[0] >> 32;
	sub_fingerprint[1] = fingerprint[0] & 0xffffffff;

	sub_fingerprint[2] = fingerprint[1] & 0xffffffff;
	fingerprint[1] = fingerprint[1] >> 32;
	sub_fingerprint[3] = fingerprint[1] & 0xffffffff;
}
void containers::get_full_fingerprint32(uint64_t *fingerprint, uint32_t *sub_fingerprint)
{
	fingerprint[0] = (uint64_t)sub_fingerprint[0];
	fingerprint[0] = fingerprint[0] | (((uint64_t)sub_fingerprint[1]) << 32);

	fingerprint[1] = (uint64_t)sub_fingerprint[2];
	fingerprint[1] = fingerprint[1] | ((uint64_t)sub_fingerprint[3] << 32);
}
uint32_t containers::random_uuid()
{
	static uint32_t id = 0U;
	id++;
	return id;
}
void containers::prepare(uint32_t sub_hammdist, vector<uint32_t> &C_0_TO_subhammdis)
{
	LOGGER("Prepare");
	int tmp1, tmp2, tmp3, tmp4 = 1;
	int tmp = 0;
	uint32_t tmpx = 0;
	switch (sub_hammdist)
	{
	case 5:
		for (int a = 0; a < sub_keybit - 4; a++)
		{
			tmp1 = 0x0000000000000001 << a;
			for (int b = 1 + a; b < sub_keybit - 3; b++)
			{
				tmp2 = 0x0000000000000001 << b;
				for (int c = 1 + b; c < sub_keybit - 2; c++)
				{
					tmp3 = 0x0000000000000001 << c;
					for (int d = 1 + c; d < sub_keybit - 1; d++)
					{
						tmp4 = 0x0000000000000001 << d;
						for (int e = 1 + d; e < sub_keybit; e++)
						{
							tmp = 0x0000000000000001 << e;
							tmp += tmp1 + tmp2 + tmp3 + tmp4;
							tmpx = (uint32_t)tmp;
							C_0_TO_subhammdis.push_back(tmpx);
						}
					}
				}
			}
		}
		break;
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
		break;
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
		break;
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
		break;
	case 1:
		for (int x = 0; x < sub_keybit; x++)
		{
			tmp = 0x0000000000000001 << x;
			tmpx = (uint32_t)tmp;
			C_0_TO_subhammdis.push_back(tmpx);
		}
		break;
	case 0:
	{
		C_0_TO_subhammdis.push_back(0);
		break;
	}
	default:
		break;
	}
}
void testHash()
{
	uint32_t tmp[3] = {1, 2, 3};
	uint8_t out[32];
	sha256_digest(reinterpret_cast<const unsigned char *>(tmp), sizeof(tmp), out);
	// for(int i=0;i<32;i++){
	// 	printf("%x\n",out[i]);
	// }
}
void containers::initialize()
{
	// testHash();
	uint64_t temp_key[2] = {0};
	uint32_t out_id = 0;
	uint32_t sub[4] = {0};
	information temp_information;
	uint32_t data_len;
	if (!dataSet)
	{
		data_len = DATA_LEN;
	}
	else
	{
		data_len = SIFT_LEN;
	}
	// full_key_sorted.reserve(DATA_LEN);
	containers::initialize_size = data_len;
	// full_key_sorted.reserve(data_len);
	// full_index.reserve(6000000);
	// sub_index_liner = new vector<sub_information>[SUBINDEX_NUM];
	// for (int i = 0; i < SUBINDEX_NUM; i++)
	// 	sub_index_liner[i].reserve(initialize_size);

	containers::sub_map_size = initialize_size / 2000; // initialize_size//1500,2500,1000
	for (int i = 0; i < 4; i++)
	{
		lru_n[i] = lru_node{sub_map_size, 0, nullptr, nullptr};
		sub_index_node *head1 = new sub_index_node;
		lru_n[i].index_head = head1;
		lru_n[i].index_tail = head1;
		sub_index_node node_temp{0, 0, nullptr, nullptr};
		new_data_head[i] = new sub_index_node{0, 0, nullptr, nullptr};
	}
	sub_information sub_info[4];

	for (int j = 0; j < sub_index_num; j++)
		inc_max_dist[j] = 2;
	// bloom_parameters parameters;
	// parameters.projected_element_count = SUBINDEX_NUM * 1000000; // 预计插入initialize_size个元素 //cautious
	// parameters.false_positive_probability = 0.1;				 // 期望的误判率为0.1 cautious
	// parameters.compute_optimal_parameters();					 // 计算最优参数
	// parameters.random_seed = 0xA5A5A5A5;
	// bloom_hash_times = parameters.optimal_parameters.number_of_hashes;
	// printf("bloom_hash_times=%d\n", bloom_hash_times);
	// // for (int i = 0; i < 4; i++)
	// filters = bloom_filter(parameters);

	cryptoObj = new EcallCrypto(CIPHER_TYPE, HASH_TYPE);
	// EVP_MD_CTX *mdCtx = EVP_MD_CTX_new();
	// EVP_CIPHER_CTX *cipherCtx_ = EVP_CIPHER_CTX_new();
	uint8_t *dataKey_ = const_dataKey;
	// tmp_ids_block = new uint8_t[1024 * 300];

	ids_node *entry = new ids_node();
	entry->next = nullptr;
	entry->pre = nullptr;
	lru_cache.index_head = entry;
	lru_cache.index_tail = entry;
	// lru_cache.capacity = 5000;
	// exist_ids = new ids_node[lru_cache.capacity];
	lru_cache.len = 0;

	// delete cryptoObj;
	return;
}
void containers::get_test_pool()
{
	// 从测试集获取test pool数据
	uint32_t index1 = 0;
	uint32_t end = tmp_test_pool.size();
	while (test_pool.size() < test_size && end > 0)
	{
		index1++;
		sgx_read_rand(reinterpret_cast<unsigned char *>(&index1), sizeof(index1));
		index1 %= end;
		test_pool.push_back(tmp_test_pool[index1]);
		// test_targets.push_back(tmp_test_targets[index1]);
		auto tmp = tmp_test_pool[index1];
		// tmp_test_pool[index1] = tmp_test_pool[end - 1];
		// // tmp_test_targets[index1] = tmp_test_targets[end - 1];
		// end--;
	}

	uint64_t temp_key[2] = {0};
	uint32_t begin = 0, index = 0; // begin:the first index of test
	uint32_t skip = 1;			   // skip query

	// initialize_size = full_index.size();
	uint32_t range = initialize_size; // range query
	sgx_read_rand(reinterpret_cast<unsigned char *>(&begin), sizeof(begin));

	// // for temporal Locality
	// vector<uint32_t> local_list;
	// uint32_t temp;
	// for (int i = 0; i < 100; i++)
	// {
	// 	sgx_read_rand(reinterpret_cast<unsigned char *>(&temp), sizeof(temp));
	// 	local_list.push_back(temp % initialize_size);
	// }

	// for (int i = 0; i < initialize_size; i++)
	// {
	// 	if (test_pool.size() >= test_size)
	// 	{
	// 		return;
	// 	}
	// 	index = (begin + (i * skip) % range);
	// 	if (i % 20 == 0)
	// 	{
	// 		// sgx_read_rand(reinterpret_cast<unsigned char *>(&begin), sizeof(begin));
	// 	}																		 // space locality
	// 	sgx_read_rand(reinterpret_cast<unsigned char *>(&index), sizeof(index)); // rand query
	// 	// index=local_list[index%local_list.size()];//temporal locality
	// 	index = index % initialize_size;
	// 	// auto it = full_index[index];
	// 	auto it = full_key_sorted[index];
	// 	temp_key[0] = it.fullkey[0];
	// 	temp_key[1] = it.fullkey[1];
	// 	int h = 0, y = 0;
	// 	uint64_t t = 1;
	// 	unsigned char rand[3] = {0};
	// 	sgx_read_rand(rand, 2);
	// 	h = rand[0] % 3;
	// 	for (int i = 0; i < h; i++)
	// 	{
	// 		y = rand[i + 1] % 64;
	// 		temp_key[0] = temp_key[0] ^ (t << y);
	// 		temp_key[1] = temp_key[1] ^ (t << y);
	// 	}
	// 	test_pool.push_back(pair<uint64_t, uint64_t>(temp_key[0], temp_key[1]));
	// }
}
int zero_num = 0;

int times_gen = 0, combs = 0, combs_hit = 0, find_clrs_num = 0;
std::vector<uint32_t> containers::find_sim(uint64_t query[], uint32_t tmp_test_target, int client_id) // ocall_get_timeNow
{
	uint64_t *total_time_now = new uint64_t[1];
	long long total_begin_time = 0, total_end_time = 0;
	// ocall_get_timeNow(total_time_now);
	total_begin_time = *total_time_now;

	unordered_set<uint32_t> candidate;
	std::unordered_map<uint32_t, int> reached_subkey;

	candidate.clear();
	candidate.reserve(50000);
	uint64_t tmpquery[2] = {0};
	tmpquery[0] = query[0];
	tmpquery[1] = query[1];
	uint32_t sub[SUBINDEX_NUM] = {0};

	split(sub, reinterpret_cast<uint8_t *>(tmpquery), sub_index_num, sub_index_plus, sub_keybit);
	// get_sub_fingerprint32(sub, tmpquery);

	uint32_t *out_tmp = out;
	uint32_t tmpsub1, tmpsub2, tmpsub3, tmpsub4 = 0;
	vector<uint32_t> temp;
	// tsl::hopscotch_map<uint32_t, std::vector<uint32_t>>::iterator got;
	unordered_map<uint32_t, std::vector<uint32_t>>::iterator got;

	vector<fetch_ids_node> visited_keys; // first: subkeys of candidates, second: begin index of sub_identifiers
	sub_info_comp tmp_info;

	static uint64_t bloomHit = 0;
	static uint64_t bloomMiss = 0;
	static int num = 0;
	static int hitmap = 0;
	static int hitliner = 0;
	static int mapsize = 0;
	static int linersize = 0;
	uint64_t *time = new uint64_t[1];
	long long begin_time, end_time;
	static int loopBegin = 0;
	static int times = 0;
	static int line_times = 0;
	static int hittt = 0;
	static int misss = 0;
	int out_key[1], sub_key_I[2];
	uint32_t tmp_hash[2], hash_size = ((bloom_hash_times >> 2) + (bloom_hash_times & 0x3 != 0) * 4) * INT_SIZE; // ceil(times/4)*4
	uint8_t tmp_hash_out[32], bloom_hash[hash_size];
	static uint32_t candiNUM = 0;

	vector<key_find> existed_subkeys;
	vector<cluster_info> tmp_clrs, bigger_clrs, mid_clrs; // xx;hamm+dist;hamm+dist-1
	cluster_info c_info;
	unordered_set<uint32_t> visited_subkeys;
	int begin_ids = 0, dt;
	uint32_t tmp_dist = 0, tmp_count, tmp_min_idx, min_dist;
	uint32_t begin_idx, end_idx, lookup_all_size = 0, lookup_radius;

	for (int i = 0; i < SUBINDEX_NUM; i++)
	{
		// ocall_get_timeNow(time);
		begin_time = *time;

		lookup_all_size = 0;
		lookup_radius = sub_hammdist[client_id] + max_dist;
		// get_times(1, 0);
		tmp_dist = 0;
		dt = 0;
		tmp_visit.clear();
		// printf("reach size %d\n", reached_subkey.size());
		reached_subkey.clear();
		existed_subkeys.clear();
		tmp_clrs.clear();
		bigger_clrs.clear();
		mid_clrs.clear();
		visited_keys.clear();

		min_dist = UINT16_MAX;
		// find the near clusters that may contains the subkey; hamming(subkey, query_sub_key) <= sub_hamm[i]
		// based on triangular inequality
		for (int t = 0; t < clr[i].size() - 1; t++)
		{
			begin_idx = clr[i][t].begin_idx;
			end_idx = clr[i][t + 1].begin_idx;
			tmp_dist = popcount(sub[i] ^ clr[i][t].subkey);
			lookup_all_size += end_idx - begin_idx;

			c_info.node = clr[i][t];
			c_info.end = end_idx;
			c_info.dist = tmp_dist;
			if (tmp_dist > sub_hammdist[client_id] + max_dist - 2) //- 2 -1
			{
				if (tmp_dist == sub_hammdist[client_id] + max_dist - 1)
				{
					mid_clrs.push_back(c_info);
				}
				else if (tmp_dist == sub_hammdist[client_id] + max_dist)
				{
					bigger_clrs.push_back(c_info);
					// for dist == hammdist+max_dist; it must only contains subkey whose hamm dist from cluster equals max_dist, and dist from subkey equals sub_hamm;
					// so bigger_clrs's all dist is max_dist
				}
				continue;
			}
			// if (min_dist > c_info.dist)
			// {
			// 	min_dist = c_info.dist;
			// 	tmp_min_idx = tmp_clrs.size();
			// }
			// if (c_info.dist == 0)
			// {
			// 	zero_num++;
			// }
			tmp_clrs.push_back(c_info);
		}

		min_dist = UINT16_MAX;
		if (tmp_clrs.size())
		{
			std::sort(tmp_clrs.begin(), tmp_clrs.end(), [](cluster_info &a, cluster_info &b)
					  { if(a.dist!=b.dist)return a.dist < b.dist;else return a.node.begin_idx < b.node.begin_idx; });
			min_dist = tmp_clrs[0].dist;
		}
		// min_dist = (tmp_clrs.size() > 0 ? tmp_clrs[0].dist : UINT16_MAX);
		cluster_node tmp_node;

		c_info.node = clr[i][clr[i].size() - 1];
		c_info.end = sub_linear_comp[i].size();
		c_info.dist = 0; // popcount(sub[i] ^ clr[i][clr[i].size() - 1].subkey);
		tmp_clrs.push_back(c_info);
		uint32_t tmpkey = sub[i];

		for (int t = 0; t < bloom_hash_times; t += 4)
		{
			tmp_hash[0] = sub[i];
			tmp_hash[1] = i + t * sub_index_num * 2;
			MurmurHash3_x86_128(tmp_hash, 8, hash_seed[0], bloom_hash + t * INT_SIZE);
			// memcpy(bloom_hash + t * INT_SIZE, tmp_hash_out, std::min(bloom_hash_times - t, (uint32_t)4) * INT_SIZE);
		}
		if (filters->contains(bloom_hash, bloom_hash_times * INT_SIZE)) // filters.contains(bloom_hash, bloom_hash_times * INT_SIZE)
		{
			if (sub_hammdist[client_id] <= 1 && tmp_clrs.size() == 1 && mid_clrs.size()) // tmp-clrs只有stash，可以从bigger里面查找
			{
				tmp_node = mid_clrs[0].node;
				begin_idx = tmp_node.begin_idx;
				end_idx = mid_clrs[0].end;
				auto its = std::lower_bound(sub_linear_comp[i].begin() + begin_idx, sub_linear_comp[i].begin() + end_idx, tmpkey, compareFirst_comp);
				if (its < (sub_linear_comp[i].begin() + end_idx) && (its->sub_key == tmpkey || its->length & MASK_INF)) //&& its->sub_key == tmpsub1
				{
					key_find kf{0, 0, 0};
					// visited_keys.push_back(sub_info_comp{tmpsub1, its->skiplen, its->length});
					gen_candidate(kf, candidate, {tmpkey, its->skiplen, its->length}, tmp_visit, i, sub[i], dt + 1, its->sub_key);
				}
			}
			else if (sub_hammdist[client_id] <= 0 && tmp_clrs.size() == 1 && bigger_clrs.size()) // tmp-clrs只有stash，可以从bigger里面查找
			{
				for (int id = 0; id < 1; id++)
				{
					tmp_node = bigger_clrs[id].node;
					begin_idx = tmp_node.begin_idx;
					end_idx = bigger_clrs[id].end;
					auto its = std::lower_bound(sub_linear_comp[i].begin() + begin_idx, sub_linear_comp[i].begin() + end_idx, tmpkey, compareFirst_comp);
					if (its < (sub_linear_comp[i].begin() + end_idx) && (its->sub_key == tmpkey || its->length & MASK_INF)) //&& its->sub_key == tmpsub1
					{
						key_find kf{0, 0, 0};
						// visited_keys.push_back(sub_info_comp{tmpsub1, its->skiplen, its->length});
						gen_candidate(kf, candidate, {tmpkey, its->skiplen, its->length}, tmp_visit, i, sub[i], dt + 1, its->sub_key);
					}
				}
			}
			else
			{
				if (min_dist > max_dist)
				{
					tmp_min_idx = tmp_clrs.size() - 1;
				}
				else
					tmp_min_idx = 0;
				// for (int t = 0; t < tmp_clrs.size(); t++) // find 0,实际上只需要考虑stash和最近的，因为最近的一定是最小的
				{
					// if (tmp_clrs[t].dist > tmp_clrs[0].dist)
					// 	break;
					// if (tmp_clrs[t].dist > max_dist)
					// {
					// 	t = tmp_clrs.size() - 1;
					// } // cautious
					tmp_node = tmp_clrs[tmp_min_idx].node;
					begin_idx = tmp_clrs[tmp_min_idx].node.begin_idx;
					end_idx = tmp_clrs[tmp_min_idx].end;

					auto its = std::lower_bound(sub_linear_comp[i].begin() + begin_idx, sub_linear_comp[i].begin() + end_idx, tmpkey, compareFirst_comp);
					if (its < (sub_linear_comp[i].begin() + end_idx) && (its->sub_key == tmpkey || its->length & MASK_INF)) //&& its->sub_key == tmpsub1
					{
						key_find kf{0, 0, 0};
						// visited_keys.push_back(sub_info_comp{tmpsub1, its->skiplen, its->length});
						gen_candidate(kf, candidate, {tmpkey, its->skiplen, its->length}, tmp_visit, i, sub[i], dt + 1, its->sub_key);

						// begin_ids = its->length;
						// key_find tmpk{1, 1, 1};
						// if (begin_ids & MASK_SIM)
						// {
						// 	tmp_info = visited_keys.back();
						// 	visited_keys.pop_back();
						// 	gen_candidate(tmpk, candidate, tmp_info, visited_keys, visited_keys, i, sub[i], dt, its->sub_key);
						// 	dt += inc_max_dist[i] //+ 1;
						// }
					}
				}
			}
		}
		dt = 1; // sub[0] is finded
		tmp_clrs.pop_back();
		// get_times(0, 0);

		uint32_t find_max_d = std::min(min_dist + sub_hammdist[client_id], (uint64_t)max_dist), tmp_dist = min_dist; // 这个find-max-d是不是太大了，应该写在mindist增加之前

		for (auto val = tmp_clrs.begin(); val < tmp_clrs.end();)
		{
			tmp_node = val->node;
			begin_idx = val->node.begin_idx;
			end_idx = val->end;																				 // get_search_numbers(sub_keybit,sub_hammdist[i])
			if ((val->dist + max_dist) <= sub_hammdist[client_id] || val->node.group_size < combine_clr_min) // end_idx - begin_idx < 500 (val->dist + max_dist - 1) <= sub_hammdist[i] || val->node.group_size < combine_clr_min
			{
				linear_scan(i, begin_idx, end_idx, sub[i], sub_hammdist[client_id], candidate, reached_subkey);

				// if (!tmp_node.is_combined) //*2的位置错了？//有效，但是无法和combkey=50结合起来//这里的find时间不高&& (end_idx - begin_idx) < existed_subkeys.size() * 2
				// {combine_clr_min
				// 	sub_info_comp tmp;
				// 	for (int k = begin_idx; k < end_idx; k++) // cautious error in it
				// 	{
				// 		tmp = sub_linear_comp[i][k];
				// 		if (popcount(tmp.sub_key ^ sub[i]) <= sub_hammdist[i])
				// 		{
				// 			reached_subkey[tmp.sub_key] = 1;
				// 			visited_keys.push_back({tmp.sub_key, tmp.skiplen, tmp.length});
				// 		}
				// 	}
				val = tmp_clrs.erase(val);
			}
			else
				val++;
		}
		// get_times(0, 3);

		for (int t = dt; t <= sub_hammdist[client_id]; t++)
		{
			for (auto &its : C_0_TO_subhammdis[t])
			{
				tmpsub1 = sub[i] ^ its;
				sub_key_I[0] = tmpsub1, sub_key_I[1] = i;

				for (int j = 0; j < bloom_hash_times; j += 4)
				{
					tmp_hash[0] = tmpsub1;
					tmp_hash[1] = i + j * sub_index_num * 2;
					MurmurHash3_x86_128(tmp_hash, 8, hash_seed[0], bloom_hash + j * INT_SIZE);
					// memcpy(bloom_hash + j * INT_SIZE, tmp_hash_out, std::min(bloom_hash_times - j, INT_SIZE) * INT_SIZE);
				}
				if (filters->contains(bloom_hash, bloom_hash_times * INT_SIZE)) // filters.contains(bloom_hash, bloom_hash_times * INT_SIZE)
				{
					if (reached_subkey.find(tmpsub1) == reached_subkey.end())
					{
						existed_subkeys.push_back(key_find{tmpsub1, (uint16_t)t, (uint16_t)find_max_d});
					}
				}
			}
		}
		// printf("linear size %d exist size %d clr_num%d \n", reached_subkey.size(), existed_subkeys.size(),tmp_clrs.size());
		reached_subkey.clear();
		// get_times(0, 1);

		uint32_t min_dist0 = min_dist;
		// uint32_t find_max_d = std::min(min_dist + sub_hammdist[i], (uint64_t)max_dist), tmp_dist = min_dist; // 这个find-max-d是不是太大了，应该写在mindist增加之前
		min_dist += sub_hammdist[client_id] * 2; // cautious- 1
		find_clrs_num += (tmp_clrs.size() ? tmp_clrs.size() : 1);

		if (min_dist0 + sub_hammdist[client_id] > max_dist)
		{
			lookup_all_size + sub_linear_comp[i].size() - clr[i][clr[i].size() - 1].begin_idx;
		}
		if (1) // lookup_all_size >= (sub_linear_comp[i].size() >> 1) lookup_all_size >= ceil((double)sub_linear_comp[i].size() / 3)
		{
			// search only in nearest cluster
			// for (auto val = tmp_clrs.begin(); val < tmp_clrs.end();)
			// {
			// 	tmp_node = val->node;
			// 	begin_idx = val->node.begin_idx;
			// 	end_idx = val->end;

			// 	if (!tmp_node.is_combined && (end_idx - begin_idx) < existed_subkeys.size() * 2) //*2的位置错了？//有效，但是无法和combkey=50结合起来//这里的find时间不高
			// 	{
			// 		sub_info_comp tmp;
			// 		for (int k = begin_idx; k < end_idx; k++) // cautious error in it
			// 		{
			// 			tmp = sub_linear_comp[i][k];
			// 			if (popcount(tmp.sub_key ^ sub[i]) <= sub_hammdist[i])
			// 			{
			// 				reached_subkey[tmp.sub_key] = 1;
			// 				visited_keys.push_back({tmp.sub_key, tmp.skiplen, tmp.length});
			// 			}
			// 		}
			// 		val = tmp_clrs.erase(val);
			// 	}
			// 	else
			// 		val++;
			// }

			uint32_t max_node = 0;
			// for (; max_node < tmp_clrs.size(); max_node++)
			// {
			// 	if (tmp_clrs[max_node].dist > max_dist)
			// 		break;
			// }
			for (auto tmpc = tmp_clrs.begin(); tmpc != tmp_clrs.end() && tmpc->dist <= (lookup_radius >> 1); tmpc = tmp_clrs.erase(tmpc))
			{
				tmp_node = tmpc->node;
				begin_idx = tmp_node.begin_idx;
				end_idx = tmpc->end;
				for (int j = 0; j < existed_subkeys.size(); j++)
				{
					auto &val = existed_subkeys[j];
					if (val.max_dist == 0)
						continue;

					auto &tmpsub1 = val.subkey;
					// if (val.dist < dt) // if 的次数太多，能否优化  || visited_subkeys.find(tmpsub1) != visited_subkeys.end()
					// 	continue;
					uint16_t tmp = popcount(tmp_node.subkey ^ tmpsub1); // 开销很大？？
					if (tmp > val.max_dist)								// find max太大可省略，是不是小于呢？
						continue;
					val.max_dist = tmp;

					auto its = std::lower_bound(sub_linear_comp[i].begin() + begin_idx, sub_linear_comp[i].begin() + end_idx, tmpsub1, compareFirst_comp);
					if (its != sub_linear_comp[i].end() && (its->sub_key == tmpsub1 || its->length & MASK_INF)) //&& its->sub_key == tmpsub1
					{
						if (its->sub_key == tmpsub1)
						{
							val.max_dist = 0;
							// val.dist = INT16_MAX;
							val.clr_idx = INT16_MAX;
						}
						// visited_keys.push_back(fetch_ids_node{sub_info_comp{tmpsub1, its->skiplen, its->length}, val, its->sub_key});
						gen_candidate(val, candidate, {tmpsub1, its->skiplen, its->length}, tmp_visit, i, sub[i], dt + 1, its->sub_key);
					}
				}

				// get_times(0, 3);
				// for (auto &tmpnode : visited_keys)
				// {
				// 	gen_candidate(tmpnode.kf, candidate, tmpnode.sub_info, tmp_visit, i, sub[i], dt + 1, tmpnode.cache_key);
				// }
				// visited_keys.clear();
				// get_times(0, 4);
			}

			if (tmp_clrs.size())
				std::sort(tmp_clrs.begin(), tmp_clrs.end(), [](cluster_info &a, cluster_info &b)
						  { return a.node.begin_idx < b.node.begin_idx; });
			uint16_t tmp_min = 0, idx = 0, tmp_d;
			uint32_t tmpkey_, max_find_dist;
			for (int x = 0; x < existed_subkeys.size(); x++)
			{
				// if (reached_subkey.find(existed_subkeys[x].subkey) != reached_subkey.end())
				// {
				// 	existed_subkeys[x].max_dist = 0;
				// 	existed_subkeys[x].dist = INT16_MAX;
				// 	continue;
				// }

				if (existed_subkeys[x].clr_idx == INT16_MAX)
					continue;

				tmp_min = UINT8_MAX;
				tmpkey_ = existed_subkeys[x].subkey;
				max_find_dist = min_dist0 + existed_subkeys[x].dist * 2;
				for (int t = 0; t < tmp_clrs.size(); t++)
				{
					if (tmp_clrs[t].dist > max_find_dist)
						continue;
					tmp_d = popcount(tmp_clrs[t].node.subkey ^ tmpkey_);
					if (tmp_d < tmp_min)
					{
						tmp_min = tmp_d;
						idx = t; // cautious
					}
				}

				if (tmp_min <= max_dist)
				{
					existed_subkeys[x].max_dist = tmp_min;
					// existed_subkeys[x].max_dist = 0;//cautious
					// search in tmpclr[idx]
					existed_subkeys[x].clr_idx = idx;
				}
				else
				{
					// search in stash
					existed_subkeys[x].clr_idx = tmp_clrs.size(); // too minor，不要随便乱改字段意义
				}
			}
			c_info.node = clr[i][clr[i].size() - 1];
			c_info.end = sub_linear_comp[i].size();
			c_info.dist = popcount(sub[i] ^ clr[i][clr[i].size() - 1].subkey);
			tmp_clrs.push_back(c_info);

			std::sort(existed_subkeys.begin(), existed_subkeys.end(), [](key_find &a, key_find &b)
					  { return a.clr_idx < b.clr_idx; }); // times too long cautious

			bool flag = true;
			int val_idx = 0;
			for (; val_idx < existed_subkeys.size(); val_idx++) // auto &val : existed_subkeys
			{
				auto &val = existed_subkeys[val_idx];
				// if (reached_subkey.find(val.subkey) != reached_subkey.end())
				// {
				// 	val.max_dist = 0;
				// 	continue;
				// }
				if (val.clr_idx == INT16_MAX)
					continue;

				if (val.clr_idx == tmp_clrs.size() - 1 && flag)
				{
					// get_times(0, 3);
					flag = false;
					break;
					// continue;
				}
				int begin = tmp_clrs[val.clr_idx].node.begin_idx;
				int end = tmp_clrs[val.clr_idx].end;

				auto tmpsub1 = val.subkey;
				auto its = std::lower_bound(sub_linear_comp[i].begin() + begin, sub_linear_comp[i].begin() + end, tmpsub1, compareFirst_comp);
				if (its != sub_linear_comp[i].end() && (its->sub_key == tmpsub1 || its->length & MASK_INF)) //&& its->sub_key == tmpsub1
				{
					if (its->sub_key == tmpsub1)
						val.max_dist = 0;
					// visited_subkeys.insert(its->sub_key); // why must ==? cautious
					++hitliner;
					// visited_keys.push_back(fetch_ids_node{sub_info_comp{tmpsub1, its->skiplen, its->length}, val, its->sub_key});

					// visited_keys.push_back({tmpsub1, its->skiplen, its->length}); // cautious 9-17
					gen_candidate(val, candidate, {tmpsub1, its->skiplen, its->length}, tmp_visit, i, sub[i], dt + 1, its->sub_key);
				}
			}
			// get_times(0, 3);
			// for (auto &tmpnode : visited_keys)
			// {
			// 	gen_candidate(tmpnode.kf, candidate, tmpnode.sub_info, tmp_visit, i, sub[i], dt + 1, tmpnode.cache_key);
			// }
			// visited_keys.clear();
			// get_times(0, 4);

			uint32_t mid_idx, mid_dist;
			for (auto &val : existed_subkeys)
			{
				mid_idx = -1;
				mid_dist = -1;
				tmpsub1 = val.subkey;

				if (val.dist == sub_hammdist[client_id] - 1 && val.max_dist >= max_dist) //!=0
				{
					for (auto &val1 : mid_clrs)
					{
						tmp_node = val1.node;
						begin_idx = tmp_node.begin_idx;
						end_idx = val1.end;
						uint16_t tmp = popcount(tmp_node.subkey ^ tmpsub1); // 开销很大？？
						if (tmp > val.max_dist)								// find max太大可省略，是不是小于呢？
							continue;
						val.max_dist = tmp;

						auto its = std::lower_bound(sub_linear_comp[i].begin() + begin_idx, sub_linear_comp[i].begin() + end_idx, tmpsub1, compareFirst_comp);
						if (its != sub_linear_comp[i].end() && (its->sub_key == tmpsub1 || its->length & MASK_INF)) //&& its->sub_key == tmpsub1
						{
							// if (its->sub_key == tmpsub1)
							// {
							// 	val.max_dist = 0;
							// 	// val.dist = INT16_MAX;
							// 	val.clr_idx = INT16_MAX;
							// }

							// visited_keys.push_back(fetch_ids_node{sub_info_comp{tmpsub1, its->skiplen, its->length}, val, its->sub_key});
							gen_candidate(val, candidate, {tmpsub1, its->skiplen, its->length}, tmp_visit, i, sub[i], dt + 1, its->sub_key);
						}
						val.max_dist = 0; // cautious only stash later
						break;
					}
				}
				else if (val.dist == sub_hammdist[client_id] && val.max_dist >= (max_dist - 1)) //!=0
				{
					for (int t = 0; t < mid_clrs.size(); t++)
					{
						auto &val1 = mid_clrs[t];
						tmp_node = val1.node;
						uint16_t tmp = popcount(tmp_node.subkey ^ tmpsub1); // 开销很大？？
						if (tmp < mid_dist)									// find max太大可省略，是不是小于呢？
						{
							mid_idx = t;
							mid_dist = tmp;
							if (tmp == max_dist - 1)
								break;
						}
					}

					if (mid_dist > max_dist)
						continue;

					tmp_node = mid_clrs[mid_idx].node;
					begin_idx = tmp_node.begin_idx;
					end_idx = mid_clrs[mid_idx].end;
					auto its = std::lower_bound(sub_linear_comp[i].begin() + begin_idx, sub_linear_comp[i].begin() + end_idx, tmpsub1, compareFirst_comp);
					if (its != sub_linear_comp[i].end() && (its->sub_key == tmpsub1 || its->length & MASK_INF)) //&& its->sub_key == tmpsub1
					{
						// if (its->sub_key == tmpsub1)
						// {
						// 	val.max_dist = 0;
						// 	// val.dist = INT16_MAX;
						// 	val.clr_idx = INT16_MAX;
						// }
						// visited_keys.push_back(fetch_ids_node{sub_info_comp{tmpsub1, its->skiplen, its->length}, val, its->sub_key});

						gen_candidate(val, candidate, {tmpsub1, its->skiplen, its->length}, tmp_visit, i, sub[i], dt + 1, its->sub_key);
					}
					val.max_dist = 0; // cautious only stash later
				}
			}
			// get_times(0, 3);
			// for (auto &tmpnode : visited_keys)
			// {
			// 	gen_candidate(tmpnode.kf, candidate, tmpnode.sub_info, tmp_visit, i, sub[i], dt + 1, tmpnode.cache_key);
			// }
			// visited_keys.clear();
			// get_times(0, 4);

			uint32_t bigger_idx = 0;
			for (auto &val : existed_subkeys)
			{
				if (val.dist == sub_hammdist[client_id] && val.max_dist >= max_dist) //!=0
				{
					for (auto &val1 : bigger_clrs)
					{
						auto tmpsub1 = val.subkey;
						tmp_node = val1.node;
						begin_idx = tmp_node.begin_idx;
						end_idx = val1.end;
						uint16_t tmp = popcount(tmp_node.subkey ^ tmpsub1); // 开销很大？？
						if (tmp > val.max_dist)								// find max太大可省略，是不是小于呢？
							continue;
						val.max_dist = tmp;

						auto its = std::lower_bound(sub_linear_comp[i].begin() + begin_idx, sub_linear_comp[i].begin() + end_idx, tmpsub1, compareFirst_comp);
						if (its != sub_linear_comp[i].end() && (its->sub_key == tmpsub1 || its->length & MASK_INF)) //&& its->sub_key == tmpsub1
						{
							// if (its->sub_key == tmpsub1)
							// {
							// 	val.max_dist = 0;
							// 	// val.dist = INT16_MAX;
							// 	val.clr_idx = INT16_MAX;
							// }
							// visited_keys.push_back(fetch_ids_node{sub_info_comp{tmpsub1, its->skiplen, its->length}, val, its->sub_key});

							gen_candidate(val, candidate, {tmpsub1, its->skiplen, its->length}, tmp_visit, i, sub[i], dt + 1, its->sub_key);
						}
						val.max_dist = 0; // cautious only stash later
						break;
					}
				}
			}
			// get_times(0, 3);
			// for (auto &tmpnode : visited_keys)
			// {
			// 	gen_candidate(tmpnode.kf, candidate, tmpnode.sub_info, tmp_visit, i, sub[i], dt + 1, tmpnode.cache_key);
			// }
			// visited_keys.clear();
			// get_times(0, 4);

			// if (flag)
			// 	get_times(0, 3);
			// set before clusters
			uint32_t dt1 = std::max(dt, (int)(max_dist - min_dist0)); // cautious
			if (min_dist0 + sub_hammdist[client_id] > max_dist)
			{
				// min_dist = UINT16_MAX;
				uint32_t idx1 = clr[i].size() - 1;
				begin_idx = clr[i][idx1].begin_idx;
				end_idx = sub_linear_comp[i].size();
				if (begin_idx < end_idx) // cautious for stash==0
				{
					for (; val_idx < existed_subkeys.size(); val_idx++) // auto &val : existed_subkeys
					{
						auto &val = existed_subkeys[val_idx];
						auto &tmpsub1 = val.subkey;					   // why val.dist< is right not <
						if (val.max_dist < max_dist || val.dist < dt1) //|| visited_subkeys.find(tmpsub1) != visited_subkeys.end() val.clr_idx != tmp_clrs.size() - 1 ||
							continue;								   // stash只查max_dist没有减小的,==0表示已经查找到了？？cautious
						// if (reached_subkey.find(tmpsub1) != reached_subkey.end())
						// 	continue;

						auto its = std::lower_bound(sub_linear_comp[i].begin() + begin_idx, sub_linear_comp[i].begin() + end_idx, tmpsub1, compareFirst_comp);
						if (its != sub_linear_comp[i].end() && (its->sub_key == tmpsub1 || its->length & MASK_INF)) //&& its->sub_key == tmpsub1
						{
							if (its->sub_key == tmpsub1)
								val.max_dist = 0;
							// visited_subkeys.insert(its->sub_key); // why must ==? cautious
							++hitliner;
							// visited_keys.push_back({tmpsub1, its->skiplen, its->length}); // cautious 9-17

							// visited_keys.push_back(fetch_ids_node{sub_info_comp{tmpsub1, its->skiplen, its->length}, val, its->sub_key});

							gen_candidate(val, candidate, {tmpsub1, its->skiplen, its->length}, tmp_visit, i, sub[i], dt + 1, its->sub_key);
							// begin_ids = its->length;
							// if (begin_ids & MASK_SIM)
							// {
							// 	tmp_info = visited_keys.back();
							// 	visited_keys.pop_back();
							// 	gen_candidate(candidate, tmp_info, visited_keys, tmp_visit, i, sub[i], val.dist);
							// 	for (int t = 0; t < tmp_visit.size(); t++)
							// 	{
							// 		gen_candidate(candidate, tmp_visit[t], visited_keys, tmp_visit, i, sub[i], val.dist + 1);
							// 	}
							// 	tmp_visit.clear();
							// }
						}
					}

					// get_times(0, 3);
					// for (auto &tmpnode : visited_keys)
					// {
					// 	gen_candidate(tmpnode.kf, candidate, tmpnode.sub_info, tmp_visit, i, sub[i], dt + 1, tmpnode.cache_key);
					// }
					// visited_keys.clear();
					// get_times(0, 4);
				}
			}
		}

	search_end:
		// get_times(0, 2);
		// ocall_get_timeNow(time);
		end_time = *time;
		find_time += end_time - begin_time;
		// ocall_get_timeNow(time);
		begin_time = *time;

		vector<sub_info_comp> tmpv;
		std::map<uint32_t, int> tmpm;
		// the node finded by linear list or hashmap, to get candidate's id

		// candi_num += visited_keys.size();
		// std::sort(visited_keys.begin(), visited_keys.end(), [](sub_info_comp &a, sub_info_comp &b)
		// 		  { return a.length > b.length; });
		reached_subkey.clear();
		key_find tmpk{0, 0, 0};
		// for (int y = 0; y < visited_keys.size(); y += 1)
		// {
		// 	auto val = reached_subkey.find(visited_keys[y].sub_key);
		// 	if (val != reached_subkey.end() && val->second == -1)
		// 		continue;
		// 	gen_candidate(tmpk, candidate, visited_keys[y], tmp_visit, tmpv, i, sub[i], 100);
		// }
		visited_keys.clear();
		// ocall_get_timeNow(time);
		end_time = *time;
		insert_time += end_time - begin_time;
	}
	// printf("%d hitt %d misss\n", hittt, misss);
	// printf("bloomHit:%lu bloomMiss:%lu sum%d\n", hitliner+hitmap, bloomMiss, hitliner+hitmap+bloomMiss);
	// printf("hitmap %d hitliner %d \n", hitmap, hitliner);
	// num+=hitliner&mapsize&linersize&hitmap;
	// printf("hitmap %d mapsize %d hitliner %d linersize %d \n",hitmap,mapsize,hitliner,linersize);
	// printf("candi %d\n", candiNUM);

	uint32_t successful_num_pre = successful_num;
	// static uint32_t candi_num = 0;
	// candi_num += candidate.size();
	// // printf("candi_num:%u\n", candi_num);

	uint64_t tmp_fullkey[2] = {0};
	uint64_t equal = 0, target = 0;
	static uint32_t unequal = 0;
	static uint32_t unequal_n = 0;

	// ocall_get_timeNow(time);
	begin_time = *time;
	uint64_t cmp_hamm[2] = {0};
	uint64_t count = 0;
	vector<uint32_t> res_id;
	res_id.reserve(5000);
	information got_out;
	// tsl::hopscotch_map<uint32_t,information>::const_iterator got_out;
	// candi_num += candidate.size();
	for (auto it = candidate.begin(); it != candidate.end();)
	{
		if (*it < full_index.size())
			got_out = full_index[*it];
		if (1)
		{
			get_full_fingerprint32(tmp_fullkey, (uint32_t *)&full_index[*it]);
			cmp_hamm[0] = query[0] ^ (tmp_fullkey[0]);
			cmp_hamm[1] = query[1] ^ (tmp_fullkey[1]);
			count = popcount(cmp_hamm[0]) + popcount(cmp_hamm[1]);
			// count = bitset<64>(cmp_hamm[0]).count() + bitset<64>(cmp_hamm[1]).count();

			candi_num += full_index[*it + fullkey_len].len; // cautious caluate for candidate images
			if (count <= hammdist[client_id])
			{
				successful_num += full_index[*it + fullkey_len].len;

				out_tmp = out;
				uint8_t *comp_data = (uint8_t *)&full_index[*it + fullkey_len + 1];
				if (full_index[*it + fullkey_len].len <= COMPRESS_MIN_UNSORT)
				{
					// uint32_t test_target = 0;
					out_tmp = (uint32_t *)&full_index[*it + fullkey_len + 1];
					// 测试获取的图片对应的id
					for (int j = 0; j < full_index[*it + fullkey_len].len; j++)
					{
						res_id.push_back(out_tmp[j]);
						test_target += out_tmp[j];
					}
				}
				else
				{
					// uint32_t test_target = 0;
					for_uncompress(comp_data, out_tmp, full_index[*it + fullkey_len].len);
					// 测试获取的图片对应的id
					for (int j = 0; j < full_index[*it + fullkey_len].len; j++)
					{
						res_id.push_back(out_tmp[j]);
						test_target += out_tmp[j];
					}
				}

				it++;
			}
			else
				it = candidate.erase(it);
		}
	}
	// printf("targste %d\n", tmp_test_target);
	// printf("%d unequal %d\n", unequal, unequal_n);

	// 测试查询结果的数量级分布
	// static uint32_t min_num[3] = {0};
	// if (successful_num - successful_num_pre < 1)
	// {
	// 	min_num[0]++;
	// 	printf("min_num[0]:%llu %llu\n", query[0], query[1]);
	// }
	// else if (successful_num - successful_num_pre < 1000)
	// {
	// 	min_num[1]++;
	// 	printf("min_num[1]:%llu %llu\n", query[0], query[1]);
	// }
	// else
	// {
	// 	min_num[2]++;
	// 	printf("min_num[2]:%llu %llu\n", query[0], query[1]);
	// }
	// printf("min_num[0]:%u min_num[1]:%u min_num[2]:%u\n", min_num[0], min_num[1], min_num[2]);
	// ocall_get_timeNow(time);
	end_time = *time;
	verify_time += end_time - begin_time;
	// ocall_get_timeNow(total_time_now);
	total_end_time = *total_time_now;
	total_time += total_end_time - total_begin_time;
	return std::move(res_id);
}
void containers::gen_candidate(key_find &find_key, std::unordered_set<uint32_t> &cand, sub_info_comp comp, vector<sub_info_comp> &tmp_keys,
							   uint32_t i, uint32_t subkey, uint32_t dt, uint32_t cache_key)
{
	times_gen++;
	uint8_t *tmp_ids_block;
	uint64_t key = ((uint64_t)i << 32) | cache_key;

// if (val != data_cache.end())combs_hit += val->second->key;
#if CACHE_SIZE >= 500000
	auto val = data_cache.find(key);
	if (val != data_cache.end())
	{
		tmp_ids_block = val->second->ids.data();
		// lru_ids_visit(key, val->second);
	}
	else
	{
		// tmp_ids_block = lru_ids_add(key, i, comp);
	}

#else
	lru_mtx.lock();
	auto val = data_cache.find(key);
	if (val != data_cache.end())
	{
		tmp_ids_block = val->second->ids.data();
		lru_ids_visit(key, val->second);
	}
	else
	{
		tmp_ids_block = lru_ids_add(key, i, comp);
	}
	lru_mtx.unlock();
#endif
	// auto val = data_cache[i].find(comp.skiplen);
	// if (val != data_cache[i].end())
	// {
	// 	tmp_ids_block = val->second.data();
	// }
	// else
	// {
	// 	vector<uint8_t> tmp_ids;
	// 	tmp_ids.resize(comp.length & 0x3fffffff);
	// 	dec_page_block(id_point[i] + comp.skiplen, comp.length & 0x3fffffff, tmp_ids.data());
	// 	tmp_ids_block = tmp_ids.data();
	// 	data_cache[i].emplace(comp.skiplen, std::move(tmp_ids));
	// }

	// dec_page_block(id_point[i] + comp.skiplen, comp.length & 0x3fffffff, tmp_ids_block); // tmp_ids_block max=1024 * 300
	// tmp_ids_block = id_point[i] + comp.skiplen;

	uint32_t tempKey = comp.sub_key;
	uint32_t tmp_size = 0;
	int tmp_begin = 0;
	bool is_combined_keys = false;

	auto out_tmp = out;
	// if (tmp_begin < 0) ,some continuous  subkeys are Combined to one biggest subkey in there
	if (comp.length & MASK_INF)
	{
		is_combined_keys = true;
	}
	out_tmp = (uint32_t *)tmp_ids_block;
	tmp_size = comp.length; //*((uint32_t *)&tmp_ids_block[tmp_begin]);
							/*	if ((int)tmp_size < 0)
								{
									tmp_begin += sizeof(uint32_t);
									tmp_size = *((uint32_t *)&tmp_ids_block[tmp_begin]);
								}
						
								// 解压，如果多个subkey是被合并后的，is-combine=true；解压的是unsort数组；否则解压产生sorted数组
								if (!is_combined_keys)
								{
									if (tmp_size <= COMPRESS_MIN)
									{
										out_tmp = (uint32_t *)(tmp_ids_block + tmp_begin + 4);
									}
									else
									{
										for_uncompress(tmp_ids_block + tmp_begin + 4, out_tmp, tmp_size); // decompress
																										  //   printf("tmp_size: %u\n", tmp_size);
									}
								}
								else
								{
									if (tmp_size <= COMPRESS_MIN_UNSORT)
										out_tmp = (uint32_t *)(tmp_ids_block + tmp_begin + 4);
									else
										for_uncompress(tmp_ids_block + tmp_begin + 4, out_tmp, tmp_size); // decompress
								}
							*/
	// get the true identifiers of the subkey
	if (is_combined_keys)
	{
		combs++;
		uint32_t lens = 0;

		// out_tmp结构:[keys_len, subkey0,...,subkeyN,-id0,id1,-id4,id8,...,idm]
		// keys_len: 这个block里面subkey的数量，subkey：这个block里面包含的subkey，所有subkey在排列在一起
		// id：前面subkey对应的图片id集合，按照subkey的先后顺序，每个subkey对应一个id序列，这个id序列开头为-id，以表示开始一个新的序列
		uint32_t keys_len = out_tmp[0];
		// printf("keys_len %d\n", keys_len);

		// auto x = std::lower_bound(out_tmp + 1, out_tmp + 1 + keys_len, tempKey);
		// if (x != out_tmp + 1 + keys_len && *x == tempKey)
		// {
		// 	uint32_t times = (x - out_tmp);
		// 	for (int t = 1 + keys_len; t < tmp_size; t++)
		// 	{
		// 		if ((int)out_tmp[t] < 0)
		// 		{
		// 			times--;
		// 			if (times == 0)
		// 			{
		// 				find_key.max_dist = 0;
		// 				reached_subkey[comp.sub_key] = -1;
		// 				combs_hit++;
		// 				cand.emplace_hint(cand.begin(), -out_tmp[t] - 1);
		// 				for (int l = t + 1; l < tmp_size; l++)
		// 				{
		// 					if ((int)out_tmp[l] < 0)
		// 						break;
		// 					cand.emplace_hint(cand.begin(), out_tmp[l]);
		// 				}
		// 				break;
		// 			}
		// 		}
		// 	}
		// }

		// out_tmp结构:[subkey0,len0,id0,id1,...,subkey1,len1,id0,id1,...]
		tmp_size = *((uint32_t *)&tmp_ids_block[0]);
		for (int j = 1; j < tmp_size;)
		{
			if (out_tmp[j] == tempKey)
			{
				find_key.clr_idx = INT16_MAX;
				// reached_subkey[comp.sub_key] = -1;
				find_key.max_dist = 0;
				j++;
				uint32_t len = out_tmp[j];
				for (int l = j + 1; l <= j + len; l++)
				{
					cand.emplace_hint(cand.begin(), out_tmp[l]);
					lens++;
				}
				j += out_tmp[j] + 1;
				break;
			}
			else
			{
				j += out_tmp[j + 1] + 2;
			}
		}

		// for (int j = 1; j <= keys_len; j++)
		// {
		// 	if (out_tmp[j] > tempKey)
		// 		break;
		// 	else if (out_tmp[j] == tempKey)
		// 	{
		// 		uint32_t times = j;
		// 		for (int t = 1 + keys_len; t < tmp_size; t++)
		// 		{
		// 			if ((int)out_tmp[t] < 0)
		// 			{
		// 				times--;
		// 				if (times == 0)
		// 				{
		// 					cand.emplace_hint(cand.begin(), -out_tmp[t]);
		// 					for (int l = t + 1; l < tmp_size; l++)
		// 					{
		// 						if ((int)out_tmp[l] < 0)
		// 							break;
		// 						cand.emplace_hint(cand.begin(), out_tmp[l]);
		// 					}
		// 					break;
		// 				}
		// 			}
		// 		}
		// 		break;
		// 	}
		// }
	}
	else
	{
		// reached_subkey[comp.sub_key] = -1;
		find_key.max_dist = 0;
		find_key.clr_idx = INT16_MAX;
		for (int j = 0; j < tmp_size; j++)
		{
			cand.emplace_hint(cand.begin(), out_tmp[j]);
		}
	}
}
void containers::linear_scan(uint32_t i, uint32_t begin, uint32_t end, uint32_t subkey, uint32_t hammdist,
							 unordered_set<uint32_t> &candidate, std::unordered_map<uint32_t, int> &reached_subkey)
{
	sub_info_comp tmp_info;
	uint8_t *tmp_ids_block;
	for (uint32_t c = begin; c < end; c++)
	{
		tmp_info = sub_linear_comp[i][c];
		if (tmp_info.length & MASK_INF)
		{
			// tmp_info.sub_key = subkey;
			// key_find kf{sub_linear_comp[i][c].sub_key,10,10};
			// gen_candidate(kf,candidate,tmp_info,visited_keys,visited_keys,i,subkey,0);
			times_gen++;

			uint64_t key = ((uint64_t)i << 32) | tmp_info.sub_key;
			// if (val != data_cache.end())combs_hit += val->second->key;
#if CACHE_SIZE >= 500000
			auto val = data_cache.find(key);
			if (val != data_cache.end())
			{
				tmp_ids_block = val->second->ids.data();
				// lru_ids_visit(key, val->second);
			}
			else
			{
				// tmp_ids_block = lru_ids_add(key, i, tmp_info);
			}
#else
			lru_mtx.lock();
			auto val = data_cache.find(key);
			if (val != data_cache.end())
			{
				tmp_ids_block = val->second->ids.data();
				lru_ids_visit(key, val->second);
			}
			else
			{
				tmp_ids_block = lru_ids_add(key, i, tmp_info);
			}
			lru_mtx.unlock();
#endif

			uint32_t tempKey = subkey;
			uint32_t tmp_size = 0;
			int tmp_begin = 0;
			bool is_combined_keys = false;

			auto out_tmp = out;
			out_tmp = (uint32_t *)tmp_ids_block;
			// (tmp_begin < 0) ,some continuous  subkeys are Combined to one biggest subkey in there
			// if (tmp_info.length & MASK_INF)
			{
				is_combined_keys = true;
			}

			// tmp_size = *((uint32_t *)&tmp_ids_block[tmp_begin]);
			// if ((int)tmp_size < 0)
			// {
			// 	tmp_begin += sizeof(uint32_t);
			// 	tmp_size = *((uint32_t *)&tmp_ids_block[tmp_begin]);
			// }

			// // 解压，如果多个subkey是被合并后的，is-combine=true；解压的是unsort数组；否则解压产生sorted数组
			// if (!is_combined_keys)
			// {
			// 	if (tmp_size <= COMPRESS_MIN)
			// 	{
			// 		out_tmp = (uint32_t *)(tmp_ids_block + tmp_begin + 4);
			// 	}
			// 	else
			// 	{
			// 		for_uncompress(tmp_ids_block + tmp_begin + 4, out_tmp, tmp_size); // decompress
			// 																		  //   printf("tmp_size: %u\n", tmp_size);
			// 	}
			// }
			// else
			// {
			// 	if (tmp_size <= COMPRESS_MIN_UNSORT)
			// 		out_tmp = (uint32_t *)(tmp_ids_block + tmp_begin + 4);
			// 	else
			// 		for_uncompress(tmp_ids_block + tmp_begin + 4, out_tmp, tmp_size); // decompress
			// }

			// get the true identifiers of the subkey
			if (is_combined_keys)
			{
				combs++;
				uint32_t lens = 0;

				// // out_tmp结构:[keys_len, subkey0,...,subkeyN,-id0,id1,-id4,id8,...,idm]
				// // keys_len: 这个block里面subkey的数量，subkey：这个block里面包含的subkey，所有subkey在排列在一起
				// // id：前面subkey对应的图片id集合，按照subkey的先后顺序，每个subkey对应一个id序列，这个id序列开头为-id，以表示开始一个新的序列
				// uint32_t keys_len = out_tmp[0];
				// // printf("keys_len %d\n", keys_len);

				// int ids_begin = 1 + keys_len;

				// for (int j = 1; j <= keys_len; j++)
				// {
				// 	// if ((int)out_tmp[ids_begin] >= 0)
				// 	// 	printf("id %d %d %d size%d\n", out_tmp[ids_begin], ids_begin, 1 + keys_len, tmp_size);
				// 	if (popcount(out_tmp[j] ^ subkey) <= hammdist)
				// 	{
				// 		reached_subkey[out_tmp[j]] = -1;
				// 		uint32_t times = j;
				// 		// if ((int)out_tmp[ids_begin] >= 0)
				// 		// 	printf("id %d %d %d\n", out_tmp[ids_begin], ids_begin, 1 + keys_len);
				// 		candidate.emplace_hint(candidate.begin(), -out_tmp[ids_begin] - 1);
				// 		ids_begin++;
				// 		for (; ids_begin < tmp_size && ((int)out_tmp[ids_begin]) >= 0; ids_begin++)
				// 		{
				// 			candidate.emplace_hint(candidate.begin(), out_tmp[ids_begin]);
				// 		}
				// 		// break;
				// 	}
				// 	else
				// 	{
				// 		// candidate.emplace_hint(candidate.begin(), -out_tmp[ids_begin] - 1);
				// 		for (ids_begin++; ids_begin < tmp_size && ((int)out_tmp[ids_begin]) >= 0; ids_begin++)
				// 			; // 	{
				// 			  // 	candidate.emplace_hint(candidate.begin(), out_tmp[ids_begin]);
				// 			  // };
				// 	}
				// }

				tmp_size = *((uint32_t *)&tmp_ids_block[0]);
				;
				for (int j = 1; j < tmp_size;)
				{
					if (popcount(out_tmp[j] ^ subkey) <= hammdist)
					{
						j++;
						uint32_t len = out_tmp[j];
						reached_subkey[out_tmp[j - 1]] = -1;
						for (int l = j + 1; l <= j + len; l++)
						{
							candidate.emplace_hint(candidate.begin(), out_tmp[l]);
							lens++;
						}
						j += out_tmp[j] + 1;
						// break;
					}
					else
					{
						j += out_tmp[j + 1] + 2;
					}
				}

				// if(ids_begin!=tmp_size)printf("error ids_begin %d tmp_size %d\n",ids_begin,tmp_size);
			}
			// else
			// {
			// 	reached_subkey[comp.sub_key] = -1;
			// 	find_key.max_dist = 0;
			// 	for (int j = 0; j < tmp_size; j++)
			// 	{
			// 		cand.emplace_hint(cand.begin(), out_tmp[j]);
			// 	}
			// }
		}
		else
		{
			if (popcount(tmp_info.sub_key ^ subkey) <= hammdist)
			{
				key_find kf{0, 0, 0};
				reached_subkey[tmp_info.sub_key] = -1;
				// if(reached_subkey.find(tmp_info.sub_key)!=reached_subkey.end())printf("error\n");
				gen_candidate(kf, candidate, {tmp_info.sub_key, tmp_info.skiplen, tmp_info.length}, tmp_visit, i, subkey, 0, tmp_info.sub_key);

				// visited_keys.push_back(tmp_info);
			}
		}
	}
}
void containers::test()
{
	// ------------test insert and query----------
	// int insert_num=500;
	// pair<uint64_t, uint64_t>* tempPair = new pair<uint64_t, uint64_t>[insert_num];
	// for(int i=0;i<insert_num;i++)tempPair[i] = make_pair(full_index[3000+i].fullkey[0], full_index[3000+i].fullkey[1]);
	// insert_fingerprint(tempPair,insert_num);

	// int insert_num=1;
	// pair<uint64_t, uint64_t> tempPair(full_index[0].fullkey[0],full_index[0].fullkey[1]);
	// insert_fingerprint(&tempPair,insert_num);

	//------test insert new data to linear-list------
	// for(int i=0;i<4;i++)this->insert_new_datamap(i);

	printf("Test!\n");
	uint64_t temp_key[2] = {0};

	uint32_t i = 0;
	for (auto &itx : test_pool)
	{
		temp_key[0] = itx.first;
		temp_key[1] = itx.second;
		find_sim(temp_key, 0, 0); // test_targets[i]
		// 					   // i++;
		int k = 1000;
		// auto res = find_knn(temp_key, k);
		// uint64_t cmp_hamm[2], tmp_fullkey[2];
		// for (int i = 0; i < res.size(); i++)
		// {
		// 	// auto got_out = full_index[res[i]];
		// 	// cmp_hamm[0] = temp_key[0] ^ (got_out.fullkey[0]);
		// 	// cmp_hamm[1] = temp_key[1] ^ (got_out.fullkey[1]);
		// 	// uint64_t count = bitset<64>(cmp_hamm[0]).count() + bitset<64>(cmp_hamm[1]).count();
		// 	printf("count %d dist %d\n", res[i].first, res[i].second);
		// }
		// break;
	}

	// 用线性方式查找，观察数据集中特征值分布
	// find_sim_linear(test_pool, test_targets);

	// 线性遍历，查找topK
	//  temp_key[0] = 16909314365230085166ULL;
	//  temp_key[1] = 2629030462899310375ULL;
	//  uint32_t index = 0;
	//  sgx_read_rand(reinterpret_cast<unsigned char *>(&index), 4);
	//  index %= cont.tmp_test_pool.size();
	//  temp_key[0] = cont.tmp_test_pool[index].first;
	//  temp_key[1] = cont.tmp_test_pool[index].second;
	//  find_topk(temp_key);

	total_time /= 1e6;
	find_time /= 1e6;
	insert_time /= 1e6;
	verify_time /= 1e6;
	printf("resize times %d size %lld finded clrs times %d\n", resize_times, resize_size, find_clrs_num);

	printf("fetch candidate time %d candi_num %d combs %d combs_hit %d bigun%d\n", times_gen, candi_num, combs, combs_hit, big_uneq);
	// total时间（ms）， find：查询map和linear的时间，insert：插入到set<candidate>的时间，verify：验证candidate的时间
	printf("total=time:%d,sum:%d, find-time:%d, insert-time:%d, verify-time:%d\n", total_time, find_time + insert_time + verify_time, find_time, insert_time, verify_time);
	for (int t = 0; t < 6; t++)
		bd_time[t] /= 1e6;
	printf("cal-cer one %d, bitmask %d, stash %d, cluster %d id_loading %d \n", bd_time[0], bd_time[1], bd_time[2], bd_time[3], bd_time[4]);
	printf("zero_num=%d  combine_clr_min=%d test target %d\n", zero_num, combine_clr_min, test_target);

	printf("max_cache value%d\n", max_val);
}
void containers::changeHammingDist(uint64_t hammdist, int client_id)
{
	this->hammdist[client_id] = hammdist;
	// for (int i = 0; i < SUBINDEX_NUM; i++)
	{
		this->sub_hammdist[client_id] = floor((double)hammdist / SUBINDEX_NUM);
	}
	// if (hammdist == this->hammdist)
	// 	return;
	// this->hammdist = hammdist;
	// // this->sub_hammdist=hammdist/4;
	// for (int i = 0; i < cont.sub_index_num; i++)
	// 	sub_hammdist[i] = 0;
	// for (int j = hammdist - sub_index_num + 1; j > 0;)
	// {
	// 	// the sum of sub_hammdist is hammdist - sub_index_num + 1
	// 	for (int i = 0; i < sub_index_num; i++)
	// 	{
	// 		if (j <= 0)
	// 			break;
	// 		sub_hammdist[i]++;
	// 		j--;
	// 	}
	// }
	// for (int i = 0; i < cont.sub_index_num; i++)
	// {
	// 	cont.C_0_TO_subhammdis[i].clear();
	// 	cont.prepare(cont.sub_hammdist[i], cont.C_0_TO_subhammdis[i]);
	// }
	// // this->prepare();
}
void containers::insert_fingerprint(pair<uint64_t, uint64_t> *data, uint32_t length)
{
	// uint64_t temp_key[2]={0};
	// uint32_t out_id=0;
	// uint32_t sub[4]={0};
	// information temp_information;
	// sub_information sub_info[4];
	// if(length>sub_map_size*5){//改成length>0，则测试直接insert线性表的时间
	// 	vector<sub_information> tmp_sub_vector[4] ;
	// 	for(int i=0;i<4;i++)tmp_sub_vector[i].reserve(length);
	// 	for(int i=0;i<length;i++)
	// 	{
	// 		temp_information.fullkey[0]=data[i].first;//temp_key[0];
	// 		temp_information.fullkey[1]=data[i].second;//temp_key[1];
	// 		temp_key[0]=temp_information.fullkey[0];temp_key[1]=temp_information.fullkey[1];
	// 		get_sub_fingerprint32(sub,temp_key);
	// 		out_id=random_uuid()-1;
	// 		for(int j=0;j<4;j++){
	// 			filters[j].insert(sub[j]);
	// 			sub_info[j].sub_key=sub[j];
	// 			sub_info[j].identifiers=out_id;
	// 			tmp_sub_vector[j].push_back(sub_info[j]);
	// 			if(sub_index[j].find(sub[j])!=sub_index[j].end()){
	// 				sub_index[j][sub[j]]->identifiers.push_back(out_id);
	// 			}
	// 		}
	// 		full_index.push_back(temp_information);
	// 	}

	// 	//sort and merge new elements
	// 	for(int j=0;j<4;j++){
	// 		std::sort(tmp_sub_vector[j].begin(),tmp_sub_vector[j].end(),customCompare);
	// 		sub_index_liner[j].reserve(sub_index_liner[j].size()+(length<1000?1000:length));
	// 		sub_index_liner[j].insert(sub_index_liner[j].end(), tmp_sub_vector[j].begin(), tmp_sub_vector[j].end());
	// 		// std::merge(cont.sub_index_liner[j].begin(),cont.sub_index_liner[j].end(),tmp_sub_vector[j].begin(),tmp_sub_vector[j].end(),std::back_inserter(cont.sub_index_liner[j]),customCompare);
	// 		std::inplace_merge(sub_index_liner[j].begin(), sub_index_liner[j].end()-tmp_sub_vector[j].size(), sub_index_liner[j].end(), customCompare);
	// 		initialize_size+=tmp_sub_vector[j].size();
	// 	}
	// }else{
	// 	for(int i=0;i<length;i++)
	// 	{
	// 		temp_information.fullkey[0]=data[i].first;//temp_key[0];
	// 		temp_information.fullkey[1]=data[i].second;//temp_key[1];
	// 		temp_key[0]=temp_information.fullkey[0];temp_key[1]=temp_information.fullkey[1];
	// 		get_sub_fingerprint32(sub,temp_key);
	// 		out_id=random_uuid()-1;
	// 		for(int j=0;j<4;j++){
	// 			filters[j].insert(sub[j]);
	// 			insert_to_submap(j,sub[j],out_id);

	// 			//直接插入sub-index，测试纯hashmap的insert时间,注释掉insert_to_submap
	// 			// if(sub_index[j].find(sub[j])!=sub_index[j].end())sub_index[j][sub[j]]->identifiers.push_back(out_id);
	// 			// else {
	// 			// 	sub_index_node* temp_node=new sub_index_node;
	// 			// 	sub_index[j][sub[j]]=temp_node;
	// 			// 	temp_node->identifiers.push_back(out_id);
	// 			// }
	// 		}
	// 		full_index.push_back(temp_information);
	// 	}
	// }
}
void init()
{
	printf("run code!\n");
	for (int i = 0; i < 6; i++)
	{
		cont.prepare(i, cont.C_0_TO_subhammdis[i]);
	}
	printf("c_o size: %d\n", cont.C_0_TO_subhammdis[0].size());
	printf("Init!\n");
	cont.initialize();
	// cont.get_test_pool();
	// printf("The full index entry is: %d \n",cont.full_index.size());
	// printf("The number of queries is: %d \n",cont.test_pool.size());
}
void test_run()
{
	cont.test();
	printf("Successfully found similar photos! successful_num=%d.\n", cont.successful_num);
}
void init_after_send()
{
	cont.get_test_pool(); // get test pool before sort the linearlist
	cont.full_key_sorted.shrink_to_fit();

	cont.init_filters(0);
	cont.opt_full_index();
	// // cont.opt_sub_index();
	// printf("lll %d %f\n", (uint32_t)(1.0 * cont.sub_index_liner[0].size() / 2000), (1.0 * cont.sub_index_liner[0].size() / 1.0 * 1000));

	cont.make_clusters();

	cont.init_sub_maps();

	uint32_t nums = 0;
	for (int i = 0; i < SUBINDEX_NUM; i++)
		nums += cont.sub_linear_comp[i].size();
	cont.lru_cache.capacity = CACHE_SIZE; // 5000 ((uint32_t)floor((double)nums / 100) < 20000 ? 20000 : (uint32_t)floor((double)nums / 100)); //	nums + 100000; //
	cont.lru_cache.len = 0;
	cont.lru_cache.remain_size = cont.lru_cache.capacity * 3000;
	cont.init_ids_cache();

	printf("The full index entry is: %d \n", cont.full_index.size());
	printf("The number of queries is: %d \n", cont.test_pool.size());

	printf("The full sort entry is: %d \n", cont.full_key_sorted[0].target);
	printf("comp_subkey %d\n", cont.sub_linear_comp->size());
	printf("cache size %d\n", cont.data_cache.size());
}

void ecall_send_data(void *dataptr, size_t len)
{
	std::pair<uint64_t, uint64_t> *data = reinterpret_cast<std::pair<uint64_t, uint64_t> *>(dataptr);
	uint32_t out_id;
	info_uncomp info;
	for (int i = 0; i < len; i++)
	{
		if (cont.full_key_sorted.size() < DATA_LEN)
		{
			info.fullkey[0] = data[i].first;
			info.fullkey[1] = data[i].second;
			out_id = cont.random_uuid() - 1;
			info.identify = out_id;
			cont.full_key_sorted.push_back(info);
			// if (cont.test_pool.size() < cont.test_size)
			// 	cont.test_pool.insert(data[i]);
		}
		else
		{
			cont.tmp_test_pool.push_back(data[i]);
		}
	}

	// // printf("The full index entry is: %d \n",cont.test_pool.size()-1);
	// std::pair<uint64_t, uint64_t> *data = reinterpret_cast<std::pair<uint64_t, uint64_t> *>(dataptr);
	// // sign_data.insert(sign_data.end(),data,data+len);
	// uint64_t temp_key[2] = {0};
	// uint32_t out_id = 0;
	// uint32_t sub[4] = {0};
	// information temp_information;
	// sub_information sub_info[4];
	// for (int i = 0; i < len; i++)
	// {

	// 	// random_128(temp_key);
	// 	temp_information.fullkey[0] = data[i].first;  // temp_key[0];
	// 	temp_information.fullkey[1] = data[i].second; // temp_key[1];
	// 	temp_key[0] = temp_information.fullkey[0];
	// 	temp_key[1] = temp_information.fullkey[1];
	// 	cont.get_sub_fingerprint32(sub, temp_key);
	// 	out_id = cont.random_uuid() - 1;
	// 	for (int j = 0; j < 4; j++)
	// 	{
	// 		cont.filters[j].insert(sub[j]);
	// 		sub_info[j].sub_key = sub[j];
	// 		sub_info[j].identifiers = out_id;
	// 		// cont.tmp_index[j][sub[j]].push_back(out_id);
	// 		cont.sub_index_liner[j].push_back(sub_info[j]);
	// 	} // cont.sub_index_liner[3].push_back(sub_info[3]);
	// 	cont.full_index.push_back(temp_information);
	// }
}
void ecall_send_targets(void *dataptr, size_t len)
{
	static int index = 0;
	uint32_t *data = reinterpret_cast<uint32_t *>(dataptr);
	for (int i = 0; i < len; i++)
	{
		cont.full_key_sorted[index].target = data[i];
		index++;
	}
	// targets_data.insert(targets_data.end(),data,data+len);
}
void ecall_send_query(void *dataptr, size_t len)
{
	std::pair<uint64_t, uint64_t> *data = reinterpret_cast<std::pair<uint64_t, uint64_t> *>(dataptr);
	cont.tmp_test_pool.insert(cont.tmp_test_pool.end(), data, data + len);
}
void ecall_send_qtargets(void *dataptr, size_t len)
{
	uint32_t *data = reinterpret_cast<uint32_t *>(dataptr);
	cont.tmp_test_targets.insert(cont.tmp_test_targets.end(), data, data + len);
}
void ecall_send_data_enc(void *dataptr, size_t batch_size, int is_img_dataset)
{
	// EcallCrypto *cryptoObj = new EcallCrypto(CIPHER_TYPE, HASH_TYPE);
	EVP_MD_CTX *mdCtx = EVP_MD_CTX_new();
	EVP_CIPHER_CTX *cipherCtx_ = EVP_CIPHER_CTX_new();
	uint8_t *sessionKey_ = const_sessionKey;

	uint8_t *dataE = reinterpret_cast<uint8_t *>(dataptr);
	cont.cryptoObj->SessionKeyDec(cipherCtx_, dataE,
								  batch_size, sessionKey_,
								  dataE);
	uint64_t *tmp_fullkey1;
	uint32_t out_id;
	info_uncomp info;
	int tmp_size = 0;
	while (tmp_size < batch_size)
	{
		tmp_fullkey1 = (uint64_t *)(dataE + tmp_size);
		info.fullkey[0] = *tmp_fullkey1;
		tmp_size += sizeof(uint64_t);

		tmp_fullkey1 = (uint64_t *)(dataE + tmp_size);
		info.fullkey[1] = *tmp_fullkey1;
		tmp_size += sizeof(uint64_t);

		out_id = cont.random_uuid() - 1;
		info.identify = out_id;
		if (is_img_dataset || cont.full_key_sorted.size() < SIFT_LEN) /// SIFT_LEN
		{
			cont.full_key_sorted.push_back(info);

			// info.fullkey[0]++;
			// info.fullkey[1]++;
			// cont.full_key_sorted.push_back(info);
			// info.fullkey[0]+=10;
			// info.fullkey[1]+=10;
			// cont.full_key_sorted.push_back(info);
			// info.fullkey[0]+=100;
			// info.fullkey[1]+=100;
			// cont.full_key_sorted.push_back(info);
			// printf("id%d\n", out_id);
		}
		if (is_img_dataset)
			tmp_size += sizeof(uint64_t); // skip img's target 32bit
	}
	EVP_MD_CTX_free(mdCtx);
	EVP_CIPHER_CTX_free(cipherCtx_);
}
void ecall_send_query_enc(void *dataptr, size_t batch_size, int is_img_dataset)
{
	// std::pair<uint64_t, uint64_t> *data = reinterpret_cast<std::pair<uint64_t, uint64_t> *>(dataptr);
	// cont.tmp_test_pool.insert(cont.tmp_test_pool.end(), data, data + len);
	// EcallCrypto *cryptoObj = new EcallCrypto(CIPHER_TYPE, HASH_TYPE);
	EVP_MD_CTX *mdCtx = EVP_MD_CTX_new();
	EVP_CIPHER_CTX *cipherCtx_ = EVP_CIPHER_CTX_new();
	uint8_t *sessionKey_ = const_sessionKey;

	uint8_t *dataE = reinterpret_cast<uint8_t *>(dataptr);
	cont.cryptoObj->SessionKeyDec(cipherCtx_, dataE,
								  batch_size, sessionKey_,
								  dataE);
	uint64_t *tmp_fullkey1;
	std::pair<uint64_t, uint64_t> tmp_fullkey;
	uint64_t key1, key2;
	int tmp_size = 0;
	while (tmp_size < batch_size)
	{
		key1 = *(uint64_t *)(dataE + tmp_size);
		tmp_size += sizeof(uint64_t);

		key2 = *(uint64_t *)(dataE + tmp_size);
		tmp_size += sizeof(uint64_t);

		cont.tmp_test_pool.push_back({key1, key2});
		if (is_img_dataset)
			tmp_size += sizeof(uint64_t); // skip img's target 32bit
	}
	EVP_MD_CTX_free(mdCtx);
	EVP_CIPHER_CTX_free(cipherCtx_);
}
void ecall_enc_dataset(void *dataptr, size_t len)
{
	// EcallCrypto *cryptoObj = new EcallCrypto(CIPHER_TYPE, HASH_TYPE);
	EVP_MD_CTX *mdCtx = EVP_MD_CTX_new();
	EVP_CIPHER_CTX *cipherCtx_ = EVP_CIPHER_CTX_new();
	uint8_t *sessionKey_ = const_sessionKey;

	uint8_t *dataE = reinterpret_cast<uint8_t *>(dataptr);
	cont.cryptoObj->SessionKeyEnc(cipherCtx_, dataE,
								  len, sessionKey_,
								  dataE);
	EVP_MD_CTX_free(mdCtx);
	EVP_CIPHER_CTX_free(cipherCtx_);
}
void containers::opt_full_index()
{
	uint32_t tmp_hash[2], hash_size = ((bloom_hash_times >> 2) + (bloom_hash_times & 0x3 != 0) * 4) * INT_SIZE; // ceil(times/4)*4
	uint8_t tmp_hash_out[32], bloom_hash[hash_size];

	information temp_information;
	information idy_info;
	information len_info;
	std::sort(cont.full_key_sorted.begin(), cont.full_key_sorted.end(), customCompare_fullkey);

	uint32_t fullkey_len = 0, filter_nums = 0;
	uint64_t temp_keys[2] = {0};
	uint32_t out_id = 0;
	uint32_t sub[SUBINDEX_NUM] = {0}, old_sub[SUBINDEX_NUM] = {0};
	sub_information sub_info[SUBINDEX_NUM];
	vector<uint32_t> info_idy;
	uint8_t *tmp_compress_data = new uint8_t[80000]; // 临时空间用于进行压缩，数据量大时可能需要增大
	uint32_t complen = 0;

	for (int i = 0; i < full_key_sorted.size();)
	{
		fullkey_len++;
		info_idy.clear();

		temp_keys[0] = full_key_sorted[i].fullkey[0];
		temp_keys[1] = full_key_sorted[i].fullkey[1];
		// cont.get_sub_fingerprint32(sub, temp_keys);
		split(sub, (uint8_t *)temp_keys, sub_index_num, sub_index_plus, sub_keybit);
		// out_id = cont.random_uuid() - 1;

		for (int j = 0; j < SUBINDEX_NUM; j++)
		{
			int out[1], sub_key_I[2];
			sub_key_I[0] = sub[j], sub_key_I[1] = j;

			if (sub[j] != old_sub[j])
				filter_nums++;
			// // printf("hash\n");
			// for (int t = 0; t < bloom_hash_times; t += 4)
			// {
			// 	tmp_hash[0] = sub[j];
			// 	tmp_hash[1] = j + t * sub_index_num * 2;
			// 	MurmurHash3_x86_128(tmp_hash, 8, hash_seed[j], bloom_hash + t * INT_SIZE);
			// 	// sha256_digest(reinterpret_cast<const unsigned char*>(tmp_hash),sizeof(tmp_hash),tmp_hash_out);
			// 	// memcpy(bloom_hash + t * INT_SIZE, tmp_hash_out, std::min(bloom_hash_times - t, (uint32_t)4) * INT_SIZE);
			// }
			// // printf("hash2\n");

			// // MurmurHash3_x86_32(sub_key_I, 8, hash_seed[j], out); // murmur hash(sub_key,i) to one filter
			// cont.filters.insert(bloom_hash, bloom_hash_times * INT_SIZE);
			// // cont.filters[j].insert(sub[j]);

			sub_info[j].sub_key = sub[j];
			sub_info[j].identifiers = full_index.size(); // size - j

			// cont.sub_index_liner[j].push_back(sub_info[j]);

			// temp_information.sub_fullkey = sub[j];
			// full_index.push_back(temp_information);
			memcpy(old_sub, sub, sizeof(sub));

			for (int t = 0; t < bloom_hash_times; t += 4)
			{
				tmp_hash[0] = sub[j];
				tmp_hash[1] = j + t * SUBINDEX_NUM * 2;
				MurmurHash3_x86_128(tmp_hash, 8, hash_seed[0], bloom_hash + t * INT_SIZE);
			}
			filters->insert(bloom_hash, bloom_hash_times * INT_SIZE);
		}

		uint32_t tmp_sub[4];
		cont.get_sub_fingerprint32(tmp_sub, temp_keys);
		for (int j = 0; j < 4; j++)
		{
			temp_information.sub_fullkey = tmp_sub[j];
			full_index.push_back(temp_information);
		}

		uint32_t len = 0;
		temp_keys[0] = full_key_sorted[i].fullkey[0];
		temp_keys[1] = full_key_sorted[i].fullkey[1];
		for (int j = i; j < full_key_sorted.size() && full_key_sorted[j].fullkey[0] == temp_keys[0] && full_key_sorted[j].fullkey[1] == temp_keys[1]; j++)
		{
			len++;
		}
		len_info.len = len;
		full_index.push_back(len_info);

		// 加入target字段，用于测试精确度
		//  information targets;
		//  uint32_t tmp_target = -1, num = 0;
		//  uint32_t tmps[1000] = {0};
		//  for (int j = i; j < full_key_sorted.size() && full_key_sorted[j].fullkey[0] == temp_keys[0] && full_key_sorted[j].fullkey[1] == temp_keys[1]; j++)
		//  {
		//  	tmps[full_key_sorted[j].target]++;
		//  }
		//  for (int j = i; j < full_key_sorted.size() && full_key_sorted[j].fullkey[0] == temp_keys[0] && full_key_sorted[j].fullkey[1] == temp_keys[1]; j++)
		//  {
		//  	if (num < tmps[full_key_sorted[j].target])
		//  	{
		//  		num = tmps[full_key_sorted[j].target];
		//  		tmp_target = full_key_sorted[j].target;
		//  	}
		//  }
		//  if (tmp_target == -1)
		//  	tmp_target = full_key_sorted[i].target;
		//  targets.target = tmp_target;
		//  full_index.push_back(targets);

		for (; i < full_key_sorted.size() && full_key_sorted[i].fullkey[0] == temp_keys[0] && full_key_sorted[i].fullkey[1] == temp_keys[1]; i++)
		{
			info_idy.push_back(full_key_sorted[i].identify);

			full_key_sorted[i].identify = full_index.size() - 5; // 4 for 4*32bit subkey, 1 for len
																 // idy_info.identify = full_key_sorted[i].identify;
																 // full_index.push_back(idy_info);
		}
		uint32_t compress_len = for_compressed_size_unsorted((uint32_t *)info_idy.data(), info_idy.size());
		complen += compress_len - info_idy.size() * 4;
		for_compress_unsorted((uint32_t *)info_idy.data(), tmp_compress_data, info_idy.size());
		uint32_t tmp = 0;

		// 如果size小于COMPRESS_MIN_FULLKEY，不压缩，直接存储uint32_t;否则需要把压缩后产生的uint8用小端方式转换为uint32
		if (info_idy.size() <= COMPRESS_MIN_UNSORT)
		{
			for (int j = 0; j < info_idy.size(); j++)
			{
				idy_info.comp_data = info_idy[j];
				full_index.push_back(idy_info);
			}
		}
		else
		{
			for (int j = 0; j < compress_len; j += 4)
			{
				tmp = 0;
				for (int t = 0; t < 4; t++)
				{
					if (j + t < compress_len)
					{
						tmp += ((uint32_t)tmp_compress_data[j + t]) << (8 * t);
					}
				}
				idy_info.comp_data = tmp; // tmp_compress_data[j];
				full_index.push_back(idy_info);
			}
		}
	}

	auto last = std::unique(full_key_sorted.begin(), full_key_sorted.end(), [](info_uncomp &a, info_uncomp &b)
							{ return a.fullkey[0] == b.fullkey[0] && a.fullkey[1] == b.fullkey[1] && a.identify == b.identify; });
	full_key_sorted.erase(last, full_key_sorted.end());
	// full_key_sorted.shrink_to_fit();
	printf("fullkey len %d filter_nums %d\n", full_key_sorted.size(), filter_nums);
	// init_filters(filter_nums);//cautious
	// printf("fullkey len %d filter_nums %d\n", fullkey_len, filter_nums);

	printf("complen=%d\n", complen); // 减少的字节数
	delete[] tmp_compress_data;
};
void containers::init_filters(uint32_t filter_nums)
{
	// tmp_ids.resize(1000000 * 8 / bits_per_char, static_cast<unsigned char>(0x00));
	bloom_parameters parameters;
	// parameters.projected_element_count = 0;		 // filter_nums; // 预计插入initialize_size个元素 //cautious
	// parameters.false_positive_probability = 0.1; // 期望的误判率为0.1 cautious
	// parameters.compute_optimal_parameters();	 // 计算最优参数
	// bloom_hash_times = parameters.optimal_parameters.number_of_hashes;
	parameters.random_seed = 0xA5A5A5A5;

	parameters.optimal_parameters.table_size = 1000000 * 8;
	parameters.optimal_parameters.number_of_hashes = 4;
	bloom_hash_times = parameters.optimal_parameters.number_of_hashes;
	printf("bloom_hash_times=%d max_table-size %lld\n", bloom_hash_times, parameters.optimal_parameters.table_size);
	// for (int i = 0; i < 4; i++)
	filters = new bloom_filter(parameters);

	// uint32_t tmp_hash[2], hash_size = ((bloom_hash_times >> 2) + (bloom_hash_times & 0x3 != 0) * 4) * INT_SIZE; // ceil(times/4)*4
	// uint8_t tmp_hash_out[32], bloom_hash[hash_size];
	// for (int i = 0; i < SUBINDEX_NUM; i++)
	// {
	// 	for (int j = 0; j < sub_index_liner[i].size(); j++)
	// 	{
	// 		for (int t = 0; t < bloom_hash_times; t += 4)
	// 		{
	// 			tmp_hash[0] = sub_index_liner[i][j].sub_key;
	// 			tmp_hash[1] = i + t * SUBINDEX_NUM * 2;
	// 			MurmurHash3_x86_128(tmp_hash, 8, hash_seed[0], bloom_hash + t * INT_SIZE);
	// 		}
	// 		filters.insert(bloom_hash, bloom_hash_times * INT_SIZE);
	// 	}
	// }
};
void containers::opt_sub_index()
{
	printf("sub_index_liner size:%d\n", sub_index_liner->size());
	// for (int i = 0; i < 4; i++)
	// {
	// 	std::sort(sub_index_liner[i].begin(), sub_index_liner[i].end(), customCompare);
	// }

	uint32_t sub[SUBINDEX_NUM];
	uint64_t temp_keys[2];
	int j = 0, num = 0, comp_idx = 0;
	uint32_t temp_key = 0;
	uint32_t pre_size = 0;
	vector<uint32_t> temp_vec, temp_vec_new, temp_subkey;
	sub_info_comp temp_sub_info;
	uint32_t begin, end, tmp_begin_add;
	uint32_t comp_size = 0, mask = 0x00000000;
	uint64_t num1 = 0, num2 = 0;
	bool is_combine;
	vector<uint8_t> tmp_ids;
	for (int i = 0; i < SUBINDEX_NUM; i++)
	{
		// 恢复原有顺序
		std::sort(sub_index_liner[0].begin(), sub_index_liner[0].end(), [](sub_information &a, sub_information &b)
				  { return a.identifiers < b.identifiers; });
		for (int f_i = 0, li = 0; f_i < full_key_sorted.size();)
		{
			temp_keys[0] = full_key_sorted[f_i].fullkey[0];
			temp_keys[1] = full_key_sorted[f_i].fullkey[1];
			// cont.get_sub_fingerprint32(sub, temp_keys);
			split(sub, (uint8_t *)temp_keys, sub_index_num, sub_index_plus, sub_keybit);
			sub_index_liner[0][li].sub_key = sub[i];
			li++;

			temp_keys[0] = full_key_sorted[f_i].fullkey[0];
			temp_keys[1] = full_key_sorted[f_i].fullkey[1];
			for (; f_i < full_key_sorted.size() && full_key_sorted[f_i].fullkey[0] == temp_keys[0] && full_key_sorted[f_i].fullkey[1] == temp_keys[1]; f_i++)
				;
		}
		std::sort(sub_index_liner[0].begin(), sub_index_liner[0].end(), customCompare);

		// inc_max_dist[i] = sub_hammdist[i]; // (sub_hammdist[i] >= 3 ? 3 : sub_hammdist[i]);
		printf("loop\n");
		j = 0;
		temp_vec.clear();
		temp_subkey.clear();
		temp_vec_new.clear();
		temp_key = sub_index_liner[0][j].sub_key;
		temp_sub_info.sub_key = temp_key;
		begin = 0;
		end = 0;
		pre_size = 0;
		tmp_begin_add = 0;
		is_combine = false;
		tmp_ids.clear();
		mask = 0x00000000;
		for (; j < sub_index_liner[0].size(); j++)
		{
			if (sub_index_liner[0][j].sub_key == temp_key)
			{
				temp_vec.push_back(sub_index_liner[0][j].identifiers);
			}
			else
			{
				uint32_t same_num = 0;
				for (int t = j; t < sub_index_liner[0].size(); t++)
				{
					if (sub_index_liner[0][t].sub_key == sub_index_liner[0][j].sub_key)
					{
						same_num++;
					}
					else
					{
						break;
					}
				}
				// combine subkey后产生的block大小不应该大于aggre_size
				if ((temp_vec.size() * 2 + 1 + same_num) < aggre_size) // cautious
				{
					temp_subkey.push_back(temp_key);
					temp_subkey.push_back(temp_vec.size() - pre_size);
					pre_size = temp_vec.size();
					temp_key = sub_index_liner[0][j].sub_key;
					temp_sub_info.sub_key = temp_key;
					j--;
					is_combine = true;
					continue;
				}
				if (is_combine)
				{
					temp_subkey.push_back(temp_key);
					temp_subkey.push_back(temp_vec.size() - pre_size);
					pre_size = temp_vec.size();
					// is_combine = false;

					uint32_t total_key = temp_subkey.size() / 2;
					temp_vec_new.push_back(total_key);
					// std::sort(temp_vec.begin(), temp_vec.end());
					for (int t = 0; t < temp_subkey.size(); t += 2)
						temp_vec_new.push_back(temp_subkey[t]);
					// 存储前面所有key对应的len和ids
					//  uint32_t total_id_num = 0;
					//  for (int t = 1; t < temp_subkey.size(); t += 2)
					//  {
					//  	temp_vec_new.push_back(total_id_num);
					//  	total_id_num += temp_subkey[t];
					//  }
					//  temp_vec_new.insert(temp_vec_new.end(), temp_vec.begin(), temp_vec.end());

					// 不存储每个的len，存储-id作为表述
					uint32_t tmp_sum = -temp_vec.size();
					for (int t = 0, k = 0; t < temp_subkey.size(); t++)
					{
						// temp_vec_new.push_back(temp_subkey[t]);
						t++;
						// temp_vec_new.push_back(temp_subkey[t]);
						tmp_sum += temp_subkey[t];
						for (int k0 = k; k < k0 + temp_subkey[t]; k++)
						{
							if (k0 == k)
							{
								temp_vec_new.push_back(-temp_vec[k]);
							}
							else
								temp_vec_new.push_back(temp_vec[k]);
						}
					}

					// temp_vec_new=temp_vec;
					// for (auto val : temp_vec)
					// {
					// 	// temp_vec.push_back();
					// 	// temp_vec_new.push_back(val);
					// 	uint32_t out_id = random_uuid() - 1;
					// 	full_index.push_back(full_index[val]);
					// 	temp_vec_new.push_back(out_id);
					// }
					temp_vec.clear();
					temp_vec = temp_vec_new;
					temp_vec_new.clear();
					temp_subkey.clear();
					pre_size = 0;
				}

				uint32_t similar_num = 0;
				// flag for comb32 0xfffffff
				if (!is_combine && temp_vec.size() > MIN_INC_NUM)
				{
					for (int dt = 0; dt <= inc_max_dist[i]; dt++)
					{
						for (auto &val : C_0_TO_subhammdis[dt])
						{
							if (val == 0)
								continue;
							uint32_t tmpkey1 = temp_key ^ val;
							auto its = std::lower_bound(sub_index_liner[0].begin(), sub_index_liner[0].end(), tmpkey1, compareFirst);
							if (its != sub_index_liner[0].end() && its->sub_key == tmpkey1)
							{
								similar_num += 2; // cautious
							}
						}
					}
					if (similar_num + temp_vec.size() > 10000) // cautious
					{
						similar_num = 0;
						goto out_jmp;
					}
					// the skipSize for near_keys. add 2 for numsOfcomp, comb32
					int comp_len1 = for_compressed_size_sorted(temp_vec.data(), temp_vec.size()) + 2 * sizeof(uint32_t);
					if (comp_len1 < 0)
						printf("error! comp_len is max than int32 %d\n", comp_len1);
					for (uint32_t t = 0, tmp = -comp_len1; t < 4; t++)
					{
						tmp_ids.push_back(tmp & 0xff);

						// sub_identifiers[i].push_back(tmp & 0xff);
						tmp >>= 8;
					}
					mask = MASK_SIM;
					tmp_begin_add += sizeof(uint32_t);
				}

				// the first 4 bytes is the length of the uncompressed data

			out_jmp:
				for (uint32_t t = 0, tmp = temp_vec.size(); t < 4; t++)
				{
					tmp_ids.push_back(tmp & 0xff);
					// sub_identifiers[i].push_back(tmp & 0xff);
					tmp >>= 8;
				}
				tmp_begin_add += sizeof(uint32_t);
				num1 += temp_vec.size();
				// compute the length of the compressed data
				int comp_len = 0;
				if (!is_combine)
				{
					comp_len = for_compressed_size_sorted(temp_vec.data(), temp_vec.size());
					tmp_ids.resize(tmp_ids.size() + comp_len);
					for_compress_sorted(temp_vec.data(), tmp_ids.data() + tmp_ids.size() - comp_len, temp_vec.size());

					// sub_identifiers[i].resize(sub_identifiers[i].size() + comp_len);

					// // compress data
					// //  if the length of the uncompressed data is less than COMPRESS_MIN, we don't compress it
					// for_compress_sorted(temp_vec.data(), sub_identifiers[i].data() + tmp_begin_add + begin, temp_vec.size());
				}
				else
				{
					comp_len = for_compressed_size_unsorted(temp_vec.data(), temp_vec.size());
					tmp_ids.resize(tmp_ids.size() + comp_len);
					for_compress_unsorted(temp_vec.data(), tmp_ids.data() + tmp_ids.size() - comp_len, temp_vec.size());

					// sub_identifiers[i].resize(sub_identifiers[i].size() + comp_len);
					// for_compress_unsorted(temp_vec.data(), sub_identifiers[i].data() + tmp_begin_add + begin, temp_vec.size());
				}
				tmp_begin_add += comp_len;

				if (similar_num)
				{

					for (uint32_t t = 0, tmp = similar_num / 2; t < 4; t++)
					{
						tmp_ids.push_back(tmp & 0xff);
						// sub_identifiers[i].push_back(tmp & 0xff);
						tmp >>= 8;
					}
					// if ((begin + tmp_begin_add + 4) != sub_identifiers[i].size() - 4)
					// 	printf("eror %d ", (begin + tmp_begin_add + 4) - sub_identifiers[i].size() + 4);
					// if (similar_num / 2 != *(uint32_t *)&sub_identifiers[i][begin + tmp_begin_add])
					// 	printf("error !===%d %d", similar_num / 2, *(uint32_t *)&sub_identifiers[i][begin + tmp_begin_add]);

					tmp_ids.resize(tmp_ids.size() + (similar_num) * sizeof(uint32_t));
					// sub_identifiers[i].resize(sub_identifiers[i].size() + (similar_num) * sizeof(uint32_t));
					tmp_begin_add += (similar_num * sizeof(uint32_t)) + sizeof(uint32_t);
				}

				// static uint32_t mnum = 0;
				// if (temp_vec.size() > 200 && !is_combine)
				// {
				// 	sub_cluster[i][temp_key] = begin;
				// 	mnum += temp_vec.size();
				// 	// printf("%d \n", mnum);
				// }

				temp_sub_info.length = tmp_ids.size();
				temp_sub_info.length |= mask;
				if (is_combine)
					temp_sub_info.length |= MASK_INF;

				if (tmp_ids.size() % PAGE_SIZE)
					tmp_ids.resize(tmp_ids.size() + (PAGE_SIZE - tmp_ids.size() % PAGE_SIZE) % PAGE_SIZE);
				enc_page_block(tmp_ids.data(), tmp_ids.size());
				ocall_write_ids(&temp_sub_info.skiplen, id_index[i], i, tmp_ids.data(), tmp_ids.size());

				is_combine = false;
				sub_linear_comp[i].emplace_back(temp_sub_info);

				begin += tmp_begin_add;
				temp_key = sub_index_liner[0][j].sub_key;
				temp_sub_info.sub_key = temp_key;
				temp_vec.clear();
				tmp_begin_add = 0;
				j--;
				tmp_ids.clear();
				mask = 0x00000000;
			}
		}
		// printf("begin %d size %d\n", begin, sub_identifiers[i].size());
		// compress the last sub_key
		if (!temp_vec.empty())
		{
			if (is_combine)
			{
				temp_subkey.push_back(temp_key);
				temp_subkey.push_back(temp_vec.size() - pre_size);
				pre_size = temp_vec.size();
				// is_combine = false;

				uint32_t total_key = temp_subkey.size() / 2;
				temp_vec_new.push_back(total_key);
				// std::sort(temp_vec.begin(), temp_vec.end());
				for (int t = 0; t < temp_subkey.size(); t += 2)
					temp_vec_new.push_back(temp_subkey[t]);
				// uint32_t total_id_num = 0;
				// for (int t = 1; t < temp_subkey.size(); t += 2)
				// {
				// 	temp_vec_new.push_back(total_id_num);
				// 	total_id_num += temp_subkey[t];
				// }
				// temp_vec_new.insert(temp_vec_new.end(), temp_vec.begin(), temp_vec.end());

				// std::sort(temp_vec.begin(), temp_vec.end());
				// uint32_t tmp_sum = 0;
				for (int t = 0, k = 0; t < temp_subkey.size(); t++)
				{
					// temp_vec_new.push_back(temp_subkey[t]);
					t++;
					// temp_vec_new.push_back(temp_subkey[t]);
					// tmp_sum += temp_subkey[t];
					for (int k0 = k; k < k0 + temp_subkey[t]; k++)
					{
						if (k0 == k)
							temp_vec_new.push_back(-temp_vec[k]);
						else
							temp_vec_new.push_back(temp_vec[k]);
					}
				}
				temp_vec.clear();
				temp_vec = temp_vec_new;
				temp_vec_new.clear();
				temp_subkey.clear();
				pre_size = 0;
			}

			for (int t = 0, tmp = temp_vec.size(); t < 4; t++)
			{
				tmp_ids.push_back(tmp & 0xff);
				// sub_identifiers[i].push_back(tmp & 0xff);
				tmp >>= 8;
			}
			// std::sort(temp_vec.begin(), temp_vec.end());

			if (!is_combine)
			{
				int comp_len = for_compressed_size_sorted(temp_vec.data(), temp_vec.size());
				tmp_ids.resize(tmp_ids.size() + comp_len);
				for_compress_sorted(temp_vec.data(), tmp_ids.data() + tmp_ids.size() - comp_len, temp_vec.size());

				// sub_identifiers[i].resize(sub_identifiers[i].size() + comp_len);
				// for_compress_sorted(temp_vec.data(), sub_identifiers[i].data() + begin + 4, temp_vec.size());
			}
			else
			{
				int comp_len = for_compressed_size_unsorted(temp_vec.data(), temp_vec.size());
				tmp_ids.resize(tmp_ids.size() + comp_len);
				for_compress_unsorted(temp_vec.data(), tmp_ids.data() + tmp_ids.size() - comp_len, temp_vec.size());

				// sub_identifiers[i].resize(sub_identifiers[i].size() + comp_len);
				// for_compress_unsorted(temp_vec.data(), sub_identifiers[i].data() + begin + 4, temp_vec.size());
			}

			temp_sub_info.length = tmp_ids.size();
			temp_sub_info.length |= mask;
			if (is_combine)
				temp_sub_info.length |= MASK_INF;

			if (tmp_ids.size() % PAGE_SIZE)
				tmp_ids.resize(tmp_ids.size() + (PAGE_SIZE - tmp_ids.size() % PAGE_SIZE) % PAGE_SIZE);
			enc_page_block(tmp_ids.data(), tmp_ids.size());
			ocall_write_ids(&temp_sub_info.skiplen, id_index[i], i, tmp_ids.data(), tmp_ids.size());
			// printf("ss%d\n", temp_sub_info.begin[0]);

			tmp_ids.clear();
			mask = 0x00000000;
			sub_linear_comp[i].emplace_back(temp_sub_info);
		}
		printf("sub_comp size %d\n", sub_linear_comp[i].size());

		ocall_init_id_point(&id_point[i], id_index[i], i);

		j = 0;
		comp_idx = 0;
		temp_vec.clear();
		temp_subkey.clear();
		temp_vec_new.clear();
		temp_key = sub_index_liner[0][j].sub_key;
		temp_sub_info.sub_key = temp_key;
		begin = 0;
		end = 0;
		pre_size = 0;
		is_combine = false;
		for (; j < sub_index_liner[0].size(); j++)
		{
			if (sub_index_liner[0][j].sub_key == temp_key)
			{
				temp_vec.push_back(sub_index_liner[0][j].identifiers);
			}
			else
			{
				uint32_t same_num = 0;
				for (int t = j; t < sub_index_liner[0].size(); t++)
				{
					if (sub_index_liner[0][t].sub_key == sub_index_liner[0][j].sub_key)
					{
						same_num++;
					}
					else
					{
						break;
					}
				}
				// combine subkey后产生的block大小不应该大于aggre_size
				if ((temp_vec.size() * 2 + 1 + same_num) < aggre_size)
				{
					temp_subkey.push_back(temp_key);
					temp_subkey.push_back(temp_vec.size() - pre_size);
					pre_size = temp_vec.size();
					temp_key = sub_index_liner[0][j].sub_key;
					temp_sub_info.sub_key = temp_key;
					j--;
					is_combine = true;
					continue;
				}
				if (is_combine)
				{
					temp_subkey.push_back(temp_key);
					temp_subkey.push_back(temp_vec.size() - pre_size);
					pre_size = temp_vec.size();
					// is_combine = false;

					uint32_t total_key = temp_subkey.size() / 2;
					temp_vec_new.push_back(total_key);
					// std::sort(temp_vec.begin(), temp_vec.end());
					for (int t = 0; t < temp_subkey.size(); t += 2)
						temp_vec_new.push_back(temp_subkey[t]);
					// 存储前面所有key对应的len和ids
					//  uint32_t total_id_num = 0;
					//  for (int t = 1; t < temp_subkey.size(); t += 2)
					//  {
					//  	temp_vec_new.push_back(total_id_num);
					//  	total_id_num += temp_subkey[t];
					//  }
					//  temp_vec_new.insert(temp_vec_new.end(), temp_vec.begin(), temp_vec.end());

					// 不存储每个的len，存储-id作为表述
					uint32_t tmp_sum = -temp_vec.size();
					for (int t = 0, k = 0; t < temp_subkey.size(); t++)
					{
						// temp_vec_new.push_back(temp_subkey[t]);
						t++;
						// temp_vec_new.push_back(temp_subkey[t]);
						tmp_sum += temp_subkey[t];
						for (int k0 = k; k < k0 + temp_subkey[t]; k++)
						{
							if (k0 == k)
							{
								temp_vec_new.push_back(-temp_vec[k]);
							}
							else
								temp_vec_new.push_back(temp_vec[k]);
						}
					}

					// temp_vec_new=temp_vec;
					// for (auto val : temp_vec)
					// {
					// 	// temp_vec.push_back();
					// 	// temp_vec_new.push_back(val);
					// 	uint32_t out_id = random_uuid() - 1;
					// 	full_index.push_back(full_index[val]);
					// 	temp_vec_new.push_back(out_id);
					// }
					temp_vec.clear();
					temp_vec = temp_vec_new;
					temp_vec_new.clear();
					temp_subkey.clear();
					pre_size = 0;
				}

				// flag for comb32 0xfffffff
				// if (!is_combine && temp_vec.size() > MIN_INC_NUM)
				// {
				// 	int comp_len = for_compressed_size_sorted(temp_vec.data(), temp_vec.size()) + 2 * sizeof(uint32_t);
				// 	if (comp_len < 0)
				// 		printf("error! comp_len is max than int32 %d\n", comp_len);
				// 	for (uint32_t t = 0, tmp = -comp_len; t < 4; t++)
				// 	{
				// 		sub_identifiers[i].push_back(tmp & 0xff);
				// 		tmp >>= 8;
				// 	}
				// }

				// the first 4 bytes is the length of the uncompressed data
				// for (uint32_t t = 0, tmp = temp_vec.size(); t < 4; t++)
				// {
				// 	sub_identifiers[i].push_back(tmp & 0xff);
				// 	tmp >>= 8;
				// }
				// begin += 4;
				num2 += temp_vec.size();
				// compute the length of the compressed data
				int comp_len = 0;
				if (!is_combine)
				{
					comp_len = for_compressed_size_sorted(temp_vec.data(), temp_vec.size());
					// sub_identifiers[i].resize(sub_identifiers[i].size() + comp_len);

					// compress data
					//  if the length of the uncompressed data is less than COMPRESS_MIN, we don't compress it
					// for_compress_sorted(temp_vec.data(), sub_identifiers[i].data() + begin + 4, temp_vec.size());
				}
				else
				{
					comp_len = for_compressed_size_unsorted(temp_vec.data(), temp_vec.size());
					// sub_identifiers[i].resize(sub_identifiers[i].size() + comp_len);
					// for_compress_unsorted(temp_vec.data(), sub_identifiers[i].data() + begin + 4, temp_vec.size());
				}

				begin += comp_len + 4; // size of uncomp

				if (!is_combine && temp_vec.size() > MIN_INC_NUM)
				{
					uint8_t *enc_ids = id_point[i] + sub_linear_comp[i][comp_idx].skiplen;
					uint32_t enc_len = sub_linear_comp[i][comp_idx].length & (~MASK_SIM) & (~MASK_INF);
					uint8_t *dec_ids = new uint8_t[enc_len];
					dec_page_block(enc_ids, enc_len, dec_ids);
					begin = comp_len + sizeof(uint32_t);

					// add Byte for sizeof comb32, size of skipSize
					uint32_t tmpLen = *(uint32_t *)dec_ids, tmps = 0;
					begin += (sizeof(uint32_t) * 2);
					uint32_t wrt_index = begin;
					for (int dt = 0; dt <= inc_max_dist[i]; dt++)
					{
						for (auto &val : C_0_TO_subhammdis[dt])
						{
							if (val == 0)
								continue;
							uint32_t tmpkey1 = temp_key ^ val;
							auto its = std::lower_bound(sub_index_liner[0].begin(), sub_index_liner[0].end(), tmpkey1, compareFirst);
							if (its != sub_index_liner[0].end() && its->sub_key == tmpkey1)
							{
								auto its2 = std::lower_bound(sub_linear_comp[i].begin(), sub_linear_comp[i].end(), tmpkey1, compareFirst_comp);
								if (its2 == sub_linear_comp[i].end() || (its2->sub_key != tmpkey1 && MASK_INF ^ (its2->length & MASK_INF))) //&& its->sub_key == tmpsub1
								{
									printf("error ! subkey %d exist in sub_liner, not int sub_comp\n", tmpkey1);
									// return;
								}
								tmps++;
								for (uint32_t t = 0, tmp = tmpkey1; t < 4; t++)
								{
									dec_ids[t + begin] = (tmp & 0xff);
									// sub_identifiers[i][t + begin] = (tmp & 0xff);
									tmp >>= 8;
								}
								begin += sizeof(uint32_t);
								for (uint32_t t = 0, tmp = (its2 - sub_linear_comp[i].begin()); t < 4; t++)
								{
									dec_ids[t + begin] = (tmp & 0xff);
									// sub_identifiers[i][t + begin] = (tmp & 0xff);
									tmp >>= 8;
								}
								begin += sizeof(uint32_t);
								// for (uint32_t t = 0, tmp = its2->length; t < 4; t++)
								// {
								// 	dec_ids[t + begin] = (tmp & 0xff);
								// 	// sub_identifiers[i][t + begin] = (tmp & 0xff);
								// 	tmp >>= 8;
								// }
								// begin += sizeof(uint32_t);
							}
						}
					}

					enc_page_block(dec_ids, enc_len);
					memcpy(enc_ids, dec_ids, enc_len); // cautious
													   // if (tmps != tmpLen)
													   // {
													   // 	printf("!= %d %d\n", tmps, tmpLen);
													   // 	// return;
													   // }
				}

				comp_idx++;
				// temp_sub_info.begin = begin;
				// if (is_combine)
				// 	temp_sub_info.begin = -temp_sub_info.begin - 1;
				is_combine = false;
				// sub_linear_comp[i].emplace_back(temp_sub_info);

				temp_key = sub_index_liner[0][j].sub_key;
				temp_sub_info.sub_key = temp_key;
				temp_vec.clear();
				pre_size = 0;
				j--;
			}
		}

		// if (num1 != num2)
		// 	printf("%llu!= %llu\n", num1, num2);
		// if (begin != sub_linear_comp[i].size())
		// 	printf("b %d comp%d\n", begin, sub_identifiers[i].size());
		// printf("sub_comp %d\n", sub_linear_comp[i].size());
	}

	printf("subsize:%d\n", sub_map_size);
};

void containers::make_clusters()
{
	int j = 0, num = 0, end_idx = 0;
	uint32_t temp_key = 0;
	uint32_t pre_size = 0, group_num;
	vector<uint32_t> temp_vec, temp_vec_new, temp_subkey;
	sub_info_comp temp_sub_info;
	uint32_t begin, end, tmp_begin_add;
	uint32_t comp_size = 0, tmp_dist = 0, mask = 0x00000000;
	bool is_combine;
	uint32_t nums_tmp = 0;
	uint64_t num1 = 0, num2 = 0;
	vector<uint8_t> tmp_ids;

	uint32_t sub[SUBINDEX_NUM];
	// for (int t = 0; t < SUBINDEX_NUM; t++)
	// {
	// 	if (nums_tmp < sub_index_liner[t].size())
	// 		nums_tmp = sub_index_liner[t].size();
	// }
	nums_tmp = full_key_sorted.size();
	// tmp_linear.resize(nums_tmp);
	resort_que.resize(nums_tmp);

	// for (int i = 0; i < SUBINDEX_NUM; i++)
	// {
	// 	std::sort(sub_index_liner[i].begin(), sub_index_liner[i].end(), customCompare); // cautious
	// }

	printf("cluster 1\n");

	printf("cluster 2\n");
	resort_node tmp_node, tmp_node1;
	info_uncomp tmp_info, tmp_info1;
	int tmp_cluster = 0, dis = 0;
	vector<uint32_t> tmp_clrs;
	vector<uint32_t> tmp_keys;
	uint32_t rq_size = 0;
	vector<uint32_t> max_dist_inClr;
	uint32_t clr_sum_size = 0, clr_max, clr_min;
	for (int i = 0; i < SUBINDEX_NUM; i++)
	{
		for (int t = 0; t < full_key_sorted.size(); t++)
		{
			split(sub, (uint8_t *)full_key_sorted[t].fullkey, sub_index_num, sub_index_plus, sub_keybit);
			full_key_sorted[t].target = sub[i];
		}
		std::sort(full_key_sorted.begin(), full_key_sorted.end(), [](const info_uncomp &a, const info_uncomp &b)
				  { return a.target < b.target; });

		if (min_clr_size < 300)
			clr[i] = kmodes(i);
		cluster_node cl_d;
		// j = 0;
		// temp_vec.clear();
		// temp_key = sub_index_liner[i][j].sub_key;
		// temp_sub_info.sub_key = temp_key;
		// begin = 0;
		// end = 0;
		// cluster_node cl_d;
		// is_combine = false;
		// for (j = 0; j < sub_index_liner[i].size(); j++)
		// {
		// 	if (sub_index_liner[i][j].sub_key == temp_key)
		// 	{
		// 		temp_vec.push_back(sub_index_liner[i][j].identifiers);
		// 	}
		// 	else
		// 	{
		// 		if (temp_vec.size() >= min_clr_size)
		// 		{
		// 			cl_d.subkey = temp_key;
		// 			clr[i].push_back(cl_d);
		// 		}
		// 		temp_key = sub_index_liner[i][j].sub_key;
		// 		temp_vec.clear();
		// 		j--;
		// 	}
		// }
		// // compress the last sub_key
		// if (!temp_vec.empty())
		// {
		// 	if (temp_vec.size() >= min_clr_size)
		// 	{
		// 		cl_d.subkey = temp_key;
		// 		clr[i].push_back(cl_d);
		// 	}
		// }
		// don't sort cluster
		//  add one more for stash
		cl_d.subkey = -1; // without practical meaning
		clr[i].push_back(cl_d);
		printf("clr_size %d %d\n", i, clr[i].size());
		// }
		// for (int i = 0; i < SUBINDEX_NUM; i++)
		// {

		clr_sum_size = 0;
		clr_max = 0;
		clr_min = UINT32_MAX;
		printf("hashtimes %d cluster 3 %d %d\n", bloom_hash_times, i, SUBINDEX_NUM);
		rq_size = 0;
		tmp_clrs.clear();

		clr_nums.clear();
		// resort_que.clear();
		clr_nums.resize(clr[i].size());
		max_dist_inClr.resize(clr[i].size());
		for (int j = 0; j < full_key_sorted.size(); j++)
		{
			tmp_dist = UINT32_MAX;
			tmp_cluster = -1;
			// tmp_node.sub_info.sub_key = sub_index_liner[i][j].sub_key;
			// tmp_node.sub_info.identifiers = sub_index_liner[i][j].identifiers;

			// tmp_node.sub_info.sub_key = full_key_sorted[j].target;
			// tmp_node.sub_info.identifiers = full_key_sorted[j].identify;

			for (int t = 0; t < (clr[i].size() - 1); t++)
			{
				dis = popcount(full_key_sorted[j].target ^ clr[i][t].subkey);
				if (dis < tmp_dist)
				{
					tmp_clrs.clear();
					tmp_clrs.push_back(t);
					tmp_cluster = t;
					tmp_dist = dis;
				}
				else if (dis == tmp_dist)
				{
					// tmp_clrs.push_back(t);
				}
			}
			if (tmp_cluster >= 0 && tmp_dist <= max_dist) // cautious
			{
				if (tmp_dist > max_dist_inClr[tmp_cluster])
					max_dist_inClr[tmp_cluster] = tmp_dist;
				for (auto &val : tmp_clrs)
				{
					tmp_node.cluster_id = val;
					// tmp_node.my_id = clr_nums[val];
					clr_nums[val]++;
					if (rq_size >= resort_que.size())
						printf("error rq_size %d %d\n", rq_size, resort_que.size());
					resort_que[rq_size] = tmp_node;
					rq_size++;
				}
				// tmp_node.cluster_id = tmp_cluster;
				// tmp_node.my_id = clr_nums[tmp_cluster];
				// clr_nums[tmp_cluster]++;
				// resort_que[j] = tmp_node;
			}
			else
			{
				tmp_cluster = clr[i].size() - 1;
				tmp_node.cluster_id = clr[i].size() - 1;
				// tmp_node.my_id = clr_nums[tmp_cluster];
				clr_nums[tmp_cluster]++;
				// resort_que[j] = tmp_node;
				if (rq_size >= resort_que.size())
					printf("error rq_size %d %d\n", rq_size, resort_que.size());
				resort_que[rq_size] = tmp_node;
				rq_size++;
			}
		}

		uint32_t minxx = 0;
		for (auto val : max_dist_inClr)
		{
			if (val < max_dist)
				minxx++;
		}
		printf("minxx-------------------- %d %d\n", minxx, clr[i].size() - 1);

		nums_tmp = 0;
		for (int t = 0; t < clr[i].size(); t++)
		{
			nums_tmp += clr_nums[t];
		}
		// printf("cluster 4 last-size%d total-num%d sub-linear-size %d\n", clr_nums[clr[i].size() - 1], nums_tmp, sub_index_liner[i].size());
		clr[i][0].begin_idx = 0;
		for (int t = 1; t < clr[i].size(); t++)
		{
			if (clr_nums[t - 1] == 0)
				printf("error no node in cluster  %d\n", t);
			clr[i][t].begin_idx = clr[i][t - 1].begin_idx + clr_nums[t - 1];
		}

		vector<uint32_t> tmp_clr_nums;
		tmp_clr_nums.resize(clr[i].size());
		// cluster_id is the index for each node sort by cluster {0,0,0,  2,2,2 1,1,} =>  {0,1,2, 5,6,7  3,4,}
		for (auto &val : resort_que)
		{
			tmp_clr_nums[val.cluster_id]++;
			val.cluster_id = tmp_clr_nums[val.cluster_id] - 1 + clr[i][val.cluster_id].begin_idx;
		}
		uint32_t tmp_index = 0, changed_index;
		for (int j = 0; j < rq_size; j++)
		{
			tmp_node1 = resort_que[j];
			tmp_info1 = full_key_sorted[j];
			tmp_index = resort_que[j].cluster_id;
			if (j == tmp_index)
				continue;
			changed_index = j;
			while (changed_index != tmp_index)
			{
				tmp_node = resort_que[tmp_index];
				tmp_info = full_key_sorted[tmp_index];

				full_key_sorted[tmp_index] = tmp_info1;
				resort_que[tmp_index] = tmp_node1;
				changed_index = tmp_index;

				tmp_info1 = tmp_info;
				tmp_node1 = tmp_node;
				tmp_index = tmp_node.cluster_id;
			}
		}
		// for (auto it = clr[i].begin(); it < clr[i].end();)
		// {
		// 	if (it->begin_idx == (it + 1)->begin_idx)
		// 		it = clr[i].erase(it);
		// 	else
		// 		it++;
		// }
		// printf("idx %d idx1 %d\n", clr[i][clr[i].size() - 1].begin_idx + clr_nums[clr[i].size() - 1], resort_que.size());
		// int maxmm = -1;
		// for (int j = 0; j < resort_que.size(); j++)
		// {
		// 	if (resort_que[j].cluster_id != maxmm && clr[i][resort_que[j].cluster_id].begin_idx + resort_que[j].my_id > resort_que.size())
		// 	{
		// 		maxmm = resort_que[j].cluster_id;
		// 		printf("error %d %d %d\n", resort_que.size(), clr[i][resort_que[j].cluster_id].begin_idx + resort_que[j].my_id, resort_que[j].cluster_id);
		// 	}
		// }

		// let same cluster's node in same region
		// for (int j = 0; j < rq_size; j++)
		// {
		// 	tmp_index = clr[i][resort_que[j].cluster_id].begin_idx + resort_que[j].my_id;
		// 	if (j == tmp_index)
		// 		continue;
		// 	changed_index = j;
		// 	tmp_node1 = resort_que[j];
		// 	tmp_info1 = full_key_sorted[j];
		// 	// cautious ,loop for changde to a right position
		// 	while (changed_index != tmp_index)
		// 	{
		// 		if (tmp_index >= resort_que.size())
		// 			printf("error index %d of maxsize %d\n", tmp_index, resort_que.size());
		// 		tmp_node = resort_que[tmp_index];
		// 		tmp_info = full_key_sorted[tmp_index];

		// 		full_key_sorted[tmp_index] = tmp_info1;
		// 		resort_que[tmp_index] = tmp_node1;
		// 		changed_index = tmp_index;

		// 		tmp_info1 = tmp_info;
		// 		tmp_node1 = tmp_node;
		// 		tmp_index = tmp_node.my_id + clr[i][tmp_node.cluster_id].begin_idx;
		// 	}
		// }

		for (int t = 0; t < clr[i].size() - 1; t++)
		{
			clr_sum_size = clr[i][t + 1].begin_idx - clr[i][t].begin_idx;
			if (clr_sum_size > clr_max)
				clr_max = clr_sum_size;
			if (clr_sum_size < clr_min)
				clr_min = clr_sum_size;
		}
		printf("avg %.2f cluster 4.1 max %d min %d\n", (double)(full_key_sorted.size() - clr[i][clr[i].size() - 1].begin_idx) / (clr[i].size() - 1), clr_max, clr_min);
		if (clr[i].size() > 1)
			combine_clr_min = ceil((double)(full_key_sorted.size() - clr[i][clr[i].size() - 1].begin_idx) / ((clr[i].size() - 1) * 4));

		printf("cluster 5 %d\n", rq_size);
		// sort every cluster? (if not sorted)

		// inc_max_dist[i] = (sub_hammdist[i] >= 3 ? 3 : sub_hammdist[i]);
		uint32_t *begin_s = new uint32_t[clr[i].size()];
		for (int t = 0; t < clr[i].size(); t++)
		{
			begin_s[t] = clr[i][t].begin_idx;
		}
		tmp_linear_size = 0;
		num1 = 0;
		num2 = 0;
		uint32_t *test_clr = new uint32_t[clr[i].size()];

		for (int c_idx = 0; c_idx < (clr[i].size()); c_idx++)
		{
			j = clr[i][c_idx].begin_idx;
			clr[i][c_idx].begin_idx = sub_linear_comp[i].size();
			begin = sub_identifiers[i].size();
			test_clr[c_idx] = begin;

			temp_subkey.clear();
			temp_vec_new.clear();
			temp_vec.clear();
			tmp_keys.clear();

			temp_key = full_key_sorted[j].target; // resort_que[j].sub_info.sub_key;
			temp_sub_info.sub_key = temp_key;
			pre_size = 0;
			tmp_begin_add = 0;
			end = 0;
			is_combine = false;
			group_num = 1;

			if (c_idx == clr[i].size() - 1)
				end_idx = rq_size;
			else
				end_idx = clr[i][c_idx + 1].begin_idx;

			bool is_comb_clr = ((end_idx - j) > combine_clr_min ? true : false); //(c_idx == clr[i].size() - 1 ? true : false);//true; //
			// bool is_comb_clr = (c_idx == clr[i].size() - 1 ? true : false); // cautious TODO
			if (!is_comb_clr)
				clr[i][c_idx].is_combined = 0;
			else
				clr[i][c_idx].is_combined = 1;

			for (; j < end_idx; j++)
			{
				if (full_key_sorted[j].target == temp_key)
				{
					temp_vec.push_back(full_key_sorted[j].identify);
				}
				else
				{
					uint32_t same_num = 0;
					for (int t = j; t < end_idx; t++)
					{
						if (full_key_sorted[t].target == full_key_sorted[j].target)
						{
							same_num++;
						}
						else
						{
							break;
						}
					}
					// combine subkey后产生的block大小不应该大于aggre_size
					if (is_comb_clr && (temp_vec.size() + temp_subkey.size() + 4 + 1 + same_num) <= PAGE_SIZE)
					{
						group_num++;
						num2++;
						tmp_keys.push_back(temp_key);

						temp_subkey.push_back(temp_key);
						temp_subkey.push_back(temp_vec.size() - pre_size);
						pre_size = temp_vec.size();
						temp_key = full_key_sorted[j].target;
						temp_sub_info.sub_key = temp_key;
						j--;
						is_combine = true;
						continue;
					}
					if (is_combine)
					{
						temp_subkey.push_back(temp_key);
						temp_subkey.push_back(temp_vec.size() - pre_size);
						pre_size = temp_vec.size();
						// is_combine = false;

						uint32_t total_key = temp_subkey.size() / 2;
						temp_vec_new.push_back(total_key);
						// // std::sort(temp_vec.begin(), temp_vec.end());
						// for (int t = 0; t < temp_subkey.size(); t += 2)
						// 	temp_vec_new.push_back(temp_subkey[t]);

						// 不存储每个的len，存储-id作为表述
						uint32_t tmp_sum = -temp_vec.size();
						for (int t = 0, k = 0; t < temp_subkey.size(); t++)
						{
							temp_vec_new.push_back(temp_subkey[t]);
							t++;
							temp_vec_new.push_back(temp_subkey[t]);
							tmp_sum += temp_subkey[t];
							for (int k0 = k; k < k0 + temp_subkey[t]; k++)
							{
								// if (k0 == k)
								// {
								// 	temp_vec_new.push_back(-temp_vec[k] - 1);
								// }
								// else
								temp_vec_new.push_back(temp_vec[k]);
							}
						}
						temp_vec_new[0] = temp_vec_new.size(); // cautious for combine

						temp_vec.clear();
						temp_vec = temp_vec_new;
						temp_vec_new.clear();
						temp_subkey.clear();
						pre_size = 0;
						if (temp_vec.size() > PAGE_SIZE)
							printf("error of aggre_size! %d\n", temp_vec.size());
					}

					// // flag for comb32 0xfffffff
					// uint32_t similar_num = 0;
					// if (!is_combine && temp_vec.size() > MIN_INC_NUM)
					// {
					// 	for (int dt = 0; dt <= inc_max_dist[i]; dt++)
					// 	{
					// 		for (auto &val : C_0_TO_subhammdis[dt])
					// 		{
					// 			if (val == 0)
					// 				continue;
					// 			uint32_t tmpkey1 = temp_key ^ val;
					// 			auto its = std::lower_bound(sub_index_liner[i].begin(), sub_index_liner[i].end(), tmpkey1, compareFirst);
					// 			if (its != sub_index_liner[i].end() && its->sub_key == tmpkey1)
					// 			{
					// 				similar_num += 2; // cautious
					// 			}
					// 		}
					// 	}
					// 	if (similar_num + temp_vec.size() > 5000) // cautious
					// 	{
					// 		similar_num = 0;
					// 		goto out_jmp;
					// 	}
					// 	// the skipSize for near_keys. add 2 for numsOfcomp, comb32
					// 	int comp_len1 = for_compressed_size_sorted(temp_vec.data(), temp_vec.size()) + 2 * sizeof(uint32_t);
					// 	if (comp_len1 < 0)
					// 		printf("error! comp_len is max than int32 %d\n", comp_len1);
					// 	for (uint32_t t = 0, tmp = -comp_len1; t < 4; t++)
					// 	{
					// 		tmp_ids.push_back(tmp & 0xff);
					// 		// sub_identifiers[i].push_back(tmp & 0xff);
					// 		tmp >>= 8;
					// 	}
					// 	mask = MASK_SIM;
					// 	tmp_begin_add += sizeof(uint32_t);
					// }

					uint32_t temp_vec_size = temp_vec.size() * sizeof(uint32_t);
					tmp_ids.resize(temp_vec_size);
					memcpy(tmp_ids.data(), temp_vec.data(), temp_vec_size);

					// the first 4 bytes is the length of the uncompressed data
				out_jmp:
					num1 += temp_vec.size();

					max_id_page = std::max(max_id_page, temp_vec_size);
					temp_sub_info.length = temp_vec.size();
					// temp_sub_info.length |= mask;
					if (is_combine)
					{
						temp_sub_info.length = -1; //|= MASK_INF
						tmp_ids.resize(tmp_ids.size() + (PAGE_SIZE_B - tmp_ids.size() % PAGE_SIZE_B) % PAGE_SIZE_B);
						if (tmp_ids.size() != PAGE_SIZE_B)
							printf("error tmpids_size! %d\n", tmp_ids.size());
					}

					enc_page_block(tmp_ids.data(), tmp_ids.size());
					if (tmp_ids.size() % PAGE_SIZE_B) //*4 byte
						tmp_ids.resize(tmp_ids.size() + (PAGE_SIZE_B - tmp_ids.size() % PAGE_SIZE_B) % PAGE_SIZE_B);
					ocall_write_ids(&temp_sub_info.skiplen, id_index[i], i, tmp_ids.data(), tmp_ids.size());

					tmp_ids.clear();
					mask = 0;
					is_combine = false;
					sub_linear_comp[i].emplace_back(temp_sub_info);

					tmp_keys.push_back(temp_sub_info.sub_key);
					num2++;
					tmp_keys.clear();

					begin += tmp_begin_add;
					temp_key = full_key_sorted[j].target;
					temp_sub_info.sub_key = temp_key;
					group_num++;
					temp_vec.clear();
					tmp_begin_add = 0;
					j--;
				}
			}
			if (temp_vec.size() != 0)
			{
				if (is_combine)
				{
					temp_subkey.push_back(temp_key);
					temp_subkey.push_back(temp_vec.size() - pre_size);
					pre_size = temp_vec.size();
					// is_combine = false;

					uint32_t total_key = temp_subkey.size() / 2;
					temp_vec_new.push_back(total_key);
					// // std::sort(temp_vec.begin(), temp_vec.end());
					// for (int t = 0; t < temp_subkey.size(); t += 2)
					// 	temp_vec_new.push_back(temp_subkey[t]);

					// std::sort(temp_vec.begin(), temp_vec.end());
					// uint32_t tmp_sum = 0;
					for (int t = 0, k = 0; t < temp_subkey.size(); t++)
					{
						temp_vec_new.push_back(temp_subkey[t]);
						t++;
						temp_vec_new.push_back(temp_subkey[t]);
						// tmp_sum += temp_subkey[t];
						for (int k0 = k; k < k0 + temp_subkey[t]; k++)
						{
							// if (k0 == k)
							// 	temp_vec_new.push_back(-temp_vec[k] - 1);
							// else
							temp_vec_new.push_back(temp_vec[k]);
						}
					}
					temp_vec_new[0] = temp_vec_new.size(); // cautious for combine
					temp_vec.clear();
					temp_vec = temp_vec_new;
					temp_vec_new.clear();
					temp_subkey.clear();
					pre_size = 0;
					if (temp_vec.size() > PAGE_SIZE)
						printf("error of aggre_size! %d\n", temp_vec.size());
				}

				tmp_ids.resize(temp_vec.size() * sizeof(uint32_t));
				memcpy(tmp_ids.data(), temp_vec.data(), temp_vec.size() * sizeof(uint32_t));
				max_id_page = std::max(max_id_page, (uint32_t)tmp_ids.size());
				temp_sub_info.length = temp_vec.size();
				// temp_sub_info.length |= mask;
				if (is_combine)
				{
					temp_sub_info.length = -1; // |= MASK_INF;
					tmp_ids.resize(tmp_ids.size() + (PAGE_SIZE_B - tmp_ids.size() % PAGE_SIZE_B) % PAGE_SIZE_B);
					if (tmp_ids.size() != PAGE_SIZE_B)
						printf("error tmpids_size! %d\n", tmp_ids.size());
				}

				enc_page_block(tmp_ids.data(), tmp_ids.size());
				if (tmp_ids.size() % PAGE_SIZE_B)
					tmp_ids.resize(tmp_ids.size() + (PAGE_SIZE_B - tmp_ids.size() % PAGE_SIZE_B) % PAGE_SIZE_B);
				ocall_write_ids(&temp_sub_info.skiplen, id_index[i], i, tmp_ids.data(), tmp_ids.size());

				tmp_keys.push_back(temp_sub_info.sub_key);
				// for (auto val : tmp_keys)
				// {
				// 	tmp_linear[tmp_linear_size] = (sub_info_comp{val, temp_sub_info.skiplen, sub_linear_comp[i].size()}); // cautious for .size is the pointer to sub_comp
				// 	tmp_linear_size++;
				// }

				tmp_keys.clear();
				sub_linear_comp[i].emplace_back(temp_sub_info);

				tmp_ids.clear();
				mask = 0;
			}
			clr[i][c_idx].group_size = group_num;
		}

		ocall_init_id_point(&id_point[i], id_index[i], i);

		uint32_t comp_idx = 0;
		printf("clr %d\n", num1++);

		for (auto it = clr[i].begin(); it < clr[i].end() - 1;)
		{
			if (it->begin_idx == (it + 1)->begin_idx)
				it = clr[i].erase(it);
			else
				it++;
		}

		printf("cluster 6\n");
	}
#if CACHE_SIZE < 500000
	for (auto &val : full_index)
	{
		add_sum += val.len;
	}
	for (int i = 0; i < SUBINDEX_NUM; i++)
	{
		for (int j = 0; j < sub_linear_comp[i].size(); j++)
		{
			add_sum += sub_linear_comp[i][j].length;
		}
	}
	for (int t = 0; t < SUBINDEX_NUM; t++)
	{
		for (auto &val : clr[t])
		{
			add_sum += val.begin_idx;
		}
	}
	printf("add %d\n", add_sum);
#endif
	printf("subsize:%d\n", sub_map_size);
	printf("resort_que size %d\n", resort_que.size());
};
void containers::init_sub_maps(){
	// int index[4] = {0};
	// // for(int i=0;i<4;i++)index[i]=sub_index_liner[i][0];
	// sub_nodes = new sub_index_node *[4];
	// for (int i = 0; i < 4; i++)
	// {
	// 	sub_nodes[i] = new sub_index_node[sub_map_size];
	// }
	// // randomly select node to insert the sub_index
	// for (int k = 0; k < 4; k++)
	// {
	// 	for (int i = 0; sub_index[k].size() < sub_map_size && i < sub_map_size * 20; i++) // sub_index[k].size()
	// 	{
	// 		sgx_read_rand(reinterpret_cast<unsigned char *>(&index[k]), sizeof(int));
	// 		index[k] = index[k] % sub_linear_comp[k].size();
	// 		uint32_t temp = sub_linear_comp[k][index[k]].sub_key;
	// 		// for(;index[k]>0&&temp==sub_index_liner[k][index[k]-1].sub_key;index[k]--);
	// 		auto its = sub_linear_comp[k].begin() + index[k];
	// 		if (sub_index[k].find(temp) == sub_index[k].end())
	// 		{
	// 			lru_index_add(k, its->sub_key, its->begin); // int temps=index[k];
	// 														// for(;its->sub_key==temp&&its<sub_linear_comp[k].end();its++,index[k]++);

	// 			// vector<uint32_t> temp_vec;
	// 			// temp_vec.push_back(its->begin);
	// 			// for (auto &val : C_0_TO_subhammdis[k])
	// 			// {
	// 			// 	uint32_t temp_key = temp ^ val;
	// 			// 	if (filters[k].contains(temp_key))
	// 			// 	{
	// 			// 		auto its = std::lower_bound(sub_linear_comp[k].begin(), sub_linear_comp[k].end(), temp_key, compareFirst_comp);
	// 			// 		if (its != sub_linear_comp[i].end() && its->sub_key == temp_key)
	// 			// 		{
	// 			// 			temp_vec.push_back(its->begin);
	// 			// 		}
	// 			// 	}
	// 			// }
	// 			// lru_index_add(k, temp, temp_vec);
	// 		}
	// 	}
	// }
	// // printf sub_index size
	// for (int i = 0; i < 4; i++)
	// {
	// 	printf("sub_index%d size:%d\n", i, sub_index[i].size());
	// }
};

void ecall_find_one(void *dataptr, uint32_t *res, uint32_t *res_len, uint32_t pre_len, uint64_t hammdist)
{
	cont.successful_num = 0;
	cont.changeHammingDist(hammdist, 0);

	EcallCrypto *cryptoObj = new EcallCrypto(CIPHER_TYPE, HASH_TYPE);
	EVP_MD_CTX *mdCtx = EVP_MD_CTX_new();
	EVP_CIPHER_CTX *cipherCtx_ = EVP_CIPHER_CTX_new();
	uint8_t *sessionKey_ = const_sessionKey;

	uint8_t *dataE = reinterpret_cast<uint8_t *>(dataptr);
	int dataSize = cont.keybit / 8;
	cryptoObj->SessionKeyDec(cipherCtx_, dataE,
							 dataSize, sessionKey_,
							 dataE);

	printf("nums%d\n", (uint64_t *)dataE[0]);
	uint64_t *data = reinterpret_cast<uint64_t *>(dataE);
	std::vector<uint32_t> res_set = cont.find_sim(data, 0, 0);
	uint8_t *res_old = reinterpret_cast<uint8_t *>(res);
	for (auto &it : res_set)
	{
		*res = it;
		res++;
	}
	*res_len = res_set.size();
	//*len=res_set.size();
	cryptoObj->SessionKeyEnc(cipherCtx_, (uint8_t *)res_old, *res_len * sizeof(uint32_t), sessionKey_, (uint8_t *)res_old);
	printf("Successfully found  photos! successful_num=%d.\n", res_set.size());
	// printf("%d",sign_data.size());
}
void ecall_find_batch(void *dataptr, uint32_t *res, uint32_t len, uint32_t len_res, uint64_t hammdist, int client_id)
{
	cont.successful_num = 0;
	candi_num = 0;

	cont.changeHammingDist(hammdist, client_id);

	EcallCrypto *cryptoObj = new EcallCrypto(CIPHER_TYPE, HASH_TYPE);
	EVP_MD_CTX *mdCtx = EVP_MD_CTX_new();
	EVP_CIPHER_CTX *cipherCtx_ = EVP_CIPHER_CTX_new();
	uint8_t *sessionKey_ = const_sessionKey;

	uint8_t *dataE = reinterpret_cast<uint8_t *>(dataptr);
	int dataSize = sizeof(uint64_t) * len * 2;

	cryptoObj->SessionKeyDec(cipherCtx_, dataE,
							 dataSize, sessionKey_,
							 dataE);
	uint8_t *res_old = reinterpret_cast<uint8_t *>(res);
	Query_batch_t query;
	query.sendData = res;
	*(query.sendData) = len;
	query.index = query.sendData + 1;
	query.dataBuffer = query.sendData + 1 * (len + 1);
	uint64_t *data = reinterpret_cast<uint64_t *>(dataE);
	uint64_t temp2[2];
	printf("query len=%d\n", len);
	for (int i = 0; i < len; i++)
	{
		temp2[0] = data[2 * i];
		temp2[1] = data[2 * i + 1];
		vector<uint32_t> res_set = cont.find_sim(temp2, 0, client_id);
		query.index[i] = res_set.size();
		// printf("res_set.size()=%d\n",res_set.size());
		for (auto &it : res_set)
		{
			*(query.dataBuffer) = it;
			query.dataBuffer++;
		}
	}

	printf("successful_num=%d cand%d\n", cont.successful_num, candi_num);
	//*len=res_set.size();
	cryptoObj->SessionKeyEnc(cipherCtx_, (uint8_t *)res_old, len_res * sizeof(uint32_t), sessionKey_, (uint8_t *)res_old);
	// printf("Successfully found  photos! successful_num=%d.\n",res_set.size());
	printf("%d", sign_data.size());

	total_time /= 1e6;
	find_time /= 1e6;
	insert_time /= 1e6;
	verify_time /= 1e6;
	printf("resize times %d size %lld\n", resize_times, resize_size);

	// total时间（ms）， find：查询map和linear的时间，insert：插入到set<candidate>的时间，verify：验证candidate的时间
	printf("total=time:%d,sum:%d, find-time:%d, insert-time:%d, verify-time:%d\n", total_time, find_time + insert_time + verify_time, find_time, insert_time, verify_time);
	for (int t = 0; t < 6; t++)
		bd_time[t] /= 1e6;
	printf("cal-cer one %d, bitmask %d, stash %d, cluster %d\n", bd_time[0], bd_time[1], bd_time[2], bd_time[3]);
	delete cryptoObj;
}

// move the visited node to the tail of the list
void containers::lru_index_visit(int sub_i, sub_index_node *node){
	// // if node->pre==this, the node is not in LRU list, return
	// if (node->pre == nullptr || node->pre == new_data_head[sub_i])
	// 	return;
	// if (node == lru_n[sub_i].index_tail)
	// 	return; // if the node is the tail of the list,return
	// // move the node to the tail of the index list
	// node->next->pre = node->pre;
	// node->pre->next = node->next;
	// node->pre = lru_n[sub_i].index_tail;
	// lru_n[sub_i].index_tail->next = node;
	// lru_n[sub_i].index_tail = node;
};

// add the node to the tail of the list
void containers::lru_index_add(int sub_i, uint32_t sub_key, int begin){
	// // if(sub_index[sub_i].find(sub_key)!=sub_index[sub_i].end())
	// // 	return;

	// // if the size of the index list is larger than the max size,remove the first node
	// sub_index_node *remove_node = nullptr;
	// if (lru_n[sub_i].index_size >= lru_n[sub_i].map_size)
	// {
	// 	remove_node = lru_n[sub_i].index_head->next;
	// 	sub_index_node *first = remove_node->next;
	// 	lru_n[sub_i].index_head->next = first;
	// 	first->pre = lru_n[sub_i].index_head;
	// 	auto tmp = sub_index[sub_i].find(remove_node->sub_key);

	// 	// if tmp is not in the new_data_head,remove it from the map
	// 	if (tmp != sub_index[sub_i].end() && tmp->second->pre == lru_n[sub_i].index_head)
	// 		sub_index[sub_i].erase(remove_node->sub_key);
	// 	remove_node->pre = nullptr;
	// 	remove_node->next = nullptr;
	// }
	// else
	// {
	// 	lru_n[sub_i].index_size++;
	// }

	// // add node to the tail of the LRU list
	// sub_index_node *node = nullptr;
	// if (remove_node == nullptr)
	// 	node = &cont.sub_nodes[sub_i][lru_n[sub_i].index_size - 1]; // new sub_index_node{node_liner->sub_key,node_liner,nullptr,nullptr};
	// else
	// 	node = remove_node;

	// // change the sub_key and begin of the node
	// // node->sub_key = node_liner->sub_key;
	// node->begin = begin;
	// node->sub_key = sub_key;
	// // node->begin.clear();
	// // node->begin.resize(begin_index.size());
	// // memcpy(node->begin.data(), begin_index.data(), begin_index.size() * sizeof(uint32_t));

	// node->next = nullptr;
	// node->pre = nullptr;
	// sub_index[sub_i][node->sub_key] = node;

	// // move the node to the tail of the LRU list
	// lru_n[sub_i].index_tail->next = node;
	// node->pre = lru_n[sub_i].index_tail;
	// lru_n[sub_i].index_tail = node;
};

// 线性遍历，测试数据集中的特征值分布情况
struct ComparePairs
{
	// 重载函数调用运算符，定义比较规则
	bool operator()(const std::pair<uint32_t, uint32_t> &lhs, const std::pair<uint32_t, uint32_t> &rhs) const
	{
		// 自定义比较规则：按照第二个元素（第二个uint32_t）降序排序
		return lhs.second < rhs.second;
	}
};
void find_sim_linear(vector<pair<uint64_t, uint64_t>> test_pool, vector<uint32_t> target_pool)
{
	unordered_set<pair<uint64_t, uint64_t>, pair_hash> candidate;
	uint64_t cmp_hamm[2] = {0};
	uint32_t count = 0;
	int is = 0;
	uint32_t unequal = 0;
	for (auto &val : cont.full_key_sorted)
	{
		// candidate.insert({val.fullkey[0], val.fullkey[1]});
		int i = 0;
		for (auto &query : test_pool)
		{
			cmp_hamm[0] = query.first ^ (val.fullkey[0]);
			cmp_hamm[1] = query.second ^ (val.fullkey[1]);
			count = bitset<64>(cmp_hamm[0]).count() + bitset<64>(cmp_hamm[1]).count();
			if (count <= cont.hammdist[0])
			{
				cont.successful_num++;
				if (val.target != target_pool[i])
				{
					unequal++;
					// printf("%d target\n", val.target);
				}
			}
			i++;
		}
	}
	printf("%d unequal target%d \n", unequal, target_pool.size());
	// printf("candidate size:%lu\n", candidate.size());
}
void find_topk(uint64_t query[])
{
	uint64_t cmp_hamm[2] = {0};
	uint32_t count = 0, begin = 0;
	uint32_t heap_size = 4000;
	std::priority_queue<std::pair<uint32_t, uint32_t>, std::vector<std::pair<uint32_t, uint32_t>>, ComparePairs> maxHeap;
	for (auto &val : cont.full_key_sorted)
	{
		cmp_hamm[0] = query[0] ^ (val.fullkey[0]);
		cmp_hamm[1] = query[1] ^ (val.fullkey[1]);
		count = bitset<64>(cmp_hamm[0]).count() + bitset<64>(cmp_hamm[1]).count();
		maxHeap.push({begin, count});
		if (maxHeap.size() > heap_size)
			maxHeap.pop();
		begin++;
	}
	vector<std::pair<uint32_t, uint32_t>> tmp;
	for (int i = 0; i < heap_size; i++)
	{
		// printf("index:%u hammdist:%u\n", maxHeap.top().first, maxHeap.top().second);
		tmp.push_back({maxHeap.top().first, maxHeap.top().second});
		maxHeap.pop();
	}
	for (int i = tmp.size() - 1; i >= 0; i--)
		printf("x:%d index:%u hammdist:%u\n", tmp.size() - i, tmp[i].first, tmp[i].second);
}
// TODO: insert functions，ignored
/*
//add the node in the new_data_head list to the linear list
void containers::insert_new_datamap(int sub_i){
	vector<sub_information> tmp_sub_vector;
	sub_information sub_info;
	sub_index_node* node = new_data_head[sub_i]->next;
	new_data_head[sub_i]->next = nullptr;
	while(node != nullptr){
		if(node->pre == new_data_head[sub_i]){
			for(auto &it:node->identifiers){
				sub_info.sub_key=node->sub_key;
				sub_info.identifiers=it;
				tmp_sub_vector.push_back(sub_info);
			}
		}else{
			for(auto &it:node->identifiers){
				sub_info.sub_key=node->sub_key;
				sub_info.identifiers=it;
				auto is_exists = std::lower_bound(sub_index_liner[sub_i].begin(),sub_index_liner[sub_i].end() , sub_info, customCompare);
				//insert the un-exists data to the linear list
				if(is_exists == sub_index_liner[sub_i].end()||is_exists->sub_key!=sub_info.sub_key)tmp_sub_vector.push_back(sub_info);
			}
		}
		sub_index_node* tmp = node;
		node = node->next;
		sub_index[sub_i].erase(tmp->sub_key);
		delete tmp;
	}

	//insert to linear list
	std::sort(tmp_sub_vector.begin(),tmp_sub_vector.end(),customCompare);
	sub_index_liner[sub_i].reserve(sub_index_liner[sub_i].size()+(tmp_sub_vector.size()<1000?1000:tmp_sub_vector.size()));
	sub_index_liner[sub_i].insert(sub_index_liner[sub_i].end(), tmp_sub_vector.begin(), tmp_sub_vector.end());
	std::inplace_merge(sub_index_liner[sub_i].begin(), sub_index_liner[sub_i].end()-tmp_sub_vector.size(), sub_index_liner[sub_i].end(), customCompare);
	initialize_size+=tmp_sub_vector.size();
	change_sub_map(sub_i);
};
//insert the data to the submap
void containers::insert_to_submap(int sub_i,uint32_t sub_key,uint32_t identifier){
	auto sub_node = sub_index[sub_i].find(sub_key);
	if(sub_node != sub_index[sub_i].end()){
		//if the sub_node is not in LRU, add new data directly because its vector has all data with same sub_key
		if(sub_node->second->pre==nullptr||sub_node->second->pre==new_data_head[sub_i]){
			sub_node->second->identifiers.push_back(identifier);
			return;
		}
		//if the sub_node is in LRU, add the identifiers in old_node to the new_node, and remove the useless old_node from sub_index
		//the new node is in the new_data_head list,not in the LRU list
		sub_index_node* tmp = new sub_index_node{sub_key,vector<uint32_t>(),nullptr,nullptr};
		tmp->next = new_data_head[sub_i]->next;
		new_data_head[sub_i]->next = tmp;

		tmp->identifiers.push_back(identifier);
		for(auto &it:sub_node->second->identifiers){
			tmp->identifiers.push_back(it);
		}
		tmp->identifiers.shrink_to_fit();
		auto node = sub_node->second;
		sub_index[sub_i][sub_key] = tmp;
		// sub_node->second->identifiers.clear();
		// sub_node->second->identifiers.shrink_to_fit();

		//move the useless node in LRU to the head of the LRU list
		node->pre->next = node->next;
		node->next->pre = node->pre;
		if(node == lru_n[sub_i].index_tail) lru_n[sub_i].index_tail = node->pre;
		node->next = lru_n[sub_i].index_head->next;
		node->pre = lru_n[sub_i].index_head;
		lru_n[sub_i].index_head->next->pre = node;
		lru_n[sub_i].index_head->next = node;
		return;
	}

	//add node to the new_data_list
	sub_index_node* node = new sub_index_node{sub_key,vector<uint32_t>(),nullptr,nullptr};
	auto node_liner = std::lower_bound(sub_index_liner[sub_i].begin(),sub_index_liner[sub_i].end(), sub_key,compareFirst);
	if(node_liner == sub_index_liner[sub_i].end()) node->pre = new_data_head[sub_i]; //this is a new sub_key in the data_set
	for(;node_liner != sub_index_liner[sub_i].end()&&node_liner->sub_key == node->sub_key;node_liner++){
		node->identifiers.push_back(node_liner->identifiers);// add the data in the linear list to the new node
	}
	node->identifiers.push_back(identifier);

	//add node to new_data_head
	sub_index[sub_i][sub_key] = node;
	node->next = new_data_head[sub_i]->next;
	new_data_head[sub_i]->next = node;
};

//if insert too many data, increase the size of the submap
void containers::change_sub_map(int sub_i){
	uint32_t new_sub_map_size = initialize_size/2000;
	sub_information sub_info;
	if(new_sub_map_size-sub_map_size > sub_map_size/10){
		sub_index_node* new_sub_nodes;
		lru_n[sub_i].index_head->next=nullptr;
		new_sub_nodes = new sub_index_node[new_sub_map_size];
		int j = 0;
		sub_index_node* pre=lru_n[sub_i].index_head;
		for(auto& val:sub_index[sub_i]){
			new_sub_nodes[j].sub_key = val.first;
			new_sub_nodes[j].identifiers = std::move(val.second->identifiers);
			new_sub_nodes[j].pre = pre;
			pre->next = &new_sub_nodes[j];
			pre = &new_sub_nodes[j];
			sub_index[sub_i][val.first] = &new_sub_nodes[j];
			// delete val.second;
			j++;
		}
		delete[] sub_nodes[sub_i];
		pre->next = nullptr;
		lru_n[sub_i].index_tail = pre;
		sub_nodes[sub_i] = new_sub_nodes;
	}
}

*/

// void ecall_change_para(uint32_t hamm, uint32_t comb_num, uint32_t aggre_size)
// {
// 	cont.aggre_size = aggre_size;
// 	cont.hammdist = hamm;
// 	cont.MIN_INC_NUM = comb_num;
// 	printf("hamm:%d comb_num:%d\n", cont.hammdist, cont.MIN_INC_NUM);
// 	for (int j = 0; j < SUBINDEX_NUM; j++)
// 		cont.sub_hammdist[j] = floor((double)cont.hammdist / SUBINDEX_NUM);

// 	// for (int j = hamm; j > 0;)
// 	// {
// 	// 	for (int i = 0; i < 4; i++)
// 	// 	{
// 	// 		if (j <= 0)
// 	// 			break;
// 	// 		cont.sub_hammdist[i]++; // if hammdist=8,sub_hammdist={2,1,1,1}
// 	// 		j--;
// 	// 	}
// 	// }
// 	for (int i = 0; i < 4; i++)
// 	{
// 		// sub_hammdist[i] = temp[i];
// 		printf("sub_hammdist[%d]=%d\n", i, cont.sub_hammdist[i]);
// 	}
// }
void ecall_change_para(uint32_t dataSet, uint32_t hamm, uint32_t clr_size, uint32_t clr_dist, uint32_t comb_num, uint32_t aggre_size, int kmodes, int steps, int is_var, float ktime)
{
	cont.aggre_size = aggre_size;
	cont.hammdist[0] = hamm;
	cont.min_clr_size = clr_size;
	cont.max_dist = clr_dist;
	cont.MIN_INC_NUM = comb_num;

	cont.kmod = kmodes;
	cont.steps = steps;
	cont.is_var = is_var;
	cont.ktimes = ktime;
	printf("kkkkk kmodes %d steps %d is_var %d ktime %lf\n", cont.kmod, steps, is_var, ktime);

	printf("hamm:%d clr_size:%d clr_dist:%d comb_num:%d  aggre %d\n", cont.hammdist[0], cont.min_clr_size, cont.max_dist, cont.MIN_INC_NUM, cont.aggre_size);

	// for (int i = 0; i < SUBINDEX_NUM; i++)
	{
		cont.sub_hammdist[0] = (uint64_t)floor(1.0 * hamm / SUBINDEX_NUM);
	}
	// for (int i = 0; i < 4; i++)
	{
		// sub_hammdist[i] = temp[i];
		printf("sub_hammdist[%d]=%d\n", 0, cont.sub_hammdist[0]);
	}
}
void ecall_init_id_index(void *id_index, uint32_t idx)
{
	cont.id_index[idx] = id_index;
}
void containers::enc_page_block(uint8_t *data, uint32_t len)
{
	// EcallCrypto *cryptoObj = new EcallCrypto(CIPHER_TYPE, HASH_TYPE);
	EVP_MD_CTX *mdCtx = EVP_MD_CTX_new();
	EVP_CIPHER_CTX *cipherCtx_ = EVP_CIPHER_CTX_new();
	// uint8_t *sessionKey_ = sessionKey_;

	cryptoObj->SessionKeyEnc(cipherCtx_, data,
							 len, const_dataKey,
							 data);
	EVP_MD_CTX_free(mdCtx);
	EVP_CIPHER_CTX_free(cipherCtx_);
}

void containers::dec_page_block(uint8_t *data, uint32_t len, uint8_t *dec_data)
{
	// EcallCrypto *cryptoObj = new EcallCrypto(CIPHER_TYPE, HASH_TYPE);
	EVP_MD_CTX *mdCtx = EVP_MD_CTX_new();
	EVP_CIPHER_CTX *cipherCtx_ = EVP_CIPHER_CTX_new();
	// uint8_t *sessionKey_ = sessionKey_;

	// memcpy(dec_data, data, len);
	cryptoObj->SessionKeyDec(cipherCtx_, data,
							 len, const_dataKey,
							 dec_data);
	EVP_MD_CTX_free(mdCtx);
	EVP_CIPHER_CTX_free(cipherCtx_);
}

vector<uint32_t> containers::get_rand_keys(int i, int k, vector<uint32_t> &old_keys)
{
	vector<uint32_t> keys;
	uint32_t ridx;
	while (1)
	{
		sgx_read_rand(reinterpret_cast<unsigned char *>(&ridx), sizeof(int));
		ridx = ridx % full_key_sorted.size();

		for (auto &val : old_keys)
		{
			auto dist = popcount(val ^ full_key_sorted[ridx].target);
			if (dist <= max_dist)
				goto loop1;
		}
		// for (auto &val : keys)
		// {
		// 	auto dist = popcount(val ^ sub_index_liner[i][ridx].sub_key);
		// 	if (dist < max_dist)
		// 		goto loop1;
		// }
		if (keys.size() < k)
		{
			keys.push_back(full_key_sorted[ridx].target);
		}
		else
		{
			break;
		}
	loop1:
		ridx = 0;
	}
	// for (int t = 0; t < 6 && keys.size() < k; t++)
	// {
	// 	for (int index = 0; index < sub_index_liner[i].size(); index++)
	// 	{
	// 		for (auto &val : old_keys)
	// 		{
	// 			auto dist = popcount(val ^ sub_index_liner[i][index].sub_key);
	// 			if (dist <= max_dist)
	// 				goto loop;
	// 		}
	// 		for (auto &val : keys)
	// 		{
	// 			auto dist = popcount(val ^ sub_index_liner[i][index].sub_key);
	// 			if (dist < max_dist)
	// 				goto loop;
	// 		}
	// 		if (keys.size() < k)
	// 		{
	// 			keys.push_back(sub_index_liner[i][index].sub_key);
	// 		}
	// 		else
	// 		{
	// 			uint32_t j = 0;
	// 			sgx_read_rand(reinterpret_cast<unsigned char *>(&j), sizeof(int));
	// 			if (j < k)
	// 			{
	// 				keys[j] = sub_index_liner[i][index].sub_key; // data[index];
	// 			}
	// 		}
	// 	loop:
	// 		for (; index + 1 < sub_index_liner[i].size() && sub_index_liner[i][index + 1].sub_key == sub_index_liner[i][index].sub_key; index++)
	// 			;
	// 	}
	// 	set<uint32_t> tmp_set(keys.begin(), keys.end());
	// 	keys.clear();
	// 	keys = vector<uint32_t>(tmp_set.begin(), tmp_set.end());
	// }
	return std::move(keys);
}
vector<cluster_node> containers::kmodes(int i)
{
	int k = (uint32_t)(1.0 * cont.full_key_sorted.size() / 2000), tmp_cluster, dis, tmp_dist; //((1.0 * sub_linear_comp[i].size() / 1000 > 1.0 * 1000) ? 1000 : (1.0 * sub_linear_comp[i].size() / 1000))
	k = (uint32_t)(1.0 * k / (SUBINDEX_NUM - 3));
	if ((uint32_t)k < 300)
		k = 300;
	k = 200; // cautious 200 for img,70 for sift

	k = 50; // 800;//

	k = kmod;
	// k = 400;
	vector<uint32_t> keys, keys2;
	vector<pair<uint32_t, uint32_t>> tmp_clrs; // nums keys
	uint64_t sum = 0, sum0 = INT64_MAX, stash_nums = 0;
	EcallCMSketch cmsketch(100000);
	uint8_t out[16];
	vector<vector<uint32_t>> value_nums;

	vector<vector<uint32_t>> clusterk; // store k cluster
	clusterk.resize(k);
	// printf("keys size %d \n", keys.size());

	keys = get_rand_keys(i, k, keys);
	keys2 = keys;
	// for (int t = 0; t < 2 && keys.size() < k; t++)
	// {
	// 	for (int index = 0; index < sub_index_liner[i].size(); index++)
	// 	{
	// 		if (keys.size() < k)
	// 		{
	// 			keys.push_back(sub_index_liner[i][index].sub_key);
	// 		}
	// 		else
	// 		{
	// 			uint32_t j = 0;
	// 			sgx_read_rand(reinterpret_cast<unsigned char *>(&j), sizeof(int));
	// 			if (j < k)
	// 			{
	// 				keys[j] = sub_index_liner[i][index].sub_key; // data[index];
	// 			}
	// 		}
	// 		for (; index + 1 < sub_index_liner[i].size() && sub_index_liner[i][index + 1].sub_key == sub_index_liner[i][index].sub_key; index++)
	// 			;
	// 	}
	// 	set<uint32_t> tmp_set(keys.begin(), keys.end());
	// 	keys.clear();
	// 	keys = vector<uint32_t>(tmp_set.begin(), tmp_set.end());
	// }

	k = keys.size();
	value_nums.resize(k + 1);
	value_nums[0].resize(k + 1);
	for (int t = 1; t < k + 1; t++)
	{
		value_nums[t].resize(32);
	}
	printf("1\n");
	// for (int t = 0; t < k; t++)
	// {
	// 	printf("keys %d \n", keys[t]);
	// }
	// printf("keys size %d \n", keys.size());

	// only catagory to under max_dist to the cluster, update the cluster without larger than max_dist
	int times = 0;
	while (times < 80) // 15
	{
		// printf("times %d\n", times);
		// printf("2\n");
		times++;
		tmp_clrs.clear();
		tmp_clrs.resize(k);
		stash_nums = 0;
		for (int j = 0; j < full_key_sorted.size(); j++)
		{
			tmp_dist = INT16_MAX;
			tmp_cluster = -1;
			for (int t = 0; t < k; t++)
			{
				dis = bitset<32>(full_key_sorted[j].target ^ keys[t]).count();
				if (dis < tmp_dist) // tmp_dist
				{
					tmp_cluster = t;
					tmp_dist = dis;
				}
				else if (dis == tmp_dist)
				{
					// tmp_clrs.push_back(t);
				}
			}
			{
				// sum += tmp_dist;
				// if (tmp_cluster != -1)
				{
					if (tmp_dist <= max_dist)
					{
						sum += tmp_dist;
						MurmurHash3_x86_128(&full_key_sorted[j].target, sizeof(uint32_t), 0, out);
						cmsketch.Update(out, 16, 1);
						int num_tmp = cmsketch.Estimate(out, 16);
						if (num_tmp > tmp_clrs[tmp_cluster].first)
						{
							tmp_clrs[tmp_cluster].first = num_tmp;
							tmp_clrs[tmp_cluster].second = full_key_sorted[j].target;
						}
					}

					if (tmp_dist <= max_dist)
					{
						value_nums[0][tmp_cluster + 1]++;
						for (int t = 0; t < 32; t++)
						{
							if ((full_key_sorted[j].target >> t) & 1)
								value_nums[tmp_cluster + 1][t]++;
						}

						// clusterk[tmp_cluster].push_back(sub_index_liner[i][j].sub_key);
					}
				}
			}

			if (tmp_dist > max_dist)
			{
				stash_nums++;
			}
		}
		// loop end
		// printf("sum %d \n", sum);
		// if (sum >= sum0) //&& stash_nums < ceil((double)sub_index_liner[i].size() / 2)
		// {
		// 	cmsketch.ClearUp();
		// 	sum = 0;
		// 	// {printf("sum %d cluster times %d\n",sum0,times);break;}
		// 	break;
		// 	continue;
		// }
		// else
		{
			int out = 1;
			// right k-modes
			for (int t = 0; t < k; t++)
			{
				int size = value_nums[0][t + 1], tmp_key = 0;
				for (int j = 0; j < 32; j++)
				{
					if (value_nums[t + 1][j] > (size >> 1))
					{
						tmp_key |= (1 << j);
					}
				}
				if (keys[t] != tmp_key)
					out = 0;
				keys[t] = tmp_key;
			}

			// old k-modes
			// for (int t = 0; t < k; t++)
			// {
			// 	if (keys[t] != tmp_clrs[t].second)
			// 		out = 0;
			// 	keys[t] = tmp_clrs[t].second;
			// }
			// if (out && sum == sum0)
			// {
			// 	printf("sum %d cluster times %d\n", sum0, times);
			// 	break;
			// }

			// // k-medoids
			// for (int t = 0; t < k; t++)
			// {
			// 	int min_dist = INT32_MAX, tmpid = -1;
			// 	for (int j = 0; j < clusterk[t].size(); j++)
			// 	{
			// 		int tmp_dist = 0;
			// 		for (int m = 0; m < clusterk[t].size(); m++)
			// 		{
			// 			tmp_dist += bitset<32>(clusterk[t][j] ^ clusterk[t][m]).count();
			// 		}
			// 		if (tmp_dist < min_dist)
			// 		{
			// 			min_dist = tmp_dist;
			// 			tmpid = j;
			// 			// keys[t]=clusterk[t][j];
			// 		}
			// 	}
			// 	if (tmpid != -1)
			// 	{
			// 		out = 0;
			// 		keys[t] = clusterk[t][tmpid];
			// 	}
			// }

			if (out && sum == sum0)
			{
				printf("sum %d cluster times %d\n", sum0, times);
				break;
			}
			sum0 = sum;

			// for (int i = 0, sub = 0; i < k; i++)
			// {
			// 	if (value_nums[0][i + 1] > 10000 || value_nums[0][i + 1] < 1000)
			// 	{
			// 		keys.erase(keys.begin() + i - sub);
			// 		sub++;
			// 	}
			// }
			if (is_var && stash_nums >= ceil((double)full_key_sorted.size() * ktimes)) // size / 2
			{
				auto tmp = get_rand_keys(i, 2 * k, keys);
				unordered_set<uint32_t> tmp_set(keys.begin(), keys.end());
				for (auto &val : tmp)
				{
					if (tmp_set.find(val) == tmp_set.end() && keys.size() < k + steps) //+20
						keys.push_back(val);
				}
			}
			for (int t = 0; t < k + 1; t++)
			{
				value_nums[t].clear();
			}
			k = keys.size();

			clusterk.resize(k);
			for (int t = 0; t < k; t++)
			{
				clusterk[t].clear();
			}
			value_nums.resize(k + 1);
			value_nums[0].resize(k + 1);
			for (int t = 1; t < k + 1; t++)
			{
				value_nums[t].resize(32);
			}
		}
		sum = 0;
		cmsketch.ClearUp();

		// // cautious
		// if (stash_nums >= ceil((double)sub_index_liner[i].size() / 3)) // cautious /2
		// {
		// 	auto tmp = get_rand_keys(i, k);
		// 	unordered_set<uint32_t> tmp_set(keys.begin(), keys.end());
		// 	for (auto &val : tmp)
		// 	{
		// 		if (tmp_set.find(val) == tmp_set.end() && keys.size() < k + 20)
		// 			keys.push_back(val);
		// 	}
		// 	k = keys.size();
		// }
	}
	vector<cluster_node> tmps;
	for (int t = 0; t < k; t++)
	{
		cluster_node cl_info;
		cl_info.subkey = keys[t];
		tmps.push_back(cl_info);
		// printf("keys %d \n", keys[t]);
	}
	return tmps;
}

void containers::lru_ids_visit(uint64_t key, ids_node *node)
{
	if (node->pre == nullptr || node->pre == lru_cache.index_head)
		return;
	if (node == lru_cache.index_tail)
		return;

	// lru_mtx.lock();
	node->next->pre = node->pre;
	node->pre->next = node->next;
	node->pre = lru_cache.index_tail;
	node->next = nullptr;
	lru_cache.index_tail->next = node;
	lru_cache.index_tail = node;
	// lru_mtx.unlock();
};

uint8_t *containers::lru_ids_add(uint64_t key, uint32_t sub_i, sub_info_comp comp)
{
	ids_node *remove_node = nullptr;
	uint32_t val_size = (comp.length & MASK_LEN) * INT_SIZE, tmp_size = (comp.length <= 0 || val_size < 2048 ? 2048 : val_size);

	if (lru_cache.len >= lru_cache.capacity)
	{
		resize_times++;
		remove_node = lru_cache.index_head->next;
		remove_node->pre->next = remove_node->next;
		remove_node->next->pre = lru_cache.index_head;

		data_cache.erase(remove_node->key);
		remove_node->pre = nullptr;
		remove_node->next = nullptr;
	}
	else
	{
		lru_cache.len++;
	}
	ids_node *node = nullptr;
	if (remove_node == nullptr)
	{
		node = &exist_ids[lru_cache.len - 1];
#if CACHE_SIZE < 500000
		max_size += 2048;
		node->ids.resize(2048); // / 2 ceil((double)max_id_page / 2)
#endif
		if (node->ids.size() < PAGE_SIZE_B)
			node->ids.resize(PAGE_SIZE_B);
	}
	else
		node = remove_node;

	node->key = key;
	if (comp.length > 0 && ((comp.length & MASK_LEN) * INT_SIZE) > node->ids.size())
	{
		max_size = max_size - node->ids.size() + (comp.length & MASK_LEN) * INT_SIZE;

		resize_size += ((comp.length & MASK_LEN) * INT_SIZE - node->ids.size()) / 4;
		vector<uint8_t> tmp;
		node->ids.swap(tmp);
		node->ids.resize((comp.length & MASK_LEN) * INT_SIZE); // vector.swap ?? for add-similar-keys
	}
	else if (tmp_size < (node->ids.size() >> 1))
	{
		max_size = max_size - node->ids.size() + tmp_size;
		node->ids.resize(tmp_size);
	}

	if (comp.length > 0)
	{
		dec_page_block(id_point[sub_i] + comp.skiplen, comp.length * sizeof(uint32_t), node->ids.data());
	}
	else
	{
		dec_page_block(id_point[sub_i] + comp.skiplen, PAGE_SIZE_B, node->ids.data());
	}

	if (max_size > max_val)
	{
		max_val = max_size;
	}

	data_cache[key] = node;

	lru_cache.index_tail->next = node;
	node->pre = lru_cache.index_tail;
	node->next = nullptr;
	lru_cache.index_tail = node;
	// lru_mtx.unlock();
	return node->ids.data();
}

// uint8_t *lru_ids_add1(uint64_t key, uint32_t sub_i, sub_info_comp comp)
// {
// 	uint32_t val_size = (comp.length & MASK_LEN) * INT_SIZE, tmp_size = ((comp.length <= 0 || val_size < 2048) ? 2048 : val_size);
// 	ids_node *remove_node = nullptr;

// 	// if (comp.length > 0 && ((comp.length & MASK_LEN) * INT_SIZE) > 2048)
// 	// {
// 	// 	max_ids.resize(comp.length * sizeof(uint32_t));
// 	// 	dec_page_block(id_point[sub_i] + comp.skiplen, comp.length * sizeof(uint32_t), max_ids.data());
// 	// 	return max_ids.data();
// 	// }
// 	if (lru_cache.len >= lru_cache.capacity)
// 	{
// 		resize_times++;
// 		remove_node = lru_cache.index_head->next;
// 		remove_node->pre->next = remove_node->next;
// 		remove_node->next->pre = lru_cache.index_head;

// 		data_cache.erase(remove_node->key);
// 		remove_node->pre = nullptr;
// 		remove_node->next = nullptr;

// 		// while (lru_cache.remain_size < tmp_size)
// 		// {
// 		// 	remove_node->ids.clear();
// 		// 	remove_node = lru_cache.index_head->next;
// 		// 	remove_node->pre->next = remove_node->next;
// 		// 	remove_node->next->pre = lru_cache.index_head;

// 		// 	data_cache.erase(remove_node->key);
// 		// 	remove_node->pre = nullptr;
// 		// 	remove_node->next = nullptr;
// 		// }
// 	}
// 	else
// 	{
// 		lru_cache.len++;
// 	}

// 	// if (lru_cache.remain_size < tmp_size)
// 	// {
// 	// 	printf("cache size is not enough! maxlen %d maxsize %d tmp%d\n", lru_cache.len, lru_cache.remain_size, tmp_size);
// 	// 	// exit(-1);
// 	// }
// 	// else
// 	// 	lru_cache.remain_size -= tmp_size;
// 	ids_node *node = nullptr;
// 	if (remove_node == nullptr)
// 	{
// 		node = &exist_ids[lru_cache.len - 1];
// #if CACHE_SIZE < 500000
// 		if (node->ids.size() < 2048)
// 		{
// 			max_size -= node->ids.size();
// 			max_size += 2048;
// 			if (lru_cache.remain_size < 2048)
// 			{
// 				printf("cache size is not enough! maxlen %d maxsize %d tmp%d\n", lru_cache.len, lru_cache.remain_size, tmp_size);
// 				// exit(-1);
// 			}
// 			lru_cache.remain_size += node->ids.size();
// 			lru_cache.remain_size -= 2048;
// 		}

// 		node->ids.resize(2048); // / 2 ceil((double)max_id_page / 2)
// #endif
// 		if (node->ids.size() < PAGE_SIZE_B)
// 		{
// 			node->ids.resize(PAGE_SIZE_B);
// 			max_size += PAGE_SIZE_B;
// 		}
// 	}
// 	// else
// 	// {
// 	// 	vector<uint8_t> tmp(2048);
// 	// 	node = remove_node;
// 	// 	node->ids.swap(tmp);
// 	// }

// 	node->key = key;
// 	if (comp.length > 0 && ((comp.length & MASK_LEN) * INT_SIZE) > node->ids.size())
// 	{
// 		resize_size += ((comp.length & MASK_LEN) * INT_SIZE - node->ids.size()) / 4;
// 		vector<uint8_t> tmp;

// 		max_size = max_size - node->ids.size() + (comp.length & MASK_LEN) * INT_SIZE;
// 		lru_cache.remain_size += node->ids.size();
// 		if (lru_cache.remain_size < (comp.length & MASK_LEN) * INT_SIZE)
// 		{
// 			printf("cache size is not enough! maxlen %d maxsize %d tmp%d\n", lru_cache.len, lru_cache.remain_size, tmp_size);
// 			// exit(-1);
// 		}
// 		lru_cache.remain_size -= (comp.length & MASK_LEN) * INT_SIZE;

// 		node->ids.swap(tmp);

// 		node->ids.resize((comp.length & MASK_LEN) * INT_SIZE); // vector.swap ?? for add-similar-keys
// 	}
// 	// else if ((comp.length & MASK_LEN) * INT_SIZE > 2048 && (comp.length & MASK_LEN) * INT_SIZE < node->ids.size() >> 2)
// 	// {
// 	// 	node->ids.resize((comp.length & MASK_LEN) * INT_SIZE);
// 	// }
// 	// if(comp.length<=0)
// 	if (comp.length > 0)
// 	{
// 		dec_page_block(id_point[sub_i] + comp.skiplen, comp.length * sizeof(uint32_t), node->ids.data());
// 	}
// 	else
// 	{
// 		dec_page_block(id_point[sub_i] + comp.skiplen, PAGE_SIZE_B, node->ids.data());
// 	}

// 	if (max_size > max_val)
// 	{
// 		max_val = max_size;
// 	}
// 	data_cache[key] = node;

// 	lru_cache.index_tail->next = node;
// 	node->pre = lru_cache.index_tail;
// 	node->next = nullptr;
// 	lru_cache.index_tail = node;
// 	// lru_mtx.unlock();
// 	return node->ids.data();
// }

void containers::init_ids_cache()
{
	printf("max id page--- %d\n", max_id_page);
#if CACHE_SIZE >= 500000
	uint32_t total_cache_item = 0;
	for (int i = 0; i < SUBINDEX_NUM; i++)
	{
		total_cache_item += sub_linear_comp[i].size();
	}
	lru_cache.capacity = total_cache_item;
#endif
	printf("cap %d\n", lru_cache.capacity);
	exist_ids = new ids_node[lru_cache.capacity];
	uint32_t len = (uint32_t)(1.0 * lru_cache.capacity / SUBINDEX_NUM), index = 0;
	for (int i = 0; i < SUBINDEX_NUM; i++)
	{
#if CACHE_SIZE >= 500000
		len = sub_linear_comp[i].size();
#endif
#if CACHE_SIZE < 500000
		for (int k = 0; k < 5; k++)
#endif
		{
			index = 0;
			for (int j = 0; j < len; j++)
			{
				// sgx_read_rand(reinterpret_cast<unsigned char *>(&index), sizeof(int));
				auto node = sub_linear_comp[i][index % sub_linear_comp[i].size()];
				uint64_t key = ((uint64_t)i << 32) | node.sub_key;
				if (data_cache.find(key) != data_cache.end())
				{
					index++;
					continue;
				}
				lru_ids_add(key, i, node);
				index++;
			}
		}
	}
	printf("ids_cache len%d cap%d each_size %d\n", lru_cache.len, lru_cache.capacity, sizeof(ids_node));
};

void encall_find_knn(void *dataptr, uint32_t *res, uint32_t len, uint32_t len_res, uint64_t hammdist)
{
	// cont.changeHammingDist(hammdist);
	cont.successful_num = 0;
	EcallCrypto *cryptoObj = new EcallCrypto(CIPHER_TYPE, HASH_TYPE);
	EVP_MD_CTX *mdCtx = EVP_MD_CTX_new();
	EVP_CIPHER_CTX *cipherCtx_ = EVP_CIPHER_CTX_new();
	uint8_t *sessionKey_ = const_sessionKey;
	uint8_t *dataE = reinterpret_cast<uint8_t *>(dataptr);
	int dataSize = sizeof(uint64_t) * len * 2;
	cryptoObj->SessionKeyDec(cipherCtx_, dataE,
							 dataSize, sessionKey_,
							 dataE);

	printf("query batch len %d\n", len_res);
	uint8_t *res_old = reinterpret_cast<uint8_t *>(res); // res=query times + success num of query i + targets of query i
	Query_batch_t query;
	query.sendData = res;
	*(query.sendData) = len; // write query times to res
	query.index = query.sendData + sizeof(uint32_t);
	query.dataBuffer = query.sendData + sizeof(uint32_t) * (len + 1);
	uint64_t *data = reinterpret_cast<uint64_t *>(dataE);
	uint64_t temp2[2];
	printf("query len=%d\n", len);
	for (int i = 0; i < len; i++)
	{
		temp2[0] = data[2 * i];
		temp2[1] = data[2 * i + 1];
		auto res_set = cont.find_knn(temp2, hammdist);
		query.index[i] = res_set.size(); // write success num of query i to res
										 // printf("res_set.size()=%d max _dist %d\n", res_set.size(), res_set[res_set.size() - 1].first);

		// for (auto &it : res_set)
		// {
		// 	*(query.dataBuffer) = it;
		// 	query.dataBuffer++; // write targets of query i to res
		// }
	}
	times_[0] /= 1e6;
	times_[1] /= 1e6;
	times_[2] /= 1e6;
	printf("fetch times cand %d ,hit times %d", cont.knn_cand_get, cont.knn_hit_cand);
	printf("times %lld clr %lld stash %lld\n", times_[0], times_[1], times_[2]);
	printf("successful_num=%d\n", cont.successful_num);
	//*len=res_set.size();
	cryptoObj->SessionKeyEnc(cipherCtx_, (uint8_t *)res_old, len_res * sizeof(uint32_t), sessionKey_, (uint8_t *)res_old);
	// printf("Successfully found  photos! successful_num=%d.\n",res_set.size());
	printf("sign_data_size %d\n", sign_data.size());
}