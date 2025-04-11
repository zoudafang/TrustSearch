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

	for (int j = 0; j < sub_index_num; j++)
		sub_hammdist[0][j] = -1;

	// the sum of sub_hammdist is hammdist - sub_index_num + 1
	for (int j = hammdist[0] + 1; j > 0;)
	{
		for (int i = 0; i < sub_index_num; i++)
		{
			if (j <= 0)
				break;
			sub_hammdist[0][i]++; // if hammdist=8,sub_hammdist={2,1,1,1}; 12={2,1,1,1,1,1}
			j--;
		}
	}
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

	cryptoObj = new EcallCrypto(CIPHER_TYPE, HASH_TYPE);
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
pair<uint32_t, uint32_t> find_nearest_element_avx2(const std::vector<uint32_t> &vec, uint32_t q, uint32_t begin, uint32_t end)
{
	size_t len = end - begin;
	// size_t len = vec.size();
	uint32_t min_distance = std::numeric_limits<uint32_t>::max();
	int min_index = -1;

	const __m256i q_vec = _mm256_set1_epi32(q);

	int simd_len = len - 7;
	for (size_t i = 0; i < simd_len; i += 8)
	{
		__m256i vec_data = _mm256_loadu_si256((__m256i *)(vec.data() + i + begin));
		__m256i xor_result = _mm256_xor_si256(vec_data, q_vec);

		// 计算汉明距离
		__m256i hamming_dist = _mm256_set1_epi32(0);
		for (int j = 0; j < 32; j++)
		{
			__m256i mask = _mm256_set1_epi32(1 << j);
			__m256i bit_set = _mm256_and_si256(xor_result, mask);
			hamming_dist = _mm256_add_epi32(hamming_dist, _mm256_srli_epi32(bit_set, j));
		}

		// 查找最小汉明距离及其索引
		for (int j = 0; j < 8; j++)
		{
			uint32_t distance;
			switch (j)
			{
			case 0:
				distance = _mm256_extract_epi32(hamming_dist, 0);
				break;
			case 1:
				distance = _mm256_extract_epi32(hamming_dist, 1);
				break;
			case 2:
				distance = _mm256_extract_epi32(hamming_dist, 2);
				break;
			case 3:
				distance = _mm256_extract_epi32(hamming_dist, 3);
				break;
			case 4:
				distance = _mm256_extract_epi32(hamming_dist, 4);
				break;
			case 5:
				distance = _mm256_extract_epi32(hamming_dist, 5);
				break;
			case 6:
				distance = _mm256_extract_epi32(hamming_dist, 6);
				break;
			case 7:
				distance = _mm256_extract_epi32(hamming_dist, 7);
				break;
			}
			if (distance < min_distance)
			{
				min_distance = distance;
				min_index = i + j + begin;
			}
		}
	}

	// 处理剩余的元素
	for (size_t i = (len / 8) * 8; i < len; i++)
	{
		uint32_t distance = __builtin_popcount(vec[i + begin] ^ q);
		if (distance < min_distance)
		{
			min_distance = distance;
			min_index = i + begin;
		}
	}

	return {min_index, min_distance};
}
void containers::get_test_pool()
{
	std::vector<int> numbers = {590,591,707,513,720,569,710,161,106,192,140,659,95,919,886,873,918,696,702,92,662,532,903,91,331,69,511,592,751,83,82,821,107,540,556,826,81,889,523,522,689,699,563,887,566,570,721,103,898,900,712,533,330,663,705,516,719,723,902,99,971,701,698,656,752,822,557,517,559,558,823,852,479,480,518,561,529,708,519,969,520,571,560,521,96,482,98,649,481,483,97,648,709,711,713 };
	for(auto&num:numbers)
	{
	filter_query.set(num);
		// std::cout << "filter_query.set(" << num << ");" << std::endl;
	}

	// 从测试集获取test pool数据
	uint32_t index1 = 5556;
	// sgx_read_rand(reinterpret_cast<unsigned char *>(&index1), sizeof(index1));
	uint32_t end = tmp_test_pool.size();
	index1 %= end;
	// index1 = 8437;
	printf("query index1: %d\n", index1);
	while (test_pool.size() < 1000 && end > 0)
	{
		index1 += 1;
		// sgx_read_rand(reinterpret_cast<unsigned char *>(&index1), sizeof(index1));
		index1 %= end;
		test_pool.push_back(tmp_test_pool[index1]);
		if (tmp_test_targets.size())
		{
			test_targets.push_back(tmp_test_targets[index1]);
			tmp_test_targets[index1] = tmp_test_targets[end - 1];
		}
		else
			test_targets.push_back(0);
		auto tmp = tmp_test_pool[index1];
		tmp_test_pool[index1] = tmp_test_pool[end - 1];
		end--;
	}

	// uint64_t t1, t2;
	// t1 = 0b1001111110000110111100110000110010000100000010100010010100010011ULL, t2 = 0b0110100110011101101110110100101110010001101110101101010111011100ULL;
	// test_pool.push_back({t1, t2});
	// t1 = 0b1001110110010111010101110001110110000101001100011010000000000101ULL, t2 = 0b1110011101111110010010110000101101001111011100000011010000110110ULL;
	// test_pool.push_back({t1, t2});
	// t1 = 0b1000011101110011000011100011000100110001101001110001000111011000ULL, t2 = 0b0000101110011000110101111111010001111000101010101100001010010001ULL;
	// test_pool.push_back({t1, t2});
	// t1 = 0b0000101110011000110101111111010001111000101010101100001010010001ULL, t2 = 0b0101111010011100011110100011101110100111001000111001011011010001ULL;
	// test_pool.push_back({t1, t2});
	// t1 = 0b1011011101100101101011101000010101100010110001000001010111011101ULL, t2 = 0b0010010100100011010011110111110001001101110010111000100111101001ULL;
	// test_pool.push_back({t1, t2});
	// t1 = 0b0110101010100111001001011001011111011101011110111001011011010000ULL, t2 = 0b1100100010000000100101111011011011100110001100010011111010011101ULL;
	// test_pool.push_back({t1, t2});

	// t1 = 0b0011010111111111100011111101110100010000000110011001011001100000ULL, t2 = 0b1000001001111011011001110110010101010101111100100010011010111111ULL;
	// test_pool.push_back({t1, t2});
	// t1 = 0b0000000011110011111110000011100011100110100001000010010101000101ULL, t2 = 0b0000010100000100101100110010000010100100111010100011110000100011ULL;
	// test_pool.push_back({t1, t2});
	// t1 = 0b0001000101010111111101000101100001001100000110001110101101001001ULL, t2 = 0b1110100010001101010011110110101001000011110100110110011001010101ULL;
	// test_pool.push_back({t1, t2});
	// t1 = 0b0001110110100001101011110011100011101011001001111110110010011010ULL, t2 = 0b1011001010111001101010001001101011000010001110010011101010110010ULL;
	// test_pool.push_back({t1, t2});

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

static int cand_nums[10] = {0};
static int cand_nums_set[10] = {0};
static int cand_set_nums = 0, mix = 0, mix2 = 0;
static int thres_cand1 = 0, thres_cand2 = 50090000; // cautious
int step2_flag;
int times_gen = 0, combs = 0, combs_hit = 0, find_clrs_num = 0;
uint32_t client_id = 0;
static uint32_t query_times = 0;
static int hittt = 0;
static int misss = 0;
int dataset_size = 0, feature_size = 0, opt_refine = 0;
std::vector<uint32_t> containers::find_sim(uint64_t query[], uint32_t tmp_test_target, int client_id) // ocall_get_timeNow
{
	cand_set_nums = 0;
	query_times++;
	uint32_t binary_times = 1;
	// candi_num=0;

	int verifty_step = 0;
	uint64_t *total_time_now = new uint64_t[1];
	long long total_begin_time = 0, total_end_time = 0;
	ocall_get_timeNow(total_time_now);
	total_begin_time = *total_time_now;

	uint64_t fetch_cand_step1,fetch_cand_times = 0,reduce_total_num=0;
	uint64_t time_begin, time_step1, time_step2;

	vector<uint32_t> candidate;
	std::unordered_map<uint32_t, int> reached_subkey;
	unordered_set<uint32_t> cand_first;
	candi_first_set.reset();
	cand_step1.clear();

	candi_set_step2.reset();
	candidateAdd.clear();
	candi_set.reset();
	step2_flag = 0;
	// bitset<DATA_LEN * 5> candi_first_set1;
	// candi_first_set = std::move(candi_first_set1);

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
	int out_key[1], sub_key_I[2];
	uint32_t tmp_hash[2], hash_size = ceil((float)bloom_hash_times / 4) * 16; // ceil(times/4)*4
	uint8_t tmp_hash_out[32], bloom_hash[hash_size];
	static uint32_t candiNUM = 0;

	vector<key_find> existed_subkeys;
	vector<cluster_info> tmp_clrs, bigger_clrs, mid_clrs; // xx;hamm+dist;hamm+dist-1
	cluster_info c_info;
	unordered_set<uint32_t> visited_subkeys;
	int begin_ids = 0, dt;
	uint32_t tmp_dist = 0, tmp_count, tmp_min_idx, min_dist;
	uint32_t begin_idx, end_idx, lookup_all_size = 0, lookup_radius;

	ocall_get_timeNow(&time_begin);
	for (int i = 0; i < SUBINDEX_NUM; i++)
	{
		if (sub_hammdist[client_id][i] < 0)
			continue;
		ocall_get_timeNow(time);
		begin_time = *time;

		lookup_all_size = 0;
		lookup_radius = sub_hammdist[client_id][i] + max_dist;
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
		// for (int t = 0; t < clr[i].size() - 1; t++) // TODO:可以优化，如果计算 -1
		// {
		// 	begin_idx = clr[i][t].begin_idx;
		// 	end_idx = clr[i][t + 1].begin_idx;
		// 	tmp_dist = popcount(sub[i] ^ clr[i][t].subkey);
		// 	lookup_all_size += end_idx - begin_idx;

		// 	c_info.node = clr[i][t];
		// 	c_info.end = end_idx;
		// 	c_info.dist = tmp_dist;
		// 	if (tmp_dist > sub_hammdist[client_id][i] + max_dist - 2) //- 2 -1
		// 	{
		// 		if (tmp_dist == sub_hammdist[client_id][i] + max_dist - 1)
		// 		{
		// 			mid_clrs.push_back(c_info);
		// 		}
		// 		else if (tmp_dist == sub_hammdist[client_id][i] + max_dist)
		// 		{
		// 			bigger_clrs.push_back(c_info);
		// 			// for dist == hammdist+max_dist; it must only contains subkey whose hamm dist from cluster equals max_dist, and dist from subkey equals sub_hamm;
		// 			// so bigger_clrs's all dist is max_dist
		// 		}
		// 		continue;
		// 	}
		// 	tmp_clrs.push_back(c_info);
		// }

		// min_dist = UINT16_MAX;
		// if (tmp_clrs.size())
		// {
		// 	std::sort(tmp_clrs.begin(), tmp_clrs.end(), [](cluster_info &a, cluster_info &b)
		// 			  { if(a.dist!=b.dist)return a.dist < b.dist;else return a.node.begin_idx < b.node.begin_idx; });
		// 	min_dist = tmp_clrs[0].dist;
		// }
		// min_dist = (tmp_clrs.size() > 0 ? tmp_clrs[0].dist : UINT16_MAX);
		cluster_node tmp_node;

		c_info.node = clr[i][clr[i].size() - 1];
		c_info.end = sub_linear_comp[i].size();
		c_info.dist = 0; // popcount(sub[i] ^ clr[i][clr[i].size() - 1].subkey);
		tmp_clrs.push_back(c_info);
		uint32_t tmpkey = sub[i];

		/*	for (int t = 0; t < bloom_hash_times; t += 4)
			{
				tmp_hash[0] = sub[i];
				tmp_hash[1] = i + t * sub_index_num * 2;
				MurmurHash3_x86_128(tmp_hash, 8, hash_seed[0], bloom_hash + t * INT_SIZE);
				// memcpy(bloom_hash + t * INT_SIZE, tmp_hash_out, std::min(bloom_hash_times - t, (uint32_t)4) * INT_SIZE);
			}
			if (filters->contains(bloom_hash, bloom_hash_times * INT_SIZE)) // filters.contains(bloom_hash, bloom_hash_times * INT_SIZE)
			{
				if (sub_hammdist[client_id][i] <= 1 && tmp_clrs.size() == 1 && mid_clrs.size()) // tmp-clrs只有stash，可以从bigger里面查找
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
				else if (sub_hammdist[client_id][i] <= 0 && tmp_clrs.size() == 1 && bigger_clrs.size()) // tmp-clrs只有stash，可以从bigger里面查找
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
						}
					}
				}
			}
		*/
		dt = 0; // sub[0] is finded
		tmp_clrs.pop_back();
		// get_times(0, 0);
		uint32_t find_max_d = std::min(min_dist + sub_hammdist[client_id][i], max_dist), tmp_dist = min_dist; // 这个find-max-d是不是太大了，应该写在mindist增加之前

		// for optimal to reduce the candidate; cautious
		int sed_size = sub_hammdist[client_id][i] - 1; // sub_hammdist[client_id][i]-1;
		if (i == (hammdist[client_id] - SUBINDEX_NUM + 1) % SUBINDEX_NUM)
			sed_size = sub_hammdist[client_id][i];
		/*
				for (auto val = tmp_clrs.begin(); val < tmp_clrs.end();)
				{
					tmp_node = val->node;
					begin_idx = val->node.begin_idx;
					end_idx = val->end;																					// get_search_numbers(sub_keybit,sub_hammdist[i])
					if ((val->dist + max_dist) <= sub_hammdist[client_id][i] || val->node.group_size < combine_clr_min) // end_idx - begin_idx < 500 (val->dist + max_dist - 1) <= sub_hammdist[i] || val->node.group_size < combine_clr_min
					{

						linear_scan(client_id, i, begin_idx, end_idx, sub[i], sed_size, candidate, reached_subkey); // cautious 效果可能不好？？

						val = tmp_clrs.erase(val);
					}
					else
						val++;
				}
				get_times(0, 3);
*/
		for (int t = dt; t <= sed_size; t++)
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
		}fetch_cand_step1+=existed_subkeys.size();
		// printf("linear size %d exist size %d clr_num%d \n", reached_subkey.size(), existed_subkeys.size(),tmp_clrs.size());
		reached_subkey.clear();
		// get_times(0, 1);

		uint32_t min_dist0 = min_dist;
		// uint32_t find_max_d = std::min(min_dist + sub_hammdist[i], (uint64_t)max_dist), tmp_dist = min_dist; // 这个find-max-d是不是太大了，应该写在mindist增加之前
		min_dist += sub_hammdist[client_id][i] * 2; // cautious- 1
		find_clrs_num += (tmp_clrs.size() ? tmp_clrs.size() : 1);

		// if (min_dist0 + sub_hammdist[client_id][i] > max_dist)
		// {
		// 	lookup_all_size + sub_linear_comp[i].size() - clr[i][clr[i].size() - 1].begin_idx;
		// }
		if (1) // lookup_all_size >= (sub_linear_comp[i].size() >> 1) lookup_all_size >= ceil((double)sub_linear_comp[i].size() / 3)
		{
			uint32_t max_node = 0;
			// for (; max_node < tmp_clrs.size(); max_node++)
			// {
			// 	if (tmp_clrs[max_node].dist > max_dist)
			// 		break;
			// }
			/*	for (auto tmpc = tmp_clrs.begin(); tmpc != tmp_clrs.end() && tmpc->dist <= (lookup_radius >> 1); tmpc = tmp_clrs.erase(tmpc))
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
	*/
			// if (tmp_clrs.size())
			// 	std::sort(tmp_clrs.begin(), tmp_clrs.end(), [](cluster_info &a, cluster_info &b)
			// 			  { return a.node.begin_idx < b.node.begin_idx; });
			uint16_t tmp_min = 0, idx = 0, tmp_d;
			uint32_t tmpkey_, max_find_dist;
			for (int x = 0; x < existed_subkeys.size(); x++)
			{
				if (existed_subkeys[x].clr_idx == INT16_MAX)
					continue;

				// for (int t = 0; t < bloom_hash_times; t += 4)
				// {
				// 	tmp_hash[0] = existed_subkeys[x].subkey;
				// 	tmp_hash[1] = i + t * SUBINDEX_NUM * 2;
				// 	MurmurHash3_x86_128(tmp_hash, 8, hash_seed[0], bloom_hash + t * INT_SIZE);
				// }
				// if (!sub_filters[i][sed_size].contains(bloom_hash, bloom_hash_times * INT_SIZE))
				// {
				// 	existed_subkeys[x].clr_idx = tmp_clrs.size();
				// 	continue;
				// }

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
			// for (; val_idx < existed_subkeys.size(); val_idx++) // auto &val : existed_subkeys
			// {
			// 	auto &val = existed_subkeys[val_idx];
			// 	// if (reached_subkey.find(val.subkey) != reached_subkey.end())
			// 	// {
			// 	// 	val.max_dist = 0;
			// 	// 	continue;
			// 	// }
			// 	if (val.clr_idx == INT16_MAX)
			// 		continue;

			// 	if (val.clr_idx == tmp_clrs.size() - 1 && flag)
			// 	{
			// 		// get_times(0, 3);
			// 		flag = false;
			// 		break;
			// 		// continue;
			// 	}
			// 	int begin = tmp_clrs[val.clr_idx].node.begin_idx;
			// 	int end = tmp_clrs[val.clr_idx].end;

			// 	auto tmpsub1 = val.subkey;
			// 	auto its = std::lower_bound(sub_linear_comp[i].begin() + begin, sub_linear_comp[i].begin() + end, tmpsub1, compareFirst_comp);
			// 	if (its != sub_linear_comp[i].end() && (its->sub_key == tmpsub1 || its->length & MASK_INF)) //&& its->sub_key == tmpsub1
			// 	{
			// 		if (its->sub_key == tmpsub1)
			// 			val.max_dist = 0;
			// 		// visited_subkeys.insert(its->sub_key); // why must ==? cautious
			// 		++hitliner;
			// 		// visited_keys.push_back(fetch_ids_node{sub_info_comp{tmpsub1, its->skiplen, its->length}, val, its->sub_key});

			// 		// visited_keys.push_back({tmpsub1, its->skiplen, its->length}); // cautious 9-17
			// 		gen_candidate(val, candidate, {tmpsub1, its->skiplen, its->length}, tmp_visit, i, sub[i], dt + 1, its->sub_key);
			// 	}
			// }
			// get_times(0, 3);
			// for (auto &tmpnode : visited_keys)
			// {
			// 	gen_candidate(tmpnode.kf, candidate, tmpnode.sub_info, tmp_visit, i, sub[i], dt + 1, tmpnode.cache_key);
			// }
			// visited_keys.clear();
			// get_times(0, 4);
			/*
						uint32_t mid_idx, mid_dist;
						for (auto &val : existed_subkeys)
						{
							mid_idx = -1;
							mid_dist = -1;
							tmpsub1 = val.subkey;

							if (val.dist == sub_hammdist[client_id][i] - 1 && val.max_dist >= max_dist) //!=0
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

										// visited_keys.push_back(fetch_ids_node{sub_info_comp{tmpsub1, its->skiplen, its->length}, val, its->sub_key});
										gen_candidate(val, candidate, {tmpsub1, its->skiplen, its->length}, tmp_visit, i, sub[i], dt + 1, its->sub_key);
									}
									val.max_dist = 0; // cautious only stash later
									break;
								}
							}
							else if (val.dist == sub_hammdist[client_id][i] && val.max_dist >= (max_dist - 1)) //!=0
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

						// uint32_t bigger_idx = 0;
						// for optimal to reduce the candidate ; cautious
						// if (i == (hammdist[client_id] - SUBINDEX_NUM + 1) % SUBINDEX_NUM)
						{
							for (auto &val : existed_subkeys)
							{
								if (val.dist == sub_hammdist[client_id][i] && val.max_dist >= max_dist) //!=0
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

											gen_candidate(val, candidate, {tmpsub1, its->skiplen, its->length}, tmp_visit, i, sub[i], dt + 1, its->sub_key);
										}
										val.max_dist = 0; // cautious only stash later
										break;
									}
								}
							}
						}*/
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
			if (min_dist0 + sub_hammdist[client_id][i] > max_dist)
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
							if ((i != (hammdist[client_id] - SUBINDEX_NUM + 1) % SUBINDEX_NUM))
								binary_times++;
							if (its->sub_key == tmpsub1)
								val.max_dist = 0;
							// visited_subkeys.insert(its->sub_key); // why must ==? cautious
							++hitliner;
							// visited_keys.push_back({tmpsub1, its->skiplen, its->length}); // cautious 9-17

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
			}
		}

	search_end:
		// get_times(0, 2);
		ocall_get_timeNow(time);
		end_time = *time;
		find_time += end_time - begin_time;
		ocall_get_timeNow(time);
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
		ocall_get_timeNow(time);
		end_time = *time;
		insert_time += end_time - begin_time;
	}

	int x = candidate.size();
	verifty_step = 0;

	// candidate2.clear();
	// candidate2 = candidate;
	// candi_set2.reset();
	// candi_set2 = candi_set;

	// if (1) // x < thres_cand1//(1.0 * candidate.size() / binary_times) < (2 * dataset_size / feature_size * 1.0)
	// {
	// 	opt_refine++; //! filter_query.test(query_times)
	// 	// step2_flag = 1;
	// 	verifty_step = 1;
	// } // TODO:合并上下的两次遍历
	// printf("----------%d %d\n", query_times, x);

	{ // 查询，eg[2,1,1,1];下面查询dist==2 or 1，1，1，而不是小于
		step2_flag = 1;
		for (int i = 0; i < SUBINDEX_NUM; i++)
		{
			// optimal
			if (i == (hammdist[client_id] - SUBINDEX_NUM + 1) % SUBINDEX_NUM)
				continue;

			if (sub_hammdist[client_id][i] < 0)
				continue;
			ocall_get_timeNow(time);
			begin_time = *time;

			vector<key_find> existed_subkeys2;
			lookup_all_size = 0;
			lookup_radius = sub_hammdist[client_id][i] + max_dist;
			// get_times(1, 0);
			tmp_dist = 0;
			dt = 0;
			tmp_visit.clear();
			// printf("reach size %d\n", reached_subkey.size());
			reached_subkey.clear();
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
				if (tmp_dist > sub_hammdist[client_id][i] + max_dist - 2) //- 2 -1
				{
					if (tmp_dist == sub_hammdist[client_id][i] + max_dist - 1)
					{
						mid_clrs.push_back(c_info);
					}
					else if (tmp_dist == sub_hammdist[client_id][i] + max_dist)
					{
						bigger_clrs.push_back(c_info);
						// for dist == hammdist+max_dist; it must only contains subkey whose hamm dist from cluster equals max_dist, and dist from subkey equals sub_hamm;
						// so bigger_clrs's all dist is max_dist
					}
					continue;
				}
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
			// tmp_clrs.push_back(c_info);
			// uint32_t tmpkey = sub[i];

			// for (int t = 0; t < bloom_hash_times; t += 4)
			// {
			// 	tmp_hash[0] = sub[i];
			// 	tmp_hash[1] = i + t * sub_index_num * 2;
			// 	MurmurHash3_x86_128(tmp_hash, 8, hash_seed[0], bloom_hash + t * INT_SIZE);
			// 	// memcpy(bloom_hash + t * INT_SIZE, tmp_hash_out, std::min(bloom_hash_times - t, (uint32_t)4) * INT_SIZE);
			// }
			// if (filters->contains(bloom_hash, bloom_hash_times * INT_SIZE)) // filters.contains(bloom_hash, bloom_hash_times * INT_SIZE)
			// {
			// 	if (sub_hammdist[client_id][i] <= 1 && tmp_clrs.size() == 1 && mid_clrs.size()) // tmp-clrs只有stash，可以从bigger里面查找
			// 	{
			// 		tmp_node = mid_clrs[0].node;
			// 		begin_idx = tmp_node.begin_idx;
			// 		end_idx = mid_clrs[0].end;
			// 		auto its = std::lower_bound(sub_linear_comp[i].begin() + begin_idx, sub_linear_comp[i].begin() + end_idx, tmpkey, compareFirst_comp);
			// 		if (its < (sub_linear_comp[i].begin() + end_idx) && (its->sub_key == tmpkey || its->length & MASK_INF)) //&& its->sub_key == tmpsub1
			// 		{
			// 			key_find kf{0, 0, 0};
			// 			// visited_keys.push_back(sub_info_comp{tmpsub1, its->skiplen, its->length});
			// 			gen_cand_first(kf, cand_first, {tmpkey, its->skiplen, its->length}, tmp_visit, i, sub[i], dt + 1, its->sub_key, candidate);
			// 		}
			// 	}
			// 	else if (sub_hammdist[client_id][i] <= 0 && tmp_clrs.size() == 1 && bigger_clrs.size()) // tmp-clrs只有stash，可以从bigger里面查找
			// 	{
			// 		for (int id = 0; id < 1; id++)
			// 		{
			// 			tmp_node = bigger_clrs[id].node;
			// 			begin_idx = tmp_node.begin_idx;
			// 			end_idx = bigger_clrs[id].end;
			// 			auto its = std::lower_bound(sub_linear_comp[i].begin() + begin_idx, sub_linear_comp[i].begin() + end_idx, tmpkey, compareFirst_comp);
			// 			if (its < (sub_linear_comp[i].begin() + end_idx) && (its->sub_key == tmpkey || its->length & MASK_INF)) //&& its->sub_key == tmpsub1
			// 			{
			// 				key_find kf{0, 0, 0};
			// 				// visited_keys.push_back(sub_info_comp{tmpsub1, its->skiplen, its->length});
			// 				gen_cand_first(kf, cand_first, {tmpkey, its->skiplen, its->length}, tmp_visit, i, sub[i], dt + 1, its->sub_key, candidate);
			// 			}
			// 		}
			// 	}
			// 	else
			// 	{
			// 		if (min_dist > max_dist)
			// 		{
			// 			tmp_min_idx = tmp_clrs.size() - 1;
			// 		}
			// 		else
			// 			tmp_min_idx = 0;
			// 		// for (int t = 0; t < tmp_clrs.size(); t++) // find 0,实际上只需要考虑stash和最近的，因为最近的一定是最小的
			// 		{
			// 			// if (tmp_clrs[t].dist > tmp_clrs[0].dist)
			// 			// 	break;
			// 			// if (tmp_clrs[t].dist > max_dist)
			// 			// {
			// 			// 	t = tmp_clrs.size() - 1;
			// 			// } // cautious
			// 			tmp_node = tmp_clrs[tmp_min_idx].node;
			// 			begin_idx = tmp_clrs[tmp_min_idx].node.begin_idx;
			// 			end_idx = tmp_clrs[tmp_min_idx].end;

			// 			auto its = std::lower_bound(sub_linear_comp[i].begin() + begin_idx, sub_linear_comp[i].begin() + end_idx, tmpkey, compareFirst_comp);
			// 			if (its < (sub_linear_comp[i].begin() + end_idx) && (its->sub_key == tmpkey || its->length & MASK_INF)) //&& its->sub_key == tmpsub1
			// 			{
			// 				key_find kf{0, 0, 0};
			// 				// visited_keys.push_back(sub_info_comp{tmpsub1, its->skiplen, its->length});
			// 				gen_cand_first(kf, cand_first, {tmpkey, its->skiplen, its->length}, tmp_visit, i, sub[i], dt + 1, its->sub_key, candidate);
			// 			}
			// 		}
			// 	}
			// }
			// dt = 1; // sub[0] is finded
			// tmp_clrs.pop_back();
			// get_times(0, 0);

			uint32_t find_max_d = std::min(min_dist + sub_hammdist[client_id][i], max_dist), tmp_dist = min_dist; // 这个find-max-d是不是太大了，应该写在mindist增加之前

			// for (auto val = tmp_clrs.begin(); val < tmp_clrs.end();)
			// {
			// 	tmp_node = val->node;
			// 	begin_idx = val->node.begin_idx;
			// 	end_idx = val->end;																					// get_search_numbers(sub_keybit,sub_hammdist[i])
			// 	if ((val->dist + max_dist) <= sub_hammdist[client_id][i] || val->node.group_size < combine_clr_min) // end_idx - begin_idx < 500 (val->dist + max_dist - 1) <= sub_hammdist[i] || val->node.group_size < combine_clr_min
			// 	{
			// 		// linear_scan(i, begin_idx, end_idx, sub[i], sub_hammdist[client_id][i], candidate, reached_subkey);
			// 		linear_scan_first(i, begin_idx, end_idx, sub[i], sub_hammdist[client_id][i], cand_first, reached_subkey, candi_first_set, candidate);
			// 		val = tmp_clrs.erase(val);
			// 	}
			// 	else
			// 		val++;
			// }
			get_times(0, 3);

			for (int t = sub_hammdist[client_id][i]; t <= sub_hammdist[client_id][i]; t++)
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
							existed_subkeys2.push_back(key_find{tmpsub1, (uint16_t)t, (uint16_t)find_max_d});
						}
					}
				}
			}fetch_cand_step1+=existed_subkeys2.size();
			// printf("linear size %d exist size %d clr_num%d \n", reached_subkey.size(), existed_subkeys.size(),tmp_clrs.size());
			reached_subkey.clear();
			// get_times(0, 1);

			uint32_t min_dist0 = min_dist;
			// uint32_t find_max_d = std::min(min_dist + sub_hammdist[i], (uint64_t)max_dist), tmp_dist = min_dist; // 这个find-max-d是不是太大了，应该写在mindist增加之前
			min_dist += sub_hammdist[client_id][i] * 2; // cautious- 1
			find_clrs_num += (tmp_clrs.size() ? tmp_clrs.size() : 1);

			if (min_dist0 + sub_hammdist[client_id][i] > max_dist)
			{
				lookup_all_size + sub_linear_comp[i].size() - clr[i][clr[i].size() - 1].begin_idx;
			}
			if (1) // lookup_all_size >= (sub_linear_comp[i].size() >> 1) lookup_all_size >= ceil((double)sub_linear_comp[i].size() / 3)
			{
				uint32_t max_node = 0;
				// for (; max_node < tmp_clrs.size(); max_node++)
				// {
				// 	if (tmp_clrs[max_node].dist > max_dist)
				// 		break;
				// }
				// for (auto tmpc = tmp_clrs.begin(); tmpc != tmp_clrs.end() && tmpc->dist <= (lookup_radius >> 1); tmpc = tmp_clrs.erase(tmpc))
				// {
				// 	tmp_node = tmpc->node;
				// 	begin_idx = tmp_node.begin_idx;
				// 	end_idx = tmpc->end;
				// 	for (int j = 0; j < existed_subkeys2.size(); j++)
				// 	{
				// 		auto &val = existed_subkeys2[j];
				// 		if (val.max_dist == 0)
				// 			continue;

				// 		auto &tmpsub1 = val.subkey;
				// 		// if (val.dist < dt) // if 的次数太多，能否优化  || visited_subkeys.find(tmpsub1) != visited_subkeys.end()
				// 		// 	continue;
				// 		uint16_t tmp = popcount(tmp_node.subkey ^ tmpsub1); // 开销很大？？
				// 		if (tmp > val.max_dist)								// find max太大可省略，是不是小于呢？
				// 			continue;
				// 		val.max_dist = tmp;

				// 		auto its = std::lower_bound(sub_linear_comp[i].begin() + begin_idx, sub_linear_comp[i].begin() + end_idx, tmpsub1, compareFirst_comp);
				// 		if (its != sub_linear_comp[i].end() && (its->sub_key == tmpsub1 || its->length & MASK_INF)) //&& its->sub_key == tmpsub1
				// 		{
				// 			if (its->sub_key == tmpsub1)
				// 			{
				// 				val.max_dist = 0;
				// 				// val.dist = INT16_MAX;
				// 				val.clr_idx = INT16_MAX;
				// 			}
				// 			// visited_keys.push_back(fetch_ids_node{sub_info_comp{tmpsub1, its->skiplen, its->length}, val, its->sub_key});
				// 			gen_cand_first(val, cand_first, {tmpsub1, its->skiplen, its->length}, tmp_visit, i, sub[i], dt + 1, its->sub_key, candidate);
				// 		}
				// 	}

				// 	// get_times(0, 3);
				// 	// for (auto &tmpnode : visited_keys)
				// 	// {
				// 	// 	gen_candidate(tmpnode.kf, candidate, tmpnode.sub_info, tmp_visit, i, sub[i], dt + 1, tmpnode.cache_key);
				// 	// }
				// 	// visited_keys.clear();
				// 	// get_times(0, 4);
				// }

				if (tmp_clrs.size())
					std::sort(tmp_clrs.begin(), tmp_clrs.end(), [](cluster_info &a, cluster_info &b)
							  { return a.node.begin_idx < b.node.begin_idx; });
				uint16_t tmp_min = 0, idx = 0, tmp_d;
				uint32_t tmpkey_, max_find_dist;
				for (int x = 0; x < existed_subkeys2.size(); x++)
				{
					if (existed_subkeys2[x].clr_idx == INT16_MAX)
						continue;

					// for (int t = 0; t < bloom_hash_times; t += 4)
					// {
					// 	tmp_hash[0] = existed_subkeys[x].subkey;
					// 	tmp_hash[1] = i + t * SUBINDEX_NUM * 2;
					// 	MurmurHash3_x86_128(tmp_hash, 8, hash_seed[0], bloom_hash + t * INT_SIZE);
					// }
					// if (!sub_filters[i][sub_hammdist[client_id][i]].contains(bloom_hash, bloom_hash_times * INT_SIZE))
					// {
					// 	existed_subkeys[x].clr_idx = tmp_clrs.size();
					// 	continue;
					// }

					tmp_min = UINT8_MAX;
					tmpkey_ = existed_subkeys2[x].subkey;
					max_find_dist = min_dist0 + existed_subkeys2[x].dist * 2;
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
						existed_subkeys2[x].max_dist = tmp_min;
						// existed_subkeys[x].max_dist = 0;//cautious
						// search in tmpclr[idx]
						existed_subkeys2[x].clr_idx = idx;
					}
					else
					{
						// search in stash
						existed_subkeys2[x].clr_idx = tmp_clrs.size(); // too minor，不要随便乱改字段意义
					}
				}
				c_info.node = clr[i][clr[i].size() - 1];
				c_info.end = sub_linear_comp[i].size();
				c_info.dist = popcount(sub[i] ^ clr[i][clr[i].size() - 1].subkey);
				tmp_clrs.push_back(c_info);

				std::sort(existed_subkeys2.begin(), existed_subkeys2.end(), [](key_find &a, key_find &b)
						  { return a.clr_idx < b.clr_idx; }); // times too long cautious

				bool flag = true;
				int val_idx = 0;
				// for (; val_idx < existed_subkeys.size(); val_idx++) // auto &val : existed_subkeys
				// {
				// 	auto &val = existed_subkeys[val_idx];
				// 	// if (reached_subkey.find(val.subkey) != reached_subkey.end())
				// 	// {
				// 	// 	val.max_dist = 0;
				// 	// 	continue;
				// 	// }
				// 	if (val.clr_idx == INT16_MAX)
				// 		continue;

				// 	if (val.clr_idx == tmp_clrs.size() - 1 && flag)
				// 	{
				// 		// get_times(0, 3);
				// 		flag = false;
				// 		break; // 剩下的在stash里面查找
				// 			   // continue;
				// 	}
				// 	int begin = tmp_clrs[val.clr_idx].node.begin_idx;
				// 	int end = tmp_clrs[val.clr_idx].end;

				// 	auto tmpsub1 = val.subkey;
				// 	auto its = std::lower_bound(sub_linear_comp[i].begin() + begin, sub_linear_comp[i].begin() + end, tmpsub1, compareFirst_comp);
				// 	if (its != sub_linear_comp[i].end() && (its->sub_key == tmpsub1 || its->length & MASK_INF)) //&& its->sub_key == tmpsub1
				// 	{
				// 		if (its->sub_key == tmpsub1)
				// 			val.max_dist = 0;
				// 		// visited_subkeys.insert(its->sub_key); // why must ==? cautious
				// 		++hitliner;
				// 		// visited_keys.push_back(fetch_ids_node{sub_info_comp{tmpsub1, its->skiplen, its->length}, val, its->sub_key});

				// 		// visited_keys.push_back({tmpsub1, its->skiplen, its->length}); // cautious 9-17

				// 		// gen_candidate(val, candidate, {tmpsub1, its->skiplen, its->length}, tmp_visit, i, sub[i], dt + 1, its->sub_key);
				// 		gen_cand_first(val, cand_first, {tmpsub1, its->skiplen, its->length}, tmp_visit, i, sub[i], dt + 1, its->sub_key, candidate);
				// 	}
				// }
				// get_times(0, 3);
				// for (auto &tmpnode : visited_keys)
				// {
				// 	gen_candidate(tmpnode.kf, candidate, tmpnode.sub_info, tmp_visit, i, sub[i], dt + 1, tmpnode.cache_key);
				// }
				// visited_keys.clear();
				// get_times(0, 4);

				// uint32_t mid_idx, mid_dist;
				// for (auto &val : existed_subkeys)
				// {
				// 	mid_idx = -1;
				// 	mid_dist = -1;
				// 	tmpsub1 = val.subkey;

				// 	if (val.dist == sub_hammdist[client_id][i] - 1 && val.max_dist >= max_dist) //!=0
				// 	{
				// 		for (auto &val1 : mid_clrs)
				// 		{
				// 			tmp_node = val1.node;
				// 			begin_idx = tmp_node.begin_idx;
				// 			end_idx = val1.end;
				// 			uint16_t tmp = popcount(tmp_node.subkey ^ tmpsub1); // 开销很大？？
				// 			if (tmp > val.max_dist)								// find max太大可省略，是不是小于呢？
				// 				continue;
				// 			val.max_dist = tmp;

				// 			auto its = std::lower_bound(sub_linear_comp[i].begin() + begin_idx, sub_linear_comp[i].begin() + end_idx, tmpsub1, compareFirst_comp);
				// 			if (its != sub_linear_comp[i].end() && (its->sub_key == tmpsub1 || its->length & MASK_INF)) //&& its->sub_key == tmpsub1
				// 			{

				// 				// visited_keys.push_back(fetch_ids_node{sub_info_comp{tmpsub1, its->skiplen, its->length}, val, its->sub_key});
				// 				gen_cand_first(val, cand_first, {tmpsub1, its->skiplen, its->length}, tmp_visit, i, sub[i], dt + 1, its->sub_key, candidate);
				// 			}
				// 			val.max_dist = 0; // cautious only stash later
				// 			break;
				// 		}
				// 	}
				// 	else if (val.dist == sub_hammdist[client_id][i] && val.max_dist >= (max_dist - 1)) //!=0
				// 	{
				// 		for (int t = 0; t < mid_clrs.size(); t++)
				// 		{
				// 			auto &val1 = mid_clrs[t];
				// 			tmp_node = val1.node;
				// 			uint16_t tmp = popcount(tmp_node.subkey ^ tmpsub1); // 开销很大？？
				// 			if (tmp < mid_dist)									// find max太大可省略，是不是小于呢？
				// 			{
				// 				mid_idx = t;
				// 				mid_dist = tmp;
				// 				if (tmp == max_dist - 1)
				// 					break;
				// 			}
				// 		}

				// 		if (mid_dist > max_dist)
				// 			continue;

				// 		tmp_node = mid_clrs[mid_idx].node;
				// 		begin_idx = tmp_node.begin_idx;
				// 		end_idx = mid_clrs[mid_idx].end;
				// 		auto its = std::lower_bound(sub_linear_comp[i].begin() + begin_idx, sub_linear_comp[i].begin() + end_idx, tmpsub1, compareFirst_comp);
				// 		if (its != sub_linear_comp[i].end() && (its->sub_key == tmpsub1 || its->length & MASK_INF)) //&& its->sub_key == tmpsub1
				// 		{

				// 			gen_cand_first(val, cand_first, {tmpsub1, its->skiplen, its->length}, tmp_visit, i, sub[i], dt + 1, its->sub_key, candidate);
				// 		}
				// 		val.max_dist = 0; // cautious only stash later
				// 	}
				// }
				// get_times(0, 3);
				// for (auto &tmpnode : visited_keys)
				// {
				// 	gen_candidate(tmpnode.kf, candidate, tmpnode.sub_info, tmp_visit, i, sub[i], dt + 1, tmpnode.cache_key);
				// }
				// visited_keys.clear();
				// get_times(0, 4);

				// uint32_t bigger_idx = 0;
				// for (auto &val : existed_subkeys)
				// {
				// 	if (val.dist == sub_hammdist[client_id][i] && val.max_dist >= max_dist) //!=0
				// 	{
				// 		for (auto &val1 : bigger_clrs)
				// 		{
				// 			auto tmpsub1 = val.subkey;
				// 			tmp_node = val1.node;
				// 			begin_idx = tmp_node.begin_idx;
				// 			end_idx = val1.end;
				// 			uint16_t tmp = popcount(tmp_node.subkey ^ tmpsub1); // 开销很大？？
				// 			if (tmp > val.max_dist)								// find max太大可省略，是不是小于呢？
				// 				continue;
				// 			val.max_dist = tmp;

				// 			auto its = std::lower_bound(sub_linear_comp[i].begin() + begin_idx, sub_linear_comp[i].begin() + end_idx, tmpsub1, compareFirst_comp);
				// 			if (its != sub_linear_comp[i].end() && (its->sub_key == tmpsub1 || its->length & MASK_INF)) //&& its->sub_key == tmpsub1
				// 			{

				// 				gen_cand_first(val, cand_first, {tmpsub1, its->skiplen, its->length}, tmp_visit, i, sub[i], dt + 1, its->sub_key, candidate);
				// 			}
				// 			val.max_dist = 0; // cautious only stash later
				// 			break;
				// 		}
				// 	}
				// }
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
				// val_idx = 0;
				if (min_dist0 + sub_hammdist[client_id][i] > max_dist)
				{
					// min_dist = UINT16_MAX;
					uint32_t idx1 = clr[i].size() - 1;
					begin_idx = clr[i][idx1].begin_idx;
					end_idx = sub_linear_comp[i].size();
					if (begin_idx < end_idx) // cautious for stash==0
					{
						for (; val_idx < existed_subkeys2.size(); val_idx++) // auto &val : existed_subkeys
						{
							auto &val = existed_subkeys2[val_idx];
							// if (val.clr_idx != tmp_clrs.size() - 1) // cautious
							// 	continue;

							auto &tmpsub1 = val.subkey;					   // why val.dist< is right not <
							if (val.max_dist < max_dist || val.dist < dt1) //|| visited_subkeys.find(tmpsub1) != visited_subkeys.end() val.clr_idx != tmp_clrs.size() - 1 ||
								continue;								   // stash只查max_dist没有减小的,==0表示已经查找到了？？cautious
							// if (reached_subkey.find(tmpsub1) != reached_subkey.end())
							// 	continue;

							auto its = std::lower_bound(sub_linear_comp[i].begin() + begin_idx, sub_linear_comp[i].begin() + end_idx, tmpsub1, compareFirst_comp);
							if (its != sub_linear_comp[i].end() && (its->sub_key == tmpsub1 || its->length & MASK_INF)) //&& its->sub_key == tmpsub1
							{
								binary_times++;
								if (its->sub_key == tmpsub1)
									val.max_dist = 0;
								// visited_subkeys.insert(its->sub_key); // why must ==? cautious
								++hitliner;
								// visited_keys.push_back({tmpsub1, its->skiplen, its->length}); // cautious 9-17

								// visited_keys.push_back(fetch_ids_node{sub_info_comp{tmpsub1, its->skiplen, its->length}, val, its->sub_key});
								// gen_candidate(val, candidate, {tmpsub1, its->skiplen, its->length}, tmp_visit, i, sub[i], dt + 1, its->sub_key);

								gen_cand_first(val, cand_first, {tmpsub1, its->skiplen, its->length}, tmp_visit, i, sub[i], dt + 1, its->sub_key, candidate);
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

		search_end1:
			// get_times(0, 2);
			ocall_get_timeNow(time);
			end_time = *time;
			find_time += end_time - begin_time;
			ocall_get_timeNow(time);
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
			ocall_get_timeNow(time);
			end_time = *time;
			insert_time += end_time - begin_time;
		}
		step2_flag = 0;
		if (1)
		{
			x = candidate.size() + cand_set_nums;
			if (x < 10)
			{
				cand_nums_set[0]++;
			}
			else if (x < 10000)
			{
				cand_nums_set[1]++;
			}
			else if (x < 50000)
			{
				cand_nums_set[2]++;
			}
			else if (x < 100000)
			{
				cand_nums_set[3]++;
			}
			else if (x < 200000)
			{
				cand_nums_set[4]++;
			}
			else if (x < 300000)
			{
				cand_nums_set[5]++;
			}
			else
			{
				cand_nums_set[6]++;
			}
		}
		
		reduce_total_num=cand_step1.size()-candidateAdd.size();
		ocall_get_timeNow(&time_step1);
		uint64_t esp1 = (time_step1 - time_begin) / 1e3;
		// // auto para_opt=1.0 * (reduce_total_num*cand_set0_nums) / (esp1* cand_set2_nums);
		// // printf("cand rate %lf data query %lf\n", dataset_size / feature_size * 1.0, (1.0 * candidate.size() / binary_times));
		// if (!filter_query.test(query_times)) // x < thres_cand1//(1.0 * candidate.size() / binary_times) < (2 * dataset_size / feature_size * 1.0)
		// {									 //??? >
		// 	opt_refine++;					 //! filter_query.test(query_times)
		// 	// step2_flag = 1;
		// 	verifty_step = 1;
		// } // TODO:合并上下的两次遍历

		// step2_flag = 1;
		// // // printf("----------%d %d\n", query_times, x);
		// if (x >= thres_cand1 && x < thres_cand2)
		// {
		// 	step2_flag = 0;
		// }
		// mix += candi_set_step2.count();

		for (int times = 0; times < 1; times++)
		{
			// if (times)
			// {
			// 	mix2 += candi_set_step2.count();
			// }
			if (verifty_step == 1)
			{
				verifty_step = 1;
				// for (auto &val : cand_step1)
				// {
				// 	if (!candi_set.test(val))
				// 	{
				// 		candidate.push_back(val);
				// 		candi_set.set(val);
				// 	}
				// }
				// candidate.insert(cand_step1.begin(), cand_step1.end());
				break;
			}
			if (!step2_flag && times)
				break;
			int i = (hammdist[client_id] - SUBINDEX_NUM + 1 - times) % SUBINDEX_NUM;
			sub_hammdist[client_id][i] += 1;
			// printf("%d %d\n", i,
			// 	   sub_hammdist[client_id][i]);

			ocall_get_timeNow(time);
			begin_time = *time;

			lookup_all_size = 0;
			lookup_radius = sub_hammdist[client_id][i] + max_dist;
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
				if (tmp_dist > sub_hammdist[client_id][i] + max_dist - 2) //- 2 -1
				{
					if (tmp_dist == sub_hammdist[client_id][i] + max_dist - 1)
					{
						mid_clrs.push_back(c_info);
					}
					else if (tmp_dist == sub_hammdist[client_id][i] + max_dist)
					{
						bigger_clrs.push_back(c_info);
						// for dist == hammdist+max_dist; it must only contains subkey whose hamm dist from cluster equals max_dist, and dist from subkey equals sub_hamm;
						// so bigger_clrs's all dist is max_dist
					}
					continue;
				}
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
				if (sub_hammdist[client_id][i] <= 1 && tmp_clrs.size() == 1 && mid_clrs.size()) // tmp-clrs只有stash，可以从bigger里面查找
				{
					tmp_node = mid_clrs[0].node;
					begin_idx = tmp_node.begin_idx;
					end_idx = mid_clrs[0].end;
					auto its = std::lower_bound(sub_linear_comp[i].begin() + begin_idx, sub_linear_comp[i].begin() + end_idx, tmpkey, compareFirst_comp);
					if (its < (sub_linear_comp[i].begin() + end_idx) && (its->sub_key == tmpkey || its->length & MASK_INF)) //&& its->sub_key == tmpsub1
					{
						key_find kf{0, 0, 0};
						// visited_keys.push_back(sub_info_comp{tmpsub1, its->skiplen, its->length});
						gen_cand_first(kf, cand_first, {tmpkey, its->skiplen, its->length}, tmp_visit, i, sub[i], dt + 1, its->sub_key, candidate);
					}
				}
				else if (sub_hammdist[client_id][i] <= 0 && tmp_clrs.size() == 1 && bigger_clrs.size()) // tmp-clrs只有stash，可以从bigger里面查找
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
							gen_cand_first(kf, cand_first, {tmpkey, its->skiplen, its->length}, tmp_visit, i, sub[i], dt + 1, its->sub_key, candidate);
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
							gen_cand_first(kf, cand_first, {tmpkey, its->skiplen, its->length}, tmp_visit, i, sub[i], dt + 1, its->sub_key, candidate);
						}
					}
				}
			}
			dt = 1; // sub[0] is finded
			tmp_clrs.pop_back();
			// get_times(0, 0);

			uint32_t find_max_d = std::min(min_dist + sub_hammdist[client_id][i], max_dist), tmp_dist = min_dist; // 这个find-max-d是不是太大了，应该写在mindist增加之前

			// for (auto val = tmp_clrs.begin(); val < tmp_clrs.end();)
			// {
			// 	tmp_node = val->node;
			// 	begin_idx = val->node.begin_idx;
			// 	end_idx = val->end;																					// get_search_numbers(sub_keybit,sub_hammdist[i])
			// 	if ((val->dist + max_dist) <= sub_hammdist[client_id][i] || val->node.group_size < combine_clr_min) // end_idx - begin_idx < 500 (val->dist + max_dist - 1) <= sub_hammdist[i] || val->node.group_size < combine_clr_min
			// 	{
			// 		// linear_scan(i, begin_idx, end_idx, sub[i], sub_hammdist[client_id][i], candidate, reached_subkey);

			// 		linear_scan_first(i, begin_idx, end_idx, sub[i], sub_hammdist[client_id][i], cand_first, reached_subkey, candi_first_set, candidate);
			// 		val = tmp_clrs.erase(val);
			// 	}
			// 	else
			// 		val++;
			// }
			get_times(0, 3);

			for (int t = sub_hammdist[client_id][i]; t <= sub_hammdist[client_id][i]; t++)
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

		fetch_cand_times = existed_subkeys.size();
		auto para_opt= (1.0 *reduce_total_num / esp1)*(fetch_cand_step1/fetch_cand_times);
			// printf("%lf \n",para_opt);	
		if (0) // x < thres_cand1//(1.0 * candidate.size() / binary_times) < (2 * dataset_size / feature_size * 1.0)
		{							 //??? >
			opt_refine++;					 //! filter_query.test(query_times)
			step2_flag = 1;
			verifty_step = 1;
		} // TODO:合并上下的两次遍历

		
			// step2_flag = 1;
			// // printf("-----   %lf \n", (1.0 * x / existed_subkeys.size()));
			// // printf("-----   %d %d %d\n", x, existed_subkeys.size(), thres_cand1);
			// // if (x > thres_cand1)
			// if ((1.0 * x / existed_subkeys.size()) > (thres_cand1 * 1.0))
			// {
			// 	step2_flag = 0;
			// }
			if (step2_flag)
			{
				sub_hammdist[client_id][i] -= 1;
				verifty_step = 1;
				break;
			}

			// printf("linear size %d exist size %d clr_num%d \n", reached_subkey.size(), existed_subkeys.size(),tmp_clrs.size());
			reached_subkey.clear();
			// get_times(0, 1);

			uint32_t min_dist0 = min_dist;
			// uint32_t find_max_d = std::min(min_dist + sub_hammdist[i], (uint64_t)max_dist), tmp_dist = min_dist; // 这个find-max-d是不是太大了，应该写在mindist增加之前
			min_dist += sub_hammdist[client_id][i] * 2; // cautious- 1
			find_clrs_num += (tmp_clrs.size() ? tmp_clrs.size() : 1);

			if (min_dist0 + sub_hammdist[client_id][i] > max_dist)
			{
				lookup_all_size + sub_linear_comp[i].size() - clr[i][clr[i].size() - 1].begin_idx;
			}
			if (1) // lookup_all_size >= (sub_linear_comp[i].size() >> 1) lookup_all_size >= ceil((double)sub_linear_comp[i].size() / 3)
			{
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
							gen_cand_first(val, cand_first, {tmpsub1, its->skiplen, its->length}, tmp_visit, i, sub[i], dt + 1, its->sub_key, candidate);
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
						gen_cand_first(val, cand_first, {tmpsub1, its->skiplen, its->length}, tmp_visit, i, sub[i], dt + 1, its->sub_key, candidate);
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

					if (val.dist == sub_hammdist[client_id][i] - 1 && val.max_dist >= max_dist) //!=0
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

								// visited_keys.push_back(fetch_ids_node{sub_info_comp{tmpsub1, its->skiplen, its->length}, val, its->sub_key});
								gen_cand_first(val, cand_first, {tmpsub1, its->skiplen, its->length}, tmp_visit, i, sub[i], dt + 1, its->sub_key, candidate);
							}
							val.max_dist = 0; // cautious only stash later
							break;
						}
					}
					else if (val.dist == sub_hammdist[client_id][i] && val.max_dist >= (max_dist - 1)) //!=0
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

							gen_cand_first(val, cand_first, {tmpsub1, its->skiplen, its->length}, tmp_visit, i, sub[i], dt + 1, its->sub_key, candidate);
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
					if (val.dist == sub_hammdist[client_id][i] && val.max_dist >= max_dist) //!=0
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

								gen_cand_first(val, cand_first, {tmpsub1, its->skiplen, its->length}, tmp_visit, i, sub[i], dt + 1, its->sub_key, candidate);
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
				if (min_dist0 + sub_hammdist[client_id][i] > max_dist)
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
								fetch_cand_times++;
								if (its->sub_key == tmpsub1)
									val.max_dist = 0;
								// visited_subkeys.insert(its->sub_key); // why must ==? cautious
								++hitliner;
								// visited_keys.push_back({tmpsub1, its->skiplen, its->length}); // cautious 9-17

								// visited_keys.push_back(fetch_ids_node{sub_info_comp{tmpsub1, its->skiplen, its->length}, val, its->sub_key});

								gen_cand_first(val, cand_first, {tmpsub1, its->skiplen, its->length}, tmp_visit, i, sub[i], dt + 1, its->sub_key, candidate);
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

			get_times(0, 2);
			ocall_get_timeNow(time);
			end_time = *time;
			find_time += end_time - begin_time;
			ocall_get_timeNow(time);
			begin_time = *time;

			vector<sub_info_comp> tmpv;
			std::map<uint32_t, int> tmpm;
			// the node finded by linear list or hashmap, to get candidate's id

			// candi_num += visited_keys.size();
			// std::sort(visited_keys.begin(), visited_keys.end(), [](sub_info_comp &a, sub_info_comp &b)
			// 		  { return a.length > b.length; });
			reached_subkey.clear();
			visited_keys.clear();
			ocall_get_timeNow(time);
			end_time = *time;
			insert_time += end_time - begin_time;

			sub_hammdist[client_id][i] -= 1;
		}
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

	ocall_get_timeNow(time);
	begin_time = *time;
	uint64_t cmp_hamm[2] = {0};
	uint64_t count = 0;
	vector<uint32_t> res_id;
	res_id.reserve(5000);
	information got_out;
	// candi_num += candidate2.size() + candidateAdd.size();

	candi_num += candidate.size();
	if (verifty_step)
		candi_num += cand_step1.size();
	else
		candi_num += candidateAdd.size();
	if (candidate.size() < 10)
	{
		cand_nums[0]++;
	}
	else if (candidate.size() < 100)
	{
		cand_nums[1]++;
	}
	else if (candidate.size() < 1000)
	{
		cand_nums[2]++;
	}
	else if (candidate.size() < 10000)
	{
		cand_nums[3]++;
	}
	else if (candidate.size() < 50000)
	{
		cand_nums[4]++;
	}
	else if (candidate.size() < 100000)
	{
		cand_nums[5]++;
	}
	else
		cand_nums[6]++;

	hittt += candidate2.size() + candidateAdd.size();
	misss += candidate.size();
	// printf("htu  %d   miss %d\n", hittt, misss);
	// -- -- -- -- -

	// 使用push_back插入Record实例
	// record_info.push_back({fetch_cand_times, query_times, candidate.size(), candidate2.size() + candidateAdd.size(),
	// 					   candidate.size() - candidate2.size() - candidateAdd.size(),
	// 					   1.0 * (candidate.size() - candidate2.size() - candidateAdd.size()) / fetch_cand_times});

	// printf("----size %d-----query %d candidate %d candi2 %d sub-nums %d rate %lf\n", fetch_cand_times, query_times, candidate.size(),
	// 	   candidate2.size() + candidateAdd.size(), candidate.size() - candidate2.size() - candidateAdd.size(),
	// 	   1.0 * (candidate.size() - candidate2.size() - candidateAdd.size()) / fetch_cand_times);

	for (auto it = candidate.begin(); it != candidate.end();)
	{
		// if (*it < full_index.size())
		auto got_out = full_key_sorted[*it];
		if (1)
		{
			// get_full_fingerprint32(tmp_fullkey, (uint32_t *)&full_index[*it]);
			cmp_hamm[0] = query[0] ^ (got_out.fullkey[0]);
			cmp_hamm[1] = query[1] ^ (got_out.fullkey[1]);
			count = popcount(cmp_hamm[0]) + popcount(cmp_hamm[1]);
			// count = bitset<64>(cmp_hamm[0]).count() + bitset<64>(cmp_hamm[1]).count();

			// candi_num += full_index[*it + fullkey_len].len; // cautious caluate for candidate images
			if (count <= hammdist[client_id])
			{
				res_id.push_back(got_out.identify);

				// printf("target %d\n", got_out.identify);
				successful_num++;
				// successful_num += full_index[*it + fullkey_len].len;

				out_tmp = out;
				if (got_out.target == tmp_test_target)
				{
					hit_succ_num++;
					// equal = 1;
				}
				else
					false_num++;
				// it++;
			}
			// else
			// 	it = candidate.erase(it);
			it++;
		}
	}
	if (verifty_step)
	{
		for (auto it = cand_step1.begin(); it != cand_step1.end(); it++)
		{
			// if (candi_set.test(*it))
			// 	continue;
			auto got_out = full_key_sorted[*it];
			// get_full_fingerprint32(tmp_fullkey, (uint32_t *)&full_index[*it]);
			cmp_hamm[0] = query[0] ^ (got_out.fullkey[0]);
			cmp_hamm[1] = query[1] ^ (got_out.fullkey[1]);
			count = popcount(cmp_hamm[0]) + popcount(cmp_hamm[1]);
			// count = bitset<64>(cmp_hamm[0]).count() + bitset<64>(cmp_hamm[1]).count();

			// candi_num += full_index[*it + fullkey_len].len; // cautious caluate for candidate images
			if (count <= hammdist[client_id])
			{
				res_id.push_back(got_out.identify);

				// printf("target %d\n", got_out.identify);
				successful_num++;
				// successful_num += full_index[*it + fullkey_len].len;

				out_tmp = out;
				if (got_out.target == tmp_test_target)
				{
					hit_succ_num++;
					// equal = 1;
				}
				else
					false_num++;
			}
		}
	}
	else
	{
		for (auto it = candidateAdd.begin(); it != candidateAdd.end(); it++)
		{
			auto got_out = full_key_sorted[*it];
			cmp_hamm[0] = query[0] ^ (got_out.fullkey[0]);
			cmp_hamm[1] = query[1] ^ (got_out.fullkey[1]);
			count = popcount(cmp_hamm[0]) + popcount(cmp_hamm[1]);

			if (count <= hammdist[client_id])
			{
				res_id.push_back(got_out.identify);

				successful_num++;
				out_tmp = out;
				if (got_out.target == tmp_test_target)
				{
					hit_succ_num++;
				}
				else
					false_num++;
			}
		}
	}

	// printf("targste %d\n", tmp_test_target);
	// printf("%d unequal %d\n", unequal, unequal_n);
	if (equal)
	{
		hit_succ_num++;
	}
	ocall_get_timeNow(time);
	end_time = *time;
	verify_time += end_time - begin_time;
	ocall_get_timeNow(total_time_now);
	total_end_time = *total_time_now;
	total_time += total_end_time - total_begin_time;
	return std::move(res_id);
}

void containers::gen_cand_first(key_find &find_key, std::unordered_set<uint32_t> &cand_first, sub_info_comp comp, vector<sub_info_comp> &tmp_keys,
								uint32_t i, uint32_t subkey, uint32_t dt, uint32_t cache_key, std::vector<uint32_t> &cand)
{

	times_gen++;
	uint8_t *tmp_ids_block;
	uint64_t key = ((uint64_t)i << 32) | cache_key;

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
					// if (cand_first.find(out_tmp[l]) != cand_first.end())
					// 	cand.emplace_back( out_tmp[l]);
					// else
					// 	cand_first.emplace_hint(cand_first.begin(), out_tmp[l]);
					// if (step2_flag)
					// {
					// 	if (!candi_set.test(out_tmp[l]))
					// 	{
					// 		cand.emplace_back(out_tmp[l]);
					// 		candi_set.set(out_tmp[l]);
					// 	}
					// 	// if (candi_set_step2.test(out_tmp[l]) && !candi_set.test(out_tmp[l]))
					// 	// {
					// 	// 	cand.emplace_back(out_tmp[l]);
					// 	// 	candi_set.set(out_tmp[l]);
					// 	// }
					// 	// if (candi_first_set.test(out_tmp[l]))
					// 	// 	candi_set_step2.set(out_tmp[l]);
					// }
					// else
					{
						if (!candi_set.test(out_tmp[l]))
						{
							if (candi_first_set.test(out_tmp[l]))
							{
								candidateAdd.emplace_back(out_tmp[l]); // cautious
								// cand.emplace_back(out_tmp[l]);
								candi_set.set(out_tmp[l]);
							}
							else
							{
								// if (i == (hammdist[client_id] - SUBINDEX_NUM) % SUBINDEX_NUM)
								// {
								// 	candi_set_step2.set(out_tmp[l]);
								// }
								candi_first_set.set(out_tmp[l]);
								cand_step1.push_back(out_tmp[l]);
								cand_set_nums++;
							}
						}
					}
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
	}
	else
	{
		// reached_subkey[comp.sub_key] = -1;
		find_key.max_dist = 0;
		find_key.clr_idx = INT16_MAX;
		for (int j = 0; j < tmp_size; j++)
		{
			// if (step2_flag)
			// {
			// 	if (!candi_set.test(out_tmp[j]))
			// 	{
			// 		cand.emplace_back(out_tmp[j]);
			// 		candi_set.set(out_tmp[j]);
			// 	}
			// 	// if (candi_set_step2.test(out_tmp[j]) && !candi_set.test(out_tmp[j]))
			// 	// {
			// 	// 	cand.emplace_back(out_tmp[j]);
			// 	// 	candi_set.set(out_tmp[j]);
			// 	// }
			// 	// if (candi_first_set.test(out_tmp[j]))
			// 	// 	candi_set_step2.set(out_tmp[j]);
			// }
			// else
			{
				if (!candi_set.test(out_tmp[j]))
				{
					if (candi_first_set.test(out_tmp[j]))
					{
						candidateAdd.emplace_back(out_tmp[j]);
						// cand.emplace_back(out_tmp[j]);
						candi_set.set(out_tmp[j]);
					}
					else
					{
						// if (i == (hammdist[client_id] - SUBINDEX_NUM) % SUBINDEX_NUM)
						// {
						// 	candi_set_step2.set(out_tmp[j]);
						// }
						candi_first_set.set(out_tmp[j]);
						cand_step1.push_back(out_tmp[j]);
						cand_set_nums++;
					}
				}
			}
			// if (cand_first.find(out_tmp[j]) != cand_first.end())
			// 	cand.emplace_back( out_tmp[j]);
			// else
			// 	cand_first.emplace_hint(cand_first.begin(), out_tmp[j]);
		}
	}
}

void containers::gen_candidate(key_find &find_key, std::vector<uint32_t> &cand, sub_info_comp comp, vector<sub_info_comp> &tmp_keys,
							   uint32_t i, uint32_t subkey, uint32_t dt, uint32_t cache_key)
{
	times_gen++;
	uint8_t *tmp_ids_block;
	uint64_t key = ((uint64_t)i << 32) | cache_key;

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
					if (!candi_set.test(out_tmp[l]))
					{
						cand.emplace_back(out_tmp[l]);
						candi_set.set(out_tmp[l]);
					}
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
	}
	else
	{
		// reached_subkey[comp.sub_key] = -1;
		find_key.max_dist = 0;
		find_key.clr_idx = INT16_MAX;
		for (int j = 0; j < tmp_size; j++)
		{
			if (!candi_set.test(out_tmp[j]))
			{
				cand.emplace_back(out_tmp[j]);
				candi_set.set(out_tmp[j]);
			}
			// cand.emplace_back( out_tmp[j]);
		}
	}
}
void containers::linear_scan(uint32_t client, uint32_t i, uint32_t begin, uint32_t end, uint32_t subkey, uint32_t hamm,
							 vector<uint32_t> &candidate, std::unordered_map<uint32_t, int> &reached_subkey)
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

				tmp_size = *((uint32_t *)&tmp_ids_block[0]);
				;
				for (int j = 1; j < tmp_size;)
				{
					auto dis = popcount(out_tmp[j] ^ subkey);
					if (dis <= hamm)
					{
						j++;
						uint32_t len = out_tmp[j];
						reached_subkey[out_tmp[j - 1]] = -1;
						for (int l = j + 1; l <= j + len; l++)
						{
							if (!candi_set.test(out_tmp[l]))
							{
								candidate.emplace_back(out_tmp[l]);
								candi_set.set(out_tmp[l]);
							}
							// candidate.emplace_back(candidate.begin(), out_tmp[l]);
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
			// 		cand.emplace_back( out_tmp[j]);
			// 	}
			// }
		}
		else
		{
			auto dis = popcount(tmp_info.sub_key ^ subkey);
			if (dis <= hamm)
			{
				key_find kf{0, 0, 0};
				reached_subkey[tmp_info.sub_key] = -1;
				// if(reached_subkey.find(tmp_info.sub_key)!=reached_subkey.end())printf("error\n");
				gen_candidate(kf, candidate, {tmp_info.sub_key, tmp_info.skiplen, tmp_info.length}, tmp_visit, i, subkey, 0, tmp_info.sub_key);

				// visited_keys.push_back(tmp_info);
			}
			// else if (dis == hamm + 1 && hamm < sub_hammdist[client][i])
			// {
			// 	key_find kf{0, 0, 0};
			// 	reached_subkey[tmp_info.sub_key] = -1;
			// 	gen_cand_first(kf, candidate, {tmp_info.sub_key, tmp_info.skiplen, tmp_info.length}, tmp_visit, i, subkey, 0, tmp_info.sub_key, candidate);
			// }
		}
	}
}

template <size_t T>
void containers::linear_scan_first(uint32_t i, uint32_t begin, uint32_t end, uint32_t subkey, uint32_t sub_hammdist,
								   unordered_set<uint32_t> &cand_first, std::unordered_map<uint32_t, int> &reached_subkey, bitset<T> &cand_set, std::vector<uint32_t> &cand)
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
			// //gen_candidate(kf,candidate,tmp_info,visited_keys,visited_keys,i,subkey,0);
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
			// tmp_ids_block = id_point[i] + tmp_info.skiplen;
			uint32_t tempKey = subkey;
			uint32_t tmp_size = 0;
			int tmp_begin = 0;
			bool is_combined_keys = false;

			auto out_tmp = out;
			// printf("test first byte %d\n", tmp_ids_block[0]);
			out_tmp = (uint32_t *)tmp_ids_block;
			// (tmp_begin < 0) ,some continuous  subkeys are Combined to one biggest subkey in there
			// if (tmp_info.length & MASK_INF)
			{
				is_combined_keys = true;
			}
			// bitset<DATA_LEN * 10> set2;
			// get the true identifiers of the subkey
			if (is_combined_keys)
			{
				combs++;
				uint32_t lens = 0;
				tmp_size = *((uint32_t *)&tmp_ids_block[0]);
				;
				// printf("tmp %d %d\n", tmp_size, tmp_size);
				for (int j = 1; j < tmp_size;)
				{
					if (popcount(out_tmp[j] ^ subkey) == sub_hammdist)
					{
						j++;
						uint32_t len = out_tmp[j];
						reached_subkey[out_tmp[j - 1]] = -1;
						for (int l = j + 1; l <= j + len; l++)
						{
							// printf("%d\n", out_tmp[l]);
							// if (!cand_set.test(out_tmp[l]))
							// {
							// 	candidate.push_back(out_tmp[l]);
							// 	cand_set.set(out_tmp[l]);
							// }

							if (step2_flag)
							{
								if (!candi_set.test(out_tmp[l]))
								{
									cand.emplace_back(out_tmp[l]);
									candi_set.set(out_tmp[l]);
								}
								// if (candi_set_step2.test(out_tmp[l]))
								// 	cand.emplace_back(out_tmp[l]);
								// if (candi_first_set.test(out_tmp[l]))
								// 	candi_set_step2.set(out_tmp[l]);
							}
							else
							{
								if (!candi_set.test(out_tmp[l]))
								{
									if (candi_first_set.test(out_tmp[l]))
									{
										cand.emplace_back(out_tmp[l]);
										candi_set.set((out_tmp[l]));
									}
									else
									{
										// if (i == (hammdist[client_id] - SUBINDEX_NUM) % SUBINDEX_NUM)
										// {
										// 	candi_set_step2.set(out_tmp[l]);
										// }
										candi_first_set.set(out_tmp[l]);
										cand_step1.push_back(out_tmp[l]);
										cand_set_nums++;
									}
								}
							}
							// if (out_tmp[l] < set2.size())
							// 	set2.set(out_tmp[l]);
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
			// 		cand.emplace_back( out_tmp[j]);
			// 	}
			// }
		}
		else
		{
			if (popcount(tmp_info.sub_key ^ subkey) == sub_hammdist)
			{
				key_find kf{0, 0, 0};
				reached_subkey[tmp_info.sub_key] = -1;
				// if(reached_subkey.find(tmp_info.sub_key)!=reached_subkey.end())printf("error\n");
				gen_cand_first(kf, cand_first, {tmp_info.sub_key, tmp_info.skiplen, tmp_info.length}, tmp_visit, i, subkey, 0, tmp_info.sub_key, cand);
				// visited_keys.push_back(tmp_info);
			}
		}
	}
}

void containers::test()
{
	record_info.clear();
	query_times = 0;candi_num =0;
	// hittt = 0;
	// misss = 0;
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

	uint64_t begin_time, end_time;
	vector<uint64_t> time_esp;
	uint32_t i = 0;
	for (int t = 0; t < test_pool.size(); t++)
	{
		ocall_get_timeNow(&begin_time);
		auto itx = test_pool[t];
		auto img_id = test_targets[t];
		temp_key[0] = itx.first;
		temp_key[1] = itx.second;
		find_sim(temp_key, img_id, 0);
		// 					   // i++;
		int k = 1000;
		ocall_get_timeNow(&end_time);
		time_esp.push_back((end_time - begin_time));

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

	// 根据rate字段对recoInfo进行排序
	// std::sort(record_info.begin(), record_info.end(), [](const Record_Info_Refine &a, const Record_Info_Refine &b)
	// 		  { return a.sub_nums < b.sub_nums; });

	// // 打印前10个Record作为示例
	// for (auto &record : record_info)
	// {
	// 	// const auto &record = record_info[i];
	// 	printf("%d \n", record.fetch_cand_times);
	// 	// printf("----size %u-----query %u candidate %u candi2 %u sub-nums %u rate %lf\n",
	// 	// 	   record.fetch_cand_times,
	// 	// 	   record.query_times,
	// 	// 	   record.candidate_size,
	// 	// 	   record.candidate2_size,
	// 	// 	   record.sub_nums,
	// 	//    record.rate);
	// }

	// sort in ascend
	sort(time_esp.begin(), time_esp.end());
	// // printf 95th tail
	// printf("25th tail: %d\n", time_esp[time_esp.size() * 0.15]);
	// printf("25th tail: %d\n", time_esp[time_esp.size() * 0.25]);
	// printf("45th tail: %d\n", time_esp[time_esp.size() * 0.45]);
	// printf("95th tail: %d\n", time_esp[time_esp.size() * 0.65]);
	printf("95th tail: %d\n", time_esp[time_esp.size() * 0.95]);

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
	// printf("resize times %d size %lld finded clrs times %d\n", resize_times, resize_size, find_clrs_num);

	printf("fetch candidate time %d candi_num %d combs %d combs_hit %d bigun%d\n", times_gen, candi_num, combs, combs_hit, big_uneq);
	// total时间（ms）， find：查询map和linear的时间，insert：插入到set<candidate>的时间，verify：验证candidate的时间
	printf("total=time:%d,sum:%d, find-time:%d, insert-time:%d, verify-time:%d\n", total_time, find_time + insert_time + verify_time, find_time, insert_time, verify_time);
	for (int t = 0; t < 6; t++)
		bd_time[t] /= 1e6;
	// printf("cal-cer one %d, bitmask %d, stash %d, cluster %d id_loading %d \n", bd_time[0], bd_time[1], bd_time[2], bd_time[3], bd_time[4]);
	// printf("zero_num=%d  combine_clr_min=%d test target %d\n", zero_num, combine_clr_min, test_target);

	// printf("max_cache value %d %d\n", mix, mix2);
}
void containers::changeHammingDist(uint64_t hammdist, int client_id)
{
	this->hammdist[client_id] = hammdist;
	// for (int i = 0; i < SUBINDEX_NUM; i++)
	// {
	// 	this->sub_hammdist[client_id] = floor((double)hammdist / SUBINDEX_NUM);
	// }
	// if (hammdist == this->hammdist)
	// 	return;
	// this->hammdist = hammdist;
	// // this->sub_hammdist=hammdist/4;
	for (int i = 0; i < cont.sub_index_num; i++)
		this->sub_hammdist[client_id][i] = -1;
	for (int j = hammdist + 1; j > 0;)
	{
		// the sum of sub_hammdist is hammdist - sub_index_num + 1
		for (int i = 0; i < sub_index_num; i++)
		{
			if (j <= 0)
				break;
			this->sub_hammdist[client_id][i]++;
			j--;
		}
	}
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
	// printf("c_o size: %d\n", cont.C_0_TO_subhammdis[0].size());
	printf("Init!\n");
	cont.initialize();
	// cont.get_test_pool();
	// printf("The full index entry is: %d \n",cont.full_index.size());
	// printf("The number of queries is: %d \n",cont.test_pool.size());
}
void test_run()
{
	opt_refine = 0;
	cont.successful_num = 0;
	cont.false_num = 0;
	cont.hit_succ_num = 0;
	for (int i = 0; i < 7; i++)
	{
		cand_nums[i] = 0;
		cand_nums_set[i] = 0;
	}
	cont.test();
	// for (int i = 0; i < 7; i++)
	// {
	// 	printf("cand %d before %d after %d\n", i, cand_nums_set[i], cand_nums[i]);
	// }
	printf("optm= %d.\n", opt_refine);
	printf("Successfully found similar photos! successful_num=%d.\n", cont.successful_num);
	// printf("Successfully found similar photos! successful_num=%d hit %d false %d.\n", cont.successful_num, cont.hit_succ_num, cont.false_num);
}
void init_after_send()
{
	cont.get_test_pool(); // get test pool before sort the linearlist
	// cont.full_key_sorted.shrink_to_fit();

	cont.init_filters(0);
	cont.opt_full_index();
	// // cont.opt_sub_index();
	// printf("lll %d %f\n", (uint32_t)(1.0 * cont.sub_index_liner[0].size() / 2000), (1.0 * cont.sub_index_liner[0].size() / 1.0 * 1000));

	cont.make_clusters();

	uint32_t nums = 0;
	for (int i = 0; i < SUBINDEX_NUM; i++)
		nums += cont.sub_linear_comp[i].size();
	cont.lru_cache.capacity = CACHE_SIZE; // 5000 ((uint32_t)floor((double)nums / 100) < 20000 ? 20000 : (uint32_t)floor((double)nums / 100)); //	nums + 100000; //
	cont.lru_cache.len = 0;
	cont.init_ids_cache();

	printf("The full index entry is: %d \n", cont.full_index.size());
	printf("The number of queries is: %d \n", cont.test_pool.size());

	printf("The full sort entry is: %d \n", cont.full_key_sorted.size());
	printf("comp_subkey %d\n", cont.sub_linear_comp->size());
	printf("cache size %d\n", cont.data_cache.size());
	printf("---------------- feature Rate %d\n", dataset_size / feature_size);
}

void ecall_send_data(void *dataptr, size_t len)
{
	std::pair<uint64_t, uint64_t> *data = reinterpret_cast<std::pair<uint64_t, uint64_t> *>(dataptr);
	uint32_t out_id;
	info_uncomp info;
	for (int i = 0; i < len; i++)
	{
		// if (cont.full_key_sorted.size() < DATA_LEN)
		{
			info.fullkey[0] = data[i].first;
			info.fullkey[1] = data[i].second;
			out_id = cont.random_uuid() - 1;
			info.identify = out_id;
			cont.full_key_sorted.push_back(info);
			// if (cont.test_pool.size() < cont.test_size)
			// 	cont.test_pool.insert(data[i]);
		}
		// else
		// {
		// 	cont.tmp_test_pool.push_back(data[i]);
		// }
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
		// cont.full_key_sorted[index].identify = data[i];
		cont.full_ids.push_back(data[i]);
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
	uint32_t tmp_hash[2], hash_size = ceil((float)bloom_hash_times / 4) * 16; // ceil(times/4)*4
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

	int real_total_num = 0;
	for (int i = 0; i < full_key_sorted.size();)
	{
		real_total_num++;
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

		// uint32_t tmp_sub[4];
		// cont.get_sub_fingerprint32(tmp_sub, temp_keys);
		// for (int j = 0; j < 4; j++)
		// {
		// 	temp_information.sub_fullkey = tmp_sub[j];
		// 	full_index.push_back(temp_information);
		// }

		// uint32_t len = 0;
		// temp_keys[0] = full_key_sorted[i].fullkey[0];
		// temp_keys[1] = full_key_sorted[i].fullkey[1];
		// for (int j = i; j < full_key_sorted.size() && full_key_sorted[j].fullkey[0] == temp_keys[0] && full_key_sorted[j].fullkey[1] == temp_keys[1]; j++)
		// {
		// 	len++;
		// }
		// len_info.len = len;
		// full_index.push_back(len_info);

		// // 加入target字段，用于测试精确度
		// //  information targets;
		// //  uint32_t tmp_target = -1, num = 0;
		// //  uint32_t tmps[1000] = {0};
		// //  for (int j = i; j < full_key_sorted.size() && full_key_sorted[j].fullkey[0] == temp_keys[0] && full_key_sorted[j].fullkey[1] == temp_keys[1]; j++)
		// //  {
		// //  	tmps[full_key_sorted[j].target]++;
		// //  }
		// //  for (int j = i; j < full_key_sorted.size() && full_key_sorted[j].fullkey[0] == temp_keys[0] && full_key_sorted[j].fullkey[1] == temp_keys[1]; j++)
		// //  {
		// //  	if (num < tmps[full_key_sorted[j].target])
		// //  	{
		// //  		num = tmps[full_key_sorted[j].target];
		// //  		tmp_target = full_key_sorted[j].target;
		// //  	}
		// //  }
		// //  if (tmp_target == -1)
		// //  	tmp_target = full_key_sorted[i].target;
		// //  targets.target = tmp_target;
		// //  full_index.push_back(targets);

		// for (; i < full_key_sorted.size() && full_key_sorted[i].fullkey[0] == temp_keys[0] && full_key_sorted[i].fullkey[1] == temp_keys[1]; i++)
		// {
		// 	info_idy.push_back(full_key_sorted[i].identify);

		// 	full_key_sorted[i].identify = full_index.size() - 5; // 4 for 4*32bit subkey, 1 for len
		// 														 // idy_info.identify = full_key_sorted[i].identify;
		// 														 // full_index.push_back(idy_info);
		// }
		// uint32_t compress_len = for_compressed_size_unsorted((uint32_t *)info_idy.data(), info_idy.size());
		// complen += compress_len - info_idy.size() * 4;
		// for_compress_unsorted((uint32_t *)info_idy.data(), tmp_compress_data, info_idy.size());
		// uint32_t tmp = 0;

		// // 如果size小于COMPRESS_MIN_FULLKEY，不压缩，直接存储uint32_t;否则需要把压缩后产生的uint8用小端方式转换为uint32
		// if (info_idy.size() <= COMPRESS_MIN_UNSORT)
		// {
		// 	for (int j = 0; j < info_idy.size(); j++)
		// 	{
		// 		idy_info.comp_data = info_idy[j];
		// 		full_index.push_back(idy_info);
		// 	}
		// }
		// else
		// {
		// 	for (int j = 0; j < compress_len; j += 4)
		// 	{
		// 		tmp = 0;
		// 		for (int t = 0; t < 4; t++)
		// 		{
		// 			if (j + t < compress_len)
		// 			{
		// 				tmp += ((uint32_t)tmp_compress_data[j + t]) << (8 * t);
		// 			}
		// 		}
		// 		idy_info.comp_data = tmp; // tmp_compress_data[j];
		// 		full_index.push_back(idy_info);
		// 	}
		// }
		++i;
	}

	// auto last = std::unique(full_key_sorted.begin(), full_key_sorted.end(), [](info_uncomp &a, info_uncomp &b)
	// 						{ return a.fullkey[0] == b.fullkey[0] && a.fullkey[1] == b.fullkey[1] && a.identify == b.identify; });
	// full_key_sorted.erase(last, full_key_sorted.end());
	// full_key_sorted.shrink_to_fit();
	// printf("fullkey len %d filter_nums %d\n", full_key_sorted.size(), filter_nums);
	// init_filters(filter_nums);//cautious
	// printf("fullkey len %d filter_nums %d\n", fullkey_len, filter_nums);

	// printf("dataset real num %d\n", real_total_num);
	// printf("complen=%d\n", complen); // 减少的字节数
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
	// printf("bloom_hash_times=%d max_table-size %lld\n", bloom_hash_times, parameters.optimal_parameters.table_size);
	//  for (int i = 0; i < 4; i++)
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

	bloom_parameters parameters2;
	parameters2.random_seed = 0xA5A5A5A5;

	parameters2.optimal_parameters.table_size = 100000;
	parameters2.optimal_parameters.number_of_hashes = 4;
	bloom_hash_times = parameters2.optimal_parameters.number_of_hashes;
	// printf("bloom_hash_times=%d max_table-size %lld\n", bloom_hash_times, parameters.optimal_parameters.table_size);
	//  for (int i = 0; i < 4; i++)

	for (int i = 0; i < SUBINDEX_NUM; i++)
	{
		sub_filters[i] = new bloom_filter[5]{parameters2, parameters2, parameters2, parameters2, parameters2};
	}
};
void containers::make_clusters()
{
	{
		query_t qt[CLR_THD_NUM];
		for (int t = 0; t < CLR_THD_NUM; t++)
		{
			qt[t].tmp_conts = this;
			qt[t].thd_idx = t;
			qt[t].type = 0;
			pthread_create(&clr_thread[t], NULL, func_forward, (void *)&qt[t]);
		}
	}

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
	// resort_que.resize(nums_tmp);

	// for (int i = 0; i < SUBINDEX_NUM; i++)
	// {
	// 	std::sort(sub_index_liner[i].begin(), sub_index_liner[i].end(), customCompare); // cautious
	// }

	printf("cluster 1\n");

	resort_node tmp_node, tmp_node1;
	info_uncomp tmp_info, tmp_info1;
	int tmp_cluster = 0, dis = 0;
	vector<uint32_t> tmp_clrs;
	vector<uint32_t> tmp_keys;
	uint32_t rq_size = 0;
	vector<uint32_t> max_dist_inClr;
	uint32_t clr_sum_size = 0, clr_max, clr_min;
	vector<uint32_t> clr_keys(0);
	dataset_size += full_key_sorted.size() * SUBINDEX_NUM;
	for (int i = 0; i < SUBINDEX_NUM; i++)
	{
		for (int t = 0; t < full_key_sorted.size(); t++)
		{
			split(sub, (uint8_t *)full_key_sorted[t].fullkey, sub_index_num, sub_index_plus, sub_keybit);
			full_key_sorted[t].target = sub[i];
		}
		std::sort(full_key_sorted.begin(), full_key_sorted.end(), [](const info_uncomp &a, const info_uncomp &b)
				  { return a.target < b.target; });

		for (int t = 0; t < full_key_sorted.size(); t++)
		{
			if (t == 0 || full_key_sorted[t].target != full_key_sorted[t - 1].target)
			{
				feature_size++;
			}
		}
		if (min_clr_size < 300)
			clr[i] = kmodes(i, clr_keys);
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
		//  }
		//  for (int i = 0; i < SUBINDEX_NUM; i++)
		//  {

		clr_sum_size = 0;
		clr_max = 0;
		clr_min = UINT32_MAX;
		// printf("hashtimes %d cluster 3 %d %d\n", bloom_hash_times, i, SUBINDEX_NUM);
		rq_size = 0;
		tmp_clrs.clear();

		vector<uint32_t> tmp_clr_endIdx;
		tmp_clr_endIdx.resize(clr[i].size());
		clr[i][0].begin_idx = 0;
		for (int t = 1; t < clr[i].size(); t++)
		{
			clr[i][t].begin_idx = clr[i][t - 1].begin_idx + clr[i][t - 1].group_size;
			tmp_clr_endIdx[t - 1] = clr[i][t].begin_idx;
		}
		tmp_clr_endIdx[tmp_clr_endIdx.size() - 1] = full_key_sorted.size();

		// printf("hashtimes %d cluster 3 %d %d\n", bloom_hash_times, i, SUBINDEX_NUM);
		clr_nums.clear();
		// resort_que.clear();
		clr_nums.resize(clr[i].size());
		for (int t = 0; t < clr_nums.size() - 1; t++)
			clr_nums[t] = clr[i][t].group_size;
		max_dist_inClr.resize(clr[i].size());
		for (int j = 0; j < full_key_sorted.size(); j++)
		{
			tmp_dist = UINT32_MAX;
			tmp_cluster = -1;
			// tmp_node.sub_info.sub_key = sub_index_liner[i][j].sub_key;
			// tmp_node.sub_info.identifiers = sub_index_liner[i][j].identifiers;

			// tmp_node.sub_info.sub_key = full_key_sorted[j].target;
			// tmp_node.sub_info.identifiers = full_key_sorted[j].identify;

			if (clr_keys.size())
			{
				auto res = find_nearest_element_avx2(clr_keys, full_key_sorted[j].target, 0, clr_keys.size());

				tmp_clrs.clear();
				tmp_clrs.push_back(res.first);
				tmp_dist = res.second;
				tmp_cluster = res.first;
				// printf("%d %d %d\n", tmp_dist, tmp_cluster, clr_keys.size());
			}
			// for (int t = 0; t < (clr[i].size() - 1); t++)
			// {
			// 	dis = popcount(full_key_sorted[j].target ^ clr[i][t].subkey);
			// 	if (dis < tmp_dist)
			// 	{
			// 		tmp_clrs.clear();
			// 		tmp_clrs.push_back(t);
			// 		tmp_cluster = t;
			// 		tmp_dist = dis;
			// 	}
			// 	else if (dis == tmp_dist)
			// 	{
			// 		// tmp_clrs.push_back(t);
			// 	}
			// }

			if (tmp_cluster >= 0 && tmp_dist <= max_dist) // cautious
			{
				// if (tmp_dist > max_dist_inClr[tmp_cluster])
				//     max_dist_inClr[tmp_cluster] = tmp_dist;
				for (auto &val : tmp_clrs)
				{
					// if (clr[i][val].begin_idx >= tmp_clr_endIdx[val])
					//     printf("err %d %d\n", clr[i][val].begin_idx, tmp_clr_endIdx[val]);
					std::swap(full_key_sorted[clr[i][val].begin_idx], full_key_sorted[j]);
					// tmp_info = full_key_sorted[clr[i][val].begin_idx];
					// full_key_sorted[clr[i][val].begin_idx] = full_key_sorted[j];
					// full_key_sorted[j] = tmp_info;
					// printf("%d %d %d\n", clr[i][val].begin_idx, j, clr_nums[val]);
					if (clr[i][val].begin_idx == j)
					{
						clr[i][val].begin_idx++;
						int k = 0;
						for (k = 0; k < clr[i].size() && clr[i][k].begin_idx >= tmp_clr_endIdx[k]; k++)
							;
						if (k < clr[i].size())
							j = clr[i][k].begin_idx;
						else
							j = full_key_sorted.size();
					}
					else
					{
						clr[i][val].begin_idx++;
					}
					j--;

					// tmp_node.cluster_id = val;
					// // tmp_node.my_id = clr_nums[val];
					clr_nums[val]--;
					// if (rq_size >= resort_que.size())
					//     printf("error rq_size %d %d\n", rq_size, resort_que.size());
					// resort_que[rq_size] = tmp_node;
					// rq_size++;
				}
			}
			else
			{
				int clr_idx = clr[i].size() - 1;
				// printf("%d %d %d\n", clr[i][clr_idx].begin_idx, j, clr_nums[tmp_cluster]);
				// if (clr[i][clr_idx].begin_idx >= tmp_clr_endIdx[clr_idx])
				//     printf("err %d %d\n", clr_idx, tmp_clr_endIdx[clr_idx]);
				std::swap(full_key_sorted[clr[i][clr_idx].begin_idx], full_key_sorted[j]);
				// tmp_info = full_key_sorted[clr[i][clr_idx].begin_idx];
				// full_key_sorted[clr[i][clr_idx].begin_idx] = full_key_sorted[j];
				// full_key_sorted[j] = tmp_info;

				if (clr[i][clr_idx].begin_idx == j)
				{
					// clr[i][clr_idx].begin_idx++;
					// int k = 0;
					// for (k = 0; k < clr[i].size() && clr[i][k].begin_idx >= tmp_clr_endIdx[k]; k++)
					//     ;
					// if (k < clr[i].size())
					//     j = clr[i][k].begin_idx;
					// else
					j = full_key_sorted.size();
				}
				// else
				clr[i][clr_idx].begin_idx++;
				j--;

				tmp_cluster = clr[i].size() - 1;
				// tmp_node.cluster_id = clr[i].size() - 1;
				// // tmp_node.my_id = clr_nums[tmp_cluster];
				clr_nums[tmp_cluster]--;
				// // resort_que[j] = tmp_node;
				// if (rq_size >= resort_que.size())
				//     printf("error rq_size %d %d\n", rq_size, resort_que.size());
				// resort_que[rq_size] = tmp_node;
				// rq_size++;
			}
		}

		uint32_t minxx = 0;
		for (auto val : max_dist_inClr)
		{
			if (val < max_dist)
				minxx++;
		}
		// printf("minxx-------------------- %d %d\n", minxx, clr[i].size() - 1);

		nums_tmp = 0;
		for (int t = 0; t < clr[i].size(); t++)
		{
			nums_tmp += tmp_clr_endIdx[t] - clr[i][t].begin_idx;
			// if (tmp_clr_endIdx[t] != clr[i][t].begin_idx)
			// printf("%d false %d %d \n", nums_tmp, tmp_clr_endIdx[t], clr[i][t].begin_idx);
			// nums_tmp += clr_nums[t];
		}
		// printf("cluster 4 last-size%d total-num%d sub-linear-size %d\n", clr_nums[clr[i].size() - 1], nums_tmp, sub_index_liner[i].size());

		clr[i][0].begin_idx = 0;
		std::sort(full_key_sorted.begin(), full_key_sorted.begin() + tmp_clr_endIdx[0], [](const info_uncomp &a, const info_uncomp &b)
				  { return a.target < b.target; });
		for (int t = 1; t < clr[i].size(); t++)
		{
			clr[i][t].begin_idx = tmp_clr_endIdx[t - 1];
			std::sort(full_key_sorted.begin() + tmp_clr_endIdx[t - 1], full_key_sorted.begin() + tmp_clr_endIdx[t], [](const info_uncomp &a, const info_uncomp &b)
					  { return a.target < b.target; });
			// if (clr_nums[t - 1] == 0)
			//     printf("error no node in cluster  %d\n", t);
			// clr[i][t].begin_idx = clr[i][t - 1].begin_idx + clr_nums[t - 1];
		}

		// vector<uint32_t> tmp_clr_nums;
		// tmp_clr_nums.resize(clr[i].size());
		// // cluster_id is the index for each node sort by cluster {0,0,0,  2,2,2 1,1,} =>  {0,1,2, 5,6,7  3,4,}
		// for (auto &val : resort_que)
		// {
		//     tmp_clr_nums[val.cluster_id]++;
		//     val.cluster_id = tmp_clr_nums[val.cluster_id] - 1 + clr[i][val.cluster_id].begin_idx;
		// }
		// uint32_t tmp_index = 0, changed_index;
		// for (int j = 0; j < rq_size; j++)
		// {
		// 	tmp_node1 = resort_que[j];
		// 	tmp_info1 = full_key_sorted[j];
		// 	tmp_index = resort_que[j].cluster_id;
		// 	if (j == tmp_index)
		// 		continue;
		// 	changed_index = j;
		// 	while (changed_index != tmp_index)
		// 	{
		// 		tmp_node = resort_que[tmp_index];
		// 		tmp_info = full_key_sorted[tmp_index];

		// 		full_key_sorted[tmp_index] = tmp_info1;
		// 		resort_que[tmp_index] = tmp_node1;
		// 		changed_index = tmp_index;

		// 		tmp_info1 = tmp_info;
		// 		tmp_node1 = tmp_node;
		// 		tmp_index = tmp_node.cluster_id;
		// 	}
		// }

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

		// printf("cluster 5 %d\n", rq_size);
		//  sort every cluster? (if not sorted)

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

			temp_key = full_key_sorted[j].target; //                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm[j].sub_info.sub_key;
			temp_sub_info.sub_key = temp_key;
			pre_size = 0;
			tmp_begin_add = 0;
			end = 0;
			is_combine = false;
			group_num = 1;

			if (c_idx == clr[i].size() - 1)
				end_idx = full_key_sorted.size();
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
					// printf("%d\n", j);
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
		// printf("clr %d\n", num1++);

		for (auto it = clr[i].begin(); it < clr[i].end() - 1;)
		{
			if (it->begin_idx == (it + 1)->begin_idx)
				it = clr[i].erase(it);
			else
				it++;
		}

		// printf("cluster 6\n");
	}
	clr_thread_dies = 1;

	std::sort(full_key_sorted.begin(), full_key_sorted.end(), [](const info_uncomp &a, const info_uncomp &b)
			  { return a.identify < b.identify; }); // 恢复成正确的顺序，partition index和full-index一一对应

	for (int i = 0; i < full_ids.size(); i++)
		full_key_sorted[i].target = full_ids[i];
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
		printf("sub-index %d size  %d\n", i, sub_linear_comp[i].size());
	}
	for (int t = 0; t < SUBINDEX_NUM; t++)
	{
		for (auto &val : clr[t])
		{
			add_sum += val.begin_idx;
		}
	}
#endif

	int curb = 0;
	int power[100];
	int query_mask;
	uint32_t tmp_hash[2], hash_size = ceil((float)bloom_hash_times / 4) * 16; // ceil(times/4)*4
	uint8_t tmp_hash_out[32], bloom_hash[hash_size];
	// {
	// 	for (int i = 0; i < SUBINDEX_NUM; i++)
	// 	{
	// 		for (int t = 0; t < 5; t++)
	// 		{
	// 			for (auto &val : clr[i])
	// 			{
	// 				// for (int k = 0; k < 4 + t; k++)
	// 				{
	// 					if (i < sub_index_plus)
	// 						curb = sub_keybit;
	// 					else
	// 						curb = sub_keybit - 1;

	// 					{
	// 						for (int t = 0; t < bloom_hash_times; t += 4)
	// 						{
	// 							tmp_hash[0] = val.subkey;
	// 							tmp_hash[1] = i + t * SUBINDEX_NUM * 2;
	// 							MurmurHash3_x86_128(tmp_hash, 8, hash_seed[0], bloom_hash + t * INT_SIZE);
	// 						}
	// 						sub_filters[i][t].insert(bloom_hash, bloom_hash_times * INT_SIZE);
	// 					}
	// 					for (int h = 1; h <= 4 + t; h++)
	// 					{
	// 						int s = h;
	// 						uint32_t bitstr = 0; // the bit-string with s number of 1s
	// 						for (int i = 0; i < s; i++)
	// 							power[i] = i;	 // power[i] stores the location of the i'th 1
	// 						power[s] = curb + 1; // used for stopping criterion (location of (s+1)th 1)

	// 						int bit = s - 1; // bit determines the 1 that should be moving to the left

	// 						while (true)
	// 						{ // the loop for changing bitstr
	// 							if (bit != -1)
	// 							{
	// 								bitstr ^= (power[bit] == bit) ? (uint32_t)1 << power[bit] : (uint32_t)3 << (power[bit] - 1);
	// 								power[bit]++;
	// 								bit--;
	// 							}
	// 							else
	// 							{
	// 								for (int t = 0; t < bloom_hash_times; t += 4)
	// 								{
	// 									tmp_hash[0] = val.subkey ^ bitstr;
	// 									tmp_hash[1] = i + t * SUBINDEX_NUM * 2;
	// 									MurmurHash3_x86_128(tmp_hash, 8, hash_seed[0], bloom_hash + t * INT_SIZE);
	// 								}
	// 								sub_filters[i][t].insert(bloom_hash, bloom_hash_times * INT_SIZE);

	// 								while (++bit < s && power[bit] == power[bit + 1] - 1)
	// 								{
	// 									bitstr ^= (uint32_t)1 << (power[bit] - 1);
	// 									power[bit] = bit;
	// 								}
	// 								if (bit == s)
	// 									break;
	// 							}
	// 						}
	// 					}
	// 				}
	// 			}
	// 		}
	// 	}
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
	// printf("kkkkk kmodes %d steps %d is_var %d ktime %lf\n", cont.kmod, steps, is_var, ktime);

	printf("hamm:%d clr_size:%d clr_dist:%d comb_num:%d  aggre %d\n", cont.hammdist[0], cont.min_clr_size, cont.max_dist, cont.MIN_INC_NUM, cont.aggre_size);

	// // for (int i = 0; i < SUBINDEX_NUM; i++)
	// {
	// 	cont.sub_hammdist[0] = (uint64_t)floor(1.0 * hamm / SUBINDEX_NUM);
	// }
	// // for (int i = 0; i < 4; i++)
	// {
	// 	// sub_hammdist[i] = temp[i];
	// 	printf("sub_hammdist[%d]=%d\n", 0, cont.sub_hammdist[0]);
	// }

	for (int i = 0; i < cont.sub_index_num; i++)
		cont.sub_hammdist[0][i] = -1;
	for (int j = hamm + 1; j > 0;)
	{
		for (int i = 0; i < cont.sub_index_num; i++)
		{
			if (j <= 0)
				break;
			cont.sub_hammdist[0][i]++; // if hammdist=8,sub_hammdist={2,1,1,1}
			j--;
		}
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
void *containers::Keys_clustering(uint32_t thd_idx)
{
	int begin, end;
	while (!clr_thread_dies)
	{
		sgx_thread_mutex_lock(&wait_loop.mutex);
		sgx_thread_cond_wait(&wait_loop.cont, &wait_loop.mutex);
		sgx_thread_mutex_unlock(&wait_loop.mutex);

		begin = clr_indexes[thd_idx];
		if (thd_idx < CLR_THD_NUM - 1)
			end = clr_indexes[thd_idx + 1];
		else
			end = full_key_sorted.size();
		int tmp_dist, tmp_cluster, dis = 0, k = keys.size();
		for (int j = begin; j < end; j++)
		{
			tmp_dist = INT16_MAX;
			tmp_cluster = -1;
			// auto res = find_nearest_element_avx2(keys, full_key_sorted[j].target, 0, k);
			// tmp_cluster = res.first;
			// tmp_dist = res.second;
			for (int t = 0; t < k; t++)
			{
				dis = popcount(full_key_sorted[j].target ^ keys[t]);
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
				// if (!j || (full_key_sorted[j].target != full_key_sorted[j - 1].target))
				{
					if (tmp_cluster >= 0 && tmp_dist == 1 && clusterk[tmp_cluster].size() < 1000)
					{
						sgx_thread_mutex_lock(&wait_clusterk[tmp_cluster].mutex);
						clusterk[tmp_cluster].push_back(full_key_sorted[j].target);
						sgx_thread_mutex_unlock(&wait_clusterk[tmp_cluster].mutex);
					}
					if (tmp_dist <= max_dist)
					{
						cluster_sum.fetch_add(tmp_dist);
					}
					{
						if (tmp_dist <= max_dist)
						{
							clrs_size[tmp_cluster].fetch_add(1);
							// clrs_size[tmp_cluster]++;

							cluster_value_nums[0][tmp_cluster + 1].fetch_add(1);
							// value_nums[0][tmp_cluster + 1]++;
							for (int t = 0; t < 32; t++)
							{
								if ((full_key_sorted[j].target >> t) & 1)
								{
									cluster_value_nums[tmp_cluster + 1][t].fetch_add(1);
								}
							}
						}
					}
				}
			}

			if (tmp_dist > max_dist)
			{
				stash_nums.fetch_add(1);
			}
		}

		sgx_thread_mutex_lock(&wait_res_end.mutex);
		clr_finish_count++;
		if (clr_finish_count == CLR_THD_NUM)
		{
			sgx_thread_cond_signal(&wait_res_end.cont);
		}
		sgx_thread_mutex_unlock(&wait_res_end.mutex);
	}
};
void *containers::func_forward(void *arg)
{
	query_t *qt = (query_t *)arg;
	containers *cont = qt->tmp_conts;
	uint32_t type = qt->type;
	uint32_t thd_idx = qt->thd_idx;
	switch (type)
	{
	case 0:
	{
		cont->Keys_clustering(thd_idx);
		break;
	}
	default:
		break;
	}
	printf("end %d", type);
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
vector<cluster_node> containers::kmodes(int i, vector<uint32_t> &clr_keys)
{
	const int LOOP_TIMES = 80;

	int k = kmod, avgNum;
	uint32_t rand;
	vector<uint32_t> keys2;
	vector<int> tmp_new_keys;
	cluster_sum.store(0);
	stash_nums.store(0);

	vector<pair<uint32_t, uint32_t>> tmp_clrs; // nums keys
	uint64_t sum0 = INT64_MAX;
	EcallCMSketch cmsketch(100000);
	uint8_t out[16];
	// vector<vector<uint32_t>> value_nums;

	// vector<vector<uint32_t>> clusterk; // store k cluster
	clusterk.resize(k);
	wait_clusterk.resize(k);
	for (int t = 0; t < k; t++)
	{
		wait_clusterk[t].mutex = SGX_THREAD_MUTEX_INITIALIZER;
		wait_clusterk[t].cont = SGX_THREAD_COND_INITIALIZER;
	}

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

	cluster_value_nums.resize(k + 1);
	// vector<std::unique_ptr<std::atomic<uint32_t>>> tmp_mic_clrs;
	// for (int t = 0; t < k + 1; t++)
	// tmp_mic_clrs.push_back(std::make_unique<std::atomic<uint32_t>>(0));

	// cluster_value_nums[0] = std::move(tmp_mic_clrs);
	// tmp_mic_clrs.clear();
	cluster_value_nums[0].resize(k + 1);
	for (int t = 1; t < k + 1; t++)
	{
		// vector<std::unique_ptr<std::atomic<uint32_t>>> tmp_mic_clrs;
		// for (int t = 0; t < 32; t++)
		// 	tmp_mic_clrs.push_back(std::make_unique<std::atomic<uint32_t>>(0));
		// cluster_value_nums[t] = std::move(tmp_mic_clrs);
		cluster_value_nums[t].resize(32);
	}
	// printf("1\n");
	//  for (int t = 0; t < k; t++)
	//  {
	//  	printf("keys %d \n", keys[t]);
	//  }
	//  printf("keys size %d \n", keys.size());

	// only catagory to under max_dist to the cluster, update the cluster without larger than max_dist
	int times = 0;
	while (1) // 15
	{
		avgNum = cont.full_key_sorted.size() / k;
		// printf("times %d\n", times);
		// printf("2\n");
		times++;
		tmp_clrs.clear();
		tmp_clrs.resize(k);

		clrs_size.clear();
		clrs_size.resize(k);
		// for (int t = 1; t < k + 1; t++)
		// {
		// 	clrs_size.push_back(std::make_unique<std::atomic<uint32_t>>(0));
		// }
		// stash_nums = 0;
		stash_nums.store(0);

		int gap = full_key_sorted.size() / CLR_THD_NUM;
		clr_indexes.resize(CLR_THD_NUM);
		for (int i = 0; i < CLR_THD_NUM; i++)
		{
			clr_indexes[i] = i * gap;
		}

		clr_finish_count = 0;

		sgx_thread_mutex_lock(&wait_loop.mutex);
		sgx_thread_cond_broadcast(&wait_loop.cont);
		sgx_thread_mutex_unlock(&wait_loop.mutex);

		sgx_thread_mutex_lock(&wait_res_end.mutex);
		sgx_thread_cond_wait(&wait_res_end.cont, &wait_res_end.mutex);
		sgx_thread_mutex_unlock(&wait_res_end.mutex);
		// for (int j = 0; j < full_key_sorted.size(); j++)
		// {
		// 	tmp_dist = INT16_MAX;
		// 	tmp_cluster = -1;
		// 	for (int t = 0; t < k; t++)
		// 	{
		// 		dis = bitset<32>(full_key_sorted[j].target ^ keys[t]).count();
		// 		if (dis < tmp_dist) // tmp_dist
		// 		{
		// 			tmp_cluster = t;
		// 			tmp_dist = dis;
		// 		}
		// 		else if (dis == tmp_dist)
		// 		{
		// 			// tmp_clrs.push_back(t);
		// 		}
		// 	}
		// 	{
		// 		// sum += tmp_dist;
		// 		// if (tmp_cluster != -1)
		// 		{
		// 			if (tmp_dist <= max_dist)
		// 			{
		// 				sum += tmp_dist;
		// 				// MurmurHash3_x86_128(&full_key_sorted[j].target, sizeof(uint32_t), 0, out);
		// 				// cmsketch.Update(out, 16, 1);
		// 				// int num_tmp = cmsketch.Estimate(out, 16);
		// 				// if (num_tmp > tmp_clrs[tmp_cluster].first)
		// 				// {
		// 				// 	tmp_clrs[tmp_cluster].first = num_tmp;
		// 				// 	tmp_clrs[tmp_cluster].second = full_key_sorted[j].target;
		// 				// }
		// 			}

		// 			if (tmp_dist <= max_dist)
		// 			{
		// 				clrs_size[tmp_cluster]++;
		// 				value_nums[0][tmp_cluster + 1]++;
		// 				for (int t = 0; t < 32; t++)
		// 				{
		// 					if ((full_key_sorted[j].target >> t) & 1)
		// 						value_nums[tmp_cluster + 1][t]++;
		// 				}

		// 				// clusterk[tmp_cluster].push_back(sub_index_liner[i][j].sub_key);
		// 			}
		// 		}
		// 	}

		// 	if (tmp_dist > max_dist)
		// 	{
		// 		stash_nums++;
		// 	}
		// }

		{
			int out = 1;
			//  k-modes
			keys2.resize(k);
			for (int t = 0; t < k; t++)
			{
				int size = cluster_value_nums[0][t + 1].load(), tmp_key = 0;
				for (int j = 0; j < 32; j++)
				{
					if (cluster_value_nums[t + 1][j].load() > (size >> 1))
					{
						tmp_key |= (1 << j);
					}
				}
				if (keys[t] != tmp_key)
					out = 0;
				keys2[t] = tmp_key;
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

			// balance the cluster's size
			for (int t = keys2.size() - 1; t >= 0; t--)
			{
				int size = cluster_value_nums[0][t + 1].load();
				if (size > avgNum * 5)
				{
					if (clusterk[t].size() > 1)
					{
						sgx_read_rand(reinterpret_cast<unsigned char *>(&rand), sizeof(int));
						rand = rand % clusterk[t].size();
						tmp_new_keys.push_back(clusterk[t][rand]);

						sgx_read_rand(reinterpret_cast<unsigned char *>(&rand), sizeof(int));
						rand = rand % clusterk[t].size();
						tmp_new_keys.push_back(clusterk[t][rand]);
					}
					keys2.erase(keys2.begin() + t);
					out = 0;
					continue;
				}
				if (size < avgNum / 5)
				{
					keys2.erase(keys2.begin() + t);
					// out = 0;
					continue;
				}
			}
			for (auto &val : tmp_new_keys)
			{
				keys2.push_back(val);
			}
			tmp_new_keys.clear();

			if (out && cluster_sum.load() == sum0 || times >= LOOP_TIMES)
			{
				// printf("sum %d cluster times %d\n", sum0, times);
				break;
			}
			keys = keys2;
			sum0 = cluster_sum.load();

			// for (int i = 0, sub = 0; i < k; i++)
			// {
			// 	if (value_nums[0][i + 1] > 10000 || value_nums[0][i + 1] < 1000)
			// 	{
			// 		keys.erase(keys.begin() + i - sub);
			// 		sub++;
			// 	}
			// }
			if (is_var && stash_nums.load() >= ceil((double)full_key_sorted.size() * ktimes)) // size / 2
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
				cluster_value_nums[t].clear();
			}
			k = keys.size();

			clusterk.resize(k);
			wait_clusterk.resize(k);
			for (int t = 0; t < k; t++)
			{
				clusterk[t].clear();
				wait_clusterk[t].mutex = SGX_THREAD_MUTEX_INITIALIZER;
				wait_clusterk[t].cont = SGX_THREAD_COND_INITIALIZER;
			}

			cluster_value_nums.resize(k + 1);
			// vector<std::unique_ptr<std::atomic<uint32_t>>> tmp_mic_clrs;
			// for (int t = 0; t < k + 1; t++)
			// tmp_mic_clrs.push_back(std::make_unique<std::atomic<uint32_t>>(0));

			// cluster_value_nums[0] = std::move(tmp_mic_clrs);
			// tmp_mic_clrs.clear();
			cluster_value_nums[0].resize(k + 1);
			for (int t = 1; t < k + 1; t++)
			{
				// vector<std::unique_ptr<std::atomic<uint32_t>>> tmp_mic_clrs;
				// for (int t = 0; t < 32; t++)
				// 	tmp_mic_clrs.push_back(std::make_unique<std::atomic<uint32_t>>(0));
				// cluster_value_nums[t] = std::move(tmp_mic_clrs);
				cluster_value_nums[t].resize(32);
			}
		}
		cluster_sum.store(0);
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
	clr_keys.clear();
	for (int t = 0; t < k; t++)
	{
		if (!clrs_size[t].load())
			continue;
		clr_keys.push_back(keys[t]);
		cluster_node cl_info;
		cl_info.subkey = keys[t];
		cl_info.group_size = clrs_size[t].load();
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
		// max_size = max_size - node->ids.size() + (comp.length & MASK_LEN) * INT_SIZE;

		resize_size += ((comp.length & MASK_LEN) * INT_SIZE - node->ids.size()) / 4;
		vector<uint8_t> tmp;
		node->ids.swap(tmp);
		node->ids.resize((comp.length & MASK_LEN) * INT_SIZE); // vector.swap ?? for add-similar-keys
	}
	else if (tmp_size < (node->ids.size() >> 1))
	{
		// max_size = max_size - node->ids.size() + tmp_size;
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

void containers::init_ids_cache()
{
	// printf("max id page--- %d\n", max_id_page);
#if CACHE_SIZE >= 500000
	uint32_t total_cache_item = 0;
	for (int i = 0; i < SUBINDEX_NUM; i++)
	{
		total_cache_item += sub_linear_comp[i].size();
	}
	lru_cache.capacity = total_cache_item;
#endif
	// printf("cap %d\n", lru_cache.capacity);
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
	// printf("ids_cache len%d cap%d each_size %d\n", lru_cache.len, lru_cache.capacity, sizeof(ids_node));
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