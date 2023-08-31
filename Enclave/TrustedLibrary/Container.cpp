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
#include "sgx_trts.h"
#include "stdio.h"
#include <cstdio>
#include <bitset>

uint64_t containers::keybit = 128;
uint64_t containers::hammdist = 8;
uint64_t containers::sub_index_num = 4;
uint32_t containers::test_size = 1000;
uint32_t containers::initialize_size = 450000;
uint32_t containers::sub_map_size = 4500;
uint32_t hash_seed[4]{0x12345678, 0x23456789, 0x34567890, 0x45678901};

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
}

containers::containers()
{
	sub_keybit = (int)keybit / sub_index_num;
	// sub_hammdist=hammdist/sub_index_num;

	// the sum of sub_hammdist is hammdist - sub_index_num + 1
	for (int j = hammdist - sub_index_num + 1; j > 0;)
	{
		for (int i = 0; i < sub_index_num; i++)
		{
			if (j <= 0)
				break;
			sub_hammdist[i]++; // if hammdist=8,sub_hammdist={2,1,1,1}
			j--;
		}
	}
	// int temp[] = {1, 1, 1, 2}; //{1, 1, 1, 2};
	for (int i = 0; i < sub_index_num; i++)
	{
		// sub_hammdist[i] = temp[i];
		printf("sub_hammdist[%d]=%d\n", i, sub_hammdist[i]);
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
bool customCompare(const sub_information &p1, const sub_information &p2)
{
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
	return p.sub_key < x;
}
bool compareFirst_comp(const sub_info_comp &p, uint32_t x)
{
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
void containers::get_sub_fingerprint(uint32_t *sub_fingerprint, uint64_t *fingerprint)
{
	sub_fingerprint[0] = fingerprint[0] & 0xffffffff;
	fingerprint[0] = fingerprint[0] >> 32;
	sub_fingerprint[1] = fingerprint[0] & 0xffffffff;

	sub_fingerprint[2] = fingerprint[1] & 0xffffffff;
	fingerprint[1] = fingerprint[1] >> 32;
	sub_fingerprint[3] = fingerprint[1] & 0xffffffff;
}
void containers::get_full_fingerprint(uint64_t *fingerprint, uint32_t *sub_fingerprint)
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
void containers::initialize()
{
	uint64_t temp_key[2] = {0};
	uint32_t out_id = 0;
	uint32_t sub[4] = {0};
	information temp_information;
	containers::initialize_size = DATA_LEN;
	full_key_sorted.reserve(DATA_LEN);
	full_index.reserve(DATA_LEN + 1000);
	sub_index_liner = new vector<sub_information>[4];
	// for(int i=0;i<4;i++)sub_index_liner[i]=new sub_information[initialize_size];
	for (int i = 0; i < 4; i++)
		sub_index_liner[i].reserve(initialize_size);

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
	bloom_parameters parameters;
	parameters.projected_element_count = 4 * initialize_size; // 预计插入initialize_size个元素
	parameters.false_positive_probability = 0.3;			  // 期望的误判率为0.1
	parameters.compute_optimal_parameters();				  // 计算最优参数
	parameters.random_seed = 0xA5A5A5A5;
	// for (int i = 0; i < 4; i++)
	filters = bloom_filter(parameters);
	return;
}
void containers::get_test_pool()
{
	// 从测试集获取test pool数据
	uint32_t index1 = 0;
	uint32_t end = tmp_test_pool.size();
	while (test_pool.size() < test_size && end > 0)
	{
		sgx_read_rand(reinterpret_cast<unsigned char *>(&index1), sizeof(index1));
		index1 %= end;
		test_pool.push_back(tmp_test_pool[index1]);
		// test_targets.push_back(tmp_test_targets[index1]);
		auto tmp = tmp_test_pool[index1];
		tmp_test_pool[index1] = tmp_test_pool[end - 1];
		// tmp_test_targets[index1] = tmp_test_targets[end - 1];
		end--;
	}

	uint64_t temp_key[2] = {0};
	uint32_t begin = 0, index = 0; // begin:the first index of test
	uint32_t skip = 1;			   // skip query

	// initialize_size = full_index.size();
	uint32_t range = initialize_size; // range query
	sgx_read_rand(reinterpret_cast<unsigned char *>(&begin), sizeof(begin));

	// for temporal Locality
	vector<uint32_t> local_list;
	uint32_t temp;
	for (int i = 0; i < 100; i++)
	{
		sgx_read_rand(reinterpret_cast<unsigned char *>(&temp), sizeof(temp));
		local_list.push_back(temp % initialize_size);
	}

	for (int i = 0; i < initialize_size; i++)
	{
		if (test_pool.size() >= test_size)
		{
			return;
		}
		index = (begin + (i * skip) % range);
		if (i % 20 == 0)
		{
			// sgx_read_rand(reinterpret_cast<unsigned char *>(&begin), sizeof(begin));
		}																		 // space locality
		sgx_read_rand(reinterpret_cast<unsigned char *>(&index), sizeof(index)); // rand query
		// index=local_list[index%local_list.size()];//temporal locality
		index = index % initialize_size;
		// auto it = full_index[index];
		auto it = full_key_sorted[index];
		temp_key[0] = it.fullkey[0];
		temp_key[1] = it.fullkey[1];
		int h = 0, y = 0;
		uint64_t t = 1;
		unsigned char rand[3] = {0};
		sgx_read_rand(rand, 2);
		h = rand[0] % 3;
		for (int i = 0; i < h; i++)
		{
			y = rand[i + 1] % 64;
			temp_key[0] = temp_key[0] ^ (t << y);
			temp_key[1] = temp_key[1] ^ (t << y);
		}
		test_pool.push_back(pair<uint64_t, uint64_t>(temp_key[0], temp_key[1]));
	}
}
std::unordered_set<uint32_t> containers::find_sim(uint64_t query[], uint32_t tmp_test_target)
{
	uint64_t *total_time_now = new uint64_t[1];
	long long total_begin_time = 0, total_end_time = 0;
	ocall_get_timeNow(total_time_now);
	total_begin_time = *total_time_now;

	unordered_set<uint32_t> candidate;
	unordered_set<uint32_t> candi_new;
	candidate.clear();
	candidate.reserve(5000);
	uint64_t tmpquery[2] = {0};
	tmpquery[0] = query[0];
	tmpquery[1] = query[1];
	uint32_t sub[4] = {0};
	get_sub_fingerprint(sub, tmpquery);

	uint32_t *out_tmp = out;
	uint32_t tmpsub1, tmpsub2, tmpsub3, tmpsub4 = 0;
	vector<uint32_t> temp;
	// tsl::hopscotch_map<uint32_t, std::vector<uint32_t>>::iterator got;
	unordered_map<uint32_t, std::vector<uint32_t>>::iterator got;

	vector<pair<uint32_t, int32_t>> visited_keys; // first: subkeys of candidates, second: begin index of sub_identifiers

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
	for (int i = 0; i < 4; i++)
	{
		ocall_get_timeNow(time);
		begin_time = *time;
		for (auto &its : C_0_TO_subhammdis[i])
		{
			tmpsub1 = sub[i] ^ its;
			sub_key_I[0] = tmpsub1, sub_key_I[1] = i;
			MurmurHash3_x86_32(sub_key_I, 8, hash_seed[i], out_key);
			// 	tmpsub1 = sub[i];
			//	LOGGER("SUB FP INFO: %u %u %u %u",tmpsub1,tmpsub2,tmpsub3,tmpsub4);
			//	LOGGER("SUB INDEX SIZE: %zu %zu %zu %zu",sub_index1.size(),sub_index2.size(),sub_index3.size(),sub_index4.size());
			if (filters.contains(out_key[0]))
			{
				// find in hashmap
				bloomHit++;
				auto it = sub_index[i].find(tmpsub1);
				times++;
				if (it != sub_index[i].end())
				{
					hitmap++;
					visited_keys.push_back({it->second->sub_key, it->second->begin});
					lru_index_visit(i, it->second);
				}
				else
				{
					auto its = std::lower_bound(sub_linear_comp[i].begin(), sub_linear_comp[i].end(), tmpsub1, compareFirst_comp);
					if (its != sub_linear_comp[i].end() && (its->sub_key == tmpsub1 || its->begin < 0)) //&& its->sub_key == tmpsub1
					{
						++hitliner;
						// 防止添加已存在map的元素到hashmap
						if (its->sub_key == tmpsub1)
							lru_index_add(i, its->sub_key, its->begin);
						visited_keys.push_back({tmpsub1, its->begin});
						// if (its->begin < 0)
						// 	its->begin = -its->begin;
					}
				}
			} // else bloomMiss++;
		}
		ocall_get_timeNow(time);
		end_time = *time;
		find_time += end_time - begin_time;
		ocall_get_timeNow(time);
		begin_time = *time;

		// the node finded by linear list or hashmap, to get candidate's id
		for (int y = 0; y < visited_keys.size(); y += 1)
		{
			// auto its = visited_keys[y].first;
			uint32_t tempKey = visited_keys[y].first;
			uint32_t tmp_size = 0;
			int tmp_begin = visited_keys[y].second;
			bool is_combined_keys = false;

			// if (tmp_begin < 0) ,some continuous  subkeys are Combined to one biggest subkey in there
			if (tmp_begin < 0)
			{
				tmp_begin = -tmp_begin - 1;
				is_combined_keys = true;
			}

			// calculate the original size of the compressed data
			for (int t = 0; t < 4; t++)
			{
				tmp_size += ((uint32_t)(sub_identifiers[i][tmp_begin + t]) << (8 * t));
			}

			// 解压，如果多个subkey是被合并后的，is-combine=true；解压的是unsort数组；否则解压产生sorted数组
			if (!is_combined_keys)
			{
				if (tmp_size <= COMPRESS_MIN)
				{
					out_tmp = (uint32_t *)(sub_identifiers[i].data() + tmp_begin + 4);
				}
				else
				{
					for_uncompress(sub_identifiers[i].data() + tmp_begin + 4, out_tmp, tmp_size); // decompress
																								  //   printf("tmp_size: %u\n", tmp_size);
				}
			}
			else
			{
				if (tmp_size <= COMPRESS_MIN_UNSORT)
					out_tmp = (uint32_t *)(sub_identifiers[i].data() + tmp_begin + 4);
				else
					for_uncompress(sub_identifiers[i].data() + tmp_begin + 4, out_tmp, tmp_size); // decompress
			}

			// get the true identifiers of the subkey
			if (is_combined_keys)
			{
				uint32_t lens = 0;
				// printf("tmpsize %d\n", tmp_size);
				// out_tmp结构:[subkey0,len0,id0,id1,...,subkey1,len1,id0,id1,...]
				// for (int j = 0; j < tmp_size;)
				// {
				// 	if (out_tmp[j] == tempKey)
				// 	{
				// 		j++;
				// 		uint32_t len = out_tmp[j];
				// 		for (int l = j + 1; l <= j + len; l++)
				// 		{
				// 			candidate.emplace_hint(candidate.begin(), out_tmp[l]);
				// 			lens++;
				// 		}
				// 		j += out_tmp[j] + 1;
				// 		break;
				// 	}
				// 	else if (out_tmp[j] > tempKey)
				// 	{
				// 		break;
				// 	}
				// 	else
				// 	{
				// 		j += out_tmp[j + 1] + 2;
				// 	}
				// }

				// out_tmp结构:[keys_len, subkey0,...,subkeyN,-id0,id1,-id4,id8,...,idm]
				// keys_len: 这个block里面subkey的数量，subkey：这个block里面包含的subkey，所有subkey在排列在一起
				// id：前面subkey对应的图片id集合，按照subkey的先后顺序，每个subkey对应一个id序列，这个id序列开头为-id，以表示开始一个新的序列
				uint32_t keys_len = out_tmp[0];
				// printf("keys_len %d\n", keys_len);
				for (int j = 1; j <= keys_len; j++)
				{
					if (out_tmp[j] > tempKey)
						break;
					else if (out_tmp[j] == tempKey)
					{
						uint32_t times = j;
						for (int t = 1 + keys_len; t < tmp_size; t++)
						{
							if ((int)out_tmp[t] < 0)
							{
								times--;
								if (times == 0)
								{
									candidate.emplace_hint(candidate.begin(), -out_tmp[t]);
									for (int l = t + 1; l < tmp_size; l++)
									{
										if ((int)out_tmp[l] < 0)
											break;
										candidate.emplace_hint(candidate.begin(), out_tmp[l]);
									}
									break;
								}
							}
						}
						break;
					}
				}
			}
			else
			{
				for (int j = 0; j < tmp_size; j++)
				{
					candidate.emplace_hint(candidate.begin(), out_tmp[j]);
				}
			}
			out_tmp = out;
		}
		visited_keys.clear();
		ocall_get_timeNow(time);
		end_time = *time;
		insert_time += end_time - begin_time;
	}
	// printf("bloomHit:%lu bloomMiss:%lu sum%d\n", hitliner+hitmap, bloomMiss, hitliner+hitmap+bloomMiss);
	// printf("hitmap %d hitliner %d \n", hitmap, hitliner);
	// num+=hitliner&mapsize&linersize&hitmap;
	// printf("hitmap %d mapsize %d hitliner %d linersize %d \n",hitmap,mapsize,hitliner,linersize);

	uint32_t successful_num_pre = successful_num;
	static uint32_t candi_num = 0;
	candi_num += candidate.size();
	// printf("candi_num:%u\n", candi_num);

	uint64_t tmp_fullkey[2] = {0};
	uint64_t equal = 0, target = 0;
	static uint32_t unequal = 0;
	static uint32_t unequal_n = 0;

	ocall_get_timeNow(time);
	begin_time = *time;
	uint64_t cmp_hamm[2] = {0};
	uint64_t count = 0;
	information got_out;
	// tsl::hopscotch_map<uint32_t,information>::const_iterator got_out;
	for (auto it = candidate.begin(); it != candidate.end();)
	{
		if (*it < full_index.size())
			got_out = full_index[*it];
		if (1)
		{
			get_full_fingerprint(tmp_fullkey, (uint32_t *)&full_index[*it]);
			cmp_hamm[0] = query[0] ^ (tmp_fullkey[0]);
			cmp_hamm[1] = query[1] ^ (tmp_fullkey[1]);
			// count =__builtin_popcountl(cmp_hamm[0]) + __builtin_popcountl(cmp_hamm[1]);
			count = bitset<64>(cmp_hamm[0]).count() + bitset<64>(cmp_hamm[1]).count();

			if (count <= hammdist)
			{
				successful_num += full_index[*it + sub_index_num].len;

				out_tmp = out;
				uint8_t *comp_data = (uint8_t *)&full_index[*it + sub_index_num + 1];
				if (full_index[*it + sub_index_num].len <= COMPRESS_MIN_UNSORT)
				{
					uint32_t test_target = 0;
					out_tmp = (uint32_t *)&full_index[*it + sub_index_num + 1];
					// 测试获取的图片对应的id
					for (int j = 0; j < full_index[*it + sub_index_num].len; j++)
						test_target += out_tmp[j];
				}
				else
				{
					uint32_t test_target = 0;
					for_uncompress(comp_data, out_tmp, full_index[*it + sub_index_num].len);
					// 测试获取的图片对应的id
					for (int j = 0; j < full_index[*it + sub_index_num].len; j++)
						test_target += out_tmp[j];
				}

				// uint32_t *t = (uint32_t *)&full_index[*it + sub_index_num + 1];
				// uint32_t tmp_target;
				// tmp_target = *t;
				// // tmp_target <<= 32;
				// // tmp_target += *(t + 1);
				// if (tmp_target != tmp_test_target)
				// {
				// 	unequal += full_index[*it + sub_index_num].len;
				// 	// printf("%d targets!\n", tmp_target);
				// }
				it++;
			}
			else
				it = candidate.erase(it);
		}
	}
	// printf("targste %d\n", tmp_test_target);
	// printf("%d unequal %d\n", unequal, unequal_n);

	// 测试查询结果的数量级分布
	//  static uint32_t min_num[3] = {0};
	//  if (successful_num - successful_num_pre < 50)
	//  {
	//  	min_num[0]++;
	//  	printf("min_num[0]:%llu %llu\n", query[0], query[1]);
	//  }
	//  else if (successful_num - successful_num_pre < 1000)
	//  {
	//  	min_num[1]++;
	//  	printf("min_num[1]:%llu %llu\n", query[0], query[1]);
	//  }
	//  else
	//  {
	//  	min_num[2]++;
	//  	printf("min_num[2]:%llu %llu\n", query[0], query[1]);
	//  }
	//  printf("min_num[0]:%u min_num[1]:%u min_num[2]:%u\n", min_num[0], min_num[1], min_num[2]);
	ocall_get_timeNow(time);
	end_time = *time;
	verify_time += end_time - begin_time;
	ocall_get_timeNow(total_time_now);
	total_end_time = *total_time_now;
	total_time += total_end_time - total_begin_time;
	return std::move(candidate);
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
		find_sim(temp_key, 0); // test_targets[i]
							   // i++;
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
	// total时间（ms）， find：查询map和linear的时间，insert：插入到set<candidate>的时间，verify：验证candidate的时间
	printf("total=time:%d,sum:%d, find-time:%d, insert-time:%d, verify-time:%d\n", total_time, find_time + insert_time + verify_time, find_time, insert_time, verify_time);
}
void containers::changeHammingDist(uint64_t hammdist)
{
	if (hammdist == this->hammdist)
		return;
	this->hammdist = hammdist;
	// this->sub_hammdist=hammdist/4;
	for (int i = 0; i < cont.sub_index_num; i++)
		sub_hammdist[i] = 0;
	for (int j = hammdist - sub_index_num + 1; j > 0;)
	{
		// the sum of sub_hammdist is hammdist - sub_index_num + 1
		for (int i = 0; i < sub_index_num; i++)
		{
			if (j <= 0)
				break;
			sub_hammdist[i]++;
			j--;
		}
	}
	for (int i = 0; i < cont.sub_index_num; i++)
	{
		cont.C_0_TO_subhammdis[i].clear();
		cont.prepare(cont.sub_hammdist[i], cont.C_0_TO_subhammdis[i]);
	}
	// this->prepare();
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
	// 		get_sub_fingerprint(sub,temp_key);
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
	// 		get_sub_fingerprint(sub,temp_key);
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
	for (int i = 0; i < cont.sub_index_num; i++)
	{
		cont.prepare(cont.sub_hammdist[i], cont.C_0_TO_subhammdis[i]);
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

	cont.opt_full_index();
	cont.opt_sub_index();
	cont.init_sub_maps();
	printf("The full index entry is: %d \n", cont.full_index.size());
	printf("The number of queries is: %d \n", cont.test_pool.size());
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
	// 	cont.get_sub_fingerprint(sub, temp_key);
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

void containers::opt_full_index()
{
	information temp_information;
	information idy_info;
	information len_info;
	std::sort(cont.full_key_sorted.begin(), cont.full_key_sorted.end(), customCompare_fullkey);

	uint64_t temp_keys[2] = {0};
	uint32_t out_id = 0;
	uint32_t sub[4] = {0};
	sub_information sub_info[4];
	vector<uint32_t> info_idy;
	uint8_t *tmp_compress_data = new uint8_t[80000]; // 临时空间用于进行压缩，数据量大时可能需要增大
	uint32_t complen = 0;
	for (int i = 0; i < full_key_sorted.size();)
	{
		info_idy.clear();

		temp_keys[0] = full_key_sorted[i].fullkey[0];
		temp_keys[1] = full_key_sorted[i].fullkey[1];
		cont.get_sub_fingerprint(sub, temp_keys);
		// out_id = cont.random_uuid() - 1;

		for (int j = 0; j < 4; j++)
		{
			int out[1], sub_key_I[2];
			sub_key_I[0] = sub[j], sub_key_I[1] = j;
			MurmurHash3_x86_32(sub_key_I, 8, hash_seed[j], out); // murmur hash(sub_key,i) to one filter
			cont.filters.insert(out[0]);
			// cont.filters[j].insert(sub[j]);
			sub_info[j].sub_key = sub[j];
			sub_info[j].identifiers = full_index.size() - j; // out_id;

			cont.sub_index_liner[j].push_back(sub_info[j]);

			temp_information.sub_fullkey = sub[j];
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
	printf("complen=%d\n", complen); // 减少的字节数
	delete[] tmp_compress_data;
};
void containers::opt_sub_index()
{
	printf("sub_index_liner size:%d\n", sub_index_liner->size());
	for (int i = 0; i < 4; i++)
	{
		std::sort(sub_index_liner[i].begin(), sub_index_liner[i].end(), customCompare);
	}

	int j = 0, num = 0;
	uint32_t temp_key = 0;
	uint32_t pre_size = 0;
	vector<uint32_t> temp_vec, temp_vec_new, temp_subkey;
	sub_info_comp temp_sub_info;
	uint32_t begin, end;
	uint32_t comp_size = 0;
	bool is_combine;
	for (int i = 0; i < 4; i++)
	{
		j = 0;
		temp_vec.clear();
		temp_key = sub_index_liner[i][j].sub_key;
		temp_sub_info.sub_key = temp_key;
		begin = 0;
		end = 0;
		is_combine = false;
		for (; j < sub_index_liner[i].size(); j++)
		{
			if (sub_index_liner[i][j].sub_key == temp_key)
			{
				temp_vec.push_back(sub_index_liner[i][j].identifiers);
			}
			else
			{
				uint32_t same_num = 0;
				for (int t = j; t < sub_index_liner[i].size(); t++)
				{
					if (sub_index_liner[i][t].sub_key == sub_index_liner[i][j].sub_key)
					{
						same_num++;
					}
					else
					{
						break;
					}
				}
				// combine subkey后产生的block大小不应该大于combine_size
				if ((temp_vec.size() * 2 + temp_vec.size() + same_num) < combine_size)
				{
					temp_subkey.push_back(temp_key);
					temp_subkey.push_back(temp_vec.size() - pre_size);
					pre_size = temp_vec.size();
					temp_key = sub_index_liner[i][j].sub_key;
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

				// the first 4 bytes is the length of the uncompressed data
				for (uint32_t t = 0, tmp = temp_vec.size(); t < 4; t++)
				{
					sub_identifiers[i].push_back(tmp & 0xff);
					tmp >>= 8;
				}

				// compute the length of the compressed data
				int comp_len = 0;
				if (!is_combine)
				{
					comp_len = for_compressed_size_sorted(temp_vec.data(), temp_vec.size());
					sub_identifiers[i].resize(sub_identifiers[i].size() + comp_len);

					// compress data
					//  if the length of the uncompressed data is less than COMPRESS_MIN, we don't compress it
					for_compress_sorted(temp_vec.data(), sub_identifiers[i].data() + begin + 4, temp_vec.size());
				}
				else
				{
					comp_len = for_compressed_size_unsorted(temp_vec.data(), temp_vec.size());
					sub_identifiers[i].resize(sub_identifiers[i].size() + comp_len);
					for_compress_unsorted(temp_vec.data(), sub_identifiers[i].data() + begin + 4, temp_vec.size());
				}

				temp_sub_info.begin = begin;
				if (is_combine)
					temp_sub_info.begin = -temp_sub_info.begin - 1;
				is_combine = false;
				sub_linear_comp[i].emplace_back(temp_sub_info);

				begin += comp_len + 4;
				temp_key = sub_index_liner[i][j].sub_key;
				temp_sub_info.sub_key = temp_key;
				temp_vec.clear();
				j--;
			}
		}
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
				sub_identifiers[i].push_back(tmp & 0xff);
				tmp >>= 8;
			}
			// std::sort(temp_vec.begin(), temp_vec.end());

			if (!is_combine)
			{
				int comp_len = for_compressed_size_sorted(temp_vec.data(), temp_vec.size());
				sub_identifiers[i].resize(sub_identifiers[i].size() + comp_len);
				for_compress_sorted(temp_vec.data(), sub_identifiers[i].data() + begin + 4, temp_vec.size());
			}
			else
			{
				int comp_len = for_compressed_size_unsorted(temp_vec.data(), temp_vec.size());
				sub_identifiers[i].resize(sub_identifiers[i].size() + comp_len);
				for_compress_unsorted(temp_vec.data(), sub_identifiers[i].data() + begin + 4, temp_vec.size());
			}

			temp_sub_info.begin = begin;
			if (is_combine)
				temp_sub_info.begin = -temp_sub_info.begin - 1;
			sub_linear_comp[i].emplace_back(temp_sub_info);
		}
		printf("size %d\n", sub_linear_comp[i].size());
	}

	printf("subsize:%d\n", sub_map_size);
};
void containers::init_sub_maps()
{
	int index[4] = {0};
	// for(int i=0;i<4;i++)index[i]=sub_index_liner[i][0];
	sub_nodes = new sub_index_node *[4];
	for (int i = 0; i < 4; i++)
	{
		sub_nodes[i] = new sub_index_node[sub_map_size];
	}
	// randomly select node to insert the sub_index
	for (int k = 0; k < 4; k++)
	{
		for (int i = 0; sub_index[k].size() < sub_map_size && i < sub_map_size * 20; i++) // sub_index[k].size()
		{
			sgx_read_rand(reinterpret_cast<unsigned char *>(&index[k]), sizeof(int));
			index[k] = index[k] % sub_linear_comp[k].size();
			uint32_t temp = sub_linear_comp[k][index[k]].sub_key;
			// for(;index[k]>0&&temp==sub_index_liner[k][index[k]-1].sub_key;index[k]--);
			auto its = sub_linear_comp[k].begin() + index[k];
			if (sub_index[k].find(temp) == sub_index[k].end())
			{
				lru_index_add(k, its->sub_key, its->begin); // int temps=index[k];
															// for(;its->sub_key==temp&&its<sub_linear_comp[k].end();its++,index[k]++);

				// vector<uint32_t> temp_vec;
				// temp_vec.push_back(its->begin);
				// for (auto &val : C_0_TO_subhammdis[k])
				// {
				// 	uint32_t temp_key = temp ^ val;
				// 	if (filters[k].contains(temp_key))
				// 	{
				// 		auto its = std::lower_bound(sub_linear_comp[k].begin(), sub_linear_comp[k].end(), temp_key, compareFirst_comp);
				// 		if (its != sub_linear_comp[i].end() && its->sub_key == temp_key)
				// 		{
				// 			temp_vec.push_back(its->begin);
				// 		}
				// 	}
				// }
				// lru_index_add(k, temp, temp_vec);
			}
		}
	}
	// printf sub_index size
	for (int i = 0; i < 4; i++)
	{
		printf("sub_index%d size:%d\n", i, sub_index[i].size());
	}
};

void ecall_find_one(void *dataptr, uint32_t *res, uint64_t hammdist)
{
	// cont.changeHammingDist(hammdist);

	// EcallCrypto *cryptoObj = new EcallCrypto(CIPHER_TYPE, HASH_TYPE);
	// EVP_MD_CTX *mdCtx = EVP_MD_CTX_new();
	// EVP_CIPHER_CTX *cipherCtx_ = EVP_CIPHER_CTX_new();
	// uint8_t *sessionKey_ = const_sessionKey;

	// uint8_t *dataE = reinterpret_cast<uint8_t *>(dataptr);
	// int dataSize = 16;
	// cryptoObj->SessionKeyDec(cipherCtx_, dataE,
	// 						 dataSize, sessionKey_,
	// 						 dataE);
	// printf("nums%d\n", (uint64_t *)dataE[0]);
	// uint64_t *data = reinterpret_cast<uint64_t *>(dataE);
	// std::unordered_set<uint32_t> res_set = cont.find_sim(data);
	// uint8_t *res_old = reinterpret_cast<uint8_t *>(res);
	// for (auto &it : res_set)
	// {
	// 	*res = it;
	// 	res++;
	// }
	// //*len=res_set.size();
	// cryptoObj->SessionKeyEnc(cipherCtx_, (uint8_t *)res_old, 3000 * 4, sessionKey_, (uint8_t *)res_old);
	// printf("Successfully found  photos! successful_num=%d.\n", res_set.size());
	// // printf("%d",sign_data.size());
}
void ecall_find_batch(void *dataptr, uint32_t *res, uint32_t len, uint32_t len_res, uint64_t hammdist)
{
	// cont.changeHammingDist(hammdist);

	// EcallCrypto *cryptoObj = new EcallCrypto(CIPHER_TYPE, HASH_TYPE);
	// EVP_MD_CTX *mdCtx = EVP_MD_CTX_new();
	// EVP_CIPHER_CTX *cipherCtx_ = EVP_CIPHER_CTX_new();
	// uint8_t *sessionKey_ = const_sessionKey;
	// uint8_t *dataE = reinterpret_cast<uint8_t *>(dataptr);
	// int dataSize = sizeof(uint64_t) * len * 2;
	// cryptoObj->SessionKeyDec(cipherCtx_, dataE,
	// 						 dataSize, sessionKey_,
	// 						 dataE);
	// uint8_t *res_old = reinterpret_cast<uint8_t *>(res);
	// Query_batch_t query;
	// query.sendData = res;
	// *(query.sendData) = len;
	// query.index = query.sendData + sizeof(uint32_t);
	// query.dataBuffer = query.sendData + sizeof(uint32_t) * (len + 1);
	// uint64_t *data = reinterpret_cast<uint64_t *>(dataE);
	// uint64_t temp2[2];
	// printf("query len=%d\n", len);
	// for (int i = 0; i < len; i++)
	// {
	// 	temp2[0] = data[2 * i];
	// 	temp2[1] = data[2 * i + 1];
	// 	unordered_set<uint32_t> res_set = cont.find_sim(temp2);
	// 	query.index[i] = res_set.size();
	// 	// printf("res_set.size()=%d\n",res_set.size());
	// 	for (auto &it : res_set)
	// 	{
	// 		*(query.dataBuffer) = it;
	// 		query.dataBuffer++;
	// 	}
	// }

	// printf("successful_num=%d\n", cont.successful_num);
	// //*len=res_set.size();
	// cryptoObj->SessionKeyEnc(cipherCtx_, (uint8_t *)res_old, QUERY_SIZE * sizeof(uint32_t) * len, sessionKey_, (uint8_t *)res_old);
	// // printf("Successfully found  photos! successful_num=%d.\n",res_set.size());
	// printf("%d", sign_data.size());
}

// move the visited node to the tail of the list
void containers::lru_index_visit(int sub_i, sub_index_node *node)
{
	// if node->pre==this, the node is not in LRU list, return
	if (node->pre == nullptr || node->pre == new_data_head[sub_i])
		return;
	if (node == lru_n[sub_i].index_tail)
		return; // if the node is the tail of the list,return
	// move the node to the tail of the index list
	node->next->pre = node->pre;
	node->pre->next = node->next;
	node->pre = lru_n[sub_i].index_tail;
	lru_n[sub_i].index_tail->next = node;
	lru_n[sub_i].index_tail = node;
};

// add the node to the tail of the list
void containers::lru_index_add(int sub_i, uint32_t sub_key, int begin)
{
	// if(sub_index[sub_i].find(sub_key)!=sub_index[sub_i].end())
	// 	return;

	// if the size of the index list is larger than the max size,remove the first node
	sub_index_node *remove_node = nullptr;
	if (lru_n[sub_i].index_size >= lru_n[sub_i].map_size)
	{
		remove_node = lru_n[sub_i].index_head->next;
		sub_index_node *first = remove_node->next;
		lru_n[sub_i].index_head->next = first;
		first->pre = lru_n[sub_i].index_head;
		auto tmp = sub_index[sub_i].find(remove_node->sub_key);

		// if tmp is not in the new_data_head,remove it from the map
		if (tmp != sub_index[sub_i].end() && tmp->second->pre == lru_n[sub_i].index_head)
			sub_index[sub_i].erase(remove_node->sub_key);
		remove_node->pre = nullptr;
		remove_node->next = nullptr;
	}
	else
	{
		lru_n[sub_i].index_size++;
	}

	// add node to the tail of the LRU list
	sub_index_node *node = nullptr;
	if (remove_node == nullptr)
		node = &cont.sub_nodes[sub_i][lru_n[sub_i].index_size - 1]; // new sub_index_node{node_liner->sub_key,node_liner,nullptr,nullptr};
	else
		node = remove_node;

	// change the sub_key and begin of the node
	// node->sub_key = node_liner->sub_key;
	node->begin = begin;
	node->sub_key = sub_key;
	// node->begin.clear();
	// node->begin.resize(begin_index.size());
	// memcpy(node->begin.data(), begin_index.data(), begin_index.size() * sizeof(uint32_t));

	node->next = nullptr;
	node->pre = nullptr;
	sub_index[sub_i][node->sub_key] = node;

	// move the node to the tail of the LRU list
	lru_n[sub_i].index_tail->next = node;
	node->pre = lru_n[sub_i].index_tail;
	lru_n[sub_i].index_tail = node;
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
			if (count <= cont.hammdist)
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