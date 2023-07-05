#include<set>
#include<vector>
#include<iostream>
#include<unordered_map>
#include<unordered_set>
#include "Enclave_t.h"
#include "../Enclave.h"
#include "tsl/bloom_filter.hpp"
#include"tsl/hopscotch_map.h"
#include "../ServerECall/ecallEnc.h"
using namespace std;

#define LOGGER(x)
// #define DEBUG
// #ifdef WIN32
// #define FN (__builtin_strrchr(__FILE__, '\\') ? __builtin_strrchr(__FILE__, '\\') + 1 : __FILE__)
// #else
// #define FN (__builtin_strrchr(__FILE__, '/') ? __builtin_strrchr(__FILE__, '/') + 1 : __FILE__)
// #endif
// #define LOGGER(...) log(FN, __FUNCTION__, __LINE__, __VA_ARGS__)
// #define ERROR(...) error_msg(FN, __FUNCTION__, __LINE__, __VA_ARGS__)

// // #define INFO(...) fprintf(stdout, __VA_ARGS__)

// void log(const char *file_name, const char *function_name, size_t line, const char *fmt, ...);
// void error_msg(const char *file_name, const char *function_name, size_t line, const char *fmt, ...);

// #ifdef DEBUG
// #define Assert(Expr, ...) M_Assert(#Expr, Expr, __FILE__, __LINE__, __VA_ARGS__)
// #else
// #define Assert(Expr, Msg) ;
// #endif

// void M_Assert(const char *expr_str, bool expr, const char *file, int line, const char *fmt, ...);



struct information
{
	// uint32_t target;
	uint64_t fullkey[2];
	uint16_t location=111;
};

struct sub_information
{
	uint32_t identifiers;
	uint32_t sub_key;
};


typedef struct sub_index_node{
	uint32_t sub_key;
	sub_information* liner_node;
	sub_index_node* next;
	sub_index_node* pre;
}sub_index_node;

typedef struct LRU_node{
	uint32_t map_size;
	uint32_t index_size;
	sub_index_node* index_head;
	sub_index_node* index_tail;
}lru_node;

class containers
{
public:
	static uint64_t keybit;
	static uint64_t hammdist;
	static uint64_t sub_index_num;
	int sub_keybit;
	uint64_t sub_hammdist[4];	//general pigeon principle，每段的汉明距离可能不相等，但总和为hammdist-subindex_num+1
	static uint32_t initialize_size;
	static uint32_t test_size;
	static uint32_t sub_map_size;
	int successful_num=0;
	//unordered_set<uint32_t> candidate;
	// unordered_map<uint32_t,information> full_index;
	unordered_map<uint32_t,sub_index_node*>sub_index[4];
	
	// tsl::hopscotch_map<uint32_t,information> full_index;
	// tsl::hopscotch_map<uint32_t,vector<uint32_t>>sub_index1;
	// tsl::hopscotch_map<uint32_t,vector<uint32_t>>sub_index2;
	// tsl::hopscotch_map<uint32_t,vector<uint32_t>>sub_index3;
	// tsl::hopscotch_map<uint32_t,vector<uint32_t>>sub_index4;
	sub_information** sub_index_liner;
	vector<information>full_index;
	bloom_filter filters[4];bloom_filter sub_filters[4];
	sub_index_node** sub_nodes;
	vector<uint32_t>C_0_TO_subhammdis[4]; //用于与特征段做异或运算的所有数字的容器
	set<pair<uint64_t,uint64_t>>test_pool;
	containers();
	void random_128(uint64_t *temp_key);
	void get_sub_fingerprint(uint32_t *sub_fingerprint,uint64_t *fingerprint);
	uint32_t random_uuid();
	void get_test_pool();
	void prepare(uint32_t sub_hammdist,vector<uint32_t>&C_0_TO_subhammdis);
	void initialize();
	void changeHammingDist(uint64_t hammingdist);
	void init_after_recv_data();
	std::unordered_set<uint32_t> find_sim(uint64_t query[]);
	void test();
};

void lru_index_visit(int sub_i,sub_index_node* node);
void lru_index_add(int sub_i,unordered_map<uint32_t,sub_index_node*>& sub_index,sub_information* node_liner);