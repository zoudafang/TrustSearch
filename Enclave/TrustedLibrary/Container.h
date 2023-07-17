#include <set>
#include <vector>
#include <iostream>
#include <unordered_map>
#include <unordered_set>
#include "Enclave_t.h"
#include "../Enclave.h"
#include "tsl/bloom_filter.hpp"
#include "tsl/hopscotch_map.h"
#include "../ServerECall/ecallEnc.h"
extern "C"
{
#include "libfor/for.h"
}
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
	uint16_t location = 111;
};

struct sub_information
{
	uint32_t identifiers;
	uint32_t sub_key;
};

// compress sub_information, begin is the begin of sub_key in sub_identifiers[]
typedef struct sub_info_comp
{
	uint32_t sub_key;
	uint32_t begin;
} sub_info_comp;

// hot data stored in sub_map
typedef struct sub_index_node
{
	uint32_t sub_key;
	// vector<uint32_t> identifiers;
	uint32_t begin;
	sub_index_node *next;
	sub_index_node *pre;
} sub_index_node;

typedef struct LRU_node
{
	uint32_t map_size;
	uint32_t index_size;
	sub_index_node *index_head;
	sub_index_node *index_tail;
} lru_node;

class containers
{
public:
	static uint64_t keybit;
	static uint64_t hammdist;
	static uint64_t sub_index_num;
	int sub_keybit;
	uint64_t sub_hammdist[4]; // general pigeon principle，每段的汉明距离可能不相等，但总和为hammdist-subindex_num+1
	static uint32_t initialize_size;
	static uint32_t test_size;
	static uint32_t sub_map_size;
	int successful_num = 0;
	// unordered_set<uint32_t> candidate;
	//  unordered_map<uint32_t,information> full_index;
	unordered_map<uint32_t, sub_index_node *> sub_index[4];

	// tsl::hopscotch_map<uint32_t,information> full_index;
	// tsl::hopscotch_map<uint32_t,vector<uint32_t>>sub_index1;
	// tsl::hopscotch_map<uint32_t,vector<uint32_t>>sub_index2;
	// tsl::hopscotch_map<uint32_t,vector<uint32_t>>sub_index3;
	// tsl::hopscotch_map<uint32_t,vector<uint32_t>>sub_index4;

	vector<sub_information> *sub_index_liner; // 用于接收外部传入的information
	vector<sub_info_comp> sub_linear_comp[4]; // 四个特征段的sub_index_liner，仅存储sub_key和begin
	// vector<uint32_t> sub_identifiers[4];
	vector<uint8_t> sub_identifiers[4]; // 用于存储压缩后的identifiers，每个sub_key对应一个sub_identifiers，begin对应起始4byte是length，第二个4byte是压缩参数，再后面是压缩后的identifiers
	vector<information> full_index;
	bloom_filter filters[4];

	uint32_t *out = new uint32_t[7000]; // 临时变量，用于存储查询结果
	sub_index_node **sub_nodes;
	vector<uint32_t> C_0_TO_subhammdis[4]; // 用于与特征段做异或运算的所有数字的容器
	set<pair<uint64_t, uint64_t>> test_pool;
	lru_node lru_n[4];				  // sub_index的lru结构，包括map大小，lru的head,head包括一个空的头节点
	sub_index_node *new_data_head[4]; // 新insert的数据形成链表，head记录头部
	// unordered_map<uint32_t,uint32_t> insert_data[4]; //记录插入的新数据的位置
	containers();
	void random_128(uint64_t *temp_key);
	void get_sub_fingerprint(uint32_t *sub_fingerprint, uint64_t *fingerprint);
	uint32_t random_uuid();
	void get_test_pool(); // changed，注意，通过注释其中的sgx_read_rand可以调整查询方式：顺序查询，随机查询
	void prepare(uint32_t sub_hammdist, vector<uint32_t> &C_0_TO_subhammdis);
	void initialize();
	void changeHammingDist(uint64_t hammingdist);
	void init_after_recv_data();
	std::unordered_set<uint32_t> find_sim(uint64_t query[]);
	void test();
	void lru_index_visit(int sub_i, sub_index_node *node);					   // 访问lru的index，将node移到tail
	void lru_index_add(int sub_i, vector<sub_info_comp>::iterator node_liner); // 将sub_key对应结点加入

	// insert的函数，暂不考虑，设计完索引结构后再修改
	void insert_fingerprint(pair<uint64_t, uint64_t> *data, uint32_t length);
	void insert_new_datamap(int sub_i);
	void insert_to_submap(int sub_i, uint32_t sub_key, uint32_t identifier);
	void change_sub_map(int sub_i); // 如果insert太多元素，需要动态调整map和linear的比例
};