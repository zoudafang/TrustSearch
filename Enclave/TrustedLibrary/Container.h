#include <set>
#include <vector>
#include <iostream>
#include <unordered_map>
#include <unordered_set>
#include <queue>
#include "Enclave_t.h"
#include "../Enclave.h"
#include "tsl/bloom_filter.hpp"
#include "tsl/hopscotch_map.h"
#include "../ServerECall/ecallEnc.h"
#include <map>
#include "../../include/crypto.h"
#include "../../include/util.h"
#include "../../include/cmsketch.h"
#include <mutex>
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
	// union 中的所有元素都要是32bit，否则由于内存对齐，无法进行压缩
	union
	{
		uint32_t comp_data; // 压缩后的图片编号（标识符）
		uint32_t len;		// 同一个fullkey的图片数量
		// uint64_t fullkey[2];
		uint32_t sub_fullkey; // 4个128bit特征值分割后的32bit子特征值
		uint32_t target;
	};
};
struct info_uncomp
{
	uint32_t identify; // 图片编号
	uint64_t fullkey[2];
	uint32_t target; // 仅用于测试查询效率，最后可以把target字段取消掉
};
struct sub_information
{
	uint32_t identifiers;
	uint32_t sub_key;
};

struct resort_node
{
	uint32_t cluster_id;
	uint32_t my_id;
	sub_information sub_info;
};

// hot data stored in sub_map
typedef struct sub_index_node // unchanged for ocall page block
{
	uint32_t sub_key;
	// vector<uint32_t> identifiers;
	int begin;
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
	uint32_t fullkey_len;
	vector<uint64_t> hammdist;
	uint32_t sub_index_num;
	uint32_t sub_index_plus;
	uint32_t sub_keybit;
	vector<uint64_t> sub_hammdist; // general pigeon principle，每段的汉明距离可能不相等，但总和为hammdist-subindex_num+1
	static uint32_t initialize_size;
	static uint32_t test_size;
	static uint32_t sub_map_size;
	int successful_num = 0;
	// unordered_set<uint32_t> candidate;
	//  unordered_map<uint32_t,information> full_index;
	unordered_map<uint32_t, sub_index_node *> sub_index[4]; // map，存储hot data
	unordered_map<uint32_t, int> sub_cluster[4];

	// tsl::hopscotch_map<uint32_t,information> full_index;
	// tsl::hopscotch_map<uint32_t,vector<uint32_t>>sub_index1;
	// tsl::hopscotch_map<uint32_t,vector<uint32_t>>sub_index2;
	// tsl::hopscotch_map<uint32_t,vector<uint32_t>>sub_index3;
	// tsl::hopscotch_map<uint32_t,vector<uint32_t>>sub_index4;

	vector<info_uncomp> full_key_sorted;				 // 接收enclave外部传送进来的特征值数据
	vector<sub_information> *sub_index_liner;			 // 用于暂存四个子段的sub_key和id
	vector<sub_info_comp> sub_linear_comp[SUBINDEX_NUM]; // 存储并排序，四个特征段的sub_key，仅存储sub_key和begin
	// vector<uint32_t> sub_identifiers[4];
	vector<uint8_t> sub_identifiers[SUBINDEX_NUM]; // 用于存储压缩后的identifiers，每个sub_key对应一个sub_identifiers，begin对应起始4byte是length，第二个4byte是压缩参数，再后面是压缩后的identifiers
	vector<information> full_index;			   // 内部格式[128bit fullkey;32bit len;32*len bit identifiers],identifiers是图片编号，从0-data_len-1
	vector<uint32_t> C_0_TO_subhammdis[7];		   // 用于与特征段做异或运算的所有数字的容器,C0T[i]仅存储 hamming=i的所有二进制数
	bloom_filter *filters;
	uint32_t bloom_hash_times, INT_SIZE = sizeof(uint32_t);

	vector<pair<uint64_t, uint64_t>> test_pool;
	vector<pair<uint64_t, uint64_t>> tmp_test_pool; // 接收enclave外部传送进来的测试集数据，数据量为1k或10k
	vector<uint32_t> tmp_test_targets, test_targets;

	uint32_t aggre_size = 50;			 // 把多个sub_key合并为一个sub-key,combine_size指合并后一个block可以存储的数据(包括key和ids)的最大值，= 0则表示不进行combine subkey
	uint32_t *out = new uint32_t[70000]; // 临时变量，用于存储decompress后的查询结果,注意，当数据量增加可能需要修改

	lru_node lru_n[4];			// sub_index的lru结构，包括map大小，lru的head,head包括一个空的头节点
	sub_index_node **sub_nodes; // sub_nodes[i]是第i个子段中，map存储的sub_index_node集合，将一个map的所有node提前new分配内存，后续不需要重新分配空间

	// 用于insert新数据的变量
	unordered_map<uint32_t, vector<uint32_t>> tmp_index[4];
	sub_index_node *new_data_head[4]; // 新insert的数据形成链表，head记录头部
	// unordered_map<uint32_t,uint32_t> insert_data[4]; //记录插入的新数据的位置

	containers();
	void random_128(uint64_t *temp_key);
	void get_sub_fingerprint32(uint32_t *sub_fingerprint, uint64_t *fingerprint);
	void get_full_fingerprint32(uint64_t *full_fingerprint, uint32_t *sub_fingerprint);
	uint32_t random_uuid();
	void get_test_pool(); // changed，注意，通过注释其中的sgx_read_rand可以调整查询方式：顺序查询，随机查询
	void prepare(uint32_t sub_hammdist, vector<uint32_t> &C_0_TO_subhammdis);
	void initialize();
	void changeHammingDist(uint64_t hammingdist, int client_id);
	void init_after_recv_data();
	void opt_full_index(); // 优化full index；多个相同的full-key只会被存储一个
	void opt_sub_index();  // 优化sub index；包括多个相同sub-key只存储一次；连续的多个孤立sub-key会被combine为1个，减少查询线性表大小
	void init_sub_maps();  // 往sub map随机插入数据
	std::vector<uint32_t> find_sim(uint64_t query[], uint32_t test_target, int client_id);
	void test();

	void lru_index_visit(int sub_i, sub_index_node *node);		// 访问lru的index，将node移到tail
	void lru_index_add(int sub_i, uint32_t sub_key, int begin); // 将sub_key对应结点加入

	// insert的函数，暂不考虑，设计完索引结构后再修改
	void insert_fingerprint(pair<uint64_t, uint64_t> *data, uint32_t length);
	void insert_new_datamap(int sub_i);
	void insert_to_submap(int sub_i, uint32_t sub_key, uint32_t identifier);
	void change_sub_map(int sub_i); // 如果insert太多元素，需要动态调整map和linear的比例

	uint32_t MIN_INC_NUM = 10;			 // 4.972276
	uint32_t inc_max_dist[SUBINDEX_NUM]; // = {4, 4, 4, 4};
	vector<sub_info_comp> tmp_visit;

	void *id_index[SUBINDEX_NUM];
	uint8_t *id_point[SUBINDEX_NUM];
	EcallCrypto *cryptoObj;
	// EVP_MD_CTX *mdCtx;
	// EVP_CIPHER_CTX *cipherCtx_;
	uint8_t *dataKey_;
	// void gen_candidate(key_find &find_key, std::unordered_set<uint32_t> &cand, sub_info_comp comp, vector<sub_info_comp> &visited_keys, vector<sub_info_comp> &tmp_keys, uint32_t i, uint32_t subkey, uint32_t dt); // 获得candidate（图片id或者fullindex下标）
	void gen_candidate(key_find &find_key, std::unordered_set<uint32_t> &cand, sub_info_comp comp, vector<sub_info_comp> &tmp_keys,
					   uint32_t i, uint32_t subkey, uint32_t dt, uint32_t cache_key); // 获得candidate（图片id或者fullindex下标）

	void enc_page_block(uint8_t *data, uint32_t len);
	void dec_page_block(uint8_t *data, uint32_t len, uint8_t *dec_data);

	vector<cluster_node> clr[SUBINDEX_NUM];
	vector<uint32_t> clr_nums;
	uint32_t min_clr_size = 50, max_dist = 5;
	uint32_t combine_clr_min = 0; // 1000; // combine min cluster size 4000 TODO:cautious
	vector<resort_node> resort_que;
	vector<sub_info_comp> tmp_linear;
	uint32_t tmp_linear_size = 0;
	void make_clusters();
	vector<cluster_node> kmodes(int i);
	uint32_t dataSet; // 0: img512, 1: sift1M, 2: gist1M

	unordered_map<uint64_t, ids_node *> data_cache; // uint32 key; uint32 i
	uint32_t cahce_capacity;

	uint32_t max_id_page = 0;
	LRU_cache lru_cache;
	void lru_ids_visit(uint64_t key, ids_node *node);
	uint8_t *lru_ids_add(uint64_t key, uint32_t sub_i, sub_info_comp comp);
	ids_node *exist_ids;
	void init_ids_cache();
	void init_filters(uint32_t filter_nums);

	vector<uint32_t> get_rand_keys(int i, int k, vector<uint32_t> &old_keys);
	std::vector<std::pair<uint32_t, uint32_t>> find_knn(uint64_t query[], int KNN_NUM);
	void get_cand_knn(sub_info_comp comp, uint32_t i, uint64_t *query, void *res, uint32_t KNN_NUM);
	void get_knn_res(uint32_t fullkey_index, uint64_t *query, void *res, uint32_t KNN_NUM);
	uint32_t max_knn_num = 64;
	uint32_t *ids_block = new uint32_t[70000];

	uint32_t fetch_nums = 0, hit_nums = 0;
	const static int sub_clr_m = 3;
	unordered_map<uint32_t, vector<uint32_t>> sub_clrs[SUBINDEX_NUM][sub_clr_m];
	void init_sub_clrs();
	uint32_t sub_clr_thres[sub_clr_m];
	vector<uint32_t> clrs_mask[4];
	uint32_t sub_index_num_clrs = sub_clr_m;
	uint32_t sub_index_plus_clrs;
	uint32_t sub_keybit_clrs;
	void init_clrs_mask();
	uint32_t get_nearest_min_clr(uint32_t sub_i, uint32_t subkey);
	void get_clrs_near(uint32_t sub_i, uint32_t subkey, uint32_t dist, vector<cluster_info> &clrs);

	int kmod = 50, steps = 20, is_var = 1;
	float ktimes = 2;

	uint32_t big_uneq = 0;
	uint32_t knn_cand_get = 0, knn_hit_cand = 0;
	vector<pair<uint32_t, uint32_t>> idx_2_fullkey;
	void linear_scan(uint32_t i, uint32_t begin, uint32_t end, uint32_t subkey, uint32_t hammdist,
					 unordered_set<uint32_t> &candidate, std::unordered_map<uint32_t, int> &reached_subkey);

	std::mutex lru_mtx;

	int test_target = 0, add_sum = 0;
	uint32_t max_size = 0, max_val = 0;
	vector<uint8_t> max_ids;
};

void find_topk(uint64_t query[]);
void find_sim_linear(vector<pair<uint64_t, uint64_t>> test_pool, vector<uint32_t> target_pool);
