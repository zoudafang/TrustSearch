#include<set>
#include<unordered_map>
#include<vector>
#include<iostream>

#include "Enclave_t.h"
#include "../Enclave.h"

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
	uint64_t fullkey[2];
	uint16_t location=111;
	//uint64_t count;
};

class containers
{
public:
	static int keybit;
	static int hammdist;
	static int sub_index_num;
	int sub_keybit;
	int sub_hammdist;
	static int initialize_size;
	static int test_size;
	int successful_num=0;
	set<uint32_t> candidate;
	unordered_map<uint32_t,information> full_index;
	unordered_map<uint32_t,uint32_t>sub_index1;
	unordered_map<uint32_t,uint32_t>sub_index2;
	unordered_map<uint32_t,uint32_t>sub_index3;
	unordered_map<uint32_t,uint32_t>sub_index4;
	vector<uint32_t>C_0_TO_subhammdis; //用于与特征段做异或运算的所有数字的容器
	set<pair<uint64_t,uint64_t>>test_pool;
	containers();
	void prepare();
	void initialize();
	void find_sim(uint64_t query[]);
	void test();
};
