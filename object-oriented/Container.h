#include<set>
#include<unordered_map>
#include<random>
#include<ctime>
#include<iostream>

using namespace std;

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
	vector<uint32_t>C_0_TO_subhammdis;
	set<pair<uint64_t,uint64_t>>test_pool;
	containers();
	void prepare();
	void initialize();
	void find_sim(uint64_t query[]);
	void test();
};
