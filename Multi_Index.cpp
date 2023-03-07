#include <string>
#include <unordered_map>
//#include <map>
#include <iostream> 
#include <set>
#include <vector>
//#include <queue>
#include <random>
#include <ctime>

using namespace std;

#define keybit 128    //特征值的位数
#define hammdist 8    //认为图片相似的最大汉明距离
#define sub_index_num 4   //子索引的数量
#define sub_keybit keybit/sub_index_num   //特征值段的位数
#define sub_hammdist  hammdist/sub_index_num    //候选值的标准
#define initialize_size 200000 //规定的part_index的大小
#define test_size 1000 //规定的part_index的大小

int x = 0;

struct uint128_t
{
	uint64_t fullkey[2];//完整特征值
};
//完整索引所指向的内容
struct information
{
	uint64_t fullkey[2];//完整特征值
	uint16_t location=111;//存储位置
	//uint64_t count;//频率
};
/*
struct cmp
{
	bool operator()(information a, information b)
	{
		return a.count > b.count;
	}
};
*/

set<uint32_t> candidate;//候选池
unordered_map<uint32_t, information> full_index;//完整索引
unordered_map<uint32_t, uint32_t>sub_index1;//四个子索引
unordered_map<uint32_t, uint32_t>sub_index2;
unordered_map<uint32_t, uint32_t>sub_index3;
unordered_map<uint32_t, uint32_t>sub_index4;
vector<uint32_t>C_0_TO_subhammdis;//用于与特征段做异或运算的所有数字的容器
set<pair<uint64_t, uint64_t>>test_pool;

//准备与特征段做异或运算的所有数字，全部存入C_0_TO_subhammdis中，这里只写了最多两位不同的情况。
//方法很笨，后面再想想有没有其他方法。
void prepare()
{
	uint32_t tmp1 = 1;
	uint32_t tmp2 = 1;
	uint32_t tmp = 0;
	C_0_TO_subhammdis.push_back(0);
	switch (sub_hammdist)
	{
		case 2:
			for (int i = 0; i < 31; i++)
			{
				tmp1 = 0x00000001 << i;
				for (int j = 1+i; j < 32; j++)
				{
					tmp2 = 0x00000001 << j;
					tmp = tmp1 + tmp2;
					C_0_TO_subhammdis.push_back(tmp);
				}
			}
		case 1:
		{
			for (int x = 0; x < 32; x++)
			{
				tmp = 0x00000001 << x;
				C_0_TO_subhammdis.push_back(tmp);
			}
			break;
		}
		default:
			break;
	}
}

void initialize()
{
	uint64_t temp_key[2] = { 0 };
	uint64_t temp_keyx[2] = { 0 };
	uint32_t out_id = 0;
	uint32_t sub1, sub2, sub3, sub4 = 0;
	uint128_t temp_full_key;
	information temp_information;
	
	
	random_device rd;
	default_random_engine r_eng(rd());
	
	while(sub_index1.size()<initialize_size)
	{
		temp_key[0] = (uint64_t)r_eng();
		temp_key[0] = temp_key[0] << 32;
		temp_key[0] = temp_key[0] + (uint64_t)r_eng();
		temp_key[1] = (uint64_t)r_eng();
		temp_key[1] = temp_key[1] << 32;
		temp_key[1] = temp_key[1] + (uint64_t)r_eng();
		temp_keyx[0] = temp_key[0];
		temp_keyx[1] = temp_key[1];
		temp_information.fullkey[0] = temp_key[0];
		temp_information.fullkey[1] = temp_key[1];

		sub1 = temp_key[0] & 0xffffffff;
		temp_key[0] = temp_key[0] >> 32;
		sub2 = temp_key[0] & 0xffffffff;
		sub3 = temp_key[1] & 0xffffffff;
		temp_key[1] = temp_key[1] >> 32;
		sub4 = temp_key[1] & 0xffffffff;
		temp_full_key.fullkey[0] = temp_keyx[0];
		temp_full_key.fullkey[1] = temp_keyx[1];
		if ((sub_index1.find(sub1) == sub_index1.end()) && (sub_index2.find(sub2) == sub_index2.end()) && (sub_index3.find(sub3) == sub_index3.end()) && (sub_index4.find(sub4) == sub_index4.end()))
		{
			sub_index1.emplace(std::pair<uint32_t, uint32_t>(sub1, out_id));
			sub_index2.insert(std::pair<uint32_t, uint32_t>(sub2, out_id));
			sub_index3.insert(std::pair<uint32_t, uint32_t>(sub3, out_id));
			sub_index4.insert(std::pair<uint32_t, uint32_t>(sub4, out_id));
			full_index.insert(std::pair<uint32_t, information>(out_id, temp_information));
			test_pool.insert(std::pair< uint64_t, uint64_t>(temp_keyx[0], temp_keyx[1]));
			out_id++;
		}
	}
	return;
}

void find_sim(uint64_t query[])
{
	//通过位运算，截取特征值段
	uint64_t tmpquery1 = query[0];
	uint64_t tmpquery2 = query[1];
	uint32_t sub1 = tmpquery1 & 0xffffffff;
	tmpquery1 = tmpquery1 >> 32;
	uint32_t sub2 = tmpquery1 & 0xffffffff;
	uint32_t sub3 = tmpquery2 & 0xffffffff;
	tmpquery2 = tmpquery2 >> 32;
	uint32_t sub4 = tmpquery2 & 0xffffffff;

	//容器的迭代器
	std::unordered_map<uint32_t, uint32_t>::const_iterator got1;
	std::unordered_map<uint32_t, uint32_t>::const_iterator got2;
	std::unordered_map<uint32_t, uint32_t>::const_iterator got3;
	std::unordered_map<uint32_t, uint32_t>::const_iterator got4;
	std::set<uint32_t>::iterator it;
	std::vector<uint32_t>::iterator its;

	//寻找候选特征段
	uint32_t tmpsub1, tmpsub2, tmpsub3, tmpsub4 = 0;
	for (its= C_0_TO_subhammdis.begin(); its != C_0_TO_subhammdis.end(); its++)
	{
		//做异或运算，找出只有相关位不同的可能候选值
		tmpsub1 = sub1 ^ *its;
		tmpsub2 = sub2 ^ *its;
		tmpsub3 = sub3 ^ *its;
		tmpsub4 = sub4 ^ *its;

		//分别在4个子索引中查找候选值
		got1 = sub_index1.find(tmpsub1);
		if (got1 != sub_index1.end())//检查这个可能的候选值是否存在
		{
			it = candidate.find(got1->second);//检查标识符在候选池中是否已经存在
			if (it == candidate.end())
				candidate.insert(got1->second);
		}
		got2 = sub_index2.find(tmpsub2);
		if (got2 != sub_index2.end())
		{
			it = candidate.find(got2->second);
			if (it == candidate.end())
				candidate.insert(got2->second);
		}
		got3 = sub_index3.find(tmpsub3);
		if (got3 != sub_index3.end())
		{
			it = candidate.find(got3->second);
			if (it == candidate.end())
				candidate.insert(got3->second);
		}
		got4 = sub_index3.find(tmpsub4);
		if (got4 != sub_index3.end())
		{
			it = candidate.find(got4->second);
			if (it == candidate.end())
				candidate.insert(got4->second);
		}
	}

	//对候选特征段进行筛选
	uint64_t cmp_hamm[2] = { 0 };
	int count = 0;

	std::unordered_map<uint32_t, information>::const_iterator got_out;
	for (it = candidate.begin(); it != candidate.end(); ++it)
	{
		got_out = full_index.find(*it);
		if (got_out != full_index.end())
		{
			cmp_hamm[0] = query[0] ^ (got_out->second.fullkey[0]);
			cmp_hamm[1] = query[1] ^ (got_out->second.fullkey[1]);
			//异或后，统计不同位的个数
			count = 0;
			while (cmp_hamm[0]) {
				count += cmp_hamm[0] & 1;
				cmp_hamm[0] = cmp_hamm[0] >> 1;
			}
			while (cmp_hamm[1]) {
				count += cmp_hamm[1] & 1;
				cmp_hamm[1] = cmp_hamm[1] >> 1;
			}
			if (count <= hammdist)
			{
				x++;
				//printf("Successfully found similar photos! x=%d\n",x);
			}
		}
	}
	candidate.clear();
}

void test()
{
	int m = 0;
	uint64_t temp_key[2] = { 0 };
	std::set<pair<uint64_t, uint64_t >>::iterator itx;
	int h = 0, y = 0;
	uint64_t t = 0;
	
	//for (itx = test_pool.begin(); itx != test_pool.end(); ++itx)
	clock_t startTime = std::clock();
	for (itx = test_pool.begin(); m<test_size; ++itx)
	{
		t = 0x0000000000000001;
		h = rand() % 3;
		
		temp_key[0] = itx->first;
		temp_key[1] = itx->second;
		
		for (int i = 0; i < h; i++)
		{
			y = rand() % 64;
			temp_key[0] = temp_key[0] ^ (t << y);
			temp_key[1] = temp_key[1] ^ (t << y);
		}
		find_sim(temp_key);
		m++;
	}
	clock_t endTime = std::clock();
	double costTime = double(endTime - startTime) / CLOCKS_PER_SEC; //单位秒
	cout <<"完整索引条目为："<< initialize_size << endl;
	cout <<"查询数目为："<< test_size << endl;
	std::cout << "程序耗时" << costTime << "秒！" << endl;//查询总耗时
}

int main() 
{
	//初始化数据；
	//生成随机查询；
	
	prepare();
	initialize();
	test();
	//输入待查询的特征值
}
