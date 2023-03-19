#include"Container.h"
#include <cstdarg>
#define KNRM "\x1B[0m"
#define KRED "\x1B[31m"
#define KGRN "\x1B[32m"
#define KYEL "\x1B[33m"
#define KBLU "\x1B[34m"
#define KMAG "\x1B[35m"
#define KCYN "\x1B[36m"
#define KWHT "\x1B[37m"


void log(const char *file_name, const char *function_name, size_t line, const char *fmt, ...) {
#ifdef DEBUG
    va_list args;
    va_start(args, fmt);
    fprintf(stdout, KGRN "[%s:%zu @ %s]: %s", file_name, line, function_name, KWHT);
    vfprintf(stdout, fmt, args);
    fprintf(stdout, "\n");
    fflush(stdout);
#endif
}

void error_msg(const char *file_name, const char *function_name, size_t line, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    fprintf(stdout, KRED "[ERROR] [%s:%zu @ %s]: %s", file_name, line, function_name, KWHT);
    vfprintf(stdout, fmt, args);
    fprintf(stdout, "\n");
    fflush(stdout);
}
void M_Assert(const char *expr_str, bool expr, const char *file, int line, const char *msg, ...) {
    if (!expr) {
        fprintf(stderr, KRED "Assert failed:\t");
        va_list args;
        va_start(args, msg);
        vfprintf(stderr, msg, args);
        fprintf(stderr, "\nExpected: %s\n", expr_str);
        fprintf(stderr, "At Source: %s:%d\n", file, line);
        abort();
    }
}



containers::containers()
{
	sub_keybit=keybit/sub_index_num;
	sub_hammdist=hammdist/sub_index_num;
}
void containers::prepare()
{
	LOGGER("Prepare");
	uint32_t tmp1=1;
	uint32_t tmp2=1;
	uint32_t tmp=0;
	C_0_TO_subhammdis.push_back(0);
	switch(2)
	{
	case 2:
		for(int i=0;i<31;i++)
		{
			tmp1=0x00000001<<i;
			for(int j=1+i;j<32;j++)
			{
				tmp2=0x00000001<<j;
				tmp=tmp1+tmp2;
				C_0_TO_subhammdis.push_back(tmp);
			}
		}
	case 1:
	{
		for(int x=0;x<32;x++)
		{
			tmp=0x00000001<<x;
			C_0_TO_subhammdis.push_back(tmp);
		}
		break;
	}
	default:
		break;
	}
}
void containers::initialize()
{
	uint64_t temp_key[2]={0};
	uint64_t temp_keyx[2]={0};
	uint32_t out_id=0;
	uint32_t sub1,sub2,sub3,sub4=0;
	uint64_t temp_full_key[2]={0};
	information temp_information;

	random_device rd;
	default_random_engine r_eng(rd());

	while(sub_index1.size()<initialize_size)
	{
		temp_key[0]=(uint64_t)r_eng();
		temp_key[0]=temp_key[0]<<32;
		temp_key[0]=temp_key[0]+(uint64_t)r_eng();
		temp_key[1]=(uint64_t)r_eng();
		temp_key[1]=temp_key[1]<<32;
		temp_key[1]=temp_key[1]+(uint64_t)r_eng();
		temp_keyx[0]=temp_key[0];
		temp_keyx[1]=temp_key[1];
		temp_information.fullkey[0]=temp_key[0];
		temp_information.fullkey[1]=temp_key[1];

		sub1=temp_key[0]&0xffffffff;
		temp_key[0]=temp_key[0]>>32;

		sub2=temp_key[0]&0xffffffff;
		
		sub3=temp_key[1]&0xffffffff;
		temp_key[1]=temp_key[1]>>32;
		
		sub4=temp_key[1]&0xffffffff;
		temp_full_key[0]=temp_keyx[0];
		
		temp_full_key[1]=temp_keyx[1];
		if((sub_index1.find(sub1)==sub_index1.end())&&(sub_index2.find(sub2)==sub_index2.end())&&(sub_index3.find(sub3)==sub_index3.end())&&(sub_index4.find(sub4)==sub_index4.end()))
		{
			sub_index1.insert(pair<uint32_t,uint32_t>(sub1,out_id));
			sub_index2.insert(pair<uint32_t,uint32_t>(sub2,out_id));
			sub_index3.insert(pair<uint32_t,uint32_t>(sub3,out_id));
			sub_index4.insert(pair<uint32_t,uint32_t>(sub4,out_id));
			full_index.insert(pair<uint32_t,information>(out_id,temp_information));
			test_pool.insert(pair<uint64_t,uint64_t>(temp_keyx[0],temp_keyx[1]));
			out_id++;
		}
	}
	return;
}
void containers::find_sim(uint64_t query[])
{

	uint64_t tmpquery1=query[0];
	uint64_t tmpquery2=query[1];
	uint32_t sub1=tmpquery1&0xffffffff;
	tmpquery1=tmpquery1>>32;
	uint32_t sub2=tmpquery1&0xffffffff;
	uint32_t sub3=tmpquery2&0xffffffff;
	tmpquery2=tmpquery2>>32;
	uint32_t sub4=tmpquery2&0xffffffff;

	
	uint32_t tmpsub1,tmpsub2,tmpsub3,tmpsub4=0;
	


	for(auto &its: this->C_0_TO_subhammdis)
	{
		tmpsub1=sub1^its;
		tmpsub2=sub2^its;
		tmpsub3=sub3^its;
		tmpsub4=sub4^its;
	//	LOGGER("SUB FP INFO: %u %u %u %u",tmpsub1,tmpsub2,tmpsub3,tmpsub4);
	//	LOGGER("SUB INDEX SIZE: %zu %zu %zu %zu",sub_index1.size(),sub_index2.size(),sub_index3.size(),sub_index4.size());
		
		auto got1=sub_index1.find(tmpsub1);
		if(got1!=sub_index1.end())
		{
			candidate.insert(got1->second);
		}

		auto  got2=sub_index2.find(tmpsub2);
		if(got2!=sub_index2.end())
		{
			candidate.insert(got2->second);
		}
		auto got3 = sub_index3.find(tmpsub3);
		if(got3!=sub_index3.end())
		{
			candidate.insert(got3->second);
		}
		auto got4=sub_index4.find(tmpsub4);
		if(got4!=sub_index4.end())
		{
			candidate.insert(got4->second);
		}
	}



	uint64_t cmp_hamm[2]={0};
	int count=0;
	unordered_map<uint32_t,information>::const_iterator got_out;
	for(auto &it : candidate)
	{
		got_out=full_index.find(it);
		if(got_out!=full_index.end())
		{
			cmp_hamm[0]=query[0]^(got_out->second.fullkey[0]);
			cmp_hamm[1]=query[1]^(got_out->second.fullkey[1]);
			count=0;
			while(cmp_hamm[0])
			{
				count+=cmp_hamm[0]&1;
				cmp_hamm[0]=cmp_hamm[0]>>1;
			}
			while(cmp_hamm[1])
			{
				count+=cmp_hamm[1]&1;
				cmp_hamm[1]=cmp_hamm[1]>>1;
			}
			if(count<=hammdist)
				successful_num++;
		}
	}
	candidate.clear();
}
void containers::test()
{
	int m=0;
	uint64_t temp_key[2]={0};
	// set<pair<uint64_t,uint64_t>>::iterator itx;

	int h=0,y=0;
	uint64_t t=0;
	clock_t startTime=clock();
	for(auto &itx : test_pool)
	{
		t=0x0000000000000001;
		h=rand()%3;
		temp_key[0]=itx.first;
		temp_key[1]=itx.second;
		for(int i=0;i<h;i++)
		{
			y=rand()%64;
			temp_key[0]=temp_key[0]^(t<<y);
			temp_key[1]=temp_key[1]^(t<<y);
		}
		find_sim(temp_key);
		m++;
	}
	clock_t endTime=clock();
	double costTime=double(endTime-startTime)/CLOCKS_PER_SEC;
	cout << "The full index entry is:" << initialize_size << endl;
	cout << "The number of queries is:" << test_size << endl;
	cout << "The program takes " << costTime << "seconds!"<< endl;
}
