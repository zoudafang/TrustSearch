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
//change!!!
#include "Enclave_t.h"
#include "../Enclave.h"
#include "sgx_trts.h"
#include "stdio.h"
#include <cstdio>

int containers::keybit=128;
int containers::hammdist=8;
int containers::sub_index_num=4;
int containers::test_size=1;
int containers::initialize_size=11000;

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


containers::containers()
{
	sub_keybit=keybit/sub_index_num;
	sub_hammdist=hammdist/sub_index_num;
}

void containers::random_128(uint64_t *temp_key)
{
	unsigned char rand[16]={0};
	sgx_read_rand(rand,16);
	temp_key[0]=(uint64_t)rand[0];
	for(int i=1;i<8;i++)
	{
		temp_key[0]=temp_key[0]<<8;
		temp_key[0]=temp_key[0]+(uint64_t)rand[i];
	}
	temp_key[1]=(uint64_t)rand[8];
	for(int j=1;j<8;j++)
	{
	   	temp_key[1]=temp_key[1]<<8;
	   	temp_key[1]=temp_key[1]+(uint64_t)rand[j+8];
	}
}
void containers::get_sub_fingerprint(uint32_t *sub_fingerprint,uint64_t *fingerprint)
{
	sub_fingerprint[0]=fingerprint[0]&0xffffffff;
	fingerprint[0]=fingerprint[0]>>32;
	sub_fingerprint[1]=fingerprint[0]&0xffffffff;
	sub_fingerprint[2]=fingerprint[1]&0xffffffff;
	fingerprint[1]=fingerprint[1]>>32;
	sub_fingerprint[3]=fingerprint[1]&0xffffffff;
}
uint64_t containers::random_uuid()
{
	uint64_t out_id;
	unsigned char rand[8]={0};
	sgx_read_rand(rand,8);
	out_id=(uint64_t)rand[0];
	for(int i=1;i<8;i++)
	{
		out_id=out_id<<8;
		out_id=out_id+(uint64_t)rand[i];
	}
	return out_id;
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
		break;
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
	uint32_t sub[4]={0};
	information temp_information;
	

	while(sub_index1.size()<initialize_size)
	{	
		random_128(temp_key);
		temp_keyx[0]=temp_key[0];
		temp_keyx[1]=temp_key[1];
		temp_information.fullkey[0]=temp_key[0];
		temp_information.fullkey[1]=temp_key[1];
		get_sub_fingerprint(sub,temp_key);
		out_id=random_uuid();

		if((sub_index1.find(sub[0])==sub_index1.end())&&(sub_index2.find(sub[1])==sub_index2.end())&&(sub_index3.find(sub[2])==sub_index3.end())&&(sub_index4.find(sub[3])==sub_index4.end()))
		{
			sub_index1.insert(pair<uint32_t,uint32_t>(sub[0],out_id));
			sub_index2.insert(pair<uint32_t,uint32_t>(sub[1],out_id));
			sub_index3.insert(pair<uint32_t,uint32_t>(sub[2],out_id));
			sub_index4.insert(pair<uint32_t,uint32_t>(sub[3],out_id));
			full_index.insert(pair<uint32_t,information>(out_id,temp_information));
			get_test_pool(temp_keyx);
		}
	}
	printf("Return!!\n");
	return;
}
void containers::get_test_pool(uint64_t *temp_key)
{
	int h=0,y=0;
	uint64_t t=0x0000000000000001;
	unsigned char rand[2]={0};
	sgx_read_rand(rand,2);
	h=rand[0]%3;
	for(int i=0;i<h;i++)
	{
	  	y=rand[1]%64;
		temp_key[0]=temp_key[0]^(t<<y);
		temp_key[1]=temp_key[1]^(t<<y);
	}
	test_pool.insert(pair<uint64_t,uint64_t>(temp_key[0],temp_key[1]));
}
void containers::find_sim(uint64_t query[])
{
	uint64_t tmpquery[2]={0};
	tmpquery[0]=query[0];
	tmpquery[1]=query[1];
	uint32_t sub[4]={0};
	get_sub_fingerprint(sub,tmpquery);

	uint32_t tmpsub1,tmpsub2,tmpsub3,tmpsub4=0;
	for(auto &its: this->C_0_TO_subhammdis)
	{
		tmpsub1=sub[0]^its;
		tmpsub2=sub[1]^its;
		tmpsub3=sub[2]^its;
		tmpsub4=sub[3]^its;
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
	// uint64_t start_time, end_time;
	// sgx_read_tsc(&start_time);

	uint64_t temp_key[2]={0};
	for(auto &itx : test_pool)
	{
		temp_key[0]=itx.first;
		temp_key[1]=itx.second;
		find_sim(temp_key);
	}

	// sgx_read_tsc(&end_time);
	// uint64_t elapsed = end_time - start_time;
	printf("The full index entry is: %d \n",initialize_size);
	printf("The number of queries is: %d \n",test_size);
	// printf("The program takes %lu seconds!\n",elapsed);
	
}
void run_code()
{
	printf("run code!\n");
	containers example;
	printf("Prepare\n");
    example.prepare();
	printf("Init\n");
	example.initialize();	
	printf("Test\n");
	example.test();
	printf("Successfully found similar photos! successful_num=%d\n",example.successful_num);
}
