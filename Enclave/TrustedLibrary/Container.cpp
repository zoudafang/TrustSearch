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


uint64_t containers::keybit=128;
uint64_t containers::hammdist=8;
uint64_t containers::sub_index_num=4;
uint32_t containers::test_size=1000;
uint32_t containers::initialize_size=10000;

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

/*
containers::containers()
{
	sub_keybit=(int)keybit/sub_index_num;
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
	uint64_t temp_fingerprint[2]={0};
	temp_fingerprint[0]=fingerprint[0];
	temp_fingerprint[1]=fingerprint[1];
	
	sub_fingerprint[0]=temp_fingerprint[0]&0xffffffff;
	temp_fingerprint[0]=temp_fingerprint[0]>>32;
	sub_fingerprint[1]=temp_fingerprint[0]&0xffffffff;

	sub_fingerprint[2]=temp_fingerprint[1]&0xffffffff;
	temp_fingerprint[1]=temp_fingerprint[1]>>32;
	sub_fingerprint[3]=temp_fingerprint[1]&0xffffffff;
}
uint32_t containers::random_uuid()
{
	static uint32_t id = 0U;
	id++;
	return id;
}
void containers::prepare()
{
	LOGGER("Prepare");
	int tmp1,tmp2,tmp3,tmp4=1;
	int tmp=0;
	uint32_t tmpx=0;
	switch(sub_hammdist)
	{
		case 4:
			for(int a=0;a<sub_keybit-3;a++)
			{
				tmp1=0x0000000000000001<<a;
				for(int b=1+a;b<sub_keybit-2;b++)
				{
					tmp2=0x0000000000000001<<b;
					for(int c=1+b;c<sub_keybit-1;c++)
					{
						tmp3=0x0000000000000001<<c;
						for(int d=1+c;d<sub_keybit;d++)
						{
							tmp4=0x0000000000000001<<d;
							tmp=tmp1+tmp2+tmp3+tmp4;
							tmpx=(uint32_t)tmp;
							C_0_TO_subhammdis.push_back(tmpx);
						}
					}
				}
			}
		case 3:
			for(int e=0;e<sub_keybit-2;e++)
			{
				tmp1=0x0000000000000001<<e;
				for(int f=1+e;f<sub_keybit-1;f++)
				{
					tmp2=0x0000000000000001<<f;
					for(int g=1+f;g<sub_keybit;g++)
					{
						tmp3=0x0000000000000001<<g;
						tmp=tmp1+tmp2+tmp3;
						tmpx=(uint32_t)tmp;
						C_0_TO_subhammdis.push_back(tmpx);
					}
				
				}
			}
		case 2:
			for(int i=0;i<sub_keybit-1;i++)
			{
				tmp1=0x0000000000000001<<i;
				for(int j=1+i;j<sub_keybit;j++)
				{
					tmp2=0x0000000000000001<<j;
					tmp=tmp1+tmp2;
					tmpx=(uint32_t)tmp;
					C_0_TO_subhammdis.push_back(tmpx);
				}
			}
		case 1:
			for(int x=0;x<sub_keybit;x++)
			{
				tmp=0x0000000000000001<<x;
				tmpx=(uint32_t)tmp;
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
	uint64_t temp_key[2]={0};
	uint32_t out_id=0;
	uint32_t sub[4]={0};
	information temp_information;

	while(full_index.size()<initialize_size)
	{	
		random_128(temp_key);
		temp_information.fullkey[0]=temp_key[0];
		temp_information.fullkey[1]=temp_key[1];
		get_sub_fingerprint(sub,temp_key);
		out_id=random_uuid();

		sub_index1[sub[0]].insert(out_id);
		sub_index2[sub[1]].insert(out_id);
		sub_index3[sub[2]].insert(out_id);
		sub_index4[sub[3]].insert(out_id);
		full_index[out_id]=temp_information;
	}
	return;
}
void containers::get_test_pool()
{
	uint64_t temp_key[2]={0};
	for(auto it : full_index)
	{
		if(test_pool.size()>=test_size)
		{
			return;
		}
		temp_key[0]=it.second.fullkey[0];
		temp_key[1]=it.second.fullkey[1];
		int h=0,y=0;
		uint64_t t=1;
		unsigned char rand[3]={0};
		sgx_read_rand(rand,2);
		h=rand[0]%3;
		for(int i=0;i<h;i++)
		{
	  		y=rand[i+1]%64;
			temp_key[0]=temp_key[0]^(t<<y);
			temp_key[1]=temp_key[1]^(t<<y);
		}
		test_pool.insert(pair<uint64_t,uint64_t>(temp_key[0],temp_key[1]));
	}
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
		
		auto got=sub_index1.find(tmpsub1);
		if(got!=sub_index1.end())
		{
			for(auto &gotx1 : got->second)
			{
				candidate.insert(gotx1);
			}
		}
		got=sub_index2.find(tmpsub2);
		if(got!=sub_index2.end())
		{
			for(auto &gotx2 : got->second)
			{
				candidate.insert(gotx2);
			}
		}
		got=sub_index3.find(tmpsub3);
		if(got!=sub_index3.end())
		{
			for(auto &gotx3 : got->second)
			{
				candidate.insert(gotx3);
			}
		}
		got=sub_index4.find(tmpsub4);
		if(got!=sub_index4.end())
		{
			for(auto &gotx4 : got->second)
			{
				candidate.insert(gotx4);
			}
		}
	}

	uint64_t cmp_hamm[2]={0};
	uint64_t count=0;
	unordered_map<uint32_t,information>::const_iterator got_out;
	//tsl::hopscotch_map<uint32_t,information>::const_iterator got_out;
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
				count+=cmp_hamm[0]&1ul;
				cmp_hamm[0]=cmp_hamm[0]>>1;
			}
			while(cmp_hamm[1])
			{
				count+=cmp_hamm[1]&1ul;
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
	printf("Test!\n");
	uint64_t temp_key[2]={0};
	for(auto &itx : test_pool)
	{
		temp_key[0]=itx.first;
		temp_key[1]=itx.second;
		find_sim(temp_key);
	}
	
}
namespace{
	containers cont;
}
void init()
{
	printf("run code!\n");
	cont.prepare();
	printf("c_o size: %d\n",cont.C_0_TO_subhammdis.size());
	printf("Init!\n");
	cont.initialize();
	cont.get_test_pool();
	printf("The full index entry is: %d \n",cont.full_index.size());
	printf("The number of queries is: %d \n",cont.test_pool.size());
}
void test_run()
{
	cont.test();
	printf("Successfully found similar photos! successful_num=%d.\n",cont.successful_num);
}
*/
containers::containers()
{
	sub_keybit=(int)keybit/sub_index_num;
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
	uint64_t temp_fingerprint[2]={0};
	temp_fingerprint[0]=fingerprint[0];
	temp_fingerprint[1]=fingerprint[1];

	sub_fingerprint[0]=temp_fingerprint[0]&0xffffffff;
	temp_fingerprint[0]=temp_fingerprint[0]>>32;
	sub_fingerprint[1]=temp_fingerprint[0]&0xffffffff;

	sub_fingerprint[2]=temp_fingerprint[1]&0xffffffff;
	temp_fingerprint[1]=temp_fingerprint[1]>>32;
	sub_fingerprint[3]=temp_fingerprint[1]&0xffffffff;
}
uint32_t containers::random_uuid()
{
	static uint32_t id = 0U;
	id++;
	return id;
}
void containers::prepare()
{
	LOGGER("Prepare");
	int tmp1,tmp2,tmp3,tmp4=1;
	int tmp=0;
	uint32_t tmpx=0;
	switch(sub_hammdist)
	{
		case 4:
			for(int a=0;a<sub_keybit-3;a++)
			{
				tmp1=0x0000000000000001<<a;
				for(int b=1+a;b<sub_keybit-2;b++)
				{
					tmp2=0x0000000000000001<<b;
					for(int c=1+b;c<sub_keybit-1;c++)
					{
						tmp3=0x0000000000000001<<c;
						for(int d=1+c;d<sub_keybit;d++)
						{
							tmp4=0x0000000000000001<<d;
							tmp=tmp1+tmp2+tmp3+tmp4;
							tmpx=(uint32_t)tmp;
							C_0_TO_subhammdis.push_back(tmpx);
						}
					}
				}
			}
		case 3:
			for(int e=0;e<sub_keybit-2;e++)
			{
				tmp1=0x0000000000000001<<e;
				for(int f=1+e;f<sub_keybit-1;f++)
				{
					tmp2=0x0000000000000001<<f;
					for(int g=1+f;g<sub_keybit;g++)
					{
						tmp3=0x0000000000000001<<g;
						tmp=tmp1+tmp2+tmp3;
						tmpx=(uint32_t)tmp;
						C_0_TO_subhammdis.push_back(tmpx);
					}
				
				}
			}
		case 2:
			for(int i=0;i<sub_keybit-1;i++)
			{
				tmp1=0x0000000000000001<<i;
				for(int j=1+i;j<sub_keybit;j++)
				{
					tmp2=0x0000000000000001<<j;
					tmp=tmp1+tmp2;
					tmpx=(uint32_t)tmp;
					C_0_TO_subhammdis.push_back(tmpx);
				}
			}
		case 1:
			for(int x=0;x<sub_keybit;x++)
			{
				tmp=0x0000000000000001<<x;
				tmpx=(uint32_t)tmp;
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
	uint64_t temp_key[2]={0};
	uint32_t out_id=0;
	uint32_t sub[4]={0};
	full_information temp_full_information;
	sub_information temp_sub_information[4];
	uint32_t full_index_size=0; 

	while(full_index_size<initialize_size)
	{	
		random_128(temp_key);
		
		get_sub_fingerprint(sub,temp_key);
		out_id=random_uuid();

		temp_full_information.fullkey[0]=temp_key[0];
		temp_full_information.fullkey[1]=temp_key[1];
		temp_full_information.identifier=out_id;
		for(int x=0;x<4;x++)
		{
			temp_sub_information[x].identifiers=out_id;
			temp_sub_information[x].sub_key=sub[x];
		}

		sub_index1.push_front(temp_sub_information[0]);
		sub_index2.push_front(temp_sub_information[1]);
		sub_index3.push_front(temp_sub_information[2]);
		sub_index4.push_front(temp_sub_information[3]);
		full_index.push_front(temp_full_information);
		full_index_size++;
	}
	return;
}
void containers::get_test_pool()
{
	uint64_t temp_key[2]={0};
	for(auto it : full_index)
	{
		if(test_pool.size()>=test_size)
		{
			return;
		}

		temp_key[0]=it.fullkey[0];
		temp_key[1]=it.fullkey[1];
		int h=0,y=0;
		uint64_t t=1;
		unsigned char rand[3]={0};
		sgx_read_rand(rand,2);
		h=rand[0]%3;
		for(int i=0;i<h;i++)
		{
	  		y=rand[i+1]%64;
			temp_key[0]=temp_key[0]^(t<<y);
			temp_key[1]=temp_key[1]^(t<<y);
		}
		test_pool.insert(pair<uint64_t,uint64_t>(temp_key[0],temp_key[1]));
	}
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
		
		for(auto &got:sub_index1)
		{
			if(got.sub_key==tmpsub1)
			{
				candidate.insert(got.identifiers);
			}
			
		}
		for(auto &got:sub_index2)
		{
			if(got.sub_key==tmpsub2)
			{
				candidate.insert(got.identifiers);
			}
		}
		for(auto &got:sub_index3)
		{
			if(got.sub_key==tmpsub3)
			{
				candidate.insert(got.identifiers);
			}
		}
		for(auto &got:sub_index4)
		{
			if(got.sub_key==tmpsub4)
			{
				candidate.insert(got.identifiers);
			}
		}
	}
	uint64_t cmp_hamm[2]={0};
	uint64_t count=0;
	
	for(auto &it :full_index)
	{
		if(candidate.find(it.identifier)!=candidate.end())
		{
			cmp_hamm[0]=query[0]^(it.fullkey[0]);
			cmp_hamm[1]=query[1]^(it.fullkey[1]);
			count=0;
			while(cmp_hamm[0])
			{
				count+=cmp_hamm[0]&1ul;
				cmp_hamm[0]=cmp_hamm[0]>>1;
			}
			while(cmp_hamm[1])
			{
				count+=cmp_hamm[1]&1ul;
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
	printf("Test!\n");
	uint64_t temp_key[2]={0};
	for(auto &itx : test_pool)
	{
		temp_key[0]=itx.first;
		temp_key[1]=itx.second;
		find_sim(temp_key);
	}
	
}
namespace{
	containers cont;
}
void init()
{
	printf("run code!\n");
	cont.prepare();
	printf("c_o size: %d\n",cont.C_0_TO_subhammdis.size());
	printf("Init!\n");
	cont.initialize();
	cont.get_test_pool();
	//printf("The full index entry is: %d \n",cont.full_index.size());
	printf("The number of queries is: %d \n",cont.test_pool.size());
}
void test_run()
{
	cont.test();
	printf("Successfully found similar photos! successful_num=%d.\n",cont.successful_num);
}