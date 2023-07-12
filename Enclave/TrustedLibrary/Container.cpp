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
#include <bitset>

uint64_t containers::keybit=128;
uint64_t containers::hammdist=8;
uint64_t containers::sub_index_num=4;
uint32_t containers::test_size=1000;
uint32_t containers::initialize_size=0;

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

namespace{
	containers cont;
	std::vector<std::pair<uint64_t,uint64_t>> sign_data;
	std::vector<uint32_t> targets_data;
	skewed_partition parting;
}

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
	sub_fingerprint[0]=fingerprint[0]&0xffffffff;
	fingerprint[0]=fingerprint[0]>>32;
	sub_fingerprint[1]=fingerprint[0]&0xffffffff;

	sub_fingerprint[2]=fingerprint[1]&0xffffffff;
	fingerprint[1]=fingerprint[1]>>32;
	sub_fingerprint[3]=fingerprint[1]&0xffffffff;
}
uint32_t containers::random_uuid()
{
	static uint32_t id = 0U;
	id++;
	return id;
}
void containers::prepare(uint32_t tmp_sub_hammdist,uint32_t k)
{
	LOGGER("Prepare");
	int tmp1,tmp2,tmp3,tmp4=1;
	int tmp=0;
	uint32_t tmpx=0;
	switch(tmp_sub_hammdist)//sub_hammdist
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
							C_0_TO_subhammdis[k].push_back(tmpx);
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
						C_0_TO_subhammdis[k].push_back(tmpx);
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
					C_0_TO_subhammdis[k].push_back(tmpx);
				}
			}
		case 1:
			for(int x=0;x<sub_keybit;x++)
			{
				tmp=0x0000000000000001<<x;
				tmpx=(uint32_t)tmp;
				C_0_TO_subhammdis[k].push_back(tmpx);
			}
		case 0:
		{
			C_0_TO_subhammdis[k].push_back(0);
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
	// containers::initialize_size=sign_data.size();
	// sign_data.shrink_to_fit();targets_data.shrink_to_fit();

	// full_index.reserve(initialize_size/500);
	sub_information sub_info[4];
	bloom_parameters parameters;
    parameters.projected_element_count = test_data_len;//initialize_size; // 预计插入initialize_size个元素
    parameters.false_positive_probability = 0.01; // 期望的误判率为0.1
	parameters.random_seed=0xA5A5A5A5;
    parameters.compute_optimal_parameters(); // 计算最优参数
	for(int i=0;i<4;i++)filters[i]=bloom_filter(parameters);
	// uint32_t key_index=0;
	// while(full_index.size()<initialize_size)
	// {	
	// 	//random_128(temp_key);
	// 	temp_information.fullkey[0]=sign_data[key_index].first;//temp_key[0];
	// 	temp_information.fullkey[1]=sign_data[key_index].second;//temp_key[1];
	// 	// temp_information.identifier=targets_data[out_id];
	// 	temp_key[0]=temp_information.fullkey[0];temp_key[1]=temp_information.fullkey[1];
	// 	get_sub_fingerprint(sub,temp_key);
	// 	out_id=random_uuid();

	// 	filters[0].insert(sub[0]);
	// 	filters[1].insert(sub[1]);
	// 	filters[2].insert(sub[2]);
	// 	filters[3].insert(sub[3]);
	// 	sub_index1[sub[0]].push_back(out_id);
	// 	sub_index2[sub[1]].push_back(out_id);
	// 	sub_index3[sub[2]].push_back(out_id);
	// 	sub_index4[sub[3]].push_back(out_id);
	// 	full_index[out_id]=(temp_information);
	// 	++key_index;
	// }
	// printf("size:%d，%d，%d，%d\n",sub_index1.size(),sub_index2.size(),sub_index3.size(),sub_index4.size());
	return;
}
void containers::get_test_pool()
{
	// uint64_t temp_key[2]={0};
	// for(auto it : full_index)
	// {
	// 	if(test_pool.size()>=test_size)
	// 	{
	// 		return;
	// 	}
	// 	temp_key[0]=it.fullkey[0];
	// 	temp_key[1]=it.fullkey[1];
	// 	int h=0,y=0;
	// 	uint64_t t=1;
	// 	unsigned char rand[3]={0};
	// 	sgx_read_rand(rand,2);
	// 	h=rand[0]%3;
	// 	for(int i=0;i<h;i++)
	// 	{
	//   		y=rand[i+1]%64;
	// 		temp_key[0]=temp_key[0]^(t<<y);
	// 		temp_key[1]=temp_key[1]^(t<<y);
	// 	}
	// 	test_pool.insert(pair<uint64_t,uint64_t>(temp_key[0],temp_key[1]));
	// }

	uint64_t temp_key[2]={0};
	uint32_t begin=0,index=0;//begin:the first index of test
	uint32_t skip=1;//skip query
	uint32_t range=initialize_size;//range query
	uint32_t space_local=20;
   	// sgx_read_rand(reinterpret_cast<unsigned char*>(&begin), sizeof(begin));

	//for temporal Locality
	vector<uint32_t> local_list;
	uint32_t temp;
	for(int i=0;i<100;i++){
   	sgx_read_rand(reinterpret_cast<unsigned char*>(&temp), sizeof(temp));
	local_list.push_back(temp%initialize_size);}
	printf("initialize_size:%d\n",initialize_size);
	for(int i=0;i<initialize_size;i++)
	{	
		if(test_pool.size()>=test_size)
		{
			return;
		}
		index=(begin+(i*skip)%range);
		// if(i%100==0) {i=0;sgx_read_rand(reinterpret_cast<unsigned char*>(&begin), sizeof(begin));}//space locality
		sgx_read_rand(reinterpret_cast<unsigned char*>(&index), sizeof(index));//rand query
		// index=local_list[index%local_list.size()];//temporal locality
		index=index%initialize_size;
		auto it=full_index[index];
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
std::unordered_set<uint32_t> containers::find_sim(uint64_t query[])
{
	candidate.clear();
	uint64_t tmpquery[2]={0};
	tmpquery[0]=query[0];
	tmpquery[1]=query[1];
	uint32_t sub[4]={0};
	get_sub_fingerprint(sub,tmpquery);

	static uint64_t bloomHit=0;static uint64_t bloomMiss=0;
	static uint64_t valid_query=0;static uint64_t invalid_query=0;
	uint32_t tmpsub1,tmpsub2,tmpsub3,tmpsub4=0;
	vector<uint32_t> temp;
	static int loopBegin=0;static int times=0;static int line_times=0;
	uint64_t infoFullkey[2] ;uint32_t subInfo[4];
	//tsl::hopscotch_map<uint32_t, std::vector<uint32_t>>::iterator got;
	unordered_map<uint32_t, std::vector<uint32_t>>::iterator got;
	for(auto& its:this->C_0_TO_subhammdis[0])
	{
		tmpsub1=sub[0]^its;
		tmpsub2=sub[1]^its;
		tmpsub3=sub[2]^its;
		tmpsub4=sub[3]^its;
	//	LOGGER("SUB FP INFO: %u %u %u %u",tmpsub1,tmpsub2,tmpsub3,tmpsub4);
	//	LOGGER("SUB INDEX SIZE: %zu %zu %zu %zu",sub_index1.size(),sub_index2.size(),sub_index3.size(),sub_index4.size());
		//printf("num%d\n",candidate.size());
		// if(filters[0].contains(tmpsub1)){
		auto it = comp_sub_index1.find(tmpsub1);//times++;bloomHit++;
		if(it!=comp_sub_index1.end())		//如果是compress后的，用comp_sub_index1 + for_uncompress；不然用sub_index1 + for(auto& got:temp){
		{//valid_query++;
			// temp=it->second;
			// for(auto& got:temp){
			// candidate.insert(got);
			// }
			for_uncompress(it->second.first,out,it->second.second);
			for(int i=0;i<it->second.second;i++)
			{
				candidate.insert(out[i]);
			}
			}//else invalid_query++;
		// }//else bloomMiss++;
		
		// tmpsub2=sub[1]^its;
		// if(filters[1].contains(tmpsub2)){
		// auto it = sub_index2.find(tmpsub2);//times++;bloomHit++;
		// if(it!=sub_index2.end())
		// {	//valid_query++;
		// 	temp=it->second;
		// 	for(auto& got:temp){
		// 	candidate.insert(got); 
		// 	}
		// }//else invalid_query++;
		// }//else bloomMiss++;
		
		// tmpsub3=sub[2]^its;
		// if(filters[2].contains(tmpsub3)){
		// auto it = sub_index3.find(tmpsub3);//times++;bloomHit++;
		// if(it!=sub_index3.end())
		// {	//valid_query++;
		// 	temp=it->second;
		// 	for(auto& got:temp){
		// 	candidate.insert(got);
		// 	}
		// }//else invalid_query++;
		// }//else bloomMiss++;
		// tmpsub4=sub[3]^its;
		// if(filters[3].contains(tmpsub4)){
		// auto it = sub_index4.find(tmpsub4);//times++;bloomHit++;
		// if(it!=sub_index4.end())
		// {	//valid_query++;
		// 	temp=it->second;times++;
		// 	for(auto& got:temp){
		// 	candidate.insert(got); 
		// 	}
		// }//else invalid_query++;
		// }//else bloomMiss++;
	}
	for(auto& its:this->C_0_TO_subhammdis[1])
	{
		tmpsub2=sub[1]^its;
		// if(filters[1].contains(tmpsub2)){
		auto it = comp_sub_index2.find(tmpsub2);//times++;bloomHit++;
		if(it!=comp_sub_index2.end())
		{	//valid_query++;
			// temp=it->second;
			// for(auto& got:temp){
			// candidate.insert(got); 
			// }
			for_uncompress(it->second.first,out,it->second.second);
			for(int i=0;i<it->second.second;i++)
			{
				candidate.insert(out[i]);
			}
		}//else invalid_query++;
		// }//else bloomMiss++;
	}
	for(auto& its:this->C_0_TO_subhammdis[1])
	{
		tmpsub3=sub[2]^its;
		// if(filters[2].contains(tmpsub3)){
		auto it = comp_sub_index3.find(tmpsub3);//times++;bloomHit++;
		if(it!=comp_sub_index3.end())
		{	//valid_query++;
			// temp=it->second;
			// for(auto& got:temp){
			// candidate.insert(got);
			// }
			for_uncompress(it->second.first,out,it->second.second);
			for(int i=0;i<it->second.second;i++)
			{
				candidate.insert(out[i]);
			}
		}//else invalid_query++;
		// }//else bloomMiss++;
	}
	for(auto& its:this->C_0_TO_subhammdis[1])
	{
		tmpsub4=sub[3]^its;
		// if(filters[3].contains(tmpsub4)){
		auto it = comp_sub_index4.find(tmpsub4);//times++;bloomHit++;
		if(it!=comp_sub_index4.end())
		{	//valid_query++;
			// temp=it->second;//times++;
			// for(auto& got:temp){
			// candidate.insert(got); 
			// }
			for_uncompress(it->second.first,out,it->second.second);
			for(int i=0;i<it->second.second;i++)
			{
				candidate.insert(out[i]);
			}
		}//else invalid_query++;
		// }//else bloomMiss++;
	}
	uint64_t cmp_hamm[2]={0};
	uint64_t count=0;
	//printf("times1:%d times2 %d\n",line_times,times);
	// printf("bloomHit:%lu bloomMiss:%lu\n",bloomHit,bloomMiss);
	// printf("valid_query:%lu invalid_query:%lu,sum%lu\n",valid_query,invalid_query,valid_query+invalid_query);

	information got_out;
	//tsl::hopscotch_map<uint32_t,information>::const_iterator got_out;
	for(auto it = candidate.begin(); it != candidate.end();)
	{
		got_out=full_index[*it];
		if(1)
		{
			cmp_hamm[0]=query[0]^(got_out.fullkey[0]);
			cmp_hamm[1]=query[1]^(got_out.fullkey[1]);
			count=bitset<64>(cmp_hamm[0]).count()+bitset<64>(cmp_hamm[1]).count();
			// count=0;
			// while(cmp_hamm[0])
			// {
			// 	count+=cmp_hamm[0]&1ul;
			// 	cmp_hamm[0]=cmp_hamm[0]>>1;
			// }
			// while(cmp_hamm[1])
			// {
			// 	count+=cmp_hamm[1]&1ul;
			// 	cmp_hamm[1]=cmp_hamm[1]>>1;
			// }
			if(count<=hammdist){
				it++;successful_num++;
			}
			else {it=candidate.erase(it);}
		}
	}
	return candidate;
}
void containers::test()
{
	uint64_t temp_key[2]={0};
	for(auto &itx : test_pool)
	{
		temp_key[0]=itx.first;
		temp_key[1]=itx.second;
		find_sim(temp_key);
	}
}
void containers::changeHammingDist(uint64_t hammdist)
{
	// if(hammdist==this->hammdist)return;
	// this->hammdist=hammdist;
	// this->sub_hammdist=hammdist/4;
	// this->C_0_TO_subhammdis.clear();
	// this->prepare();
}
void get_rand_dim(){
	uint32_t temp;
   	sgx_read_rand(reinterpret_cast<unsigned char*>(&temp), sizeof(temp));
	for(int i=128;i>0;i--)
	{
   		sgx_read_rand(reinterpret_cast<unsigned char*>(&temp), sizeof(temp));
		temp%=i;
		int tmp=cont.dimension[i-1];
		cont.dimension[i-1]=cont.dimension[temp];
		cont.dimension[temp]=tmp;
	}
	for(int i=0;i<128;i++)printf("%d ",cont.dimension[i]);
}
void init()
{
	// uint32_t tmp[128]={0,38,111,56,45,35,121,74,67,79,120,124,23,103,80,118,36,98,44,76,19,24,87,75,77,125,18,54,29,3,114,53,32,52,71,113,83,91,16,31,107,37,46,119,88,26,90,104,25,126,64,95,66,65,116,89,12,6,47,49,61,14,11,82,50,96,4,28,100,17,20,117,15,55,21,30,8,78,58,27,22,106,70,86,101,10,85,109,110,13,63,33,112,7,59,84,39,97,69,99,68,51,102,73,93,105,81,40,108,60,41,2,92,5,42,115,9,34,72,43,1,57,122,123,62,48,94,127};
	uint32_t tmp[128]={0,40,2,46,94,36,108,57,26,49,116,20,66,61,99,12,54,101,42,11,122,119,86,78,19,102,113,118,106,6,88,50,32,103,31,22,84,60,107,127,97,95,126,91,52,76,109,62,93,121,117,59,48,92,68,104,34,85,30,33,25,1,73,98,64,125,58,71,110,43,115,124,7,100,65,96,15,21,72,63,111,10,80,24,17,44,8,69,83,9,112,53,123,3,37,90,75,13,79,14,47,5,4,51,55,105,28,38,29,23,16,82,41,35,114,70,81,56,27,77,120,89,45,87,67,74,18,39};
	printf("%d\n",tmp[127]);
	for(int i=0;i<128;i++)cont.dimension[i]=tmp[i];
	// get_rand_dim();
	printf("run code!\n");
	cont.prepare(cont.sub_hammdist,0);
	cont.prepare(cont.sub_hammdist-1,1);
	printf("c_o size: %d\n",cont.C_0_TO_subhammdis[0].size());
	printf("Init!\n");
	cont.initialize();
	// cont.get_test_pool();
	// printf("The full index entry is: %d \n",cont.full_index.size());
	// printf("The number of queries is: %d \n",cont.test_pool.size());
}
void test_run()
{
	cont.test();
	printf("Successfully found similar photos! successful_num=%d.\n",cont.successful_num);
}
void compress_sub_index()
{
	vector<uint32_t> v;
 	uint32_t length = 3000,comp_len;
  	uint8_t* comp_data;
	uint32_t sub[4]={0};
	uint64_t temp_key[2]={0};
	uint32_t origin_len=0,compress_len=0;
	for(auto& val:cont.sub_index1){
		length=val.second.size();if(length>10)origin_len+=length*4;
		comp_len = for_compressed_size_sorted(val.second.data(), length);
		comp_data=(uint8_t*)malloc(comp_len);
		// printf("length:%d comp_len:%d\n",length,comp_len);
		for_compress_sorted(val.second.data(), comp_data, length);
		val.second.clear();vector<uint32_t> empty_v=vector<uint32_t>();;val.second.swap(empty_v);
		cont.comp_sub_index1[val.first] = std::make_pair(comp_data,length);
		if(length>10)compress_len+=comp_len;
	}
	printf("origin_len:%d compress_len:%d\n",origin_len,compress_len);
	cont.sub_index1.clear();
	unordered_map<uint32_t,vector<uint32_t>>().swap(cont.sub_index1);

	for(auto& val:cont.sub_index2){
		length=val.second.size();
		comp_len = for_compressed_size_sorted(val.second.data(), length);
		comp_data=(uint8_t*)malloc(comp_len);
		for_compress_sorted(val.second.data(), comp_data, length);
		val.second.clear();vector<uint32_t> empty_v=vector<uint32_t>();;val.second.swap(empty_v);
		cont.comp_sub_index2[val.first] = std::make_pair(comp_data,length);
	}
	cont.sub_index2.clear();
	unordered_map<uint32_t,vector<uint32_t>>().swap(cont.sub_index2);

	for(auto& val:cont.sub_index3){
		length=val.second.size();
		comp_len = for_compressed_size_sorted(val.second.data(), length);
		comp_data=(uint8_t*)malloc(comp_len);
		for_compress_sorted(val.second.data(), comp_data, length);
		val.second.clear();vector<uint32_t> empty_v=vector<uint32_t>();;val.second.swap(empty_v);
		cont.comp_sub_index3[val.first] = std::make_pair(comp_data,length);
	}
	cont.sub_index3.clear();
	unordered_map<uint32_t,vector<uint32_t>>().swap(cont.sub_index3);

	for(auto& val:cont.sub_index4){
		length=val.second.size();
		comp_len = for_compressed_size_sorted(val.second.data(), length);
		comp_data=(uint8_t*)malloc(comp_len);
		for_compress_sorted(val.second.data(), comp_data, length);
		val.second.clear();vector<uint32_t> empty_v=vector<uint32_t>();;val.second.swap(empty_v);
		cont.comp_sub_index4[val.first] = std::make_pair(comp_data,length);
	}
	cont.sub_index4.clear();
	unordered_map<uint32_t,vector<uint32_t>>().swap(cont.sub_index4);
}
void init_test_pool(){
	// parting.set_skewed_partition(cont.full_index);
	// vector<uint32_t> tmp;
	// parting.make_partition(tmp);		//make partition
	// write_dimension(tmp.data());
	compress_sub_index();		//compress sub_index to comp_sub_index
	cont.get_test_pool();
	printf("sub_index1 size: %d,sub_index2 size: %d,sub_index3 size: %d,sub_index4 size: %d\n",cont.sub_index1.size(),cont.sub_index2.size(),cont.sub_index3.size(),cont.sub_index4.size());	
	printf("The full index entry is: %d \n",cont.full_index.size());
	printf("The number of queries is: %d \n",cont.test_pool.size());
}
uint32_t get_dimension(pair<uint64_t,uint64_t> info,uint32_t dim){
    uint64_t key=info.first;
    if(dim>63){key=info.second;dim-=63;}
    uint64_t mask=1ULL<<(63-dim);
    return (key&mask)>>(63-dim);
}
void get_dim(pair<uint64_t,uint64_t> &pairs){
	int left=0;
	uint64_t tmp=0;
	std::pair<uint64_t,uint64_t> pair2=pairs;
	for(int i=0;i<64;i++){
		tmp=(tmp<<1)+get_dimension(pair2,cont.dimension[i]);
		left+=1;
	}
	pairs.first=tmp;
	tmp=0;
	left=0;
	for(int i=64;i<128;i++){
		tmp=(tmp<<1)+get_dimension(pair2,cont.dimension[i]);
		left+=1;
	}
	pairs.second=tmp;
}
void encall_send_data(void *dataptr,size_t len)
{
	// sign_data.clear();
	// sign_data.reserve(sendKey_batch_size);
	std::pair<uint64_t, uint64_t>* data =  reinterpret_cast<std::pair<uint64_t, uint64_t>*>(dataptr);
	// sign_data.insert(sign_data.end(),data,data+len);

	cont.initialize_size+=len;
	uint64_t temp_key[2]={0};
	static uint32_t out_id=0;
	uint32_t sub[4]={0};
	information temp_information;
	uint32_t key_index=0;
	std::pair<uint64_t, uint64_t> tmp;
	for(int i=0;i<len;i++)//auto& tmp:sign_data
	{	tmp=data[i];
		get_dim(tmp);
		temp_information.fullkey[0]=tmp.first;//temp_key[0];
		temp_information.fullkey[1]=tmp.second;//temp_key[1];
		// temp_information.identifier=targets_data[out_id];
		temp_key[0]=temp_information.fullkey[0];temp_key[1]=temp_information.fullkey[1];
		cont.get_sub_fingerprint(sub,temp_key);
		// out_id=cont.random_uuid();

		cont.filters[0].insert(sub[0]);
		cont.filters[1].insert(sub[1]);
		cont.filters[2].insert(sub[2]);
		cont.filters[3].insert(sub[3]);
		cont.sub_index1[sub[0]].push_back(out_id);
		cont.sub_index2[sub[1]].push_back(out_id);
		cont.sub_index3[sub[2]].push_back(out_id);
		cont.sub_index4[sub[3]].push_back(out_id);
		cont.full_index[out_id]=(temp_information);
		++key_index;++out_id;
	}
}
void encall_send_targets(void *dataptr,size_t len)
{
	targets_data.clear();
	targets_data.reserve(sendKey_batch_size);
	uint32_t* data =  reinterpret_cast<uint32_t*>(dataptr);
	targets_data.insert(targets_data.end(),data,data+len);
	//printf("%d",sign_data.size());
}

void encall_find_one(void *dataptr,uint32_t* res,uint64_t hammdist)
{
	cont.changeHammingDist(hammdist);

    EcallCrypto* cryptoObj = new EcallCrypto(CIPHER_TYPE, HASH_TYPE);
    EVP_MD_CTX* mdCtx = EVP_MD_CTX_new(); 
    EVP_CIPHER_CTX* cipherCtx_ = EVP_CIPHER_CTX_new();
    uint8_t* sessionKey_=const_sessionKey;
	
	uint8_t* dataE =reinterpret_cast<uint8_t*>(dataptr);
	int dataSize = 16;
    cryptoObj->SessionKeyDec(cipherCtx_, dataE,
    dataSize, sessionKey_,
    dataE);
	printf("nums%d\n",(uint64_t*)dataE[0]);
	uint64_t* data =  reinterpret_cast<uint64_t*>(dataE);
	unordered_set<uint32_t> res_set=cont.find_sim(data);
	uint8_t* res_old=reinterpret_cast<uint8_t*>(res);
	for(auto &it:res_set)
	{
		*res=it;
		res++;
	}
	// *len=res_set.size();
	cryptoObj->SessionKeyEnc(cipherCtx_,(uint8_t*)res_old,3000*4,sessionKey_,(uint8_t*)res_old);
	//cryptoObj->SessionKeyEnc();
	//printf("Successfully found  photos! successful_num=%d.\n",res_set.size());
	//printf("%d",sign_data.size());
}

void encall_find_batch(void *dataptr,uint32_t* res,uint32_t len,uint32_t len_res,uint64_t hammdist){
	cont.changeHammingDist(hammdist);

	EcallCrypto* cryptoObj = new EcallCrypto(CIPHER_TYPE, HASH_TYPE);
    EVP_MD_CTX* mdCtx = EVP_MD_CTX_new(); 
    EVP_CIPHER_CTX* cipherCtx_ = EVP_CIPHER_CTX_new();
    uint8_t* sessionKey_=const_sessionKey;
	uint8_t* dataE =reinterpret_cast<uint8_t*>(dataptr);
	int dataSize = sizeof(uint64_t)*len*2;
    cryptoObj->SessionKeyDec(cipherCtx_, dataE,
    dataSize, sessionKey_,
    dataE);
	uint8_t* res_old=reinterpret_cast<uint8_t*>(res);//res=query times + success num of query i + targets of query i
	Query_batch_t query;
	query.sendData=res;
	*(query.sendData)=len;		//write query times to res
	query.index=query.sendData+sizeof(uint32_t);
	query.dataBuffer=query.sendData+sizeof(uint32_t)*(len+1);
	uint64_t* data =  reinterpret_cast<uint64_t*>(dataE);
	uint64_t temp2[2];
	printf("query len=%d\n",len);
	for(int i=0;i<len;i++){
		temp2[0]=data[2*i];temp2[1]=data[2*i+1];
		unordered_set<uint32_t> res_set=cont.find_sim(temp2);
		query.index[i]=res_set.size();		//write success num of query i to res
		//printf("res_set.size()=%d\n",res_set.size());
		for(auto &it:res_set)
		{
			*(query.dataBuffer)=it;
			query.dataBuffer++;		//write targets of query i to res
		}
	}

	printf("successful_num=%d\n",cont.successful_num);
	//*len=res_set.size();
	cryptoObj->SessionKeyEnc(cipherCtx_,(uint8_t*)res_old,QUERY_SIZE*sizeof(uint32_t)*len,sessionKey_,(uint8_t*)res_old);
	//printf("Successfully found  photos! successful_num=%d.\n",res_set.size());
	printf("sign_data_size %d\n",sign_data.size());
}