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
uint32_t containers::initialize_size=450000;

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
}

containers::containers()
{
	sub_keybit=(int)keybit/sub_index_num;
	sub_hammdist=hammdist/sub_index_num;
}

bool customCompare(const sub_information& p1, const sub_information& p2) {
    if (p1.sub_key < p2.sub_key) {
        return true;
    } else if (p1.sub_key == p2.sub_key) {
        return p1.identifiers < p2.identifiers;
    }
    return false;
}
bool compareFirst(const sub_information& p, uint32_t x) {
    return p.sub_key < x;
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
	containers::initialize_size=sign_data.size();

	full_index.reserve(initialize_size);
	sub_index_liner=new sub_information*[4];
	for(int i=0;i<4;i++)sub_index_liner[i]=new sub_information[initialize_size];

	sub_information sub_info[4];
	bloom_parameters parameters;
    parameters.projected_element_count = initialize_size; // 预计插入initialize_size个元素
    parameters.false_positive_probability = 0.01; // 期望的误判率为0.1
    parameters.compute_optimal_parameters(); // 计算最优参数
	parameters.random_seed=0xA5A5A5A5;
	for(int i=0;i<4;i++)filters[i]=bloom_filter(parameters);
	printf("1\n");
	uint32_t sub_map_size= initialize_size;
	while(full_index.size()<initialize_size)
	{	
		//random_128(temp_key);
		temp_information.fullkey[0]=sign_data[out_id].first;//temp_key[0];
		temp_information.fullkey[1]=sign_data[out_id].second;//temp_key[1];
		temp_information.identifier=out_id;
		temp_key[0]=temp_information.fullkey[0];temp_key[1]=temp_information.fullkey[1];
		get_sub_fingerprint(sub,temp_key);
		//out_id=random_uuid();

		filters[0].insert(sub[0]);
		filters[1].insert(sub[1]);
		filters[2].insert(sub[2]);
		filters[3].insert(sub[3]);
		for(int i=0;i<4;i++)
		{
			sub_info[i].sub_key=sub[i];
			sub_info[i].identifiers=out_id;
			sub_index_liner[i][out_id]=sub_info[i];
		}

		// sub_index1[sub[0]].push_back(out_id);
		// sub_index2[sub[1]].push_back(out_id);
		// sub_index3[sub[2]].push_back(out_id);
		// sub_index4[sub[3]].push_back(out_id);
		full_index.push_back(temp_information);
		++out_id;
	}
	//printf("size:%d，%d，%d，%d\n",sub_index1.size(),sub_index2.size(),sub_index3.size(),sub_index4.size());
	printf("2\n");
	for(int i=0;i<4;i++){
		std::sort(sub_index_liner[i],sub_index_liner[i]+initialize_size,customCompare);
	}
	int j[4]={0};
	for(int i=0;i<sub_map_size;i++)
	{
		if(j[0]>initialize_size)break;
		if(j[1]>initialize_size)break;
		if(j[2]>initialize_size)break;
		if(j[3]>initialize_size)break;
		for(int k=0;k<4;k++){
		uint32_t temp=sub_index_liner[k][j[k]].sub_key;
		auto low=&sub_index_liner[k][j[k]];
		auto its=low;
		for(;its->sub_key==temp&&its<sub_index_liner[k]+initialize_size;its++,j[k]++);
		sub_index[k][temp]=j[k];
		}
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
	// for(int i=0,k=initialize_size/test_size/2;i<initialize_size;i+=k)
	// {
	// 	if(test_pool.size()>=test_size)
	// 	{
	// 		return;
	// 	}
	// 	auto it=full_index[i];
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
}
std::unordered_set<uint32_t> containers::find_sim(uint64_t query[])
{
	candidate.clear();
	uint64_t tmpquery[2]={0};
	tmpquery[0]=query[0];
	tmpquery[1]=query[1];
	uint32_t sub[4]={0};
	get_sub_fingerprint(sub,tmpquery);

	static uint64_t bloomHit=0;static uint64_t bolomMiss=0;
	uint32_t tmpsub1,tmpsub2,tmpsub3,tmpsub4=0;
	vector<uint32_t> temp;
	static int loopBegin=0;static int times=0;static int line_times=0;
	uint64_t infoFullkey[2] ;uint32_t subInfo[4];
	//tsl::hopscotch_map<uint32_t, std::vector<uint32_t>>::iterator got;
	unordered_map<uint32_t, std::vector<uint32_t>>::iterator got;
	vector<uint32_t> map2liner;
	vector<uint32_t> miss_sub;
	for(int i=0;i<4;i++){
	for(auto& its:this->C_0_TO_subhammdis)
	{
		tmpsub1=sub[i]^its;
	//	LOGGER("SUB FP INFO: %u %u %u %u",tmpsub1,tmpsub2,tmpsub3,tmpsub4);
	//	LOGGER("SUB INDEX SIZE: %zu %zu %zu %zu",sub_index1.size(),sub_index2.size(),sub_index3.size(),sub_index4.size());
		//printf("num%d\n",candidate.size());
		if(filters[i].contains(tmpsub1)){
		auto it = sub_index[i].find(tmpsub1);times++;bloomHit++;
		if(it!=sub_index[i].end())
		{
			// temp=it->second;
			// for(auto& got:temp){
			// candidate.insert(got);
			// }
			map2liner.push_back(it->second);
		}else {
			miss_sub.push_back(tmpsub1);
			bolomMiss++;}
		}
		
		// tmpsub2=sub[1]^its;
		// if(filters[1].contains(tmpsub2)){
		// auto it = sub_index2.find(tmpsub2);times++;bloomHit++;
		// if(it!=sub_index2.end())
		// {	
		// 	temp=it->second;
		// 	for(auto& got:temp){
		// 	candidate.insert(got); 
		// 	}
		// }
		// }else bolomMiss++;
		
		// tmpsub3=sub[2]^its;
		// if(filters[2].contains(tmpsub3)){
		// auto it = sub_index3.find(tmpsub3);times++;bloomHit++;
		// if(it!=sub_index3.end())
		// {	
		// 	temp=it->second;
		// 	for(auto& got:temp){
		// 	candidate.insert(got);
		// 	}
		// }
		// }else bolomMiss++;
		// tmpsub4=sub[3]^its;
		// if(filters[3].contains(tmpsub4)){
		// auto it = sub_index4.find(tmpsub4);times++;bloomHit++;
		// if(it!=sub_index4.end())
		// {	
		// 	temp=it->second;times++;
		// 	for(auto& got:temp){
		// 	candidate.insert(got); 
		// 	}
		// }
		// }else bolomMiss++;
	}
	for(auto temp:miss_sub){
		auto its = std::lower_bound(sub_index_liner[i], sub_index_liner[i]+initialize_size, temp,compareFirst);
		for(;its->sub_key==temp&&its<sub_index_liner[i]+initialize_size;++its){
		candidate.insert(its->identifiers);}
	}
	miss_sub.clear();
	for(auto temp:map2liner){
		auto x=temp-1;
		for(;x>=0&&sub_index_liner[i][x].sub_key==sub_index_liner[i][temp-1].sub_key;--x){
		candidate.insert(sub_index_liner[i][x].identifiers);}
	}
	map2liner.clear();
	}
	// for(auto& its:this->C_0_TO_subhammdis)
	// {
	// 	tmpsub2=sub[1]^its;
	// 	if(filters[1].contains(tmpsub2)){
	// 	auto it = sub_index2.find(tmpsub2);times++;bloomHit++;
	// 	if(it!=sub_index2.end())
	// 	{	
	// 		map2liner.push_back(it->second);
	// 	}
	// 	}else {
	// 		miss_sub.push_back(tmpsub2);
	// 		bolomMiss++;}
	// }
	// for(auto temp:miss_sub){hit++;
	// 	auto its = std::lower_bound(sub_index_liner[0], sub_index_liner[0]+initialize_size, temp,compareFirst);
	// 	for(;its->sub_key==temp&&its<sub_index_liner[0]+initialize_size;++its){
	// 	candidate.insert(its->identifiers);}
	// }
	// miss_sub.clear();
	// for(auto temp:map2liner){
	// 	auto x=temp-1;
	// 	for(;x>=0&&sub_index_liner[0][x].sub_key==sub_index_liner[0][temp-1].sub_key;--x){
	// 	candidate.insert(sub_index_liner[0][x].identifiers);}
	// 	}
	// }
	// map2liner.clear();
	// for(auto& its:this->C_0_TO_subhammdis)
	// {
	// 	tmpsub3=sub[2]^its;
	// 	if(filters[2].contains(tmpsub3)){
	// 	auto it = sub_index3.find(tmpsub3);times++;bloomHit++;
	// 	if(it!=sub_index3.end())
	// 	{	
	// 		temp=it->second;
	// 		for(auto& got:temp){
	// 		candidate.insert(got);
	// 		}
	// 	}
	// 	}else bolomMiss++;
	// }
	// for(auto& its:this->C_0_TO_subhammdis)
	// {
	// 	tmpsub4=sub[3]^its;
	// 	if(filters[3].contains(tmpsub4)){
	// 	auto it = sub_index4.find(tmpsub4);times++;bloomHit++;
	// 	if(it!=sub_index4.end())
	// 	{	
	// 		temp=it->second;times++;
	// 		for(auto& got:temp){
	// 		candidate.insert(got); 
	// 		}
	// 	}
	// 	}else bolomMiss++;
	// }
	uint64_t cmp_hamm[2]={0};
	uint64_t count=0;
	//printf("times1:%d times2 %d\n",line_times,times);
	//printf("bloomHit:%lu bloomMiss:%lu\n",bloomHit,bolomMiss);

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
				successful_num++;
				it++;}
			else 
				it=candidate.erase(it);
		}
	}
	return candidate;
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
void containers::changeHammingDist(uint64_t hammdist)
{
	if(hammdist==this->hammdist)return;
	this->hammdist=hammdist;
	this->sub_hammdist=hammdist/4;
	this->C_0_TO_subhammdis.clear();
	this->prepare();
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

void encall_send_data(void *dataptr,size_t len)
{
	std::pair<uint64_t, uint64_t>* data =  reinterpret_cast<std::pair<uint64_t, uint64_t>*>(dataptr);
	sign_data.insert(sign_data.end(),data,data+len);
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
	//*len=res_set.size();
	cryptoObj->SessionKeyEnc(cipherCtx_,(uint8_t*)res_old,3000*4,sessionKey_,(uint8_t*)res_old);
	//cryptoObj->SessionKeyEnc();
	printf("Successfully found  photos! successful_num=%d.\n",res_set.size());
	//printf("%d",sign_data.size());
}

void encall_find_batch(void *dataptr,uint32_t* res,uint32_t len,uint32_t len_res,uint64_t hammdist){
	cont.changeHammingDist(hammdist);

	EcallCrypto* cryptoObj = new EcallCrypto(CIPHER_TYPE, HASH_TYPE);
    EVP_MD_CTX* mdCtx = EVP_MD_CTX_new(); 
    EVP_CIPHER_CTX* cipherCtx_ = EVP_CIPHER_CTX_new();
    uint8_t* sessionKey_=const_sessionKey;
	uint8_t* dataE =reinterpret_cast<uint8_t*>(dataptr);
	printf("saonaiso%llu\n",(uint64_t*)dataE[199]);
	int dataSize = sizeof(uint64_t)*len*2;
    cryptoObj->SessionKeyDec(cipherCtx_, dataE,
    dataSize, sessionKey_,
    dataE);
	uint8_t* res_old=reinterpret_cast<uint8_t*>(res);
	Query_batch_t query;
	query.sendData=res;
	*(query.sendData)=len;
	query.index=query.sendData+sizeof(uint32_t);
	query.dataBuffer=query.sendData+sizeof(uint32_t)*(len+1);
	uint64_t* data =  reinterpret_cast<uint64_t*>(dataE);
	uint64_t temp2[2];
	printf("query len=%d\n",len);
	for(int i=0;i<len;i++){
		temp2[0]=data[2*i];temp2[1]=data[2*i+1];
		unordered_set<uint32_t> res_set=cont.find_sim(temp2);
		query.index[i]=res_set.size();
		//printf("res_set.size()=%d\n",res_set.size());
		for(auto &it:res_set)
		{
			*(query.dataBuffer)=it;
			query.dataBuffer++;
		}
	}

	printf("successful_num=%d\n",cont.successful_num);
	//*len=res_set.size();
	cryptoObj->SessionKeyEnc(cipherCtx_,(uint8_t*)res_old,QUERY_SIZE*sizeof(uint32_t)*len,sessionKey_,(uint8_t*)res_old);
	//printf("Successfully found  photos! successful_num=%d.\n",res_set.size());
	printf("%d",sign_data.size());
}