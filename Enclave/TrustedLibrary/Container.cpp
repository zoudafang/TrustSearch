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
uint32_t containers::sub_map_size=4500;

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
	static long long total_time=0;
	static long long find_time=0;
	static long long insert_time=0;
	static long long verify_time=0;
}

containers::containers()
{
	sub_keybit=(int)keybit/sub_index_num;
	// sub_hammdist=hammdist/sub_index_num;
	for(int j=hammdist-sub_index_num+1;j>0;){//the sum of sub_hammdist is hammdist - sub_index_num + 1
		for(int i=0;i<sub_index_num;i++)
		{
			if(j<=0)break;
			sub_hammdist[i]++;		//if hammdist=8,sub_hammdist={1,1,1,2}
			j--;
		}
	}
	// int temp[]={2,2,2,2};
	for(int i=0;i<sub_index_num;i++)
	{
		// sub_hammdist[i]=temp[i];
		printf("sub_hammdist[%d]=%d\n",i,sub_hammdist[i]);
	}
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
void containers::prepare(uint32_t sub_hammdist,vector<uint32_t>&C_0_TO_subhammdis)
{
	LOGGER("Prepare");
	int tmp1,tmp2,tmp3,tmp4=1;
	int tmp=0;
	uint32_t tmpx=0;
	this->C_0_TO_subhammdis[1].push_back(0);
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
	containers::initialize_size = DATA_LEN;
	
	full_index.reserve(initialize_size+1000);
	sub_index_liner=new vector<sub_information>[4];
	// for(int i=0;i<4;i++)sub_index_liner[i]=new sub_information[initialize_size];
	for(int i=0;i<4;i++)sub_index_liner[i].reserve(initialize_size);

	containers::sub_map_size = initialize_size/2000;//initialize_size//1500,2500,1000
	for(int i=0;i<4;i++){
	lru_n[i]=lru_node{sub_map_size,0,nullptr,nullptr};
	sub_index_node* head1=new sub_index_node;
	lru_n[i].index_head=head1;
	lru_n[i].index_tail=head1;
	sub_index_node node_temp{0,vector<uint32_t>(),nullptr,nullptr};
	new_data_head[i] = new sub_index_node{0,vector<uint32_t>(),nullptr,nullptr};
	}

	sub_information sub_info[4];
	bloom_parameters parameters;
    parameters.projected_element_count = initialize_size; // 预计插入initialize_size个元素
    parameters.false_positive_probability = 0.01; // 期望的误判率为0.1
    parameters.compute_optimal_parameters(); // 计算最优参数
	parameters.random_seed=0xA5A5A5A5;
	for(int i=0;i<4;i++)filters[i]=bloom_filter(parameters);
	return;
}
void containers::init_after_recv_data(){
	for(int i=0;i<4;i++){
		std::sort(sub_index_liner[i].begin(),sub_index_liner[i].end(),customCompare);
	}
	int j[4]={0};
	//for(int i=0;i<4;i++)j[i]=sub_index_liner[i][0];
	printf("subsize:%d\n",sub_map_size);
	sub_nodes=new sub_index_node*[4];
	for(int i=0;i<4;i++){sub_nodes[i]=new sub_index_node[sub_map_size];}
	for(int k=0;k<4;k++){
		for(int i=0;sub_index[k].size()<sub_map_size&&i<sub_map_size*2;i++)//sub_index[k].size()
		{
   		sgx_read_rand(reinterpret_cast<unsigned char*>(&j[k]), sizeof(int));
		j[k]=j[k]%initialize_size;
		uint32_t temp=sub_index_liner[k][j[k]].sub_key;
		for(;j[k]>0&&temp==sub_index_liner[k][j[k]-1].sub_key;j[k]--);
		auto its=sub_index_liner[k].begin()+j[k];
		if(sub_index[k].find(temp)==sub_index[k].end())lru_index_add(k,its,sub_index_liner[k]);//int temps=j[k];
		// for(;its->sub_key==temp&&its<sub_index_liner[k].end;its++,j[k]++);
		}
	}
	//printf sub_index size
	for(int i=0;i<4;i++){
		printf("sub_index%d size:%d\n",i,sub_index[i].size());
	}
}
void containers::get_test_pool()
{
	uint64_t temp_key[2]={0};
	uint32_t begin=0,index=0;//begin:the first index of test
	uint32_t skip=1;//skip query
	uint32_t range=initialize_size;//range query
   	sgx_read_rand(reinterpret_cast<unsigned char*>(&begin), sizeof(begin));

	//for temporal Locality
	vector<uint32_t> local_list;
	uint32_t temp;
	for(int i=0;i<100;i++){
   	sgx_read_rand(reinterpret_cast<unsigned char*>(&temp), sizeof(temp));
	local_list.push_back(temp%initialize_size);}

	for(int i=0;i<initialize_size;i++)
	{
		if(test_pool.size()>=test_size)
		{
			return;
		}
		index=(begin+(i*skip)%range);
		if(i%20==0) {sgx_read_rand(reinterpret_cast<unsigned char*>(&begin), sizeof(begin));}//space locality
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
	uint64_t* total_time_now=new uint64_t[1];
	long long total_begin_time=0,total_end_time=0;
	ocall_get_timeNow(total_time_now);
	total_begin_time=*total_time_now;

	unordered_set<uint32_t> candidate;
	candidate.clear();
	candidate.reserve(5000);
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
	vector<sub_index_node*> map2liner;
	// vector<uint32_t> miss_sub;
	vector<vector<sub_information>::iterator> miss_sub;
	static int num=0;
	static int hitmap=0;static int hitliner=0;
	static int mapsize=0;static int linersize=0;
	uint64_t* time=new uint64_t[1];
	long long begin_time,end_time;
	for(int i=0;i<4;i++){
		ocall_get_timeNow(time);
		begin_time=*time;
		for(auto& its:C_0_TO_subhammdis[i])
		{
			tmpsub1=sub[i]^its;
		//	LOGGER("SUB FP INFO: %u %u %u %u",tmpsub1,tmpsub2,tmpsub3,tmpsub4);
		//	LOGGER("SUB INDEX SIZE: %zu %zu %zu %zu",sub_index1.size(),sub_index2.size(),sub_index3.size(),sub_index4.size());

			if(filters[i].contains(tmpsub1)){	
			auto it = sub_index[i].find(tmpsub1);times++;bloomHit++;
			if(it!=sub_index[i].end())
			{	
				hitmap++;
				// temp=it->second;
				// for(auto& got:temp){
				// candidate.insert(got);
				// }
				map2liner.push_back(it->second);
				lru_index_visit(i,it->second);
			}else{
				// sub_information*its;
				// for(its=sub_index_liner[i];its<sub_index_liner[i]+initialize_size,its++){
				// 	if(its->sub_key==tmpsub1){
				// 		++hitliner;
				// 		lru_index_add(i,sub_index[i],its);
				// 		break;
				// 	}
				// }
				auto its = std::lower_bound(sub_index_liner[i].begin(),sub_index_liner[i].end(), tmpsub1,compareFirst);
				if(its!=sub_index_liner[i].end()&&its->sub_key==tmpsub1){
					++hitliner;
					lru_index_add(i,its,sub_index_liner[i]);
					miss_sub.push_back(its);
				}
				// miss_sub.push_back(tmpsub1);
				bolomMiss++;}
			}
		}
		ocall_get_timeNow(time);
		end_time=*time;
		find_time+=end_time-begin_time;
		ocall_get_timeNow(time);
		begin_time=*time;
		for(auto temp:map2liner){
			uint32_t tempkey=temp->sub_key;num+=temp->sub_key;
			// auto its=temp->liner_node;num+=its->identifiers;
			for(auto& its:temp->identifiers){
			candidate.emplace_hint(candidate.begin(),its);
			}
		}
		map2liner.clear();
		for(int y=0;y<miss_sub.size();y+=1){//auto temp:miss_sub
			auto its=miss_sub[y];
			uint32_t temp=its->sub_key;
			// auto temp=miss_sub[y];
			// auto its = std::lower_bound(sub_index_liner[i], sub_index_liner[i]+initialize_size, temp,compareFirst);
			// if(its!=sub_index_liner[i]+initialize_size&&its->sub_key==temp){
			// 	++hitliner;
			// 	lru_index_add(i,sub_index[i],its);
			// }
			for(;its<sub_index_liner[i].end()&&its->sub_key==temp;++its){
			candidate.emplace_hint(candidate.begin(),its->identifiers);
			num+=its->identifiers;linersize++;
			}
		}
		miss_sub.clear();
		ocall_get_timeNow(time);
		end_time=*time;
		insert_time+=end_time-begin_time;
	}
	// for(auto& its:this->C_0_TO_subhammdis[0])
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
	// for(auto& its:this->C_0_TO_subhammdis[0])
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
	// for(auto& its:this->C_0_TO_subhammdis[0])
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
	// static uint32_t candiNum=0;candiNum+=candidate.size();
	// printf("candiNum:%d\n",candiNum);
	// printf("times1:%d times2 %d\n",line_times,times);
	// printf("bloomHit:%lu bloomMiss:%lu\n",bloomHit,bolomMiss);
	// printf("num%d\n",num);
	// printf("hitmap %d hitliner %d \n",hitmap,hitliner);
	// num+=hitliner&mapsize&linersize&hitmap;
	// printf("hitmap %d mapsize %d hitliner %d linersize %d \n",hitmap,mapsize,hitliner,linersize);
	num+=hitliner&mapsize&linersize&hitmap;//candidate.reserve(num&0xf);
	ocall_get_timeNow(time);
	begin_time=*time;
	information got_out;
	// tsl::hopscotch_map<uint32_t,information>::const_iterat/or got_out;
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
	ocall_get_timeNow(time);
	end_time=*time;
	verify_time+=end_time-begin_time;
	ocall_get_timeNow(total_time_now);
	total_end_time=*total_time_now;
	total_time+=total_end_time-total_begin_time;
	return std::move(candidate);
}
void containers::test()
{
	int insert_num=5000;
	pair<uint64_t, uint64_t>* tempPair = new pair<uint64_t, uint64_t>[insert_num];
	for(int i=0;i<insert_num;i++)tempPair[i] = make_pair(full_index[3000+i].fullkey[0], full_index[3000+i].fullkey[1]);
	insert_fingerprint(tempPair,insert_num);
	// int insert_num=1;
	// pair<uint64_t, uint64_t> tempPair(full_index[0].fullkey[0],full_index[0].fullkey[1]);
	// insert_fingerprint(&tempPair,insert_num);
	printf("Test!\n");
	uint64_t temp_key[2]={0};
	// for(int i=0;i<4;i++)this->insert_new_datamap(i);

	for(auto &itx : test_pool)
	{
		temp_key[0]=itx.first;
		temp_key[1]=itx.second;
		find_sim(temp_key);
	}
	total_time/=1e6;
	find_time/=1e6;
	insert_time/=1e6;
	verify_time/=1e6;
	printf("total=time:%d,sum:%d, find-time:%d, insert-time:%d, verify-time:%d\n",total_time,find_time+insert_time+verify_time,find_time,insert_time,verify_time);
}
void containers::changeHammingDist(uint64_t hammdist)
{
	if(hammdist==this->hammdist)return;
	this->hammdist=hammdist;
	// this->sub_hammdist=hammdist/4;
	for(int i=0;i<cont.sub_index_num;i++)sub_hammdist[i]=0;
	for(int j=hammdist-sub_index_num+1;j>0;){//the sum of sub_hammdist is hammdist - sub_index_num + 1
		for(int i=0;i<sub_index_num;i++)
		{
			if(j<=0)break;
			sub_hammdist[i]++;
			j--;
		}
	}
	for(int i=0;i<cont.sub_index_num;i++)
	{
		cont.C_0_TO_subhammdis[i].clear();
		cont.prepare(cont.sub_hammdist[i],cont.C_0_TO_subhammdis[i]);
	}
	// this->prepare();
}
void containers::insert_fingerprint(pair<uint64_t,uint64_t>* data,uint32_t length){
	uint64_t temp_key[2]={0};
	uint32_t out_id=0;
	uint32_t sub[4]={0};
	information temp_information;
	sub_information sub_info[4];
	if(length>sub_map_size*5){
		vector<sub_information> tmp_sub_vector[4] ;
		for(int i=0;i<4;i++)tmp_sub_vector[i].reserve(length);
		for(int i=0;i<length;i++)
		{
			temp_information.fullkey[0]=data[i].first;//temp_key[0];
			temp_information.fullkey[1]=data[i].second;//temp_key[1];
			temp_key[0]=temp_information.fullkey[0];temp_key[1]=temp_information.fullkey[1];
			get_sub_fingerprint(sub,temp_key);
			out_id=random_uuid()-1;
			for(int j=0;j<4;j++){
				filters[j].insert(sub[j]);
				sub_info[j].sub_key=sub[j];
				sub_info[j].identifiers=out_id;
				tmp_sub_vector[j].push_back(sub_info[j]);
				if(sub_index[j].find(sub[j])!=sub_index[j].end()){
					sub_index[j][sub[j]]->identifiers.push_back(out_id);
				}
			}
			full_index.push_back(temp_information);
		}

		//sort and merge new elements
		for(int j=0;j<4;j++){
			std::sort(tmp_sub_vector[j].begin(),tmp_sub_vector[j].end(),customCompare);
			sub_index_liner[j].reserve(sub_index_liner[j].size()+(length<1000?1000:length));
			sub_index_liner[j].insert(sub_index_liner[j].end(), tmp_sub_vector[j].begin(), tmp_sub_vector[j].end());
			// std::merge(cont.sub_index_liner[j].begin(),cont.sub_index_liner[j].end(),tmp_sub_vector[j].begin(),tmp_sub_vector[j].end(),std::back_inserter(cont.sub_index_liner[j]),customCompare);
			std::inplace_merge(sub_index_liner[j].begin(), sub_index_liner[j].end()-tmp_sub_vector[j].size(), sub_index_liner[j].end(), customCompare);
			initialize_size+=tmp_sub_vector[j].size();
		}
	}else{
		for(int i=0;i<length;i++)
		{
			temp_information.fullkey[0]=data[i].first;//temp_key[0];
			temp_information.fullkey[1]=data[i].second;//temp_key[1];
			temp_key[0]=temp_information.fullkey[0];temp_key[1]=temp_information.fullkey[1];
			get_sub_fingerprint(sub,temp_key);
			out_id=random_uuid()-1;
			for(int j=0;j<4;j++){
				filters[j].insert(sub[j]);
				insert_to_submap(j,sub[j],out_id);
				
				//直接插入sub-index，测试纯hashmap的insert时间
				// if(sub_index[j].find(sub[j])!=sub_index[j].end())sub_index[j][sub[j]]->identifiers.push_back(out_id);
				// else {
				// 	sub_index_node* temp_node=new sub_index_node;
				// 	sub_index[j][sub[j]]=temp_node;
				// 	temp_node->identifiers.push_back(out_id);
				// }
			}
			full_index.push_back(temp_information);
		}
	}
}
void init()
{
	printf("run code!\n");
	for(int i=0;i<cont.sub_index_num;i++)
	{
		cont.prepare(cont.sub_hammdist[i],cont.C_0_TO_subhammdis[i]);
	}
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
void init_after_send(){
	cont.init_after_recv_data();
	cont.get_test_pool();
	printf("The full index entry is: %d \n",cont.full_index.size());
	printf("The number of queries is: %d \n",cont.test_pool.size());
}

void encall_send_data(void *dataptr,size_t len)
{
	// printf("The full index entry is: %d \n",cont.test_pool.size()-1);
	std::pair<uint64_t, uint64_t>* data =  reinterpret_cast<std::pair<uint64_t, uint64_t>*>(dataptr);
	// sign_data.insert(sign_data.end(),data,data+len);
	uint64_t temp_key[2]={0};
	uint32_t out_id=0;
	uint32_t sub[4]={0};
	information temp_information;
	sub_information sub_info[4];
	for(int i=0;i<len;i++){
		//random_128(temp_key);
		temp_information.fullkey[0]=data[i].first;//temp_key[0];
		temp_information.fullkey[1]=data[i].second;//temp_key[1];
		temp_key[0]=temp_information.fullkey[0];temp_key[1]=temp_information.fullkey[1];
		cont.get_sub_fingerprint(sub,temp_key);
		out_id=cont.random_uuid()-1;
		for(int j=0;j<4;j++){
			cont.filters[j].insert(sub[j]);
			sub_info[j].sub_key=sub[j];
			sub_info[j].identifiers=out_id;
			cont.sub_index_liner[j].push_back(sub_info[j]);
		}
		cont.full_index.push_back(temp_information);
	}
	// printf("The full index entry is: %d \n",cont.test_pool.size()-10);
}
void encall_send_targets(void *dataptr,size_t len)
{
	uint32_t* data =  reinterpret_cast<uint32_t*>(dataptr);
	// targets_data.insert(targets_data.end(),data,data+len);
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
	std::unordered_set<uint32_t> res_set=cont.find_sim(data);
	uint8_t* res_old=reinterpret_cast<uint8_t*>(res);
	for(auto &it:res_set)
	{
		*res=it;
		res++;
	}
	//*len=res_set.size();
	cryptoObj->SessionKeyEnc(cipherCtx_,(uint8_t*)res_old,3000*4,sessionKey_,(uint8_t*)res_old);
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
//move the visited node to the tail of the list
void containers::lru_index_visit(int sub_i,sub_index_node* node){
	if(node->pre==nullptr||node->pre==new_data_head[sub_i])return;
	if(node==lru_n[sub_i].index_tail)return;
	//move the node to the tail of the index list
	node->next->pre=node->pre;
	node->pre->next=node->next;
	node->pre=lru_n[sub_i].index_tail;
	lru_n[sub_i].index_tail->next=node;
	lru_n[sub_i].index_tail=node;
};
//add the node to the tail of the list
void containers::lru_index_add(int sub_i,vector<sub_information>::iterator node_liner,vector<sub_information>& sub_linear){
	//if the size of the index list is larger than the max size,remove the first node
	sub_index_node* remove_node=nullptr;
	if(lru_n[sub_i].index_size>=lru_n[sub_i].map_size){
		remove_node = lru_n[sub_i].index_head->next;
		sub_index_node* first = remove_node->next;
		lru_n[sub_i].index_head->next = first;
		first->pre = lru_n[sub_i].index_head;
		auto tmp=sub_index[sub_i].find(remove_node->sub_key);
		if(tmp!=sub_index[sub_i].end()&&tmp->second->pre == lru_n[sub_i].index_head)sub_index[sub_i].erase(remove_node->sub_key);
		remove_node->pre = nullptr;remove_node->next=nullptr;

		//if the new data is in the removed list,add it to the linear list
		remove_node->pre = lru_n[sub_i].index_tail;
		lru_n[sub_i].index_tail->next = remove_node;
		lru_n[sub_i].index_tail = remove_node;
		//delete remove_node;
	}else{lru_n[sub_i].index_size++;}

	//add node to the tail of the index list
	sub_index_node* node=nullptr;
	if(remove_node==nullptr) node=&cont.sub_nodes[sub_i][lru_n[sub_i].index_size-1];//new sub_index_node{node_liner->sub_key,node_liner,nullptr,nullptr};
	else node=remove_node;
	node->sub_key=node_liner->sub_key;
	// node->liner_node=node_liner;
	node->identifiers.clear();
	for(;node_liner!=sub_linear.end()&&node_liner->sub_key==node->sub_key;node_liner++){
		node->identifiers.push_back(node_liner->identifiers);
	}
	// node->identifiers.shrink_to_fit();
	node->next=nullptr;node->pre=nullptr;
	// cont.sub_filters[sub_i].insert(node_liner->sub_key);
	sub_index[sub_i][node->sub_key]=node;
	sub_index_node* temp=node;//sub_index[node_liner->sub_info.sub_key];
	lru_n[sub_i].index_tail->next=temp;
	temp->pre=lru_n[sub_i].index_tail;
	lru_n[sub_i].index_tail=temp;
};
void containers::insert_new_datamap(int sub_i){
	vector<sub_information> tmp_sub_vector;
	sub_information sub_info;
	sub_index_node* node = new_data_head[sub_i]->next;
	new_data_head[sub_i]->next = nullptr;
	while(node != nullptr){
		if(node->pre == new_data_head[sub_i]){
			for(auto &it:node->identifiers){
				sub_info.sub_key=node->sub_key;
				sub_info.identifiers=it;
				tmp_sub_vector.push_back(sub_info);
			}
		}else{
			for(auto &it:node->identifiers){
				sub_info.sub_key=node->sub_key;
				sub_info.identifiers=it;
				auto is_exists = std::lower_bound(sub_index_liner[sub_i].begin(),sub_index_liner[sub_i].end() , sub_info, customCompare);
				//insert the un-exists data to the linear list
				if(is_exists == sub_index_liner[sub_i].end()||is_exists->sub_key!=sub_info.sub_key)tmp_sub_vector.push_back(sub_info);
			}
		}
		sub_index_node* tmp = node;
		node = node->next;
		sub_index[sub_i].erase(tmp->sub_key);
		delete tmp;
	}

	//insert to linear list
	std::sort(tmp_sub_vector.begin(),tmp_sub_vector.end(),customCompare);
	sub_index_liner[sub_i].reserve(sub_index_liner[sub_i].size()+(tmp_sub_vector.size()<1000?1000:tmp_sub_vector.size()));
	sub_index_liner[sub_i].insert(sub_index_liner[sub_i].end(), tmp_sub_vector.begin(), tmp_sub_vector.end());
	std::inplace_merge(sub_index_liner[sub_i].begin(), sub_index_liner[sub_i].end()-tmp_sub_vector.size(), sub_index_liner[sub_i].end(), customCompare);
	initialize_size+=tmp_sub_vector.size();
	change_sub_map(sub_i);
};
void containers::insert_to_submap(int sub_i,uint32_t sub_key,uint32_t identifier){
	auto sub_node = sub_index[sub_i].find(sub_key);
	if(sub_node != sub_index[sub_i].end()){
		if(sub_node->second->pre==nullptr||sub_node->second->pre==new_data_head[sub_i]){
			sub_node->second->identifiers.push_back(identifier);
			return;
		}
		sub_index_node* tmp = new sub_index_node{sub_key,vector<uint32_t>(),nullptr,nullptr};
		tmp->next = new_data_head[sub_i]->next;
		new_data_head[sub_i]->next = tmp;
		tmp->identifiers.push_back(identifier);
		for(auto &it:sub_node->second->identifiers){
			tmp->identifiers.push_back(it);
		}
		tmp->identifiers.shrink_to_fit();
		auto node = sub_node->second;
		sub_index[sub_i][sub_key] = tmp;
		// sub_node->second->identifiers.clear();
		// sub_node->second->identifiers.shrink_to_fit();

		//move the useless node to the head of the LRU list
		node->pre->next = node->next;
		node->next->pre = node->pre;
		if(node == lru_n[sub_i].index_tail) lru_n[sub_i].index_tail = node->pre;
		node->next = lru_n[sub_i].index_head->next;
		node->pre = lru_n[sub_i].index_head;
		lru_n[sub_i].index_head->next->pre = node;
		lru_n[sub_i].index_head->next = node;
		return;
	}

	//add node to the new_data_list
	sub_index_node* node = new sub_index_node{sub_key,vector<uint32_t>(),nullptr,nullptr};
	auto node_liner = std::lower_bound(sub_index_liner[sub_i].begin(),sub_index_liner[sub_i].end(), sub_key,compareFirst);
	if(node_liner == sub_index_liner[sub_i].end()) node->pre = new_data_head[sub_i]; //this is a new sub_key in the data_set
	for(;node_liner != sub_index_liner[sub_i].end()&&node_liner->sub_key == node->sub_key;node_liner++){
		node->identifiers.push_back(node_liner->identifiers);
	}

	node->identifiers.push_back(identifier);
	sub_index[sub_i][sub_key] = node;
	node->next = new_data_head[sub_i]->next;
	new_data_head[sub_i]->next = node;
};
//if insert too many data, increase the size of the submap
void containers::change_sub_map(int sub_i){
	uint32_t new_sub_map_size = initialize_size/2000;
	sub_information sub_info;
	if(new_sub_map_size-sub_map_size > sub_map_size/10){
		sub_index_node* new_sub_nodes;
		lru_n[sub_i].index_head->next=nullptr;
		new_sub_nodes = new sub_index_node[new_sub_map_size];
		int j = 0;
		sub_index_node* pre=lru_n[sub_i].index_head;
		for(auto& val:sub_index[sub_i]){
			new_sub_nodes[j].sub_key = val.first;
			new_sub_nodes[j].identifiers = std::move(val.second->identifiers);
			new_sub_nodes[j].pre = pre;
			pre->next = &new_sub_nodes[j];
			pre = &new_sub_nodes[j];
			sub_index[sub_i][val.first] = &new_sub_nodes[j];
			// delete val.second;
			j++;
		}
		delete[] sub_nodes[sub_i];
		pre->next = nullptr;
		lru_n[sub_i].index_tail = pre;
		sub_nodes[sub_i] = new_sub_nodes;
	}
}