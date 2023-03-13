/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include "sgx_trts.h"
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>

#include <unordered_map>
#include <iostream>
#include <set>
#include <vector>

using namespace std;

#define keybit 128 //特征值的位数
#define hammdist 8 //认为图片相似的最大汉明距离
#define sub_index_num 4 //子索引的个数
#define sub_keybit keybit/sub_index_num //特征值段的位数
#define sub_hammdist hammdist/sub_index_num //候选值的标准

int x=0;

struct uint128_t
{
    uint64_t fullkey[2];//完整特征值
};

struct information
{
    uint64_t fullkey[2];//完整特征值
    uint16_t location=111;//存储位置
    //uint64_t count;//频率
};
vector<uint32_t>C_0_TO_subhammdis;//用于与特征值做异或运算的所有数字的容器
set<uint32_t>candidate;//候选池
unordered_map<uint32_t,information>full_index;//完整索引
unordered_map<uint32_t,uint32_t>sub_index1;//四个子索引
unordered_map<uint32_t,uint32_t>sub_index2;
unordered_map<uint32_t,uint32_t>sub_index3;
unordered_map<uint32_t,uint32_t>sub_index4;
set<pair<uint64_t,uint64_t>>test_pool;

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
int printf(const char* fmt, ...)
{
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

void prepare()
{
    uint32_t tmp1=1,tmp2=1,tmp=0;
    C_0_TO_subhammdis.push_back(0);
    switch (sub_hammdist)
    {
    case 2:
	for(int i=0;i<31;i++)
	{
	    tmp1=0x00000001 << i;
	    for(int j=1+i;j<32;j++)
	    {
		tmp2=0x00000001 << j;
		tmp=tmp1+tmp2;
		C_0_TO_subhammdis.push_back(tmp);
	    }
	}
    case 1:
    {
	for(int x=0;x<32;x++)
	{
	    tmp=0x00000001 << x;
	    C_0_TO_subhammdis.push_back(tmp);
	}
	break;
    }
    default:
        break;
    }
}

void initialize(int* initialize_size)
{
    uint64_t temp_key[2]={0};
    uint64_t temp_keyx[2]={0};
    uint32_t out_id=0;
    uint32_t sub1,sub2,sub3,sub4=0;
    uint128_t temp_full_key;
    information temp_information;
    unsigned char rand[16]={0};

    while(sub_index1.size()<*initialize_size)
    {
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
	temp_full_key.fullkey[0]=temp_keyx[0];
	temp_full_key.fullkey[1]=temp_keyx[1];
	if((sub_index1.find(sub1)==sub_index1.end())&&(sub_index2.find(sub2)==sub_index2.end())&&(sub_index3.find(sub3)==sub_index3.end())&&(sub_index4.find(sub4)==sub_index4.end()))
	{
	    sub_index1.insert(std::pair<uint32_t,uint32_t>(sub1,out_id));
	    sub_index2.insert(std::pair<uint32_t,uint32_t>(sub2,out_id));
	    sub_index3.insert(std::pair<uint32_t,uint32_t>(sub3,out_id));
	    sub_index4.insert(std::pair<uint32_t,uint32_t>(sub4,out_id));
	    full_index.insert(std::pair<uint32_t,information>(out_id,temp_information));
	    test_pool.insert(std::pair<uint64_t,uint64_t>(temp_keyx[0],temp_keyx[1]));
	    out_id++;
	}
    }
    return;
}

void find_sim(uint64_t query[])
{
    //通过位运算，截取特征值段
    uint64_t tmpquery1=query[0];
    uint64_t tmpquery2=query[1];
    uint32_t sub1=tmpquery1&0xffffffff;
    tmpquery1=tmpquery1>>32;
    uint32_t sub2=tmpquery1&0xffffffff;
    uint32_t sub3=tmpquery2&0xffffffff;
    tmpquery2=tmpquery2>>32;
    uint32_t sub4=tmpquery2&0xffffffff;

    //容器的迭代器
    std::unordered_map<uint32_t,uint32_t>::const_iterator got1;
    std::unordered_map<uint32_t,uint32_t>::const_iterator got2;
    std::unordered_map<uint32_t,uint32_t>::const_iterator got3;
    std::unordered_map<uint32_t,uint32_t>::const_iterator got4;
    std::set<uint32_t>::iterator it;
    std::vector<uint32_t>::iterator its;

    //寻找候选特征值段
    uint32_t tmpsub1,tmpsub2,tmpsub3,tmpsub4=0;
    for(its=C_0_TO_subhammdis.begin();its!=C_0_TO_subhammdis.end();its++)
    {
	//做异或运算，找出只有相关位不同的可能候选值
	tmpsub1=sub1^*its;
	tmpsub2=sub2^*its;
	tmpsub3=sub3^*its;
	tmpsub4=sub4^*its;

	//分别在4个子索引中查找候选值
	got1=sub_index1.find(tmpsub1);
	if(got1!=sub_index1.end())
	{
	    it=candidate.find(got1->second);//检查标识符在候选池中是否存在
	    if(it==candidate.end())
		candidate.insert(got1->second);
	}
	got2=sub_index2.find(tmpsub2);
	if(got2!=sub_index2.end())
	{
	    it=candidate.find(got2->second);
	    if(it==candidate.end())
		candidate.insert(got2->second);
	}
	got3=sub_index3.find(tmpsub3);
	if(got3!=sub_index3.end())
	{
	    it=candidate.find(got3->second);
	    if(it==candidate.end())
		candidate.insert(got3->second);
	}
	got4=sub_index4.find(tmpsub4);
	if(got4!=sub_index4.end())
	{
	    it=candidate.find(got4->second);
	    if(it==candidate.end())
		candidate.insert(got4->second);
	}
    }

    //对候选特征值段进行筛选
    uint64_t cmp_hamm[2]={0};
    int count=0;

    std::unordered_map<uint32_t,information>::const_iterator got_out;
    for(it=candidate.begin();it!=candidate.end();++it)
    {
	got_out=full_index.find(*it);
	if(got_out!=full_index.end())
	{
	    cmp_hamm[0]=query[0]^(got_out->second.fullkey[0]);
	    cmp_hamm[1]=query[0]^(got_out->second.fullkey[1]);
	    //异或后，统计不同位的个数
	    count=0;
	    while(cmp_hamm[0])
	    {
		count+=cmp_hamm[0]^1;
		cmp_hamm[0]=cmp_hamm[0]>>1;
	    }
	    while(cmp_hamm[1])
	    {
		count+=cmp_hamm[1]&1;
		cmp_hamm[1]=cmp_hamm[1]>>1;
	    }
	    if(count<=hammdist)
	    {
		x++;
		//printf("Successfully found similar photos!,x=%d\n",x);
	    }
	}
    }
    candidate.clear();
}

void test(int* test_size)
{
    int m=0;
    uint64_t temp_key[2]={0};
    std::set<pair<uint64_t,uint64_t>>::iterator itx;
    int h=0,y=0;
    uint64_t t=0;
    unsigned char rand[2]={0};
    
    for(itx=test_pool.begin();m<*test_size;++itx)
    {
	t=0x0000000000000001;
	sgx_read_rand(rand,2);
	h=rand[0]%3;

	temp_key[0]=itx->first;
	temp_key[1]=itx->second;

	for(int i=0;i<h;i++)
	{
	    sgx_read_rand(rand,2);
	    y=rand[0]%64;
	    temp_key[0]=temp_key[0]^(t<<y);
	    temp_key[1]=temp_key[1]^(t<<y);
	}
	find_sim(temp_key);
	m++;
    }
}
