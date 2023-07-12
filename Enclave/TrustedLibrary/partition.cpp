#include "partition.h"
#include "cmath"

float fast_log2(float val) {
    union {
        float f;
        uint32_t i;
    } conv = {val};
    uint32_t x = conv.i;
    int log_2 = ((x >> 23) & 255) - 128;
    x &= ~(255 << 23);
    x += 127 << 23;
    conv.i = x;

    return conv.f + log_2;
}

void skewed_partition::set_skewed_partition(unordered_map<uint32_t,information> &skewed_partition)
{
    full_index.reserve(skewed_partition.size());
   for(auto&val:skewed_partition){
    full_index.push_back(val.second);
   }
   for(int i=0;i<128;i++){
       dimension[i]=i;
   }
   printf("full_index.size()=%d\n",full_index.size());
}
uint32_t skewed_partition::get_dimension(information info,uint32_t dim){
    uint64_t key=info.fullkey[0];
    if(dim>63){key=info.fullkey[1];dim-=64;}
    uint64_t mask=1ULL<<(63-dim);
    return (key&mask)>>(63-dim);
}
void skewed_partition::make_partition(vector<uint32_t> &dims)
{
   vector<uint32_t> sub_dim;
   unordered_map<uint32_t,uint32_t> sub_value;
   double max_value=0;int max_dim=0;
   sub_value.reserve(full_index.size());
   sub_dim.reserve(full_index.size());
   int begin=0;
   for(int i=0;i<3;i++){
    int left_shift=1;
    sub_dim.clear();
    for(auto&val:full_index){
        uint32_t dim=get_dimension(val,dimension[begin]);
        sub_dim.push_back(dim);
    }
    begin++;
    for(;(begin&0x1f)!=0;begin++){
        max_value=0;max_dim=begin;
        for(int j=begin;j<128;j++){
             sub_value.clear();
            int k=0;
            for(auto& val:full_index){
                uint32_t dim=get_dimension(val,dimension[j]);
                dim=(sub_dim[k])+(dim<<left_shift);
                sub_value[dim]++;
                k++;
            }
            double tmp=0;
            for(auto&val:sub_value){
                double p=(double)val.second;
                //tmp+=p*fast_log2(p);
                tmp+=p*log2(p);
                // tmp+=1;
            }
            if(tmp>max_value){
                // if(max_value!=0)printf("sub %f\n",tmp-max_value);
                max_value=tmp;
                max_dim=j;
                // printf("tmp=%f max%d %d\n",tmp,max_dim,j);
            }
        }
        uint32_t swap_dim=dimension[begin];dimension[begin]=dimension[max_dim];dimension[max_dim]=swap_dim;
        for(int j=0;j<full_index.size();j++){
            uint32_t dim=get_dimension(full_index[j],dimension[begin]);
            sub_dim[j]=(sub_dim[j])+(dim<<left_shift);
        }
        left_shift++;
    }
   }
   for(int i=0;i<128;i++){
       printf("%d ",dimension[i]);
       dims.push_back(dimension[i]);
   } printf("\n" );
   unordered_set<uint32_t> sub_index;for(int i=0;i<128;i++)sub_index.insert(dimension[i]);
   printf("sub_index.size()=%d\n",sub_index.size());
}