#include <iostream>
#include <cstdint>
#include <vector>
#include <math.h>
#include <bitset>
#include <string.h>
#include <unordered_map>
using namespace std;

#ifndef UTIL_H
#define UTIL_H

typedef uint64_t UINT64;
typedef uint8_t UINT8;
#define UINT32_1 ((uint32_t)0x01)

struct pair_hash
{
    template <class T1, class T2>
    std::size_t operator()(const std::pair<T1, T2> &p) const
    {
        auto h1 = std::hash<T1>{}(p.first);
        auto h2 = std::hash<T2>{}(p.second);
        return h1 ^ h2;
    }
};
struct cluster_node
{
    uint32_t subkey;
    uint32_t begin_idx;
    bool is_combined; // 是否是合并后的subkey
};
struct cluster_info
{
    cluster_node node;
    uint32_t end;
    uint32_t dist;
};
// compress sub_information, begin is the begin of sub_key in sub_identifiers[]
typedef struct sub_info_comp
{
    uint32_t sub_key;
    uint32_t skiplen; // begin < 0 ,when some sub_keys are combined to one sub_key; begin>=0,this sub_key is only represent one sub_key
    int length;
} sub_info_comp;

inline void split(uint32_t *chunks, const UINT8 *code, int m, int mplus, int b)
{
    uint32_t temp = 0x0;
    int nbits = 0;
    int nbyte = 0;
    uint32_t mask = b == 32 ? 0xFFFFFFFFU : ((UINT32_1 << b) - UINT32_1);

    for (int i = 0; i < m; i++)
    {
        while (nbits < b)
        {
            temp |= ((uint32_t)code[nbyte++] << nbits);
            nbits += 8;
        }
        chunks[i] = temp & mask;
        temp = b == 32 ? 0x0 : temp >> b;
        nbits -= b;
        if (i == mplus - 1)
        {
            b--; /* b <= 63 */
            mask = ((UINT32_1 << b) - UINT32_1);
        }
    }
}

template <typename T>
int popcount(T x)
{
    if constexpr (std::is_same<T, uint32_t>::value)
    {
        return __builtin_popcount(x);
    }
    else if constexpr (std::is_same<T, uint64_t>::value)
    {
        return __builtin_popcountll(x);
    }
    else if constexpr (std::is_same<T, __uint128_t>::value)
    {
        return __builtin_popcountll(static_cast<uint64_t>(x)) +
               __builtin_popcountll(static_cast<uint64_t>(x >> 64));
    }
    else
    {
        // static_assert(false, "Unsupported type");
    }
}
#endif