#include <iostream>
#include <cstdint>
#include <vector>
#include <math.h>
#include <bitset>
#include <string.h>
#include <unordered_map>
#include "constVar.h"
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
    uint32_t end;
    uint32_t dist;
    bool is_combined;    // 是否是合并后的subkey
    uint32_t group_size; // the items number of this cluster
};

// typedef struct cluster_node cluster_info;
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
    uint32_t skiplen;
    int length; // begin < 0 ,when some sub_keys are combined to one sub_key; begin>=0,this sub_key is only represent one sub_key
} sub_info_comp;

typedef struct fetch_ids_node
{
    sub_info_comp sub_info;
    key_find &kf;
    uint32_t cache_key;
} fetch_ids_node;

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

const int lookup[] = {0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4, 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 4, 5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8};

inline uint32_t calDistance(uint8_t *plainPart, uint8_t *query, int len)
{
    switch (len)
    {
    case 4: // 32 bit
        return popcount(*(uint32_t *)plainPart ^ *(uint32_t *)query);
    case 8: // 64 bit
        return popcount(*(uint64_t *)plainPart ^ *(uint64_t *)query);
    case 12: // 128 bit
        return popcount(*(uint32_t *)plainPart ^ *(uint32_t *)query) + popcount((*(uint64_t *)(plainPart + 4)) ^ *(uint64_t *)(query + 4));
    case 16: // 128 bit
        return popcount(*(uint64_t *)plainPart ^ *(uint64_t *)query) + popcount(((uint64_t *)plainPart)[1] ^ ((uint64_t *)query)[1]);
    case 32: // 256 bit
        return popcount(*(uint64_t *)plainPart ^ *(uint64_t *)query) + popcount(((uint64_t *)plainPart)[1] ^ ((uint64_t *)query)[1]) + popcount(((uint64_t *)plainPart)[2] ^ ((uint64_t *)query)[2]) + popcount(((uint64_t *)plainPart)[3] ^ ((uint64_t *)query)[3]);
    default:
        int output = 0;
        for (int i = 0; i < len; i++)
            output += lookup[plainPart[i] ^ query[i]];
        return output;
    }
}

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

inline uint32_t get_search_numbers(uint32_t m_bit, uint32_t dist)
{
    int res = 1, t = 1;
    for (int i = dist; i > 0; i--)
    {
        res *= m_bit;
        t *= i;
        m_bit--;
    }
    res = res / t;
    return res;
}
#endif