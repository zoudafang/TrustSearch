#ifndef UTIL_H
#define UTIL_H

#include <iostream>
#include <cstdint>
#include <vector>
#include <math.h>
#include <bitset>
#include <string.h>
#include <unordered_map>
// #include <NTL/ZZ.h>
#include <algorithm>
#include <random>
#include "constVar.h"

using namespace std;
using namespace NTL;

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

// static void BytesToZZ(const uint8_t *bytes, const int len, NTL::ZZ &zz)
// {
//     ZZFromBytes(zz, bytes, len); // 从 byte 数组构建 ZZ
// }

// static int ZZToBytes(const NTL::ZZ &zz, uint8_t *bytes)
// {
//     long numBytes = NumBytes(zz);     // 获取所需的字节数
//     BytesFromZZ(bytes, zz, numBytes); // 导出 ZZ 到 byte 数组
//     return numBytes;
// }
// 生成byte长度keysize的随机数
static int generateRandLen(size_t keySize, uint8_t *key)
{
    std::random_device rd;  // 使用硬件随机数生成器作为种子
    std::mt19937 gen(rd()); // 利用随机设备初始化 Mersenne Twister 生成器
    std::uniform_int_distribution<> dis(0, 255);

    for (size_t i = 0; i < keySize; ++i)
    {
        key[i] = static_cast<uint8_t>(dis(gen));
    }
    return 1;
}
static std::vector<uint8_t> MaskMsg(uint8_t *msg1, uint32_t len1, uint8_t *msg2, uint32_t len2)
{
    std::vector<uint8_t> res;
    res.resize(std::max(len1, len2));
    if (len1 > len2)
    {
        memcpy(res.data(), msg1, len1);
        for (int i = len1 - len2, j = 0; i < len1; i++, j++)
            res[i] = res[i] ^ msg2[j];
        return res;
    }
    else
    {
        memcpy(res.data(), msg2, len2);
        for (int i = len2 - len1, j = 0; i < len2; i++, j++)
            res[i] = res[i] ^ msg1[j];
        return res;
    }
    return res;
}
template <typename T>
static std::vector<uint8_t> to_uint8_array(T value)
{
    static_assert(std::is_same<T, int>::value || std::is_same<T, uint32_t>::value || std::is_same<T, uint64_t>::value,
                  "Input type must be uint32_t or uint64_t");

    std::vector<uint8_t> result;
    // result.reserve(sizeof(T));

    for (size_t i = 0; i < sizeof(T); ++i)
    {
        result.push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xFF));
    }

    return result;
}

// std::vector<uint8_t> connect_uint8(uint8_t *data1, uint32_t len1, uint8_t *data2, uint32_t len2)
// {
//     std::vector<uint8_t> res;
//     res.resize(len1 + len2);
//     memcpy(res.data(), data1, len1);
//     memcpy(res.data() + len1, data2, len2);
//     return res;
// }

// 基础递归函数，用于处理最后一个data和其长度
static void connect_uint8_impl(std::vector<uint8_t> &res, uint8_t *data, uint32_t len)
{
    res.insert(res.end(), data, data + len);
}

// 可变参数模板递归函数
template <typename... Args>
static void connect_uint8_impl(std::vector<uint8_t> &res, uint8_t *data, uint32_t len, Args... args)
{
    res.insert(res.end(), data, data + len);
    connect_uint8_impl(res, args...);
}

// 主函数，使用可变参数模板
template <typename... Args>
static std::vector<uint8_t> connect_uint8(Args... args)
{
    std::vector<uint8_t> res;
    connect_uint8_impl(res, args...);
    return res;
}

struct ArrayHasher
{
    std::size_t operator()(const std::array<uint8_t, RAND_PARAM_LEN> &arr) const
    {
        std::size_t hash = 0;
        for (int i = 0; i < RAND_PARAM_LEN; ++i)
        {
            hash ^= std::hash<uint8_t>{}(arr[i]) + 0x9e3779b9 + (hash << 6) + (hash >> 2);
        }
        return hash;
    }
};

struct ArrayEqual
{
    bool operator()(const std::array<uint8_t, RAND_PARAM_LEN> &arr1, const std::array<uint8_t, RAND_PARAM_LEN> &arr2) const
    {
        return arr1 == arr2;
    }
};
// // 自定义比较函数
// struct ArrayEqual
// {
//     bool operator()(const uint8_t arr1[32], const uint8_t arr2[32]) const
//     {
//         return std::memcmp(arr1, arr2, 32) == 0;
//     }
//     // bool operator()(const uint8_t lhs[RAND_KEY_LEN], const uint8_t rhs[RAND_KEY_LEN]) const
//     // {
//     //     for (size_t i = 0; i < RAND_KEY_LEN; ++i)
//     //     {
//     //         if (lhs[i] != rhs[i])
//     //         {
//     //             return false;
//     //         }
//     //     }
//     //     return true;
//     // }
// };

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