#ifndef PAILLIERENC
#define PAILLIERENC

#include <iostream>
#include <ctime>
#include <NTL/ZZ.h>
#include <string>
#include <sstream>

using namespace std;
using namespace NTL;

std::string ZZ_to_string(const NTL::ZZ &z);
// L函数
ZZ L_function(const ZZ &x, const ZZ &n);

/* 密钥生成函数
 *
 * 参数：
 *  p：大质数
 *  q：大质数
 *  n = p * q
 *  phi = (p - 1) * (q - 1)
 *  lambda = lcm(p - 1, q - 1) = (p - 1) * (q - 1) / gcd(p - 1, q - 1)
 *  g = n + 1
 *  lamdaInverse = lambda^{-1} mod n^2
 *  k : 大质数的位数
 */
void keyGeneration(ZZ &p, ZZ &q, ZZ &n, ZZ &phi, ZZ &lambda, ZZ &g, ZZ &lambdaInverse, ZZ &r, const long &k);
/* 加密函数
 *
 * 参数：
 *  m ：需要加密的明文消息
 *  (n, g) ：公钥
 *
 * 返回值：
 *  加密后得到的密文
 */
ZZ encrypt(const ZZ &m, const ZZ &n, const ZZ &g, const ZZ &r);
/* 解密函数
 *
 * 参数：
 *  c：密文
 *  (lambda，lamdaInverse)： 私钥
 */
ZZ decrypt(const ZZ &c, const ZZ &n, const ZZ &lambda, const ZZ &lambdaInverse);

void validHomomorphic(const ZZ &c1, const ZZ &c2, const ZZ &n, const ZZ &lambda, const ZZ &lambdaInverse);

ZZ addHomo(const ZZ &c1, const ZZ &c2, const ZZ &n);
#endif