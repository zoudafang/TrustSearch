#include "../include/PaillierEnc.h"

std::string ZZ_to_string(const NTL::ZZ &z)
{
    std::ostringstream oss;
    oss << z;
    return oss.str();
}
// L函数
ZZ L_function(const ZZ &x, const ZZ &n) { return (x - 1) / n; }

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
void keyGeneration(ZZ &p, ZZ &q, ZZ &n, ZZ &phi, ZZ &lambda, ZZ &g, ZZ &lambdaInverse, ZZ &r, const long &k)
{
    GenPrime(p, k), GenPrime(q, k);
    n = p * q;
    g = n + 1;
    phi = (p - 1) * (q - 1);
    lambda = phi / GCD(p - 1, q - 1);
    lambdaInverse = InvMod(lambda, n);
    r = RandomBnd(n);
    // cout << "--------------------------------------------------密钥生成阶段---------------------------------------------------" << endl;
    // cout << "公钥(n, g) : " << endl;
    // cout << "n = " << n << endl;
    // cout << "g = " << g << endl;
    // cout << "---------------------------------------------------------------------------------------------------------------" << endl;
    // cout << "私钥(lambda, mu) : " << endl;
    // cout << "lambda = " << lambda << endl;
    // cout << "mu = " << lambdaInverse << endl;
}

/* 加密函数
 *
 * 参数：
 *  m ：需要加密的明文消息
 *  (n, g) ：公钥
 *
 * 返回值：
 *  加密后得到的密文
 */
ZZ encrypt(const ZZ &m, const ZZ &n, const ZZ &g, ZZ &r)
{
    // 生成一个随机数 r < n
    r = RandomBnd(n);
    ZZ c = (PowerMod(g, m, n * n) * PowerMod(r, n, n * n)) % (n * n);
    // cout << "----------------------------------------------------加密阶段-----------------------------------------------------" << endl;
    // cout << "密文输出 : " << c << endl;
    return c;
}

/* 解密函数
 *
 * 参数：
 *  c：密文
 *  (lambda，lamdaInverse)： 私钥
 */
ZZ decrypt(const ZZ &c, const ZZ &n, const ZZ &lambda, const ZZ &lambdaInverse)
{
    ZZ m = (L_function(PowerMod(c, lambda, n * n), n) * lambdaInverse) % n;
    // cout << "----------------------------------------------------解密阶段-----------------------------------------------------" << endl;
    // cout << "解密得到 : " << m << endl;
    return m;
}

void validHomomorphic(const ZZ &c1, const ZZ &c2, const ZZ &n, const ZZ &lambda, const ZZ &lambdaInverse)
{
    ZZ c_sum = (c1 * c2) % (n * n);
    ZZ m_sum = (L_function(PowerMod(c_sum, lambda, n * n), n) * lambdaInverse) % n;
    // cout << "----------------------------------------------------验证阶段-----------------------------------------------------" << endl;
    // cout << "密文相加 : " << c_sum << endl;
    // // std::string s = ZZ_to_string(c_sum);
    // // std::cout << "s: " << s << std::endl;
    // cout << "解密得到 : " << m_sum << endl;
}

ZZ addHomo(const ZZ &c1, const ZZ &c2, const ZZ &n)
{
    ZZ c_sum = (c1 * c2) % (n * n);
    return c_sum;
}

/* 密文加明文函数
 *
 * 参数：
 *  c：密文
 *  m：明文
 *  (n, g)：公钥
 *
 * 返回值：
 *  密文加明文的结果
 */
ZZ addPlaintext(const ZZ &c, const ZZ &m, const ZZ &n, const ZZ &g)
{
    ZZ c_result = (c * PowerMod(g, m, n * n)) % (n * n);
    return c_result;
}