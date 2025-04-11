/*

Copyright 2018 Intel Corporation

This software and the related documents are Intel copyrighted materials,
and your use of them is governed by the express license under which they
were provided to you (License). Unless the License provides otherwise,
you may not use, modify, copy, publish, distribute, disclose or transmit
this software or the related documents without Intel's prior written
permission.

This software and the related documents are provided as is, with no
express or implied warranties, other than those that are expressly stated
in the License.

*/

#include <openssl/cmac.h>
#include <openssl/conf.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <string.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/sha.h>
#include "iostream"
#include <vector>
#include "../include/crypto.h"

// #include "../../include/IAS/hexutil.h"

enum _error_type
{
    e_none,
    e_crypto,
    e_system,
    e_api
};
_error_type error_type = e_none;

static const char *ep = NULL;

void crypto_init()
{
    /* Load error strings for libcrypto */
    ERR_load_crypto_strings();

    /* Load digest and ciphers */
    OpenSSL_add_all_algorithms();
}

void crypto_destroy()
{
    EVP_cleanup();

    CRYPTO_cleanup_all_ex_data();

    ERR_free_strings();
}

/* Print the error */

void crypto_perror(const char *prefix)
{
    // fprintf(stderr, "%s: ", prefix);
    // if (error_type == e_none)
    //     fprintf(stderr, "no error\n");
    // else if (error_type == e_system)
    //     perror(ep);
    // // else if (error_type == e_crypto)
    // //     ERR_print_errors_fp(stderr);
    // else if (error_type == e_api)
    //     fprintf(stderr, "invalid parameter\n");
    // else
    //     fprintf(stderr, "unknown error\n");
}

/*==========================================================================
 * EC key functions
 *========================================================================== */

/* Load an EC key from a file in PEM format */

int key_load_file(EVP_PKEY **key, const char *filename, int keytype)
{
    // 	FILE* fp;

    // 	error_type = e_none;

    // 	*key = EVP_PKEY_new();

    // #ifdef _WIN32
    // 	if ((fopen_s(&fp, filename, "r")) != 0) {
    // 		error_type = e_system;
    // 		ep = filename;
    // 		return 0;
    // 	}
    // #else
    // 	if ((fp = fopen(filename, "r")) == NULL) {
    // 		error_type = e_system;
    // 		ep = filename;
    // 		return 0;
    // 	}
    // #endif

    // 	if (keytype == KEY_PRIVATE)
    // 		PEM_read_PrivateKey(fp, key, NULL, NULL);
    // 	else if (keytype == KEY_PUBLIC)
    // 		PEM_read_PUBKEY(fp, key, NULL, NULL);
    // 	else {
    // 		error_type = e_api;
    // 	}

    // 	fclose(fp);

    // 	return (error_type == e_none);
    return 0;
}

/*==========================================================================
 * SHA
 *========================================================================== */

int sha256_digest(const unsigned char *msg, size_t mlen, unsigned char digest[32])
{
    EVP_MD_CTX *ctx;

    error_type = e_none;

    memset(digest, 0, 32);

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
    {
        error_type = e_crypto;
        goto cleanup;
    }

    if (EVP_DigestInit(ctx, EVP_sha256()) != 1)
    {
        error_type = e_crypto;
        goto cleanup;
    }

    if (EVP_DigestUpdate(ctx, msg, mlen) != 1)
    {
        error_type = e_crypto;
        goto cleanup;
    }

    if (EVP_DigestFinal(ctx, digest, NULL) != 1)
    {
        error_type = e_crypto;
        goto cleanup;
    }

cleanup:
    if (ctx != NULL)
        EVP_MD_CTX_free(ctx);
    return (error_type == e_none);
}

/*==========================================================================
 * HMAC
 *========================================================================== */

int sha256_verify(const unsigned char *msg, size_t mlen, unsigned char *sig,
                  size_t sigsz, EVP_PKEY *pkey, int *result)
{
    EVP_MD_CTX *ctx;

    error_type = e_none;

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
    {
        error_type = e_crypto;
        goto cleanup;
    }

    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey) != 1)
    {
        error_type = e_crypto;
        goto cleanup;
    }

    if (EVP_DigestVerifyUpdate(ctx, msg, mlen) != 1)
    {
        error_type = e_crypto;
        goto cleanup;
    }

    if (EVP_DigestVerifyFinal(ctx, sig, sigsz) != 1)
        error_type = e_crypto;

cleanup:
    if (ctx != NULL)
        EVP_MD_CTX_free(ctx);
    return (error_type == e_none);
}

/*==========================================================================
 * ECDSA
 *========================================================================== */

int ecdsa_sign(unsigned char *msg, size_t mlen, EVP_PKEY *key,
               unsigned char r[32], unsigned char s[32], unsigned char digest[32])
{
    ECDSA_SIG *sig = NULL;
    EC_KEY *eckey = NULL;
    const BIGNUM *bnr = NULL;
    const BIGNUM *bns = NULL;

    error_type = e_none;

    eckey = EVP_PKEY_get1_EC_KEY(key);
    if (eckey == NULL)
    {
        error_type = e_crypto;
        goto cleanup;
    }

    /* In ECDSA signing, we sign the sha256 digest of the message */

    if (!sha256_digest(msg, mlen, digest))
    {
        error_type = e_crypto;
        goto cleanup;
    }

    sig = ECDSA_do_sign(digest, 32, eckey);
    if (sig == NULL)
    {
        error_type = e_crypto;
        goto cleanup;
    }

    ECDSA_SIG_get0(sig, &bnr, &bns);

    if (!BN_bn2binpad(bnr, r, 32))
    {
        error_type = e_crypto;
        goto cleanup;
    }

    if (!BN_bn2binpad(bns, s, 32))
    {
        error_type = e_crypto;
        goto cleanup;
    }

cleanup:
    if (sig != NULL)
        ECDSA_SIG_free(sig);
    if (eckey != NULL)
        EC_KEY_free(eckey);
    return (error_type == e_none);
}

/*==========================================================================
 * Certificate verification
 *========================================================================== */

int cert_load_file(X509 **cert, const char *filename)
{
    // FILE* fp;

    // error_type = e_none;

    // if ((fp = fopen(filename, "r")) == NULL) {
    // 	error_type = e_system;
    // 	ep = filename;
    // 	return 0;
    // }

    // *cert = PEM_read_X509(fp, NULL, NULL, NULL);
    // if (*cert == NULL)
    // 	error_type = e_crypto;

    // fclose(fp);

    // return (error_type == e_none);
    return 0;
}

X509_STORE *cert_init_ca(X509 *cert)
{
    X509_STORE *store;

    error_type = e_none;

    store = X509_STORE_new();
    if (store == NULL)
    {
        error_type = e_crypto;
        return NULL;
    }

    if (X509_STORE_add_cert(store, cert) != 1)
    {
        X509_STORE_free(store);
        error_type = e_crypto;
        return NULL;
    }

    return store;
}

/*
 * Verify cert chain against our CA in store. Assume the first cert in
 * the chain is the one to validate. Note that a store context can only
 * be used for a single verification so we need to do this every time
 * we want to validate a cert.
 */

int cert_verify(X509_STORE *store, STACK_OF(X509) * chain)
{
    X509_STORE_CTX *ctx;
    X509 *cert = sk_X509_value(chain, 0);

    error_type = e_none;

    ctx = X509_STORE_CTX_new();
    if (ctx == NULL)
    {
        error_type = e_crypto;
        return 0;
    }

    if (X509_STORE_CTX_init(ctx, store, cert, chain) != 1)
    {
        error_type = e_crypto;
        goto cleanup;
    }

    if (X509_verify_cert(ctx) != 1)
        error_type = e_crypto;

cleanup:
    if (ctx != NULL)
        X509_STORE_CTX_free(ctx);

    return (error_type == e_none);
}

/*
 * Take an array of certificate pointers and build a stack.
 */

STACK_OF(X509) * cert_stack_build(X509 **certs)
{
    X509 **pcert;
    STACK_OF(X509) * stack;

    error_type = e_none;

    stack = sk_X509_new_null();
    if (stack == NULL)
    {
        error_type = e_crypto;
        return NULL;
    }

    for (pcert = certs; *pcert != NULL; ++pcert)
        sk_X509_push(stack, *pcert);

    return stack;
}

void cert_stack_free(STACK_OF(X509) * chain)
{
    sk_X509_free(chain);
}

int hmac_sha256(const uint8_t *key, int keyLen, const uint8_t *data, int dataLen, uint8_t *hmac_result)
{
    // 输出缓冲区
    unsigned int result_len = 0;

    // 创建 HMAC 上下文
    HMAC_CTX *ctx = HMAC_CTX_new();
    if (ctx == NULL)
    {
        fprintf(stderr, "HMAC_CTX_new() failed\n");
        return 1;
    }

    // 初始化 HMAC 上下文并设置密钥和哈希函数
    if (!HMAC_Init_ex(ctx, key, keyLen, EVP_sha256(), NULL))
    {
        fprintf(stderr, "HMAC_Init_ex() failed\n");
        HMAC_CTX_free(ctx);
        return 1;
    }

    // 提供数据进行 HMAC 计算
    if (!HMAC_Update(ctx, (unsigned char *)data, dataLen))
    {
        fprintf(stderr, "HMAC_Update() failed\n");
        HMAC_CTX_free(ctx);
        return 1;
    }

    // 获取最终的 HMAC 值
    if (!HMAC_Final(ctx, hmac_result, &result_len))
    {
        fprintf(stderr, "HMAC_Final() failed\n");
        HMAC_CTX_free(ctx);
        return 1;
    }

    // // 打印 HMAC 结果
    // printf(" %d \n", result_len);
    // printf("HMAC (SHA-256) is: ");
    // for (unsigned int i = 0; i < result_len; i++)
    // {
    //     printf("%02x", hmac_result[i]);
    // }
    // printf("\n");

    // 释放 HMAC 上下文
    HMAC_CTX_free(ctx);
    return 0;
}