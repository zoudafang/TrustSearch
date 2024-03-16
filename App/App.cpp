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

#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <unistd.h>
#include <pwd.h>
#define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"
#include <ctime>

#include <openssl/ssl.h>
#include <openssl/ecdh.h>
#include <openssl/ec.h>
#include <signal.h>
#include <boost/thread/thread.hpp>
#include "../include/constVar.h"
#include "../include/serverOptThead.h"
#include "../include/sslConnection.h"
#include <openssl/ssl.h>
/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t
{
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {SGX_ERROR_UNEXPECTED,
     "Unexpected error occurred.",
     NULL},
    {SGX_ERROR_INVALID_PARAMETER,
     "Invalid parameter.",
     NULL},
    {SGX_ERROR_OUT_OF_MEMORY,
     "Out of memory.",
     NULL},
    {SGX_ERROR_ENCLAVE_LOST,
     "Power transition occurred.",
     "Please refer to the sample \"PowerTransition\" for details."},
    {SGX_ERROR_INVALID_ENCLAVE,
     "Invalid enclave image.",
     NULL},
    {SGX_ERROR_INVALID_ENCLAVE_ID,
     "Invalid enclave identification.",
     NULL},
    {SGX_ERROR_INVALID_SIGNATURE,
     "Invalid enclave signature.",
     NULL},
    {SGX_ERROR_OUT_OF_EPC,
     "Out of EPC memory.",
     NULL},
    {SGX_ERROR_NO_DEVICE,
     "Invalid SGX device.",
     "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."},
    {SGX_ERROR_MEMORY_MAP_CONFLICT,
     "Memory map conflicted.",
     NULL},
    {SGX_ERROR_INVALID_METADATA,
     "Invalid enclave metadata.",
     NULL},
    {SGX_ERROR_DEVICE_BUSY,
     "SGX device was busy.",
     NULL},
    {SGX_ERROR_INVALID_VERSION,
     "Enclave version was invalid.",
     NULL},
    {SGX_ERROR_INVALID_ATTRIBUTE,
     "Enclave was not authorized.",
     NULL},
    {SGX_ERROR_ENCLAVE_FILE_ACCESS,
     "Can't open enclave file.",
     NULL},
    {SGX_ERROR_NDEBUG_ENCLAVE,
     "The enclave is signed as product enclave, and can not be created as debuggable enclave.",
     NULL},
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist / sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++)
    {
        if (ret == sgx_errlist[idx].err)
        {
            if (NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }

    if (idx == ttl)
        printf("Error: Unexpected error occurred.\n");
}

/* Initialize the enclave:
 *   Call sgx_create_enclave to initialize an enclave instance
 */
int initialize_enclave(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS)
    {
        print_error_message(ret);
        return -1;
    }

    return 0;
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate
     * the input string to prevent buffer overflow.
     */
    printf("%s", str);
}
void ocall_get_timeNow(uint64_t *time)
{
    std::chrono::high_resolution_clock::time_point t2 = std::chrono::high_resolution_clock::now();
    long long nanosSinceEpoch = std::chrono::duration_cast<std::chrono::nanoseconds>(t2.time_since_epoch()).count();
    *time = static_cast<uint64_t>(nanosSinceEpoch);
}

void start_server();
/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);

    /* Initialize the enclave */
    if (initialize_enclave() < 0)
    {
        printf("Enter a character before exit ...\n");
        getchar();
        return -1;
    }

    uint32_t threshold = 8, clr_size = 100, clr_dist = 5, dataSet = 0, comb_num = 50, aggre_size = 50, cache = 20000;
    int option;
    int invalid = 0;
    const char optString[] = "h:s:d:t:l:c:v:b:n:m:";
    int kmodes = 50, steps = 20, is_var = 1;
    float ktimes = 0.5;

    while ((option = getopt(argc, argv, optString)) != -1)
    {
        switch (option)
        {
        case 'h':
        {
            threshold = atoi(optarg);
            break;
        }
        case 's':
        {
            clr_size = atoi(optarg);
            break;
        }
        case 'd':
        {
            clr_dist = atoi(optarg);
            break;
        }
        case 't':
        {
            dataSet = atoi(optarg);
            break;
        }
        case 'l':
        {
            comb_num = atoi(optarg);
            break;
        }
        case 'c':
        {
            aggre_size = atoi(optarg);
            break;
        }
        case 'v':
        {
            kmodes = atoi(optarg);
            break;
        }
        case 'b':
        {
            steps = atoi(optarg);
            break;
        }
        case 'n':
        {
            is_var = atoi(optarg);
            break;
        }
        case 'm':
        {
            ktimes = atof(optarg);
            break;
        }
        break;
        }
    }
    ecall_change_para(global_eid, dataSet, threshold, clr_size, clr_dist, comb_num, aggre_size, kmodes, steps, is_var, ktimes);

    std::vector<std::pair<u_int64_t, u_int64_t>> res;
    std::vector<uint32_t> targets;

    Partition_IDs id_index[SUBINDEX_NUM];
    int tmps[3] = {1, 2, 3};
    for (int i = 0; i < SUBINDEX_NUM; i++)
        ecall_init_id_index(global_eid, &id_index[i], i);
    std::string data_name, query_name;
    switch (dataSet)
    {
    case 0:
    {
        data_name = "img_code512_enc.bin";
        query_name = "query_img_code512_enc.bin";
        // read_data("img_code512.bin", res, targets, 0);
        break;
    }
    case 1:
    {
        data_name = "gistM_enc.bin";
        query_name = "gistM_enc.bin";
        // read_data("gistM.bin", res, targets, 1);
        break;
    }
    case 2:
    {
        data_name = "siftM_enc.bin";
        query_name = "siftM_enc.bin";
        // read_data("siftM.bin", res, targets, 1);
        break;
    }
    default:
        break;
    }

    // two read_data's flag: {0,0} for img512, {1,2} for siftM,gistM, {1,1} for sift1B
    //  read_data("../sift1B_data.bin", res, targets, 1);
    // read_data("gistM.bin", res, targets, 1);
    // read_data("img_code512.bin", res, targets, 0);

    // printf("%llu %llu\n", res[0], res[1]);
    // change!!!
    init_from_enclave();
    // send_data(res, targets, 0);

    // enc_data_set("gistM.bin"); // 在使用加密的数据集之前-enc,调用该函数对明文数据集进行加密

    read_enc_dataset(data_name, 0);
    read_enc_dataset(query_name, 1);

    res.clear();
    targets.clear();
    // switch (dataSet)
    // {
    // case 0:
    // {
    //     read_data("query_img_code512.bin", res, targets, 0);
    //     break;
    // }
    // case 1:
    // {
    //     read_data("gistM.bin", res, targets, 2);
    //     break;
    // }
    // case 2:
    // {
    //     read_data("siftM.bin", res, targets, 2);
    //     break;
    // }
    // default:
    //     break;
    // }
    // read_data("../sift1B_query.bin", res, targets, 1);
    // read_data("gistM.bin", res, targets, 2);
    // read_data("query_img_code512.bin", res, targets, 0);

    // send_data(res, targets, 1);

    init_after_send_data();

    clock_t startTime = clock();
    // test_from_enclave();
    clock_t endTime = clock();

    double costTime = double(endTime - startTime) / CLOCKS_PER_SEC;
    printf("The test took %lf seconds.\n", costTime);

    for (int i = 0; i < 1; i++)
    {
        for (int t = 0; t < 3; t++)
        { // 12+8*t
            ecall_change_para(global_eid, dataSet, 8 + 4 * t, clr_size, clr_dist, comb_num, aggre_size, kmodes, steps, is_var, ktimes);
            startTime = clock();
            test_from_enclave();
            endTime = clock();
            costTime = double(endTime - startTime) / CLOCKS_PER_SEC;
            printf("The test took %lf seconds.\n", costTime);
        }
    }
    // start_server();//启动server

    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);

    printf("Info: Cxx14DemoEnclave successfully returned.\n");

    return 0;
}

void start_server()
{
    SSLConnection *dataSecurityChannelObj;
    vector<boost::thread *> thList;
    ServerOptThread *serverThreadObj;
    boost::thread *thTmp;
    boost::thread_attributes attrs;
    attrs.set_stack_size(THREAD_STACK_SIZE);

    dataSecurityChannelObj = new SSLConnection(SERVER_IP,
                                               SERVER_PORT, IN_SERVERSIDE);

    // init
    serverThreadObj = new ServerOptThread(dataSecurityChannelObj, 1);

    /**
     * |---------------------------------------|
     * |Finish the initialization of the server|
     * |---------------------------------------|
     */

    while (true)
    {
        // tool::Logging(myName.c_str(), "waiting the request from the client.\n");
        SSL *clientSSL = dataSecurityChannelObj->ListenSSL().second;
        thTmp = new boost::thread(attrs, boost::bind(&ServerOptThread::Run, serverThreadObj,
                                                     clientSSL));
        thList.push_back(thTmp);
    }

    return;
}
