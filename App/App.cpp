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
// #include "../include/constVar.h"
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
    {SGX_ERROR_MEMORY_MAP_FAILURE,
     "Failed to reserve memory for the enclave.",
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

uint32_t test_data_len = 0;
void start_server();
void write_querys(std::vector<std::pair<uint64_t, uint64_t>> &test);
/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    uint32_t query_type = QUERY_BATCH, threshold = 8;
    int option;
    int invalid = 0;
    const char optString[] = "l:i:";

    while ((option = getopt(argc, argv, optString)) != -1)
    {
        // l:len of data_test; i: 0=test invalid 1=valid 2,3=test time
        switch (option)
        {
        case 'l':
        {
            test_data_len = atoi(optarg);
            // setTestDataLen(atoi(optarg));
            printf("test_data_len: %d\n", test_data_len);
            // test_data_len1 = test_data_len;
        }
        case 'i':
        {
            invalid = atoi(optarg);
            break;
        }
        break;
        }
    }
    ecall_change_len(global_eid, test_data_len, invalid);

    (void)(argc);
    (void)(argv);

    /* Initialize the enclave */
    if (initialize_enclave() < 0)
    {
        printf("Enter a character before exit ...\n");
        getchar();
        return -1;
    }

    std::vector<std::pair<uint64_t, uint64_t>> res;
    std::vector<uint32_t> targets;
    std::vector<std::pair<uint64_t, uint64_t>> test_data;

    //----read gist1M and sift1M-----
    // read_data("siftM.bin", res, targets, 1); //
    // // change!!!
    // init_from_enclave();
    // send_data(res, targets, 0);
    // res.clear();
    // targets.clear();
    // read_data_query("siftM.bin", res, 0);
    // send_data(res, targets, 1);

    // //----read img_code512.bin-----暂时，因为query*.bin没有包括target，所以读取方式不一样 (如果运行时的data长度小于500w，使用query的效果不好)
    // read_data("img_code512.bin", res, targets, 0);
    // init_from_enclave();
    // send_data(res, targets, 0);
    // res.clear();
    // targets.clear();
    // read_data("query_img_code512.bin", res, targets, 1);
    // send_data(res, targets, 1);
    // printf("success\n");

    // init_test_pool(global_eid);

    printf("test_data_len: %d\n", test_data_len);
    init_from_enclave();
    printf("test_data_len: %d\n", test_data_len);
    std::vector<uint32_t> masks;
    prepare(2, masks);
    printf("test_data_len: %d\n", test_data_len);
    get_rand_keys(masks, res, test_data, invalid);
    printf("test_data_len: %d res %d\n", test_data.size(), res.size());

    send_data(res, targets, 0);
    send_data(test_data, targets, 1);
    init_test_pool(global_eid);
    write_querys(test_data);

    clock_t startTime = clock();
    // test_from_enclave();
    clock_t endTime = clock();

    double costTime = double(endTime - startTime) / CLOCKS_PER_SEC;
    printf("The test took %lf seconds.\n", costTime);
    start_server();

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

    FILE *file = fopen("app.log", "w+"); // 写入模式，覆盖现有内容
    if (file)
    {
        const char *data = "start server successful";
        fprintf(file, "%s\n", data); // 使用fprintf直接写入格式化的字符串，这里是添加一个换行符
        fclose(file);
    }
    else
    {
        const char *data = "start server error";
        fprintf(file, "%s\n", data);
        fclose(file);
    }

    printf("start server successful\n");

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

void write_querys(std::vector<pair<uint64_t, uint64_t>> &test)
{
    std::ofstream output("tmp_test.bin", std::ios::binary);
    int i = 0;
    for (const auto &pair : test)
    {
        output.write(reinterpret_cast<const char *>(&pair.first), sizeof(pair.first));
        output.write(reinterpret_cast<const char *>(&pair.second), sizeof(pair.second));
        // output.write(reinterpret_cast<const char *>(&targets[i]), sizeof(targets[i]));
        // i++;
    }
    output.close();
}

void write_dimension(void *data)
{
    uint32_t *dimension = (uint32_t *)data;
    std::ofstream outputFile("output.txt"); // 打开输出文件

    if (outputFile.is_open())
    {

        for (int i = 0; i < 128; i++)
        {
            outputFile << dimension[i] << std::endl; // 将每个元素写入文件，每个元素占据一行
        }

        outputFile.close(); // 关闭文件
        std::cout << "写入成功" << std::endl;
    }
    else
    {
        std::cout << "无法打开文件" << std::endl;
    }
    return;
}