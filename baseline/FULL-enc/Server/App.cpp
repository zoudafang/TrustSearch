

#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <unistd.h>
#include <pwd.h>
#define MAX_PATH FILENAME_MAX

#include "App.h"
#include <ctime>
#include <openssl/ssl.h>
#include <openssl/ecdh.h>
#include <openssl/ec.h>
#include <signal.h>
#include <boost/thread/thread.hpp>
#include "../include/sslConnection.h"
#include <openssl/ssl.h>
#include <ctime>

#include <iostream>
#include <typeinfo>
#include "emp-tool/emp-tool.h"
#include "emp-ot/emp-ot.h"
#include "emp-sh2pc/emp-sh2pc.h"
#include "emp-sh2pc/semihonest.h"
#include "emp-sh2pc/sh_party.h"

using namespace emp;

void init_CS_Server()
{
    Integer as;
    int port = GC_SERVER_PORT, party = ALICE;
    NetIO *io = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);
    setup_semi_honest(io, party);
    long long int x1;
    Integer X1, X2, R1, R2;
    Integer tmp, a, b, a2, b2;
    uint8_t tmps[MASK_R_BIT] = {0};
    ZZ fullkey, fullkey_q, candEnc, candEnc_q;
    ZZ n, lambda, lambdaV;

    //
    {
        int len = KEY_BIT * 4;
        ZZ tmp;
        uint8_t *bytel = new uint8_t[len];

        memset(bytel, 0, len);
        io->recv_data(bytel, len);
        n = ZZFromBytes(bytel, len);
        memset(bytel, 0, len);
        io->recv_data(bytel, len);
        lambda = ZZFromBytes(bytel, len);
        memset(bytel, 0, len);
        io->recv_data(bytel, len);
        lambdaV = ZZFromBytes(bytel, len);
        // cout << "n " << n << endl;
        // cout << "l " << lambda << endl;
        // cout << "lv " << lambdaV << endl;
    }
    while (1)
    {
        memset(tmps, 0, MASK_R_BIT);
        io->recv_data(tmps, MASK_R_BIT);
        fullkey = ZZFromBytes(tmps, 256);
        fullkey = decrypt(fullkey, n, lambda, lambdaV);

        memset(tmps, 0, MASK_R_BIT);
        io->recv_data(tmps, MASK_R_BIT);
        fullkey_q = ZZFromBytes(tmps, 256);

        fullkey_q = decrypt(fullkey_q, n, lambda, lambdaV);
        // cout << "fullkey " << fullkey << endl;
        // cout << "fullkey_q " << fullkey_q << endl;

        memset(tmps, 0, MASK_R_BIT);
        ZZToBytes(fullkey, tmps);
        a = Integer(MASK_R_BIT, tmps, ALICE); // x1
        b = Integer(MASK_R_BIT, tmps, BOB);   //

        memset(tmps, 0, MASK_R_BIT);
        ZZToBytes(fullkey_q, tmps);
        a2 = Integer(MASK_R_BIT, tmps, ALICE); // x2
        b2 = Integer(MASK_R_BIT, tmps, BOB);   //

        auto res = a.SubHammDist(a, a2, b, b2);

        x1 = res.reveal<int>(PUBLIC);
    }
    finalize_semi_honest();
    delete io;
};

/* Application entry */
int main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);

    uint32_t threshold = 8, dataSet = 0;
    int option;
    int invalid = 0, gc = 0;
    const char optString[] = "h:t:s:";

    while ((option = getopt(argc, argv, optString)) != -1)
    {
        switch (option)
        {
        case 'h':
        {
            threshold = atoi(optarg);
            break;
        }
        case 't':
        {
            dataSet = atoi(optarg);
            break;
        }
        case 's':
        {
            gc = atoi(optarg);
            break;
        }
        break;
        }
    }

    // printf("read len %d\n", read_data.size());
    // init_after_send_data(db, dataSet);
    if (gc)
    {
        init_CS_Server();
    }

    std::string data_name, query_name;
    switch (dataSet)
    {
    case 0:
    {
        data_name = "../../dataset/img_code512_enc.bin";
        query_name = "../../dataset/query_img_code512_enc.bin";
        break;
    }
    case 1:
    {
        data_name = "../../dataset/gistM_enc.bin";
        query_name = "../../dataset/gistM_enc.bin";
        break;
    }
    case 2:
    {
        data_name = "../../dataset/siftM_enc.bin";
        query_name = "../../dataset/siftM_enc.bin";
        break;
    }
    default:
        break;
    }
    std::vector<std::pair<uint64_t, uint64_t>> res;
    std::vector<uint32_t> targets;
    std::vector<uint8_t> read_data;
    int dataSize;
    read_enc_dataset(data_name, read_data, 0);
    printf("read len %d\n", read_data.size());
    auto db = partEncData(read_data, dataSet);
    read_data.clear();
    read_enc_dataset(query_name, read_data, 1);

    // {
    //     uint8_t tmp;
    //     // vector<uint8_t> read_data;
    //     read_data.clear();
    //     std::ifstream input("../../dataset/gistM.bin", std::ios::binary);
    //     for (int i = 0; i < 1000000 * 16; i++)
    //     {
    //         (input.read(reinterpret_cast<char *>(&tmp), sizeof(tmp)));
    //         // if (i >= 16 * 1000)
    //         // read_data.push_back(tmp);
    //     }
    //     while (input.read(reinterpret_cast<char *>(&tmp), sizeof(tmp)))
    //     {
    //         read_data.push_back(tmp);
    //     }
    //     input.close();
    //     read_data.resize(16000);
    // }
    printf("read len %d\n", read_data.size());
    init_test_query(read_data);

    init_after_send_data(db, dataSet);

    clock_t startTime, endTime;
    double costTime;
    // for (int i = 0; i < 1; i++)
    // {
    //     for (int t = 0; t < 2; t++)
    //     {
    //         // ecall_change_para(global_eid, dataSet, 8 + 4 * t, clr_size, clr_dist, comb_num, aggre_size, kmodes, steps, is_var, ktimes);
    //         startTime = clock();
    //         endTime = clock();
    //         costTime = double(endTime - startTime) / CLOCKS_PER_SEC;
    //         printf("The test took %lf seconds.\n", costTime);
    //     }
    // }
    start_server(); // 启动server

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
