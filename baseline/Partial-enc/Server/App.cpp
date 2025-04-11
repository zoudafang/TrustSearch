

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

/* Application entry */
int main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);

    uint32_t threshold = 8, dataSet = 0;
    int option;
    int invalid = 0;
    const char optString[] = "h:t:";

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
        break;
        }
    }

    std::string data_name, query_name;
    switch (dataSet)
    {
    case 0:
    {
        data_name = "../../dataset/img_code512_enc.bin";
        query_name = "query_img_code512_enc.bin";
        break;
    }
    case 1:
    {
        data_name = "../../dataset/gistM_enc.bin";
        query_name = "gistM_enc.bin";
        break;
    }
    case 2:
    {
        data_name = "../../dataset/siftM_enc.bin";
        query_name = "siftM_enc.bin";
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
    auto db = partEncData(read_data, dataSet);
    read_data.clear();
    // read_enc_dataset(query_name, read_data, 1);

    printf("read len %d\n", read_data.size());
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
