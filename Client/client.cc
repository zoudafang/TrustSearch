
#include <boost/thread/thread.hpp>
#include "../include/constVar.h"
#include "../include/sslConnection.h"
#include "../include/chunkStructure.h"
#include <iostream>
#include <openssl/ssl.h>
#include <openssl/ecdh.h>
#include <openssl/ec.h>
#include "../include/cryptoPrimitive.h"
#include <fstream>
#include <sys/time.h>
#include <ctime>
#include <chrono>

// #include "../include/sessionKeyExchange.h"
using namespace std;

void readData(std::string file_name, std::vector<std::pair<uint64_t, uint64_t>> &data);
void read_data_query(std::string file_name, std::vector<std::pair<uint64_t, uint64_t>> &query, int is_img_code);
void read_enc_dataset(std::string file_name, int is_query, std::vector<std::pair<uint64_t, uint64_t>> &query);
void client_query();

int main(int argc, char *argv[])
{
    uint32_t query_type = QUERY_BATCH, threshold = 8;
    int option;
    int invalid = 0, dataSet = 0;
    uint32_t test_data_len = 0;
    const char optString[] = "l:i:t:h:";

    while ((option = getopt(argc, argv, optString)) != -1)
    {
        switch (option)
        {
        case 'l':
        {
            test_data_len = atoi(optarg);
            // ecall_change_len(global_eid, atoi(optarg));
            // setTestDataLen(atoi(optarg));
            printf("test_data_len: %d\n", test_data_len);
            // test_data_len1 = test_data_len;
            break;
        }
        case 'i':
        {
            invalid = atoi(optarg);
            break;
        }
        case 't':
        {
            dataSet = atoi(optarg);
            break;
        }
        case 'h':
        {
            threshold = atoi(optarg);
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
        query_name = "../../query_img_code512_enc.bin";
        // read_data("img_code512.bin", res, targets, 0);
        break;
    }
    case 1:
    {
        query_name = "../../gistM_enc.bin";
        // read_data("gistM.bin", res, targets, 1);
        break;
    }
    case 2:
    {
        query_name = "../../siftM_enc.bin";
        // read_data("siftM.bin", res, targets, 1);
        break;
    }
    default:
        break;
    }

    vector<boost::thread *> thList;
    SSLConnection *dataSecureChannel;
    pair<int, SSL *> serverConnectionRecord;
    SSL *serverConnection;
    //     //SessionKeyExchange* sessionKeyObj;

    boost::thread *thTmp;
    boost::thread::attributes attrs;
    attrs.set_stack_size(THREAD_STACK_SIZE);
    // cryptoObj = new CryptoPrimitive(CIPHER_TYPE, HASH_TYPE);
    // EVP_MD_CTX* mdCtx = EVP_MD_CTX_new();

    //     // connect to the storage server
    dataSecureChannel = new SSLConnection(SERVER_IP,
                                          SERVER_PORT, IN_CLIENTSIDE);

    serverConnectionRecord = dataSecureChannel->ConnectSSL();
    serverConnection = serverConnectionRecord.second;
    // sessionKeyObj = new SessionKeyExchange(dataSecureChannel);
    uint32_t clientID = 1;

    // prepare the session key
    uint8_t sessionKey[CHUNK_HASH_SIZE] = {0};
    NetworkHead_t raDecision;
    raDecision.clientID = clientID;
    raDecision.messageType = SGX_RA_NOT_NEED;
    std::cout << "client success" << std::endl;
    if (!dataSecureChannel->SendData(serverConnection, (uint8_t *)&raDecision,
                                     sizeof(NetworkHead_t)))
    {
        printf("send RA_NOT_NEED fails.\n");
        exit(EXIT_FAILURE);
    }

    // test SSL send and receive
    uint8_t *data = new uint8_t[CHUNK_HASH_SIZE];
    for (int i = 0; i < CHUNK_HASH_SIZE; i++)
    {
        data[i] = i;
    }
    uint32_t dataSize = CHUNK_HASH_SIZE;
    uint64_t *testFull = new uint64_t[2];
    testFull[0] = 12390327906631358177LL;
    testFull[1] = 8489752702361977974LL;

    CryptoPrimitive *cryptoObj = new CryptoPrimitive(CIPHER_TYPE, HASH_TYPE);
    EVP_MD_CTX *mdCtx = EVP_MD_CTX_new();
    EVP_CIPHER_CTX *cipherCtx_ = EVP_CIPHER_CTX_new();
    uint8_t *sessionKey_ = const_sessionKey;

    std::vector<std::pair<uint64_t, uint64_t>> res;
    // std::vector<uint8_t> read_data;

    read_enc_dataset(query_name, 1, res);

    // // readData("../../query_img_code512.bin", res);
    // // read_data_query("../../siftM.bin", res, 0);
    // read_data_query("../../query_img_code512.bin", res, 1);
    // // read_data_query("../../tmp_test.bin", res, 1);

    // std::chrono::steady_clock::time_point startTime2, endTime2;
    // std::chrono::duration<double> duration2;
    // startTime2 = std::chrono::steady_clock::now();

    //-------test query and receive ,batch query------
    uint32_t query_num = 1000, query_size = sizeof(uint64_t) * query_num * 2;
    uint64_t *encData = new uint64_t[query_num * 2];

    srand(time(NULL));

    // uint32_t batch_size = 530, nums = floor(1.0 * test_data_len / batch_size);
    // uint32_t index1 = 0;
    // uint32_t end = res.size();
    // vector<pair<uint64_t, uint64_t>> test_pool;
    // nums = (nums < 1000 ? nums : 1000);
    // // if (!is_invalid)
    // {
    //     while (1)
    //     {
    //         for (int i = 0; i < nums; i++)
    //         {
    //             if (test_pool.size() < 1000)
    //                 test_pool.push_back(res[i]);
    //             else
    //                 goto ends;
    //         }
    //     }
    // ends:
    //     nums++;
    // }
    // for (int i = 0; i < 1000; i++)
    // {
    //     encData[i * 2] = test_pool[i].first;
    //     encData[i * 2 + 1] = test_pool[i].second;
    // }

    SendMsgBuffer_t sendMsgBuffer;
    sendMsgBuffer.sendBuffer = (uint8_t *)malloc(sizeof(NetworkHead_t) + sizeof(uint64_t) * query_num * 2);
    sendMsgBuffer.dataBuffer = sendMsgBuffer.sendBuffer + sizeof(NetworkHead_t);
    sendMsgBuffer.header = (NetworkHead_t *)sendMsgBuffer.sendBuffer;
    sendMsgBuffer.header->clientID = clientID;

    std::chrono::steady_clock::time_point startTime2, endTime2;
    std::chrono::duration<double> duration2;

    std::chrono::steady_clock::time_point startTimeE, endTimeE, startTimeE2, endTimeE2, startTimeS, endTimeS;
    std::chrono::duration<double> durationE, durationE2, total_time;
    startTimeE = std::chrono::steady_clock::now();
    NetworkHead_t *head = new NetworkHead_t();
    uint32_t size;
    // dataSecureChannel->ReceiveData(serverConnection, (uint8_t *)head, size);
    // if (head->messageType != SERVER_RUN)
    // {
    //     printf("error\n");
    //     exit(0);
    // }

    for (int h = 0; h < 2; h++)
    {
        total_time = std::chrono::duration<double>::zero();
        for (int index = 0; index < res.size(); index++)
        {
            if (index < query_num)
            {
                encData[index * 2] = res[index].first;
                encData[index * 2 + 1] = res[index].second;
            }
            else
            {
                int j = rand() % (index + 1);
                if (j < query_num)
                {
                    encData[j * 2] = res[index].first;
                    encData[j * 2 + 1] = res[index].second;
                }
            }
            // printf("encData[%d]=%llu\n", i, encData[i]);
        }

        cryptoObj->SessionKeyEnc(cipherCtx_, (uint8_t *)encData, query_size, sessionKey_, (uint8_t *)encData);

        memcpy(sendMsgBuffer.dataBuffer, encData, query_size);

        startTime2 = std::chrono::steady_clock::now(); // 记录开始时间
        sendMsgBuffer.header->messageType = QUERY_BATCH;
        sendMsgBuffer.header->dataSize = query_size;

        threshold = 4 + (h) * 4; // >> 1
        sendMsgBuffer.header->hammdist = threshold;

        dataSecureChannel->SendData(serverConnection, sendMsgBuffer.sendBuffer, sizeof(NetworkHead_t) + sendMsgBuffer.header->dataSize);

        int res_len = query_num * QUERY_SIZE;
        if (threshold > 24) // the result imgs will increase with the hamming distance
        {
            res_len = query_num * 6300;
        }
        if (threshold > 30)
        {
            res_len = query_num * 17000;
        }

        uint8_t *data2 = new uint8_t[res_len * sizeof(uint32_t)];

        startTimeS = std::chrono::steady_clock::now();

        dataSecureChannel->ReceiveData(serverConnection, data2, dataSize);

        endTimeS = std::chrono::steady_clock::now();
        durationE = endTimeS - startTimeS; // 计算持续时间
        printf("send time：%f秒\n", durationE.count());
        startTimeE2 = std::chrono::steady_clock::now();

        cryptoObj->SessionKeyDec(cipherCtx_, (uint8_t *)data2, dataSize, sessionKey_, (uint8_t *)data2);

        endTimeE2 = std::chrono::steady_clock::now();
        durationE2 = endTimeE2 - startTimeE2; // 计算持续时间
        printf("dec time：%f秒\n", durationE2.count());

        Query_batch_t query_batch;
        query_batch.sendData = (uint32_t *)data2;

        int query_num = query_batch.sendData[0];
        query_batch.index = query_batch.sendData + sizeof(uint32_t);
        query_batch.dataBuffer = query_batch.index + query_num * sizeof(uint32_t);
        printf("query_num=%d \n", query_num);
        int successful_num = 0;
        for (int i = 0; i < query_num; i++)
        {
            successful_num += query_batch.index[i];
            for (int j = 0; j < query_batch.index[i]; j++)
            {
                // printf("n: %u",query_batch.dataBuffer[i]);
            }
        }
        endTime2 = std::chrono::steady_clock::now(); // 记录结束时间
        duration2 = endTime2 - startTime2;           // 计算持续时间
        printf("hamming %d success_num:%d,函数运行时间：%f秒\n", sendMsgBuffer.header->hammdist, successful_num, duration2.count());

        delete[] data2;
    }

    free(sendMsgBuffer.sendBuffer);
    if (1)
    {
        head->messageType = KILL_SERVER;
        dataSecureChannel->SendData(serverConnection, (uint8_t *)head, sizeof(NetworkHead_t));
    }
    //     //sessionKeyObj->GeneratingSecret(sessionKey, serverConnection, clientID);

    // dataSenderObj = new DataSender(dataSecureChannel);
    //         dataSenderObj->SetConnectionRecord(serverConnectionRecord);
    //         dataSenderObj->SetSessionKey(sessionKey, CHUNK_HASH_SIZE);

    //    // thTmp = new boost::thread(attrs, boost::bind(&DataSender::Run, dataSenderObj));
    //     //        thList.push_back(thTmp);

    //     // for (auto it : thList) {
    //     //             it->join();
    //     //         }

    //     // for (auto it : thList) {
    //     //             delete it;
    //     //         }
    //     // delete chunkerObj;
    //     //         delete dataSenderObj;
    //     //         delete chunker2SenderMQ;
    //     //         thList.clear();

    //     // EVP_MD_CTX_free(mdCtx);
    //     // delete cryptoObj;
    //     // delete sessionKeyObj;
    //     delete dataSecureChannel;
}
void readData(std::string file_name, std::vector<std::pair<uint64_t, uint64_t>> &data)
{
    std::ifstream input(file_name, std::ios::binary);
    uint64_t high, low;
    uint32_t target;
    while (input.read(reinterpret_cast<char *>(&high), sizeof(high)) && input.read(reinterpret_cast<char *>(&low), sizeof(low)))
    {
        data.emplace_back(high, low);
        input.read(reinterpret_cast<char *>(&target), sizeof(target)); // read the target of sign_data
        input.read(reinterpret_cast<char *>(&target), sizeof(target));
    }
    input.close();
}

void read_data_query(std::string file_name, std::vector<std::pair<uint64_t, uint64_t>> &query, int is_img_code)
{
    std::ifstream input(file_name, std::ios::binary);
    uint64_t high, low;
    uint32_t target;
    uint32_t data_len = 1000000;
    if (is_img_code)
    {
        while (input.read(reinterpret_cast<char *>(&high), sizeof(high)) && input.read(reinterpret_cast<char *>(&low), sizeof(low)))
        {
            query.emplace_back(high, low);
            input.read(reinterpret_cast<char *>(&high), sizeof(high));
        }
    }
    else
    {
        uint32_t read_len = 0;
        while (read_len < data_len && input.read(reinterpret_cast<char *>(&high), sizeof(high)) && input.read(reinterpret_cast<char *>(&low), sizeof(low)))
        {
            read_len++;
        }
        while (input.read(reinterpret_cast<char *>(&high), sizeof(high)) && input.read(reinterpret_cast<char *>(&low), sizeof(low)))
        { // query.size() < test_data_len &&
            query.push_back({high, low});
        }
    }
    input.close();
}

void read_enc_dataset(std::string file_name, int is_query, std::vector<std::pair<uint64_t, uint64_t>> &query)
{

    EVP_MD_CTX *mdCtx = EVP_MD_CTX_new();
    EVP_CIPHER_CTX *cipherCtx_ = EVP_CIPHER_CTX_new();
    uint8_t *sessionKey_ = const_sessionKey;
    auto cryptoObj = new CryptoPrimitive(CIPHER_TYPE, HASH_TYPE);

    int is_img512_dataset = 0, sift_len = SIFT_LEN;
    if (file_name.find("img") != std::string::npos)
    {
        is_img512_dataset = 1;
    }
    std::ifstream input(file_name, std::ios::binary);
    vector<uint8_t> read_data;
    uint8_t *enc_data;
    uint8_t tmp;
    uint32_t batch_size = (is_img512_dataset == 1) ? (ENC_BATCH_SIZE_IMG) : (ENC_BATCH_SIZE_SIFT);

    int i, tmp_size, skip_len = 0;
    if (is_query && !is_img512_dataset)
    {
        skip_len = SIFT_LEN * sizeof(uint64_t) * 2;
    }

    while (1)
    {
        for (i = 1; i <= batch_size; i++)
        {
            if (input.read(reinterpret_cast<char *>(&tmp), sizeof(tmp)))
                read_data.push_back(tmp);
            else
                break;
        }
        tmp_size = (i >= batch_size) ? (batch_size) : (i - 1);
        skip_len -= tmp_size;
        if (tmp_size == 0)
            break;

        uint8_t *dataE = read_data.data();
        cryptoObj->SessionKeyDec(cipherCtx_, dataE,
                                 tmp_size, sessionKey_,
                                 dataE);
        if (skip_len < 0)
        {
            int idx = 0;
            uint64_t key1, key2;
            while (idx < batch_size)
            {
                key1 = *(uint64_t *)(dataE + idx);
                idx += sizeof(uint64_t);

                key2 = *(uint64_t *)(dataE + idx);
                idx += sizeof(uint64_t);

                query.push_back({key1, key2});
                if (is_img512_dataset == 1)
                    idx += sizeof(uint64_t); // skip img's target 32bit
            }
        }
        if (tmp_size < batch_size)
            break;
        read_data.clear();
    }
    input.close();
    printf("size of query: %d\n", query.size());
    EVP_MD_CTX_free(mdCtx);
    EVP_CIPHER_CTX_free(cipherCtx_);
}
