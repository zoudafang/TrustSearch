/**
 * @file serverOptThread.cc
 * @author Zuoru YANG (zryang@cse.cuhk.edu.hk)
 * @brief server main thread
 * @version 0.1
 * @date 2021-07-11
 *
 * @copyright Copyright (c) 2021
 *
 */

#include "../include/serverOptThead.h"

/**
 * @brief Construct a new Server Opt Thread object
 *
 * @param dataSecureChannel data security communication channel
 * @param fp2ChunkDB the index
 * @param eidSGX sgx enclave id
 * @param indexType
 */
ServerOptThread::ServerOptThread(SSLConnection *dataSecureChannel,
                                 int indexType)
{
    dataSecureChannel_ = dataSecureChannel;
    indexType_ = indexType;
}

/**
 * @brief Destroy the Server Opt Thread object
 *
 */
ServerOptThread::~ServerOptThread()
{
}

/**
 * @brief the main process
 *
 * @param clientSSL the client ssl
 */
void ServerOptThread::Run(SSL *clientSSL)
{
    boost::thread *thTmp;
    boost::thread_attributes attrs;
    attrs.set_stack_size(THREAD_STACK_SIZE);
    vector<boost::thread *> thList;
    EnclaveInfo_t enclaveInfo;

    SendMsgBuffer_t recvBuf;
    recvBuf.sendBuffer = (uint8_t *)malloc(sizeof(NetworkHead_t) + SESSION_KEY_BUFFER_SIZE);
    recvBuf.header = (NetworkHead_t *)recvBuf.sendBuffer;
    recvBuf.header->dataSize = 0;
    recvBuf.dataBuffer = recvBuf.sendBuffer + sizeof(NetworkHead_t);
    uint32_t recvSize = 0;

#if (ENABLE_SGX_RA == 1)
    // check whether do remote attestation
    if (!dataSecureChannel_->ReceiveData(clientSSL, recvBuf.sendBuffer, recvSize))
    {
        // tool::Logging(myName_.c_str(), "recv RA decision fails.\n");
        exit(EXIT_FAILURE);
    }
    sgx_ra_context_t raCtx;
    switch (recvBuf.header->messageType)
    {
    case SGX_RA_NEED:
    {
        raUtil_->DoAttestation(eidSGX_, raCtx, clientSSL);
        if (!dataSecureChannel_->ReceiveData(clientSSL, recvBuf.sendBuffer, recvSize))
        {
            // tool::Logging(myName_.c_str(), "client closed socket connect, RA finish.\n");
            dataSecureChannel_->ClearAcceptedClientSd(clientSSL);
        }
        free(recvBuf.sendBuffer);
        return;
    }
    case SGX_RA_NOT_NEED:
    {
        break;
    }
    default:
    {
        // tool::Logging(myName_.c_str(), "wrong RA request type.\n");
        exit(EXIT_FAILURE);
    }
    }

#else
    // wait the RA request
    if (!dataSecureChannel_->ReceiveData(clientSSL, recvBuf.sendBuffer, recvSize))
    {
        exit(EXIT_FAILURE);
    }
    switch (recvBuf.header->messageType)
    {
    case SGX_RA_NOT_SUPPORT:
    {
        // cannot perform RA
        if (!dataSecureChannel_->ReceiveData(clientSSL, recvBuf.sendBuffer,
                                             recvSize))
        {
            dataSecureChannel_->ClearAcceptedClientSd(clientSSL);
        }
        free(recvBuf.sendBuffer);
        return;
    }
    case SGX_RA_NOT_NEED:
    {
        printf("RA not need.\n");
        // does not need to perform RA
        break;
    }
    default:
    {
        exit(EXIT_FAILURE);
    }
    }
#endif

    uint8_t *data = new uint8_t[CHUNK_HASH_SIZE];
    uint32_t *resData = new uint32_t[QUERY_SIZE];
    uint32_t *len = new uint32_t[1];
    uint64_t *testFull = new uint64_t[2];
    uint32_t dataSize = 0;
    SendMsgBuffer_t sendBuf;
    sendBuf.sendBuffer = (uint8_t *)malloc(sizeof(NetworkHead_t) + QUERY_SIZE * sizeof(uint64_t));
    sendBuf.dataBuffer = sendBuf.sendBuffer + sizeof(NetworkHead_t);
    sendBuf.header = (NetworkHead_t *)sendBuf.sendBuffer;

    while (true)
    {
        // test reply client's query
        if (!dataSecureChannel_->ReceiveData(clientSSL, sendBuf.sendBuffer, dataSize))
            break;
        sendBuf.header = (NetworkHead_t *)sendBuf.sendBuffer;
        switch (sendBuf.header->messageType)
        {
        case QUERY_ONE:
        {
            printf("dataSize:%d,type%d\n", sendBuf.header->dataSize, sendBuf.header->messageType);

            uint64_t *temp = (uint64_t *)sendBuf.dataBuffer;
            testFull[0] = temp[0];
            testFull[1] = temp[1];
            // ecall to find the answer of the query

            uint64_t hammdist = sendBuf.header->hammdist;
            uint32_t res_len = QUERY_SIZE;
            sgx_status_t t = ecall_find_one(global_eid, testFull, resData, &res_len, QUERY_SIZE, hammdist);
            // printf("len:%d\n", t);
            // uint32_t *resData2 = new uint32_t[*len];
            // for (int i = 0; i < *len; i++)
            // {
            //     resData2[i] = resData[i];
            // }
            // uint8_t *resData3 = (uint8_t *)resData2;

            // send the answer to client
            dataSecureChannel_->SendData(clientSSL, (uint8_t *)resData, res_len);
            break;
        }
        case QUERY_BATCH:
        {
            uint64_t *temp = (uint64_t *)sendBuf.dataBuffer;
            uint64_t hammdist = sendBuf.header->hammdist;
            printf("dist:%d\n", hammdist);
            uint32_t dataLen = sendBuf.header->dataSize / sizeof(uint64_t) / 2;
            testFull = new uint64_t[dataLen * 2];
            memcpy(testFull, temp, dataLen * 2 * sizeof(uint64_t));

            // encall to find the answer of the query
            int res_len = dataLen * QUERY_SIZE;
            if (hammdist > 24) // the result imgs will increase with the hamming distance
            {
                res_len = dataLen * 6300;
            }
            if (hammdist > 30)
            {
                res_len = dataLen * 20000;
            }
            Query_batch_t queryBatch;
            queryBatch.sendData = new uint32_t[res_len];

            std::chrono::steady_clock::time_point startTime2, endTime2;
            std::chrono::duration<double> duration2;
            startTime2 = std::chrono::steady_clock::now(); // 记录开始时间
            sgx_status_t t = ecall_find_batch(global_eid, testFull, queryBatch.sendData, dataLen, res_len, hammdist);

            endTime2 = std::chrono::steady_clock::now();
            duration2 = endTime2 - startTime2; // 计算持续时间
            printf("函数运行时间：%f秒\n", duration2.count());
            // send the answer to client
            dataSecureChannel_->SendData(clientSSL, (uint8_t *)queryBatch.sendData, res_len * 4);

            // exit(EXIT_FAILURE); // cautious kill
            delete[] queryBatch.sendData;
            break;
        }
        case QUERY_KNN:
        {
            uint64_t *temp = (uint64_t *)sendBuf.dataBuffer;
            uint64_t knn_num = sendBuf.header->hammdist;
            printf("dist:%d\n", knn_num);
            uint32_t dataLen = sendBuf.header->dataSize / sizeof(uint64_t) / 2;
            testFull = new uint64_t[dataLen * 2];
            memcpy(testFull, temp, dataLen * 2 * sizeof(uint64_t));

            // encall to find the answer of the query
            int res_len = dataLen * (knn_num + 10);
            Query_batch_t queryBatch;
            queryBatch.sendData = new uint32_t[res_len];

            std::chrono::steady_clock::time_point startTime2, endTime2;
            std::chrono::duration<double> duration2;
            startTime2 = std::chrono::steady_clock::now(); // 记录开始时间
            encall_find_knn(global_eid, testFull, queryBatch.sendData, dataLen, res_len, knn_num);

            endTime2 = std::chrono::steady_clock::now();
            duration2 = endTime2 - startTime2; // 计算持续时间
            printf("hamm %d 函数运行时间：%f秒\n", knn_num, duration2.count());
            // send the answer to client
            dataSecureChannel_->SendData(clientSSL, (uint8_t *)queryBatch.sendData, res_len * 4);

            delete[] queryBatch.sendData;
            // exit(EXIT_FAILURE); // cautious kill
            break;
        }
        case KILL_SERVER:
        {
            printf("kill server\n");
            exit(EXIT_FAILURE);
            break;
        }
        default:
            break;
        }
    }
    delete[] resData;
    delete[] len;

    /*    // generate the session key
        if (!dataSecureChannel_->ReceiveData(clientSSL, recvBuf.sendBuffer,
            recvSize)) {
    //tool::Logging(myName_.c_str(), "recv the session key request error.\n");
            exit(EXIT_FAILURE);
        }
        if (recvBuf.header->messageType != SESSION_KEY_INIT) {
    //tool::Logging(myName_.c_str(), "recv the wrong session key init type.\n");
            exit(EXIT_FAILURE);
        }
    */
    // check the client lock here (ensure exist only one client with the same client ID)
    uint32_t clientID = recvBuf.header->clientID;
    // boost::mutex* tmpLock;
    // {
    //     lock_guard<mutex> lock(clientLockSetLock_);
    //     auto clientLockRes = clientLockIndex_.find(clientID);
    //     if (clientLockRes != clientLockIndex_.end()) {
    //         // try to lock this mutex
    //         tmpLock = clientLockIndex_[clientID];
    //         tmpLock->lock();
    //     } else {
    //         // add a new lock to the current index
    //         tmpLock = new boost::mutex();
    //         clientLockIndex_[clientID] = tmpLock;
    //         tmpLock->lock();
    //     }
    // }

    // Ecall_Session_Key_Exchange(eidSGX_, recvBuf.dataBuffer, clientID);

    /*
        recvBuf.header->messageType = SESSION_KEY_REPLY;
        if (!dataSecureChannel_->SendData(clientSSL, recvBuf.sendBuffer,
            sizeof(NetworkHead_t) + SESSION_KEY_BUFFER_SIZE)) {
    //tool::Logging(myName_.c_str(), "send the session key fails.\n");
            exit(EXIT_FAILURE);
        }
        if (!dataSecureChannel_->ReceiveData(clientSSL, recvBuf.sendBuffer,
            recvSize)) {
    //tool::Logging(myName_.c_str(), "recv the login message error.\n");
            exit(EXIT_FAILURE);
        }
    */
    return;
}
