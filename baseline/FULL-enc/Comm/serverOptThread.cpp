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
    client_id_.store(0);
    finish_clr_num_.store(0);
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

    SendMsgBuffer_t recvBuf;
    int recvArrSize = sizeof(NetworkHead_t) + SESSION_KEY_BUFFER_SIZE;
    recvBuf.sendBuffer = (uint8_t *)malloc(recvArrSize);
    recvBuf.header = (NetworkHead_t *)recvBuf.sendBuffer;
    recvBuf.header->dataSize = 0;
    recvBuf.dataBuffer = recvBuf.sendBuffer + sizeof(NetworkHead_t);
    uint32_t recvSize = 0;
    uint32_t client_id = client_id_.fetch_add(1);

    // wait the RA request
    if (!dataSecureChannel_->ReceiveData(clientSSL, &recvBuf.sendBuffer, recvArrSize, recvSize))
    {
        exit(EXIT_FAILURE);
    }
    switch (recvBuf.header->messageType)
    {
    case SGX_RA_NOT_SUPPORT:
    {
        // cannot perform RA
        if (!dataSecureChannel_->ReceiveData(clientSSL, &recvBuf.sendBuffer, recvArrSize,
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

    uint32_t *len = new uint32_t[1];
    uint64_t *testFull = new uint64_t[2];
    uint32_t dataSize = 0;
    recvArrSize = QUERY_SIZE; //* sizeof(uint32_t) cautious
    SendMsgBuffer_t sendBuf;
    uint32_t *resData = new uint32_t[QUERY_SIZE];
    uint8_t *resQuery = new uint8_t[QUERY_SIZE];
    sendBuf.sendBuffer = new uint8_t[recvArrSize]; //(uint8_t *)malloc(sizeof(NetworkHead_t) + QUERY_SIZE * sizeof(uint64_t));
    sendBuf.dataBuffer = sendBuf.sendBuffer + sizeof(NetworkHead_t);
    sendBuf.header = (NetworkHead_t *)sendBuf.sendBuffer;

    uint32_t old_thres = 0, res_len = QUERY_SIZE, tmp_res_size = QUERY_SIZE, query_len;
    std::chrono::steady_clock::time_point startTime2, endTime2;
    std::chrono::duration<double> duration2 = std::chrono::seconds(0);

    memset(sendBuf.sendBuffer, 0, recvArrSize);
    sendBuf.header->messageType = HOMO_PARAM;
    Con::cont.getHomoParam(sendBuf.dataBuffer);
    dataSecureChannel_->SendData(clientSSL, sendBuf.sendBuffer, recvArrSize);
    printf("send PK \n");

    vector<uint32_t> result;
    while (true)
    {
        result.clear();
        // test reply client's query
        if (!dataSecureChannel_->ReceiveData(clientSSL, &sendBuf.sendBuffer, recvArrSize, dataSize))
            break;
        sendBuf.header = (NetworkHead_t *)sendBuf.sendBuffer;
        switch (sendBuf.header->messageType)
        {
        case MULTI_CLIENT:
        {
            CLIENT_NUM = sendBuf.header->hammdist;
            break;
        }
        case MASK_QUERY:
        {
            query_len = sendBuf.header->currentItemNum;
            uint8_t *queryPart = sendBuf.dataBuffer;
            uint64_t hammdist = sendBuf.header->hammdist;
            // printf("dist:%d\n", hammdist);
            startTime2 = std::chrono::steady_clock::now(); // 记录开始时间

            // result.clear();
            // result.push_back(sendBuf.header->dataSize / VECTOR_LEN);
            *(uint32_t *)resQuery = sendBuf.header->dataSize / VECTOR_LEN;
            //*(uint32_t *)sendBuf.sendBuffer = sendBuf.header->dataSize / VECTOR_LEN;

            Con::cont.maskQuery(queryPart, resQuery + sizeof(int), query_len, hammdist, client_id);
            // printf("server send size %lld\n", result.size() * sizeof(triRes));

            uint8_t *dataPtr = reinterpret_cast<uint8_t *>(result.data());
            endTime2 = std::chrono::steady_clock::now();
            duration2 = endTime2 - startTime2; // 计算持续时间
            // dataSecureChannel_->SendData(clientSSL, resQuery, QUERY_SIZE);
            dataSecureChannel_->SendData(clientSSL, (uint8_t *)resData, QUERY_SIZE * 4);
            printf("hamm %d run-flag %d 函数运行时间：%f秒 %d res_len%d dataLen%d\n", hammdist, 1, duration2.count(), CLIENT_NUM, result.size(), 1);
            memset(sendBuf.sendBuffer, 0, recvArrSize);
            memset(resQuery, 0, QUERY_SIZE);
            break;
        }
        case KILL_SERVER:
        {
            finish_clr_num_.fetch_add(1);
            printf("kill server\n");
            if (finish_clr_num_.load() == CLIENT_NUM * 5)
                exit(EXIT_FAILURE);
            break;
        }
        default:
        {
            old_thres++;
            break;
        }
        }
    }
    delete[] testFull;
    delete[] resData;
    delete[] sendBuf.sendBuffer;
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
