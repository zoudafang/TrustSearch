/**
 * @file serverOptThead.h
 * @author Zuoru YANG (zryang@cse.cuhk.edu.hk)
 * @brief server main thead 
 * @version 0.1
 * @date 2021-07-11
 * 
 * @copyright Copyright (c) 2021
 * 
 */

#ifndef SERVER_OPT_THREAD_H
#define SERVER_OPT_THREAD_H
#include "chunkStructure.h"
#include <boost/thread/thread.hpp>
#include "constVar.h"
#include "sslConnection.h"
#include <iostream>
#include <openssl/ssl.h>
#include <openssl/ecdh.h>
#include <openssl/ec.h>
#include "../App/App.h"
#include "../App/Enclave_u.h"
//#include "../include/sessionKeyExchange.h"
using namespace std;


class ServerOptThread {
    private:
        string myName_ = "ServerOptThread";
        string logFileName_ = "server-log";

        // handlers passed from outside
        SSLConnection* dataSecureChannel_;
        // AbsDatabase* fp2ChunkDB_;

        // // for RA
        // RAUtil* raUtil_;

        // // for upload
        // DataReceiver* dataReceiverObj_;
        // AbsIndex* absIndexObj_;
        // DataWriter* dataWriterObj_;
        // StorageCore* storageCoreObj_;

        // for restore
        // EnclaveRecvDecoder* recvDecoderObj_;

        // for SGX related
        // sgx_enclave_id_t eidSGX_;

        // index type
        int indexType_;

        // the number of received client requests 
        uint64_t totalUploadReqNum_ = 0;
        uint64_t totalRestoreReqNum_ = 0;

        // store the client information 
        // unordered_map<int, boost::mutex*> clientLockIndex_;

        // for log file
        // ofstream logFile_;

        // std::mutex clientLockSetLock_;

        /**
         * @brief check the file status
         * 
         * @param fullRecipePath the full recipe path
         * @param optType the operation type
         * @return true success
         * @return false fail
         */
        // bool CheckFileStatus(string& fullRecipePath, int optType);

    public:
        /**
         * @brief Construct a new Server Opt Thread object
         * 
         * @param dataSecureChannel data security communication channel
         * @param fp2ChunkDB the index
         * @param eidSGX sgx enclave id
         * @param indexType index type
         */
        ServerOptThread(SSLConnection* dataSecureChannel,
        //  AbsDatabase* fp2ChunkDB,
        //     sgx_enclave_id_t eidSGX, 
            int indexType);

        /**
         * @brief Destroy the Server Opt Thread object
         * 
         */
        ~ServerOptThread();

        /**
         * @brief the main process
         * 
         * @param clientSSL the client ssl
         */
        void Run(SSL* clientSSL);
};

#endif