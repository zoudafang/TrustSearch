
#include <boost/thread/thread.hpp>
#include "../include/constVar.h"
#include "../include/sslConnection.h"
#include "../include/chunkStructure.h"
#include <iostream>
#include <openssl/ssl.h>
#include <openssl/ecdh.h>
#include <openssl/ec.h>
//#include "../include/sessionKeyExchange.h"
using namespace std;


int main(int argc, char* argv[]){
    vector<boost::thread*> thList;
    SSLConnection* dataSecureChannel;
    pair<int, SSL*> serverConnectionRecord;
    SSL* serverConnection;
//     //SessionKeyExchange* sessionKeyObj;


    boost::thread* thTmp;
    boost::thread::attributes attrs;
    attrs.set_stack_size(THREAD_STACK_SIZE);
    //cryptoObj = new CryptoPrimitive(CIPHER_TYPE, HASH_TYPE);
    //EVP_MD_CTX* mdCtx = EVP_MD_CTX_new(); 

//     // connect to the storage server 
    dataSecureChannel = new SSLConnection(SERVER_IP, 
        SERVER_PORT, IN_CLIENTSIDE);
    
    serverConnectionRecord = dataSecureChannel->ConnectSSL();
    serverConnection = serverConnectionRecord.second;
    //sessionKeyObj = new SessionKeyExchange(dataSecureChannel);
    uint32_t clientID = 1;

    // prepare the session key
    uint8_t sessionKey[CHUNK_HASH_SIZE] = {0};
    NetworkHead_t raDecision;
    raDecision.clientID = clientID;
    raDecision.messageType = SGX_RA_NOT_NEED;std::cout<<"client success";
    if (!dataSecureChannel->SendData(serverConnection, (uint8_t*)&raDecision,
                sizeof(NetworkHead_t))) {
               printf("send RA_NOT_NEED fails.\n");
                exit(EXIT_FAILURE);
    }

    //test SSL send and receive
    uint8_t* data=new uint8_t[CHUNK_HASH_SIZE];
    for(int i=0;i<CHUNK_HASH_SIZE;i++)
    {
        data[i]=i;
    }
    uint32_t dataSize=CHUNK_HASH_SIZE;

    //test query and receive
    uint64_t* testFull=new uint64_t[2];
    testFull[0]=12390327906631358177LL;testFull[1]=8489752702361977974LL;
    dataSecureChannel->SendData(serverConnection, (uint8_t*)testFull, 16);

    uint8_t* data2=new uint8_t[3000*4];
    dataSecureChannel->ReceiveData(serverConnection, data2, dataSize);
    uint32_t* data3=(uint32_t*)data2;
    printf("res[0]=%d,query_size=%d\n",data3[0],dataSize/4);
    
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