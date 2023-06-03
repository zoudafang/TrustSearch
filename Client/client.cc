
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

//#include "../include/sessionKeyExchange.h"
using namespace std;

void readData(std::string file_name,std::vector<std::pair<uint64_t,uint64_t>> &data);


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
    raDecision.messageType = SGX_RA_NOT_NEED;std::cout<<"client success"<<std::endl;
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
    uint64_t* testFull=new uint64_t[2];
    testFull[0]=12390327906631358177LL;testFull[1]=8489752702361977974LL;

    CryptoPrimitive* cryptoObj = new CryptoPrimitive(CIPHER_TYPE, HASH_TYPE);
    EVP_MD_CTX* mdCtx = EVP_MD_CTX_new(); 
    EVP_CIPHER_CTX* cipherCtx_ = EVP_CIPHER_CTX_new();
    uint8_t* sessionKey_=const_sessionKey;


    std::vector<std::pair<uint64_t, uint64_t>> res;
    readData("../../img_code128.bin",res);
    //test query and receive ,one query
    // uint64_t* encData=new uint64_t[2];
    // SendMsgBuffer_t sendMsgBuffer;
    // sendMsgBuffer.sendBuffer=(uint8_t*)malloc(sizeof(NetworkHead_t)+16);
    // sendMsgBuffer.dataBuffer=sendMsgBuffer.sendBuffer+sizeof(NetworkHead_t);
    // sendMsgBuffer.header=(NetworkHead_t*)sendMsgBuffer.sendBuffer;  
    // sendMsgBuffer.header->clientID=clientID;
    
    // for(int i=0;i<5;i++){
    // testFull[0]=res[i].first;testFull[1]=res[i].second;
    // sendMsgBuffer.header->hammdist=8;
    // sendMsgBuffer.header->messageType=QUERY_ONE;
    // sendMsgBuffer.header->dataSize=16;
    // memcpy(encData,testFull,2*sizeof(uint64_t));
    // cryptoObj->SessionKeyEnc(cipherCtx_, (uint8_t*)encData,16, sessionKey_,(uint8_t*)encData);
    // memcpy(sendMsgBuffer.dataBuffer,encData,16);
    // dataSecureChannel->SendData(serverConnection, sendMsgBuffer.sendBuffer, sizeof(NetworkHead_t) + sendMsgBuffer.header->dataSize);

    // uint8_t* data2=new uint8_t[3000*4];
    // dataSecureChannel->ReceiveData(serverConnection, data2, dataSize); 
    // cryptoObj->SessionKeyDec(cipherCtx_, (uint8_t*)data2, dataSize, sessionKey_, (uint8_t*)data2);
    // uint32_t* data3=(uint32_t*)data2;
    // int temp_num=dataSize-4;
    // for(;temp_num>=0;temp_num-=4){if(data3[temp_num/4]!=0)break;}//the last one is not 0,if last one is 0,maybe bug
    // printf("res[0]=%d,query_size=%d\n",data3[0],temp_num/4);
    // }



    //-------test query and receive ,batch query------
    uint32_t query_num=100,query_size=sizeof(uint64_t)*query_num*2;
    uint64_t* encData=new uint64_t[query_num*2];
    for(int i=0;i<query_num*2;i+=2){
        encData[i]=res[i/2].first;encData[i+1]=res[i/2].second;
    }
    SendMsgBuffer_t sendMsgBuffer;
    sendMsgBuffer.sendBuffer=(uint8_t*)malloc(sizeof(NetworkHead_t)+sizeof(uint64_t)*query_num*2);
    sendMsgBuffer.dataBuffer=sendMsgBuffer.sendBuffer+sizeof(NetworkHead_t);
    sendMsgBuffer.header=(NetworkHead_t*)sendMsgBuffer.sendBuffer;  
    sendMsgBuffer.header->clientID=clientID;
    
    cryptoObj->SessionKeyEnc(cipherCtx_, (uint8_t*)encData,query_size, sessionKey_,(uint8_t*)encData);
    memcpy(sendMsgBuffer.dataBuffer,encData,query_size);
    for(int i=0;i<1;i++){
        sendMsgBuffer.header->messageType=QUERY_BATCH;
        sendMsgBuffer.header->dataSize=query_size;
        sendMsgBuffer.header->hammdist=8;
        dataSecureChannel->SendData(serverConnection, sendMsgBuffer.sendBuffer, sizeof(NetworkHead_t) + sendMsgBuffer.header->dataSize);

        uint8_t* data2=new uint8_t[3000*4*query_num];
        dataSecureChannel->ReceiveData(serverConnection, data2, dataSize);
        cryptoObj->SessionKeyDec(cipherCtx_, (uint8_t*)data2, dataSize, sessionKey_, (uint8_t*)data2);

        Query_batch_t query_batch;
        query_batch.sendData=(uint32_t*)data2;
        int query_num=query_batch.sendData[0];
        query_batch.index=query_batch.sendData+sizeof(uint32_t);
        query_batch.dataBuffer=query_batch.index+query_num*sizeof(uint32_t);
        printf("query_num=%d\n",query_num);
        for(int i=0;i<query_num;i++){
            printf("index=%d\n",query_batch.index[i]);
        }
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
void readData(std::string file_name,std::vector<std::pair<uint64_t,uint64_t>> &data){
    std::ifstream input(file_name, std::ios::binary);
    uint64_t high, low;
    while (input.read(reinterpret_cast<char*>(&high), sizeof(high)) && input.read(reinterpret_cast<char*>(&low), sizeof(low))) {
        data.emplace_back(high,low);
    }
    input.close();
}