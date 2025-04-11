
#include <boost/thread/thread.hpp>
#include "../include/constVar.h"
#include "../include/sslConnection.h"
#include <iostream>
#include <openssl/ssl.h>
#include <openssl/ecdh.h>
#include <openssl/ec.h>
#include "../include/cryptoPrimitive.h"
#include <fstream>
#include <sys/time.h>
#include <ctime>
#include <chrono>
#include <random>
#include "../include/crypto.h"
#include "../include/util.h"
// #include "../include/PaillierEnc.h"
#include "../Comm/PaillierEnc.cpp"

// #include "../include/sessionKeyExchange.h"
using namespace std;

ZZ pkN, pkG;
RandKey rks[3];
int sub_index_num, sub_index_plus, sub_keybit;

void readData(std::string file_name, std::vector<std::pair<uint64_t, uint64_t>> &data);
void read_data_query(std::string file_name, std::vector<std::pair<uint64_t, uint64_t>> &query, int is_img_code);
void read_enc_dataset(std::string file_name, int is_query, std::vector<dataItem> &query);

vector<uint8_t> getMsgQuery(const uint8_t *fullkey, int sub_i, uint32_t subkey)
{
    NearJ nj;
    ZZ fullkeyZ, enc_fullkey, r, fullkeyZ_q;
    uint8_t fullkey_byte[KEY_LEN] = {0}, fullkey_byte_cmp[KEY_LEN] = {0}; // 256 or 255
    uint8_t Rj[KEY_LEN] = {0}, Pk3[RAND_KEY_LEN] = {0}, hashs[RAND_KEY_LEN] = {0}, Gk2[RAND_KEY_LEN] = {0}, Fk1_id[RAND_KEY_LEN] = {0};
    std::array<uint8_t, RAND_KEY_LEN> Fk1_w;
    vector<uint8_t> w, tmpv, nj_vec, id_vec;
    vector<uint32_t> res;

    auto tmpb = to_uint8_array(subkey);
    hmac_sha256(rks[1].rk, RAND_KEY_LEN, tmpb.data(), 4, Gk2);
    hmac_sha256(rks[0].rk, RAND_KEY_LEN, tmpb.data(), 4, Fk1_id);

    ZZFromBytes(fullkeyZ, fullkey, VECTOR_LEN);
    enc_fullkey = encrypt(fullkeyZ, pkN, pkG, r);
    // std::cout << "client query " << fullkeyZ << std::endl;
    ZZToBytes(enc_fullkey, fullkey_byte);

    return std::move(connect_uint8(Fk1_id, RAND_PARAM_LEN, Gk2, RAND_PARAM_LEN, fullkey_byte, KEY_LEN));
};
vector<uint8_t> make_query_item(dataItem query, int sub_hamm)
{
    vector<uint32_t> res;

    int curb = 0;
    int power[100];
    int query_mask;
    uint32_t sub[SUBINDEX_NUM];
    split(sub, query.fullkey, sub_index_num, sub_index_plus, sub_keybit);
    QueryBuffer qb;

    vector<uint8_t> querys;

    for (int i = 0; i < SUBINDEX_NUM; i++)
    {
        if (i < sub_index_plus)
            curb = sub_keybit;
        else
            curb = sub_keybit - 1;

        {
            query_mask = sub[i];

            auto qy = std::move(getMsgQuery(query.fullkey, i, query_mask));
            // cautious for sub_i

            querys.push_back(i); // 0,q0;1,q1
            querys.push_back(0);
            querys.push_back(0);
            querys.push_back(0);

            querys.insert(querys.end(), qy.begin(), qy.end());
        }
        // for (int h = 1; h <= sub_hamm; h++)
        // {
        //     int s = h;
        //     uint32_t bitstr = 0; // the bit-string with s number of 1s
        //     for (int i = 0; i < s; i++)
        //         power[i] = i;    // power[i] stores the location of the i'th 1
        //     power[s] = curb + 1; // used for stopping criterion (location of (s+1)th 1)

        //     int bit = s - 1; // bit determines the 1 that should be moving to the left

        //     while (true)
        //     { // the loop for changing bitstr
        //         if (bit != -1)
        //         {
        //             bitstr ^= (power[bit] == bit) ? (uint32_t)1 << power[bit] : (uint32_t)3 << (power[bit] - 1);
        //             power[bit]++;
        //             bit--;
        //         }
        //         else
        //         {
        //             // printf("%x ,", bitstr);
        //             query_mask = sub[i] ^ bitstr;
        //             auto qy = std::move(getMsgQuery(query.fullkey, i, query_mask));
        //             // cautious for sub_i
        //             querys.push_back(i); // 0,q0;1,q1
        //             querys.push_back(0);
        //             querys.push_back(0);
        //             querys.push_back(0);
        //             querys.insert(querys.end(), qy.begin(), qy.end());

        //             while (++bit < s && power[bit] == power[bit + 1] - 1)
        //             {
        //                 bitstr ^= (uint32_t)1 << (power[bit] - 1);
        //                 power[bit] = bit;
        //             }
        //             if (bit == s)
        //                 break;
        //         }
        //     }
        // }
    }
    if (querys.size() % QUERY_BUF_IDX)
        printf("error querys size %d\n", querys.size());

    return querys;
}

int main(int argc, char *argv[])
{
    uint32_t query_type = QUERY_BATCH, threshold = 8, knn_num = 1;
    int option;
    int invalid = 0, dataSet = 0;
    int client_num = 1; // the number of clients
    uint32_t test_data_len = 0;
    const char optString[] = "t:h:k:n:";

    while ((option = getopt(argc, argv, optString)) != -1)
    {
        switch (option)
        {
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
        case 'k':
        {
            knn_num = atoi(optarg);
            break;
        }
        case 'n':
        {
            client_num = atoi(optarg);
        }
        break;
        }
    }

    std::string data_name, query_name;
    switch (dataSet)
    {
    case 0:
    {
        query_name = "../../dataset/query_img_code512_enc.bin";
        // read_data("img_code512.bin", res, targets, 0);
        break;
    }
    case 1:
    {
        query_name = "../../dataset/gistM_enc.bin";
        // read_data("gistM.bin", res, targets, 1);
        break;
    }
    case 2:
    {
        query_name = "../../dataset/siftM_enc.bin";
        // read_data("siftM.bin", res, targets, 1);
        break;
    }
    default:
        break;
    }

    {
        sub_index_num = SUBINDEX_NUM;
        sub_keybit = ceil((double)PLAIN_BIT / sub_index_num);
        sub_index_plus = PLAIN_BIT - sub_index_num * (sub_keybit - 1);
    }

    vector<boost::thread *> thList;
    SSLConnection *dataSecureChannel;
    pair<int, SSL *> serverConnectionRecord;
    SSL *serverConnection;

    boost::thread *thTmp;
    boost::thread::attributes attrs;
    attrs.set_stack_size(THREAD_STACK_SIZE);

    //     // connect to the storage server
    dataSecureChannel = new SSLConnection(SERVER_IP,
                                          SERVER_PORT, IN_CLIENTSIDE);

    serverConnectionRecord = dataSecureChannel->ConnectSSL();
    serverConnection = serverConnectionRecord.second;
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

    CryptoPrimitive *cryptoObj = new CryptoPrimitive(CIPHER_TYPE, HASH_TYPE);
    EVP_MD_CTX *mdCtx = EVP_MD_CTX_new();
    EVP_CIPHER_CTX *cipherCtx_ = EVP_CIPHER_CTX_new();
    uint8_t *sessionKey_ = const_sessionKey;

    std::vector<dataItem> res;
    // std::vector<uint8_t> read_data;

    read_enc_dataset(query_name, 1, res);
    uint32_t query_num = 1, query_size = sizeof(uint64_t) * query_num * 2; // query_num =1000
    uint64_t *encData = new uint64_t[query_num * 2];
    std::random_device rd;
    std::mt19937 gen(rd()); // 使用随机设备生成种子

    int res_len = QUERY_SIZE; // max res length

    srand(gen());
    SendMsgBuffer_t sendMsgBuffer;
    sendMsgBuffer.sendBuffer = new uint8_t[res_len]; //(uint8_t *)malloc(sizeof(NetworkHead_t) + sizeof(uint64_t) * query_num * 2);
    sendMsgBuffer.dataBuffer = sendMsgBuffer.sendBuffer + sizeof(NetworkHead_t);
    sendMsgBuffer.header = (NetworkHead_t *)sendMsgBuffer.sendBuffer;
    sendMsgBuffer.header->clientID = clientID;

    std::chrono::steady_clock::time_point startTime2, endTime2;
    std::chrono::duration<double> duration2, total_time;

    std::chrono::steady_clock::time_point startTimeE, endTimeE, startTimeE2, endTimeE2, startTimeS, endTimeS;
    std::chrono::duration<double> durationE = std::chrono::seconds(0), durationE2 = std::chrono::seconds(0);
    startTimeE = std::chrono::steady_clock::now();
    vector<double> time_list;
    int recvSize = res_len;
    uint8_t *data2 = new uint8_t[recvSize];

    {
        //-----recv homoParams pkN  pkG rks[3]
        memset(data2, 0, recvSize);

        dataSecureChannel->ReceiveData(serverConnection, &data2, recvSize, dataSize);
        int offset = 0;
        uint8_t *param = data2 + sizeof(NetworkHead_t);
        uint8_t bytes[KEY_LEN];
        ZZFromBytes(pkN, param, KEY_LEN);
        param += KEY_LEN;
        ZZFromBytes(pkG, param, KEY_LEN);
        param += KEY_LEN;
        // cout << "pkN " << pkN << endl;
        // cout << "pkG " << pkG << endl;
        for (int i = 0; i < 3; i++)
        {
            memcpy(rks[i].rk, param, RAND_KEY_BIT / 8);
            param += RAND_KEY_BIT / 8;
            // for (int j = 0; j < RAND_KEY_BIT / 8; j++)
            //     cout << rks[i].rk[j];
            // cout << endl;
        }
    }

    NetworkHead_t *head = new NetworkHead_t();
    uint32_t size, total_num, tmp_idx = 0;
    {
        sendMsgBuffer.header->messageType = MULTI_CLIENT;
        sendMsgBuffer.header->dataSize = query_size;
        sendMsgBuffer.header->hammdist = client_num;
        dataSecureChannel->SendData(serverConnection, sendMsgBuffer.sendBuffer, sizeof(NetworkHead_t) + sendMsgBuffer.header->dataSize);
    }
    startTime2 = std::chrono::steady_clock::now(); // 记录开始时间
    endTime2 = std::chrono::steady_clock::now();   // 记录结束时间
    duration2 = endTime2 - startTime2;             // 计算持续时间
    printf("tatol time %lf client %d\n", duration2.count(), clientID);
    // exit(0);
    uint32_t total_succ = 0;
    uint8_t *sendQuery, *sendEncpart;

    // cautious test
    // ZZ p, q, phi, r, skL, skU;
    // keyGeneration(p, q, pkN, phi, skL, pkG, skU, r, KEY_BIT);

    for (int h = 1; h < 2; h++)
    {
        // for (int times = 0; times < 10; times++)
        {
            time_list.clear();
            total_time = std::chrono::duration<double>::zero();
            total_num = 0;
            tmp_idx = 0;
            for (int t = 0; t < 1000; t++)
            {
                tmp_idx = rand() % res.size(); // random query
                // sendQuery = res[tmp_idx].fullkey;
                // sendEncpart = sendQuery + ENC_LEN;

                auto query_list = make_query_item(res[tmp_idx], floor((double)threshold / sub_index_num));
                if (query_list.size() > res_len)
                {
                    printf("error query_list size %d\n", query_list.size());
                    // exit(0);
                }
                memset(sendMsgBuffer.sendBuffer, 0, res_len);
                memcpy(sendMsgBuffer.dataBuffer, query_list.data(), query_list.size());

                // cryptoObj->SessionKeyEnc(cipherCtx_, (uint8_t *)sendEncpart, PLAIN_LEN, sessionKey_, (uint8_t *)sendEncpart);
                // memcpy(sendMsgBuffer.dataBuffer, sendEncpart, PLAIN_LEN);

                sendMsgBuffer.header->messageType = MASK_QUERY;
                sendMsgBuffer.header->currentItemNum = query_list.size() / QUERY_BUF_IDX;

                sendMsgBuffer.header->dataSize = query_size;

                startTimeE2 = std::chrono::steady_clock::now();
                startTimeS = std::chrono::steady_clock::now(); // 记录开始时间
                // threshold = 4 + (h) * 4; // >> 1
                sendMsgBuffer.header->hammdist = threshold;

                dataSecureChannel->SendData(serverConnection, sendMsgBuffer.sendBuffer, res_len);

                int successful_num = 0;
                dataSecureChannel->ReceiveData(serverConnection, &data2, recvSize, dataSize);
                endTimeS = std::chrono::steady_clock::now();
                durationE = endTimeS - startTimeS; // 计算持续时间

                // int itemNum = dataSize / sizeof(triRes), distP, dist;
                // uint8_t *encData;
                // uint8_t *constFeatureKey = feature_key, *dataTriRes = data2;
                // printf("le %d\n", itemNum);
                // for (int k = 0; k < itemNum; k += 1)
                // {
                //     dist = *(uint32_t *)(dataTriRes + ID_LEN);
                //     encData = dataTriRes + ID_DIS_LEN;
                //     if (PLAIN_BIT < 128)
                //     {
                //         cryptoObj->SessionKeyDec(cipherCtx_, encData,
                //                                  ENC_LEN, constFeatureKey,
                //                                  encData);
                //     }
                //     // printf("id  %d  dis %d\n", *(uint32_t *)(dataTriRes), distP);
                //     dist += calDistance(sendQuery, encData, ENC_LEN);
                //     // printf("id %d dis %d disp %d\n", *(uint32_t *)(dataTriRes), dist, distP);
                //     if (dist <= threshold)
                //         successful_num++;
                //     dataTriRes += sizeof(triRes);
                // }
                // printf("successful %d\n", successful_num);

                // cryptoObj->SessionKeyDec(cipherCtx_, (uint8_t *)data2, dataSize, sessionKey_, (uint8_t *)data2);

                endTimeE2 = std::chrono::steady_clock::now();
                durationE2 += endTimeE2 - startTimeE2; // 计算持续时间
                // printf("dec time：%f秒\n", durationE2.count());

                Query_batch_t query_batch;
                query_batch.sendData = (uint32_t *)data2;

                int query_num = query_batch.sendData[0];
                query_batch.index = query_batch.sendData + 1;
                query_batch.dataBuffer = query_batch.index + query_num * 1;
                // printf("query_num=%d \n", query_num);
                for (int i = 0; i < query_num; i++)
                {
                    successful_num = query_batch.index[i];
                    for (int j = 0; j < query_batch.index[i]; j++)
                    {
                        // printf("n: %u",query_batch.dataBuffer[i]);
                    }
                }
                printf("hamming %d success_num:%d,total-time %f \n",
                       sendMsgBuffer.header->hammdist, successful_num, durationE.count());

                // total_num += successful_num;                 // successful_num;
                // endTime2 = std::chrono::steady_clock::now(); // 记录结束时间
                // duration2 = endTimeE2 - startTimeS; // 计算持续时间
                // total_time += duration2;
                // printf("hamming %d success_num:%d,函数运行时间：%f秒\n", sendMsgBuffer.header->hammdist, successful_num, duration2.count());
                // printf("%f \n", duration2.count());
                // time_list.push_back(duration2.count());
                total_succ += successful_num;
                memset(data2, 0, recvSize);

                tmp_idx = (tmp_idx + 1) % res.size();
            }
        }
        // sort(time_list.begin(), time_list.end());
        // printf("hamming %d  total_num:%d tail_latercy %lf total_timr %lf\n", sendMsgBuffer.header->hammdist, total_num, time_list[(int)((double)time_list.size() * 0.95)], total_time.count());
        printf("total hamming %d success_num:%d,total-time %f \n",
               sendMsgBuffer.header->hammdist, total_succ, durationE2.count());
    }
    delete[] sendMsgBuffer.sendBuffer;
    delete[] data2;

    if (1)
    {
        head->messageType = KILL_SERVER;
        dataSecureChannel->SendData(serverConnection, (uint8_t *)head, sizeof(NetworkHead_t));
    }
    // sleep(5);

    EVP_MD_CTX_free(mdCtx);
    delete cryptoObj;
    // delete sessionKeyObj;
    delete dataSecureChannel;
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

// void read_enc_dataset(std::string file_name, int is_query, std::vector<dataItem> &query)

void Dec_data(void *dataptr, size_t batch_size, int is_img_dataset)
{
    CryptoPrimitive *cryptoObj = new CryptoPrimitive(CIPHER_TYPE, HASH_TYPE);
    EVP_MD_CTX *mdCtx = EVP_MD_CTX_new();
    EVP_CIPHER_CTX *cipherCtx_ = EVP_CIPHER_CTX_new();
    uint8_t *sessionKey_ = const_sessionKey;

    uint8_t *dataE = reinterpret_cast<uint8_t *>(dataptr);
    cryptoObj->SessionKeyDec(cipherCtx_, dataE,
                             batch_size, sessionKey_,
                             dataE);
    EVP_MD_CTX_free(mdCtx);
    EVP_CIPHER_CTX_free(cipherCtx_);
}
void read_enc_dataset(std::string file_name, int is_query,
                      std::vector<dataItem> &query)
{
    dataItem queryD;

    vector<uint8_t> read_data;
    int is_img512_dataset = 0, sift_len = 10000;
    if (file_name.find("img") != std::string::npos)
    {
        is_img512_dataset = 1;
    }
    std::ifstream input(file_name, std::ios::binary);
    uint8_t *enc_data;
    uint8_t tmp;
    uint32_t batch_size = (is_img512_dataset == 1) ? (ENC_BATCH_SIZE_IMG) : (ENC_BATCH_SIZE_SIFT);
    uint32_t tmp1 = 0, read_len = 0;

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
        if (!is_query)
        {
            tmp1 += tmp_size;
            Dec_data(read_data.data() + read_len, tmp_size, is_img512_dataset);
        }
        else if (skip_len < 0)
        {
            Dec_data(read_data.data() + read_len, tmp_size, is_img512_dataset);
        }
        else
        {
            read_data.clear();
            read_len = -tmp_size;
        }
        read_len += tmp_size;

        if (!is_img512_dataset && tmp1 > ((sift_len) * 16 - batch_size))
        {
            break;
        }
        if (tmp_size < batch_size)
            break;
        // read_data.clear();
    }
    input.close();

    for (int i = 0; i < read_data.size(); i += VECTOR_LEN)
    {
        memset(queryD.fullkey, 0, VECTOR_LEN);
        queryD.id = i / VECTOR_LEN;
        memcpy(queryD.fullkey, read_data.data() + i, VECTOR_LEN);
        query.push_back(queryD);
    }
    printf("read data size %d\n", query.size());
}
