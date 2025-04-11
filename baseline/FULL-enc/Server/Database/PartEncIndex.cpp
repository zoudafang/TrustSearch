#include "../../include/PartEncIndex.h"

#include "../../Comm/PaillierEnc.cpp"

// ZZ pp, qp, np, phip, lambdap, lambdaInversep, gp, rp;

// long k = 512;
// void testADD_client()
// {
//     ZZ rnd, ax, rnd2, ax2;
//     int port = 9098, party = 2;
//     NetIO *io = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);
//     uint32_t len = k * 2;
//     uint8_t *bytel = new uint8_t[len];
//     ZZ tmp;

//     io->recv_data(bytel, len);
//     np = ZZFromBytes(bytel, len);
//     io->recv_data(bytel, len);
//     lambdap = ZZFromBytes(bytel, len);

//     int l2 = 32;
//     io->recv_data(bytel, l2);
//     rnd = ZZFromBytes(bytel, l2);
//     io->recv_data(bytel, l2);
//     ax = ZZFromBytes(bytel, l2);

//     io->recv_data(bytel, l2);
//     rnd2 = ZZFromBytes(bytel, l2);
//     io->recv_data(bytel, l2);
//     ax2 = ZZFromBytes(bytel, l2);

//     cout << "rnd client " << np << endl;
//     cout << "rnd client " << lambdap << endl;

//     cout << "rnd client " << rnd << endl;
//     cout << "a " << ax << endl;

//     uint8_t rndB[32], aB[32], rndB2[32], aB2[32];

//     ZZToBytes(rnd, rndB);
//     ZZToBytes(ax, aB);
//     ZZToBytes(rnd2, rndB2);
//     ZZToBytes(ax2, aB2);

//     setup_semi_honest(io, party);
//     Integer a, b, a2, b2;
//     long ia = 112, ia2 = 999;
//     {
//         ia = 3121;
//         ia2 = 9123;
//         a = Integer(256, rndB, ALICE);
//         // cout << "x1: " << ia << endl;

//         int tmp = rand() + 11111112;
//         // cout << "tmp" << tmp << endl;
//         b = Integer(256, aB, BOB);

//         // io->recv_data(&ia2, 4);
//         // cout << "x2: " << ia2 << endl;
//         a2 = Integer(256, rndB, ALICE);

//         tmp = rand() + 11111112;
//         // cout << "tmp" << tmp << endl;
//         b2 = Integer(256, aB2, BOB);

//         // std::cout << "r2: " << b2.reveal<int64_t>(PUBLIC) << std::endl;

//         auto res = a.SubHammDist(a, a2, b, b2);
//         cout << "fullkey dis2: " << res.reveal<int>(PUBLIC) << endl;
//     }
// }
// void testADD(ZZ rnd, ZZ ax, ZZ rnd2, ZZ ax2)
// { // 40/4
//     cout << "rnd s " << np << endl;
//     cout << "rnd s " << lambdap << endl;
//     int port = 9098, party = 1;
//     NetIO *io = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);

//     int len = k * 2;
//     ZZ tmp;
//     uint8_t *bytel = new uint8_t[len];

//     ZZToBytes(np, bytel);
//     io->send_data(bytel, len);
//     ZZToBytes(lambdap, bytel);
//     io->send_data(bytel, len);

//     int l2 = 32;
//     ;
//     ZZToBytes(rnd, bytel);
//     io->send_data(bytel, l2);
//     ZZToBytes(ax, bytel);
//     io->send_data(bytel, l2);

//     ZZToBytes(rnd2, bytel);
//     io->send_data(bytel, l2);
//     ZZToBytes(ax2, bytel);
//     io->send_data(bytel, l2);
//     // ZZFromBytes()
//     // keyGeneration(pp, qp, pp, phip, lambdap, gp, lambdaInversep, rp, k);

//     // auto rnd = RandomBits_ZZ(128), ax = RandomBits_ZZ(128);
//     cout << "rnd " << rnd << endl;
//     cout << "a " << ax << endl;
//     auto ranEnc = encrypt(rnd, np, gp, rp);
//     auto aEnc = encrypt(ax, np, gp, rp);

//     auto add = addHomo(ranEnc, aEnc, np);
//     auto res = decrypt(add, np, lambdap, lambdaInversep);
//     cout << " plain1 res " << res << endl;

//     // uint8_t pl[16], pl2[16] = {0};
//     // ZZToBytes(rnd, pl);
//     // // cout binary
//     // for (int i = 0; i < 16; i++)
//     // {
//     //     cout << bitset<8>(pl[i]) << "";
//     // }
//     // cout << endl;
//     // int ds = calDistance(pl, pl2, 16);
//     // cout << "distance " << ds << endl;

//     uint8_t rndB[32], aB[32], rndB2[32], aB2[32];

//     // auto randPlain = decrypt(ranEnc, np, lambda, lambdaInverse);
//     // auto aPlain = decrypt(aEnc, np, lambda, lambdaInverse);
//     ZZToBytes(rnd, rndB);
//     ZZToBytes(ax, aB);
//     ZZToBytes(rnd2, rndB2);
//     ZZToBytes(ax2, aB2);

//     // std::thread t1(testADD2, rnd, ax);

//     // another thread run testAdd2

//     // // // testADD2(rndB, aB);

//     Integer a, b, a2, b2;
//     long ia = 112, ia2 = 999;
//     setup_semi_honest(io, party);
//     {
//         ia = 3121;
//         ia2 = 9123;
//         a = Integer(256, rndB, ALICE);
//         // cout << "x1: " << ia << endl;

//         int tmp = rand() + 11111112;
//         // cout << "tmp" << tmp << endl;
//         b = Integer(256, aB, BOB);

//         // io->recv_data(&ia2, 4);
//         // cout << "x2: " << ia2 << endl;
//         a2 = Integer(256, rndB2, ALICE);

//         tmp = rand() + 11111112;
//         // cout << "tmp" << tmp << endl;
//         b2 = Integer(256, aB2, BOB);

//         auto res = b.SubHammDist(a, a2, b, b2);
//         auto ress = res.reveal<string>(PUBLIC);
//         // convert to bytes of string ress
//         //  uint8_t resInt[32];
//         //  for (int i = 0; i < 32; i++)
//         //  {
//         //      resInt[i] = ress[i];
//         //  }
//         //  ZZ resZ;
//         //  ZZFromBytes(resZ, resInt, 32);
//         //  cout << "res: " << resZ << endl;

//         cout << "res: " << res.reveal<string>(PUBLIC) << endl;
//     }

//     // t1.join();
//     // finalize_semi_honest();
//     delete io;
// }

int qindex = 1, randidx = 0;
PartEncIndex::PartEncIndex()
{
    hammdist.resize(MAX_CLIENT_NUM);
    sub_hamm.resize(MAX_CLIENT_NUM);

    hammdist[0] = 8;
    sub_index_num = SUBINDEX_NUM;
    sub_keybit = ceil((double)PLAIN_BIT / sub_index_num);
    sub_index_plus = PLAIN_BIT - sub_index_num * (sub_keybit - 1);

    // for (int j = 0; j < sub_index_num; j++)
    sub_hamm[0] = floor((double)hammdist[0] / sub_index_num);
};
PartEncIndex::~PartEncIndex()
{
    finalize_semi_honest();
    delete io;
};

void PartEncIndex::init_homo_param(int port, int party)
{
    // args n: client or server
    //  // test for gc add & homo add
    //  {
    //      keyGeneration(pp, qp, np, phip, lambdap, gp, lambdaInversep, rp, k);
    //      ZZ rnd, ax, rnd2, ax2;
    //      rnd = RandomBits_ZZ(128);
    //      ax = RandomBits_ZZ(255);
    //      rnd2 = RandomBits_ZZ(128);
    //      ax2 = RandomBits_ZZ(255);

    //     uint8_t rndB[16], aB[16];
    //     ZZToBytes(rnd, rndB);
    //     ZZToBytes(rnd2, aB);

    //     int dis = calDistance(rndB, aB, 16);
    //     cout << "fullkey distance : " << dis << endl;

    //     rnd = rnd + ax;
    //     rnd2 = rnd2 + ax2;

    //     // rnd = ZZFromBytes(bytes.data(),16);
    //     // ax = ZZFromBytes(bytes2.data(),16);
    //     // uint8_t rndB[8], aB[8];
    //     // ZZToBytes(rnd, rndB);
    //     // ZZToBytes(ax, aB);
    //     if (n == 1)
    //     {
    //         testADD(rnd, ax, rnd2, ax2);
    //     }
    //     else if (n == 0)
    //     {
    //         testADD_client();
    //     }
    // }

    { // party = BOB;
        io = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);
        setup_semi_honest(io, party);
    }

    ZZ p, q, phi, r;
    keyGeneration(p, q, pkN, phi, skL, pkG, skU, r, KEY_BIT);

    for (int i = 0; i < 3; i++)
    {
        generateRandLen(RAND_KEY_BIT / 8, rks[i].rk);
    }

    // send pkN, lambdap to CS_server
    int len = KEY_BIT * 4;
    ZZ tmp;
    uint8_t *bytes = new uint8_t[len];
    memset(bytes, 0, len);
    ZZToBytes(pkN, bytes);
    io->send_data(bytes, len);
    memset(bytes, 0, len);
    ZZToBytes(skL, bytes);
    io->send_data(bytes, len);
    memset(bytes, 0, len);
    ZZToBytes(skU, bytes);
    io->send_data(bytes, len);
    // cout << "n " << pkN << endl;
    // cout << "l " << skL << endl;
    // cout << "lv " << skU << endl;
}
void PartEncIndex::initPartIndex(std::vector<dataItem> &db, uint32_t dataSet)
{

    printf("init index %d\n", db.size());
    uint32_t sub[SUBINDEX_NUM];
    uint8_t *plain_data;

    // auto tmp = db[1];
    // for (int j = 0; j < 7; j++)
    // {
    //     tmp.fullkey[j] ^= 3;
    //     tmp.id = db.size();
    //     db.push_back(tmp);
    // }

    for (int i = 0; i < db.size(); i++)
    {
        auto &val = db[i];
        plain_data = val.fullkey + ENC_LEN;
        split(sub, plain_data, sub_index_num, sub_index_plus, sub_keybit);
        for (int j = 0; j < SUBINDEX_NUM; j++)
        {
            this->sub_index_list[j][sub[j]].push_front(i);

            // this->sub_index[j][sub[j]].push_back(i);
        }
    }

    for (int i = 0; i < SUBINDEX_NUM; i++)
        A_s[i].resize(db.size());

    // for (int i = 0; i < SUBINDEX_NUM; i++)
    //     printf("sub_index: %d \n", this->sub_index_list[i].size());
    this->fullIndex = std::move(db);
    printf("total_len: %d \n", this->fullIndex.size());
    // this->initCryptoIndex();

    std::vector<std::thread> threads;

    // 启动多个线程处理不同的子索引
    for (int i = 0; i < SUBINDEX_NUM; ++i)
    {
        threads.emplace_back([this, i]()
                             { this->initCryptoIndex(i); });
    }
    // 等待所有线程完成
    for (auto &t : threads)
    {
        t.join();
    }
};
int minm = 0, enc_nums = 0;
void PartEncIndex::initCryptoIndex(int sub_i)
{
    printf("init initCryptoIndex\n");
    ZZ r;
    uint32_t sub[SUBINDEX_NUM];
    uint8_t *plain_data;
    vector<int> rand_idx;
    for (int i = 0; i < fullIndex.size(); i++)
        rand_idx.push_back(i);

    unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
    std::default_random_engine engine(seed);

    NearJ nj;
    ZZ fullkeyZ, enc_fullkey, plainT;
    uint8_t Rj[KEY_LEN], Pk3[RAND_KEY_LEN], hashs[RAND_KEY_LEN], Gk2[RAND_KEY_LEN], Fk1_id[RAND_KEY_LEN];
    std::array<uint8_t, RAND_KEY_LEN> Fk1_w;
    std::array<uint8_t, RAND_PARAM_LEN> Fk2_w;
    vector<uint8_t> w, tmpv, nj_vec, id_vec;
    int w_len, id_len;

    // for (int i = 0; i < SUBINDEX_NUM; i++)
    int i = sub_i;
    {
        printf("sub_index: %d \n", this->sub_index_list[i].size());
        std::shuffle(rand_idx.begin(), rand_idx.end(), engine);
        int A_idx = 0, first_idx;
        for (auto &val : sub_index_list[i])
        {
            auto flist = val.second;
            auto prev = flist.before_begin();
            auto curr = flist.begin();

            // T_s = aidx;
            w_len = sizeof(val.first);
            id_len = sizeof(val.second.front());
            id_vec = (to_uint8_array(val.second.front()));
            w = (to_uint8_array(val.first));
            first_idx = rand_idx[A_idx];
            tmpv = (to_uint8_array(first_idx));

            memset(Fk1_w.data(), 0, RAND_KEY_LEN);
            memset(Fk1_id, 0, RAND_KEY_LEN);
            memset(Pk3, 0, RAND_KEY_LEN);
            memset(Gk2, 0, RAND_KEY_LEN);

            hmac_sha256(rks[2].rk, RAND_KEY_LEN, w.data(), w_len, Pk3);
            hmac_sha256(rks[1].rk, RAND_KEY_LEN, w.data(), w_len, Gk2);
            hmac_sha256(rks[0].rk, RAND_KEY_LEN, w.data(), w_len, Fk1_w.data());
            hmac_sha256(rks[0].rk, RAND_KEY_LEN, id_vec.data(), id_len, Fk1_id);
            tmpv = (connect_uint8(tmpv.data(), tmpv.size(), Fk1_id, RAND_PARAM_LEN, Pk3, RAND_PARAM_LEN));
            // mask tmpv and Gk2
            tmpv = (MaskMsg(tmpv.data(), tmpv.size(), Gk2, RAND_PARAM_LEN));

            // T_s
            memcpy(Fk2_w.data(), Fk1_w.data(), RAND_PARAM_LEN);
            T_s[i][Fk2_w] = std::move(tmpv);

            // if (qindex == 1)
            // {
            //     tmpv = (MaskMsg(T_s[i][Fk1_w].data(), T_s[i][Fk1_w].size(), Gk2, RAND_KEY_LEN));

            //     int addr = *(uint32_t *)tmpv.data();
            //     printf("addrssss %d\n", addr);
            //     qindex = *flist.begin();
            //     query = fullIndex[qindex];

            //     // printf fk1w
            //     // printf("fk1w: ");
            //     // for (int i = 0; i < RAND_KEY_LEN; i++)
            //     // {
            //     //     printf("%x", Fk1_w[i]);
            //     // }
            //     // printf("\n");
            // }

            while (curr != flist.end())
            {
                auto next = std::next(curr);
                nj.img_id = fullIndex[*curr].id;
                BytesToZZ(fullIndex[*curr].fullkey, VECTOR_LEN, fullkeyZ);

                memset(nj.encFullkey, 0, KEY_LEN); // cautious 关键，不能每次都使用之前的内存
                enc_fullkey = encrypt(fullkeyZ, pkN, pkG, r);
                int encLen = ZZToBytes(enc_fullkey, nj.encFullkey);

                // int dist = calDistance(query.fullkey, fullIndex[*curr].fullkey, PLAIN_LEN);
                // if (dist <= hammdist[0] && i == 0)
                //     minm++;
                // if (memcmp(fullIndex[*curr].fullkey, query.fullkey, VECTOR_LEN) == 0 && i == 0)
                // {
                //     randidx = rand_idx[A_idx];
                //     plainT = ZZFromBytes(nj.encFullkey, 256);
                //     auto tmpr = decrypt(plainT, pkN, skL, skU);
                //     printf("error addr %d\n", rand_idx[A_idx]);
                //     // for (int i = 0; i < VECTOR_LEN; i++)
                //     //     printf("%x", fullIndex[*curr].fullkey[i]);
                //     printf("\n");
                //     // std::cout << "first encKey :" << tmpr << std::endl;
                //     // std::cout << "first0 encKey :" << fullkeyZ << std::endl;
                // }
                // if (ZZToBytes(enc_fullkey, nj.encFullkey) != KEY_LEN)
                //     printf("enc_length error %d %d\n", ZZToBytes(enc_fullkey, nj.encFullkey), KEY_LEN);

                if (next == flist.end())
                {
                    nj.next_pos = -1;
                }
                else
                {
                    nj.next_pos = rand_idx[A_idx + 1];
                }
                // uint32_t Dj = 0;
                // Tdv = xx

                nj_vec = nj.tobytes();
                generateRandLen(KEY_LEN, Rj);
                // hmac_sha256(rks[2].rk, RAND_KEY_LEN, w.data(), w_len, Pk3);
                tmpv = (connect_uint8(Pk3, RAND_PARAM_LEN, Rj, KEY_LEN));

                memset(hashs, 0, RAND_KEY_LEN);
                sha256_digest((unsigned char *)tmpv.data(), tmpv.size(), hashs);
                tmpv = (MaskMsg(nj_vec.data(), nj_vec.size(), hashs, RAND_KEY_LEN));
                // if (nj.img_id == 60)
                // {
                //     cout << "enc_fullkeyxxxxx " << enc_fullkey << endl;
                //     printf("xxxxxx %d\n", 2);
                //     for (int i = 0; i < tmpv.size(); i++)
                //         printf("%x ", tmpv[i]);
                //     printf("\n");
                // }
                tmpv = (connect_uint8(tmpv.data(), tmpv.size(), Rj, KEY_LEN));
                // if (nj.img_id == 376)
                // {
                //     ZZ plainT = ZZFromBytes(nj.encFullkey, KEY_LEN);
                //     auto tmpr = decrypt(plainT, pkN, skL, skU);
                //     if (tmpr != fullkeyZ)
                //     {
                //         cout << tmpr << endl;
                //         cout << "error encKey " << fullkeyZ << endl;
                //         printf("error encKey %d lens %d\n", nj.img_id, encLen);
                //     }
                // }

                if (A_idx >= A_s[i].size())
                    printf("A_idx %d \n", A_idx);
                A_s[i][rand_idx[A_idx]] = std::move(tmpv); // = nj+xxx;
                A_idx++;

                prev = curr;
                curr = next;
                // printf("A_idx %d \n", A_idx);
            }
        }
    }

    // int add_sum = 0;
    // for (auto val : T_s[0])
    // {
    //     auto fir = val.second;
    //     int idx = fir
    // }

    printf("initCryptoIndex finish %d\n", sub_i);
    // printf("xaxsasxa min %d\n", minm);
    // printf("sub_index: %d \n", this->sub_index_list[0].size());
    // printf("total_len: %d \n", this->T_s[0].size());
};

void PartEncIndex::changeHammingDist(int hammdist, int client_id)
{
    if (this->hammdist.size() <= client_id)
    {
        this->hammdist.resize(client_id + 100);
        this->sub_hamm.resize(client_id + 100);
    }

    this->hammdist[client_id] = hammdist;
    sub_hamm[client_id] = floor((double)hammdist / sub_index_num);
};
vector<uint32_t> PartEncIndex::query(int client, QueryBuffer qbf, int sub_i, int &is_fetched)
{
    // printf("querys %d\n", client);
    vector<uint32_t> res;
    vector<uint8_t> tmpv, tmpvQ, Nj_vec;
    NearJ nj;
    int id_len, addr, addr_next, w, NHi_len;
    uint8_t *Fk1, *Gk2, *encFullkey_q, *encFullkey;
    uint8_t *Fk1_id, *Pk3_w, *tmpb;
    uint8_t hash_msg[HASH_KEY_LEN] = {0};
    Fk1 = qbf.dataBuffer;
    Gk2 = qbf.dataBuffer + RAND_PARAM_LEN;
    encFullkey_q = qbf.dataBuffer + RAND_PARAM_LEN + RAND_PARAM_LEN;
    std::array<uint8_t, RAND_PARAM_LEN> Fk1_v;
    memcpy(Fk1_v.data(), Fk1, RAND_PARAM_LEN);

    // printf("fk1v \n");
    // for (int i = 0; i < 32; i++)
    //     printf("%x", Fk1_v[i]);
    // printf("\n");

    auto find_val = T_s[sub_i].find(Fk1_v);
    if (find_val == T_s[sub_i].end())
    {
        is_fetched = 0;
        // for (int i = 0; i < 32; i++)
        //     printf("%x", Fk1_v[i]);
        // printf(" subi %d not find\n", sub_i);
        return res;
    }
    is_fetched = 1;
    tmpv = MaskMsg(find_val->second.data(), find_val->second.size(), Gk2, RAND_PARAM_LEN);

    addr = *(uint32_t *)tmpv.data();
    Fk1_id = tmpv.data() + sizeof(uint32_t);
    Pk3_w = tmpv.data() + sizeof(uint32_t) + RAND_PARAM_LEN;

    // if (addr >= A_s[sub_i].size())
    //     printf("out of size ----- addr %d %d\n", addr, A_s[sub_i].size());
    tmpb = A_s[sub_i][addr].data();

    NHi_len = NearJ_SIZE; // std::max(HASH_KEY_LEN, NearJ::bytesLen()); //
    tmpvQ = connect_uint8(Pk3_w, RAND_PARAM_LEN, (unsigned char *)(tmpb + NHi_len), KEY_LEN);
    sha256_digest((unsigned char *)tmpvQ.data(), tmpvQ.size(), hash_msg);
    Nj_vec = MaskMsg(tmpb, NHi_len, hash_msg, HASH_KEY_LEN);

    uint32_t img_id, dist = 0, dist2 = 0;
    id_len = sizeof(uint32_t);
    // printf("addrs %d\n", addr);
    while (1)
    {
        ZZ fullkeyZ, fullkeyZ_q;
        ZZ fullkeyZMask, fullkeyZMask_q, plain, plain_q;
        ZZ randEnc, rand_qEnc, rand, rand_q;
        uint8_t plain_full1[KEY_LEN], plain_full2[KEY_LEN], encFullkey_q2[KEY_LEN];

        img_id = *(uint32_t *)Nj_vec.data();
        addr_next = *(uint32_t *)(Nj_vec.data() + id_len);
        // cout << "img_id begin " << img_id << endl;
        // printf(" sui %d loop addr %d imd_id %d next %d\n", sub_i, addr, img_id, addr_next);
        if (cand_set.test(img_id))
        {
            goto next;
        }
        else
            cand_set.set(img_id);

        encFullkey = Nj_vec.data() + id_len + sizeof(uint32_t);
        // sham cmp distance

        // memcpy(encFullkey_q2, encFullkey, KEY_LEN);
        BytesToZZ(encFullkey, KEY_LEN, fullkeyZMask);
        BytesToZZ(encFullkey_q, KEY_LEN, fullkeyZMask_q);

        // printf fullkeyZ, fullkeyZ_q
        // std::cout << "ENC: " << fullkeyZMask << std::endl;
        // BytesToZZ(encFullkey, KEY_LEN, fullkeyZ);
        // BytesToZZ(encFullkey_q, KEY_LEN, fullkeyZ_q);
        // plain_q = decrypt(fullkeyZ_q, pkN, skL, skU);
        // plain = decrypt(fullkeyZ, pkN, skL, skU);

        // ZZToBytes(plain, plain_full1);
        // ZZToBytes(plain_q, plain_full2);
        enc_nums++;
        EncMask(fullkeyZMask, rand, randEnc);
        SendHamMsg(fullkeyZMask);

        EncMaskQ(fullkeyZMask_q, rand_q, rand_qEnc);
        SendHamMsg(fullkeyZMask_q);

        // fullkeyRndMask(fullkeyZMask, fullkeyZMask_q, rand, rand_q, randEnc, rand_qEnc);
        // candidate set to filter
        dist = SHAM(fullkeyZMask, fullkeyZMask_q, rand, rand_q, randEnc, rand_qEnc);
        // dist = calDistance(plain_full1, plain_full2, PLAIN_LEN);
        // if (dist2 != dist)
        //     cout << img_id << "error dist " << dist2 << " " << dist << endl;
        // else
        //     cout << img_id << "success dist " << dist2 << " " << dist << endl;
        if (dist <= hammdist[client])
        {
            // printf("img_id %d dist %d\n", img_id, dist);
            res.push_back(img_id);
        }

        // cout << "img_id end " << img_id << endl;
    next:
        if (addr_next == -1)
            break;
        // if (addr_next >= A_s[sub_i].size() || addr_next < 0)
        //     printf("out of size ----- addr %d %d\n", addr_next, A_s[sub_i].size());
        tmpb = A_s[sub_i][addr_next].data();
        NHi_len = NearJ_SIZE; // std::max(HASH_KEY_LEN, NearJ::bytesLen());
        tmpvQ = connect_uint8(Pk3_w, RAND_PARAM_LEN, (unsigned char *)(tmpb + NHi_len), KEY_LEN);

        memset(hash_msg, 0, HASH_KEY_LEN);
        sha256_digest((unsigned char *)tmpvQ.data(), tmpvQ.size(), hash_msg);
        // printf("xxxxxx %d\n", addr_next);
        // for (int i = 0; i < 32; i++)
        //     printf("%x ", Pk3_w[i]);
        // printf("\n");
        Nj_vec = MaskMsg(tmpb, NHi_len, hash_msg, HASH_KEY_LEN);
        // printf("xxxxxxZZZZZ %d\n", addr_next);
        // for (int i = 0; i < Nj_vec.size(); i++)
        //     printf("%x ", Nj_vec[i]);
        // printf("\n");

        addr = addr_next;
    }

    return std::move(res);
};

vector<uint8_t> PartEncIndex::getMsgQuery(const uint8_t *fullkey, int sub_i, uint32_t subkey)
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
void PartEncIndex::init_query(vector<uint8_t> &queries)
{
    this->queries.resize(queries.size());
    memcpy(this->queries.data(), queries.data(), queries.size());
    // this->queries = (queries);
};
void PartEncIndex::test_query()
{
    vector<uint32_t> res;
    qindex = 59;
    for (int c = 0; c < 1000 * VECTOR_LEN && c < queries.size(); c += VECTOR_LEN)
    {
        cand_set.reset();
        printf("test_query %d\n", c);
        // qindex = 59;
        qindex++;
        // qindex = rand() % fullIndex.size();
        dataItem query;
        query.id = c;
        // memset(query.fullkey, 0, VECTOR_LEN);
        memcpy(query.fullkey, queries.data() + c, VECTOR_LEN);
        // auto query = fullIndex[qindex];
        // if (query.id != 1)
        //     printf("error full index\n");
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
            for (int h = 1; h <= sub_hamm[0]; h++)
            {
                int s = h;
                uint32_t bitstr = 0; // the bit-string with s number of 1s
                for (int i = 0; i < s; i++)
                    power[i] = i;    // power[i] stores the location of the i'th 1
                power[s] = curb + 1; // used for stopping criterion (location of (s+1)th 1)

                int bit = s - 1; // bit determines the 1 that should be moving to the left

                while (true)
                { // the loop for changing bitstr
                    if (bit != -1)
                    {
                        bitstr ^= (power[bit] == bit) ? (uint32_t)1 << power[bit] : (uint32_t)3 << (power[bit] - 1);
                        power[bit]++;
                        bit--;
                    }
                    else
                    {
                        // printf("%x ,", bitstr);
                        query_mask = sub[i] ^ bitstr;
                        auto qy = std::move(getMsgQuery(query.fullkey, i, query_mask));
                        // cautious for sub_i
                        querys.push_back(i); // 0,q0;1,q1
                        querys.push_back(0);
                        querys.push_back(0);
                        querys.push_back(0);
                        querys.insert(querys.end(), qy.begin(), qy.end());

                        while (++bit < s && power[bit] == power[bit + 1] - 1)
                        {
                            bitstr ^= (uint32_t)1 << (power[bit] - 1);
                            power[bit] = bit;
                        }
                        if (bit == s)
                            break;
                    }
                }
            }
        }
        if (querys.size() % QUERY_BUF_IDX)
            printf("error querys size %d\n", querys.size());

        NearJ nj;
        ZZ fullkeyZ, enc_fullkey, r, fullkeyZ_q;
        uint8_t fullkey_byte[KEY_LEN], fullkey_byte_cmp[KEY_LEN];
        uint8_t Rj[KEY_LEN], Pk3[RAND_KEY_LEN], hashs[RAND_KEY_LEN], Gk2[RAND_KEY_LEN], Fk1_id[RAND_KEY_LEN];
        std::array<uint8_t, RAND_KEY_LEN> Fk1_w;
        vector<uint8_t> w, tmpv, nj_vec, id_vec;
        QueryBuffer_IDX qbx;

        for (int times = querys.size() / QUERY_BUF_IDX; times > 0; times--)
        {
            qbx.dataBuffer = querys.data() + (times - 1) * QUERY_BUF_IDX;
            qbx.idx = *(uint32_t *)qbx.dataBuffer;
            qbx.qbf.dataBuffer = qbx.dataBuffer + sizeof(uint32_t);
            int x = 0;
            auto tmp = this->query(0, qbx.qbf, qbx.idx, x);
            res.insert(res.end(), tmp.begin(), tmp.end());
        }

        // for (int i = 0; i < SUBINDEX_NUM; i++)
        // {
        //     auto tmpb = to_uint8_array(sub[i]);
        //     hmac_sha256(rks[1].rk, RAND_KEY_LEN, tmpb.data(), 4, Gk2);
        //     hmac_sha256(rks[0].rk, RAND_KEY_LEN, tmpb.data(), 4, Fk1_id);

        //     for (int i = 0; i < VECTOR_LEN; i++)
        //         printf("%x", query.fullkey[i]);
        //     printf("\n");
        //     ZZFromBytes(fullkeyZ, query.fullkey, VECTOR_LEN);
        //     enc_fullkey = encrypt(fullkeyZ, pkN, pkG, r);
        //     // std::cout << "client query " << fullkeyZ << std::endl;
        //     ZZToBytes(enc_fullkey, fullkey_byte);

        //     ZZFromBytes(fullkeyZ_q, fullkey_byte, KEY_LEN);
        //     auto resq = decrypt(fullkeyZ_q, pkN, skL, skU);
        //     ZZToBytes(resq, fullkey_byte_cmp);
        //     if (memcmp(query.fullkey, fullkey_byte_cmp, VECTOR_LEN) != 0)
        //     {
        //         printf("error\n");
        //         for (int i = 0; i < VECTOR_LEN; i++)
        //             printf("%x", query.fullkey[i]);
        //         printf("\n");
        //         for (int i = 0; i < VECTOR_LEN; i++)
        //             printf("%x", fullkey_byte_cmp[i]);
        //         printf("\n");
        //         for (int i = 0; i < VECTOR_LEN; i++)
        //             printf("%x", fullkey_byte[i]);
        //         printf("\n");
        //     }

        //     auto tmvec = connect_uint8(Fk1_id, RAND_KEY_LEN, Gk2, RAND_KEY_LEN, fullkey_byte, KEY_LEN);
        //     qb.dataBuffer = tmvec.data();

        //     // printf fk1
        //     // for (int i = 0; i < RAND_KEY_LEN; i++)
        //     // {
        //     //     printf("%x", Fk1_id[i]);
        //     // }
        //     printf(" client sub i query %d\n", i);
        //     auto tmp = this->query(0, qb, i);
        //     res.insert(res.end(), tmp.begin(), tmp.end());
        // }

        // // dedup in res
        // std::sort(res.begin(), res.end());
        // res.erase(std::unique(res.begin(), res.end()), res.end());
        printf("nums size %d\n", enc_nums);
    }
    printf("res size %d\n", res.size());
    printf("xaxsasxa min %d\n", minm);
}
unordered_set<uint32_t> PartEncIndex::rangeQuery(int client, uint8_t query[PLAIN_LEN])
{
    unordered_set<uint32_t> candidate;
    int curb = 0;
    int power[100];
    int query_mask;
    uint32_t sub[SUBINDEX_NUM];
    split(sub, query, sub_index_num, sub_index_plus, sub_keybit);

    for (int i = 0; i < SUBINDEX_NUM; i++)
    {
        if (i < sub_index_plus)
            curb = sub_keybit;
        else
            curb = sub_keybit - 1;

        {
            query_mask = sub[i];
            auto fg = sub_index[i].find(query_mask);
            if (fg != sub_index[i].end())
            {
                for (auto &val : fg->second)
                {
                    candidate.emplace_hint(candidate.end(), val);
                }
            }
        }
        for (int h = 1; h <= sub_hamm[client]; h++)
        {
            int s = h;
            uint32_t bitstr = 0; // the bit-string with s number of 1s
            for (int i = 0; i < s; i++)
                power[i] = i;    // power[i] stores the location of the i'th 1
            power[s] = curb + 1; // used for stopping criterion (location of (s+1)th 1)

            int bit = s - 1; // bit determines the 1 that should be moving to the left

            while (true)
            { // the loop for changing bitstr
                if (bit != -1)
                {
                    bitstr ^= (power[bit] == bit) ? (uint32_t)1 << power[bit] : (uint32_t)3 << (power[bit] - 1);
                    power[bit]++;
                    bit--;
                }
                else
                {
                    // printf("%x ,", bitstr);
                    query_mask = sub[i] ^ bitstr;
                    auto fg = sub_index[i].find(query_mask);
                    if (fg != sub_index[i].end())
                    {
                        for (auto &val : fg->second)
                        {
                            candidate.emplace_hint(candidate.end(), val);
                        }
                    }
                    while (++bit < s && power[bit] == power[bit + 1] - 1)
                    {
                        bitstr ^= (uint32_t)1 << (power[bit] - 1);
                        power[bit] = bit;
                    }
                    if (bit == s)
                        break;
                }
            }
        }
    }
    return std::move(candidate);
};
static uint32_t candi = 0, resN = 0;
vector<triRes> PartEncIndex::verifyCand(int client_id, uint8_t *query, unordered_set<uint32_t> &cand)
{
    vector<triRes> res;
    uint32_t hamm = hammdist[client_id], tmp_dis;
    dataItem dtm;
    uint8_t encPart[ENC_LEN];
    triRes tmp;
    res.push_back(tmp);
    for (auto &val : cand)
    {
        dtm = fullIndex[val];
        tmp_dis = calDistance(dtm.fullkey + ENC_LEN, query, PLAIN_LEN);
        if (tmp_dis <= hamm)
        {
            // printf("%d %d \n", dtm.id, tmp_dis);
            // #if PLAIN_BIT < 128
            memcpy(tmp.res + ID_DIS_LEN, dtm.fullkey, ENC_LEN);
            // #endif
            *((uint32_t *)tmp.res) = dtm.id;
            *(uint32_t *)(tmp.res + ID_LEN) = tmp_dis;
            res.emplace_back(tmp);
        }
    }
    *(uint32_t *)res.front().res = (res.size() - 1); // 在第一个位置存储res的个数，主要是为了记录ssl传输的数组有效长度，ssl每次传递N大小的数据
    candi += cand.size(), resN += res.size();
    printf("size sc %d res %d\n", candi, resN);
    return std::move(res);
};

void PartEncIndex::fullkeyRndMask(ZZ &fullkeyMask, ZZ &fullkeyMask_q, ZZ &rand, ZZ &rand_cand, ZZ &randEnc, ZZ &rand_candEnc)
{
    ZZ r;
    rand = RandomBits_ZZ(MASK_R_BIT - 10);
    rand_cand = RandomBits_ZZ(MASK_R_BIT - 10);

    // randEnc = encrypt(rand, pkN, pkG, r);
    // rand_candEnc = encrypt(rand_cand, pkN, pkG, r);

    // fullkeyMask = addHomo(fullkeyMask, randEnc, pkN);
    // fullkeyMask_q = addHomo(fullkeyMask_q, rand_candEnc, pkN);
    fullkeyMask = addPlaintext(fullkeyMask, rand, pkN, pkG);
    fullkeyMask_q = addPlaintext(fullkeyMask_q, rand_cand, pkN, pkG);

    return;
};
void PartEncIndex::EncMask(ZZ &fullkeyMask_q, ZZ &rand_cand, ZZ &rand_candEnc)
{
    ZZ r;
    rand_cand = RandomBits_ZZ(MASK_R_BIT - 10);
    // rand_candEnc = encrypt(rand_cand, pkN, pkG, r);
    // fullkeyMask_q = addHomo(fullkeyMask_q, rand_candEnc, pkN);
    fullkeyMask_q = addPlaintext(fullkeyMask_q, rand_cand, pkN, pkG);
    return;
};
void PartEncIndex::EncMaskQ(ZZ &fullkeyMask, ZZ &rand, ZZ &randEnc)
{
    ZZ r;
    rand = RandomBits_ZZ(MASK_R_BIT - 10);
    // randEnc = encrypt(rand, pkN, pkG, r);
    // fullkeyMask = addHomo(fullkeyMask, randEnc, pkN);
    fullkeyMask = addPlaintext(fullkeyMask, rand, pkN, pkG);
    return;
};
void PartEncIndex::SendHamMsg(ZZ &fullkey)
{
    uint8_t tmp[KEY_LEN] = {0};
    BytesFromZZ(tmp, fullkey, 256);
    io->send_data(tmp, KEY_LEN);
};
int PartEncIndex::SHAM(ZZ &fullkey, ZZ &fullkey_q, ZZ &rand, ZZ &rand_cand, ZZ &randEnc, ZZ &rand_candEnc)
{
    uint8_t tmp[KEY_LEN] = {0};
    // BytesFromZZ(tmp, fullkey, 256);
    // io->send_data(tmp, KEY_LEN);
    // memset(tmp, 0, KEY_LEN);
    // BytesFromZZ(tmp, fullkey_q, 256);
    // io->send_data(tmp, KEY_LEN);

    Integer a, b, a2, b2;
    uint8_t tmps[MASK_R_BIT] = {0};
    // client bob GC
    {
        memset(tmps, 0, MASK_R_BIT);
        ZZToBytes(rand, tmps);
        a = Integer(MASK_R_BIT, tmps, ALICE);
        b = Integer(MASK_R_BIT, tmps, BOB); // r1

        memset(tmps, 0, MASK_R_BIT);
        ZZToBytes(rand_cand, tmps);
        a2 = Integer(MASK_R_BIT, tmps, ALICE);
        b2 = Integer(MASK_R_BIT, tmps, BOB); // r2

        auto res = a.SubHammDist(a, a2, b, b2);

        return res.reveal<int>(PUBLIC);
    }
};
void PartEncIndex::changeHammingDist(uint64_t hammdist, int client_id)
{
    this->hammdist[client_id] = hammdist;
    // for (int i = 0; i < SUBINDEX_NUM; i++)
    {
        this->sub_hamm[client_id] = floor((double)hammdist / SUBINDEX_NUM);
    }
}
void PartEncIndex::getHomo(uint8_t *res)
{
    // pkN, pkG, sk[3] to bytes
    int offset = 0;
    uint8_t bytes[KEY_LEN] = {0};
    ZZToBytes(pkN, bytes);
    memcpy(res + offset, bytes, KEY_LEN);
    offset += KEY_LEN;

    memset(bytes, 0, KEY_LEN);
    ZZToBytes(pkG, bytes);
    memcpy(res + offset, bytes, KEY_LEN);
    offset += KEY_LEN;

    for (int i = 0; i < 3; i++)
    {
        memset(bytes, 0, KEY_LEN);
        memcpy(res + offset, rks[i].rk, RAND_KEY_BIT / 8);
        offset += RAND_KEY_BIT / 8;
    }
    cout << pkN << endl;
    cout << pkG << endl;
    // offset = 0;
    // uint8_t *param = res;
    // bytes[KEY_LEN];
    // memcpy(res + offset, bytes, KEY_LEN);

    // BytesFromZZ(param, pkN, KEY_LEN);
    // param += KEY_LEN;
    // BytesFromZZ(param, pkG, KEY_LEN);
    // param += KEY_LEN;
    // cout << "pkN " << pkN << endl;
    // cout << "pkG " << pkG << endl;
    // for (int i = 0; i < 3; i++)
    // {
    //     memcpy(rks[i].rk, param, RAND_KEY_BIT / 8);
    //     param += RAND_KEY_BIT / 8;
    //     for (int j = 0; j < RAND_KEY_BIT / 8; j++)
    //         cout << rks[i].rk[j];
    //     cout << endl;
    // }
};