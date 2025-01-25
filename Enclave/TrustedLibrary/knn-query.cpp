
#include "Container.h"

// uint32_t hash_seed2[4]{0x12345678, 0x23456789, 0x34567890, 0x45678901};
// bool compareFirst_comp2(const sub_info_comp &p, uint32_t x)
// {
//     if ((p.sub_key) != (x))
//     {
//         return (p.sub_key < x);
//     }
//     return p.sub_key < x;
// }
// long long times_[5] = {0};
// std::vector<std::pair<uint32_t, uint32_t>> containers::find_knn(uint64_t query[], int KNN_NUM)
// {
//     cand_filters.clear();
//     vector<bool> clrs_visited[SUBINDEX_NUM], clrs_searched[SUBINDEX_NUM];
//     for (int i = 0; i < SUBINDEX_NUM; i++)
//     {
//         clrs_visited[i].resize(clr[i].size());
//         clrs_searched[i].resize(clr[i].size());
//     }
//     auto compare = [](const std::pair<uint32_t, uint32_t> &lhs, const std::pair<uint32_t, uint32_t> &rhs)
//     {
//         return lhs.first < rhs.first;
//     };
//     priority_queue<std::pair<uint32_t, uint32_t>, vector<std::pair<uint32_t, uint32_t>>, decltype(compare)> knn_res(compare);
//     uint32_t max_hammdist = 10, search_max = 80; // 5*6=30 hamming

//     uint64_t *total_time_now = new uint64_t[1];
//     long long total_begin_time = 0, total_end_time = 0;
//     // ocall_get_timeNow(total_time_now);
//     total_begin_time = *total_time_now;

//     vector<std::pair<uint32_t, uint32_t>> candidate;
//     unordered_set<uint32_t> candi_new;
//     uint64_t tmpquery[2] = {0};
//     tmpquery[0] = query[0];
//     tmpquery[1] = query[1];
//     uint32_t sub[SUBINDEX_NUM] = {0};
//     split(sub, reinterpret_cast<uint8_t *>(tmpquery), sub_index_num, sub_index_plus, sub_keybit);
//     // get_sub_fingerprint32(sub, tmpquery);

//     uint32_t *out_tmp = out;
//     uint32_t tmpsub1, tmpsub2, tmpsub3, tmpsub4 = 0;
//     vector<uint32_t> temp;
//     // tsl::hopscotch_map<uint32_t, std::vector<uint32_t>>::iterator got;
//     unordered_map<uint32_t, std::vector<uint32_t>>::iterator got;

//     vector<sub_info_comp> visited_keys; // first: subkeys of candidates, second: begin index of sub_identifiers
//     sub_info_comp tmp_info;

//     uint64_t *time = new uint64_t[1];
//     long long begin_time, end_time;
//     int out_key[1], sub_key_I[2];
//     uint32_t tmp_hash[2], hash_size = ((bloom_hash_times >> 2) + (bloom_hash_times & 0x3 != 0) * 4) * uint_size; // ceil(times/4)*4
//     uint8_t tmp_hash_out[32], bloom_hash[hash_size];
//     static uint32_t candiNUM = 0;

//     vector<key_find> existed_subkeys;
//     vector<cluster_info> tmp_clrs[SUBINDEX_NUM];
//     cluster_info c_info;
//     unordered_set<uint32_t> visited_subkeys;
//     int begin_ids = 0, dt;
//     uint32_t tmp_dist = 0, tmp_count;
//     uint32_t begin_idx, end_idx, lookup_all_size = 0, pre_dist = 0, ham_dist = 0, total = 0;

//     // vector<cluster_info> **clrs_cache = new vector<cluster_info> *[SUBINDEX_NUM];
//     // vector<uint32_t> clr_index;
//     // for (int i = 0; i < SUBINDEX_NUM; i++)
//     // {
//     //     clrs_cache[i] = new vector<cluster_info>[32]; // max hamm dist=32
//     //     clr_index.push_back(0);
//     // }
//     // for (int i = 0; i < SUBINDEX_NUM; i++)
//     // {
//     //     for (int t = 0; t < clr[i].size() - 1; t++)
//     //     {
//     //         begin_idx = clr[i][t].begin_idx;
//     //         end_idx = (t == clr[i].size() - 1 ? sub_linear_comp[i].size() : clr[i][t + 1].begin_idx);
//     //         // if (clrs_visited[i][t] || t < clr[i].size() - 1 && popcount(sub[i] ^ clr[i][t].subkey) > ham_dist + max_dist)
//     //         //     continue;
//     //         // clrs_visited[i][t] = true;
//     //         // lookup_all_size += end_idx - begin_idx;
//     //         c_info.node = clr[i][t];
//     //         c_info.end = end_idx;
//     //         c_info.dist = popcount(sub[i] ^ clr[i][t].subkey);
//     //         clrs_cache[i][c_info.dist].push_back(c_info);
//     //         // tmp_clrs[i].push_back(c_info);
//     //     }
//     // }

//     tmp_count = (KNN_NUM >= 300 ? 0 : 5);
//     for (ham_dist = 0; ham_dist < search_max; ham_dist++)
//     {
//         for (int i = 0; i < SUBINDEX_NUM; i++)
//         {
//             for (int t = 0; t < clr[i].size() - 1; t++)
//             {
//                 begin_idx = clr[i][t].begin_idx;
//                 end_idx = (t == clr[i].size() - 1 ? sub_linear_comp[i].size() : clr[i][t + 1].begin_idx);
//                 if (clrs_visited[i][t] || t < clr[i].size() - 1 && popcount(sub[i] ^ clr[i][t].subkey) > ham_dist + max_dist)
//                     continue;
//                 clrs_visited[i][t] = true;
//                 lookup_all_size += end_idx - begin_idx;
//                 total += end_idx - begin_idx;
//                 c_info.node = clr[i][t];
//                 c_info.end = end_idx;
//                 c_info.dist = popcount(sub[i] ^ clr[i][t].subkey);
//                 tmp_clrs[i].push_back(c_info);
//             }
//         }
//         if (total > SUBINDEX_NUM * (KNN_NUM)*tmp_count)
//             break;
//     }
//     // if (ham_dist != 0)
//     //     printf("%d %d %d\n", ham_dist, total, SUBINDEX_NUM * KNN_NUM * 100);

//     for (pre_dist = 0; ham_dist < search_max; ham_dist++)
//     {
//         // if (ham_dist > 5)
//         //     break;
//         for (int i = 0; i < SUBINDEX_NUM; i++)
//         {
//             lookup_all_size = 0;
//             tmp_dist = 0;
//             dt = 0;
//             tmp_visit.clear();
//             // printf("reach size %d\n", reached_subkey.size());
//             reached_subkey.clear();
//             existed_subkeys.clear();

//             // ocall_get_timeNow(total_time_now);
//             total_begin_time = *total_time_now;

//             // for (int t = clr_index[i]; t <= ham_dist + max_dist; t++)
//             // {
//             //     for (int j = 0; j < clrs_cache[i][t].size(); j++)
//             //     {
//             //         tmp_clrs[i].push_back(clrs_cache[i][t][j]);
//             //     }
//             // }
//             // clr_index[i] = ham_dist + max_dist;
//             for (int t = 0; t < clr[i].size() - 1; t++)
//             {
//                 begin_idx = clr[i][t].begin_idx;
//                 end_idx = (t == clr[i].size() - 1 ? sub_linear_comp[i].size() : clr[i][t + 1].begin_idx);
//                 if (clrs_visited[i][t] || t < clr[i].size() - 1 && popcount(sub[i] ^ clr[i][t].subkey) > ham_dist + max_dist)
//                     continue;
//                 clrs_visited[i][t] = true;
//                 lookup_all_size += end_idx - begin_idx;
//                 c_info.node = clr[i][t];
//                 c_info.end = end_idx;
//                 c_info.dist = popcount(sub[i] ^ clr[i][t].subkey);
//                 tmp_clrs[i].push_back(c_info);
//             }
//             if (tmp_clrs[i].size())
//             {
//                 std::sort(tmp_clrs[i].begin(), tmp_clrs[i].end(), [](cluster_info &a, cluster_info &b)
//                           { return a.dist < b.dist; });
//             }
//             cluster_node tmp_node;
//             uint32_t min_dist = (tmp_clrs[i].size() > 0 ? tmp_clrs[i][0].dist : UINT16_MAX);

//             uint32_t tmpkey = sub[i];

//             uint32_t find_max_d = std::min(min_dist + ham_dist, max_dist), tmp_dist = min_dist; // 这个find-max-d是不是太大了，应该写在mindist增加之前

//             for (int tdx = pre_dist; tdx <= ham_dist; tdx++)
//             {
//                 if (tdx == 0)
//                 {
//                     tmpsub1 = sub[i] ^ 0;
//                     sub_key_I[0] = tmpsub1, sub_key_I[1] = i;
//                     for (int j = 0; j < bloom_hash_times; j += 4)
//                     {
//                         tmp_hash[0] = tmpsub1;
//                         tmp_hash[1] = i + j * sub_index_num * 2;
//                         MurmurHash3_x86_128(tmp_hash, 8, hash_seed2[0], bloom_hash + j * uint_size);
//                     }
//                     if (filters.contains(bloom_hash, bloom_hash_times * uint_size)) // filters.contains(bloom_hash, bloom_hash_times * uint_size)
//                     {
//                         existed_subkeys.push_back(key_find{tmpsub1, (uint16_t)0, (uint16_t)find_max_d});
//                     }
//                 }
//                 else
//                 {
//                     int curb = 32;
//                     int power[100];
//                     int s = tdx;
//                     uint32_t bitstr = 0; // the bit-string with s number of 1s
//                     for (int i = 0; i < s; i++)
//                         power[i] = i;    // power[i] stores the location of the i'th 1
//                     power[s] = curb + 1; // used for stopping criterion (location of (s+1)th 1)

//                     int bit = s - 1; // bit determines the 1 that should be moving to the left

//                     while (true)
//                     { // the loop for changing bitstr
//                         if (bit != -1)
//                         {
//                             bitstr ^= (power[bit] == bit) ? (uint32_t)1 << power[bit] : (uint32_t)3 << (power[bit] - 1);
//                             power[bit]++;
//                             bit--;
//                         }
//                         else
//                         {
//                             tmpsub1 = sub[i] ^ bitstr;

//                             for (int j = 0; j < bloom_hash_times; j += 4)
//                             {
//                                 tmp_hash[0] = tmpsub1;
//                                 tmp_hash[1] = i + j * sub_index_num * 2;
//                                 MurmurHash3_x86_128(tmp_hash, 8, hash_seed2[0], bloom_hash + j * uint_size);
//                             }
//                             if (filters.contains(bloom_hash, bloom_hash_times * uint_size)) // filters.contains(bloom_hash, bloom_hash_times * uint_size)
//                             {
//                                 existed_subkeys.push_back(key_find{tmpsub1, (uint16_t)tdx, (uint16_t)find_max_d});
//                             }

//                             while (++bit < s && power[bit] == power[bit + 1] - 1)
//                             {
//                                 bitstr ^= (uint32_t)1 << (power[bit] - 1);
//                                 power[bit] = bit;
//                             }
//                             if (bit == s)
//                                 break;
//                         }
//                     }
//                 }
//             }

//             // ocall_get_timeNow(total_time_now);
//             times_[0] += *total_time_now - total_begin_time;

//             uint32_t min_dist0 = min_dist;
//             // uint32_t find_max_d = std::min(min_dist + sub_hammdist[i], (uint64_t)max_dist), tmp_dist = min_dist; // 这个find-max-d是不是太大了，应该写在mindist增加之前
//             min_dist += ham_dist * 2; // cautious- 1

//             if (min_dist0 + ham_dist > max_dist)
//             {
//                 lookup_all_size + sub_linear_comp[i].size() - clr[i][clr[i].size() - 1].begin_idx;
//             }
//             if (0) // lookup_all_size >= (sub_linear_comp[i].size() >> 1) lookup_all_size >= ceil((double)sub_linear_comp[i].size() / 3)
//             {
//                 // ocall_get_timeNow(total_time_now);
//                 total_begin_time = *total_time_now;
//                 // search only in nearest cluster
//                 for (auto val = tmp_clrs[i].begin(); val < tmp_clrs[i].end();)
//                 {
//                     tmp_node = val->node;
//                     begin_idx = val->node.begin_idx;
//                     end_idx = val->end;

//                     if (!tmp_node.is_combined && (end_idx - begin_idx) < existed_subkeys.size() * 2) //*2的位置错了？//有效，但是无法和combkey=50结合起来//这里的find时间不高
//                     {
//                         sub_info_comp tmp;
//                         for (int k = begin_idx; k < end_idx; k++) // cautious error in it
//                         {
//                             tmp = sub_linear_comp[i][k];
//                             if (popcount(tmp.sub_key ^ sub[i]) <= sub_hammdist[i])
//                             {
//                                 visited_keys.push_back({tmp.sub_key, tmp.skiplen, tmp.length});
//                             }
//                         }
//                         val = tmp_clrs[i].erase(val);
//                     }
//                     else
//                         val++;
//                 }

//                 std::sort(tmp_clrs[i].begin(), tmp_clrs[i].end(), [](cluster_info &a, cluster_info &b)
//                           { return a.node.begin_idx < b.node.begin_idx; });
//                 uint16_t tmp_min = 0, idx = 0, tmp_d;
//                 uint32_t tmpkey_, max_find_dist;
//                 for (int x = 0; x < existed_subkeys.size(); x++)
//                 {
//                     max_find_dist = min_dist0 + existed_subkeys[x].dist * 2;
//                     tmp_min = UINT8_MAX;
//                     tmpkey_ = existed_subkeys[x].subkey;
//                     for (int t = 0; t < tmp_clrs[i].size(); t++)
//                     {
//                         if (tmp_clrs[i][t].dist > max_find_dist)
//                             continue;
//                         tmp_d = popcount(tmp_clrs[i][t].node.subkey ^ tmpkey_);
//                         if (tmp_d < tmp_min)
//                         {
//                             tmp_min = tmp_d;
//                             idx = t; // cautious
//                         }
//                     }

//                     if (tmp_min <= max_dist)
//                     {
//                         // search in tmpclr[idx]
//                         existed_subkeys[x].dist = idx;
//                     }
//                     else
//                     {
//                         // search in stash
//                         existed_subkeys[x].dist = tmp_clrs[i].size();
//                     }
//                 }
//                 c_info.node = clr[i][clr[i].size() - 1];
//                 c_info.end = sub_linear_comp[i].size();
//                 c_info.dist = popcount(sub[i] ^ clr[i][clr[i].size() - 1].subkey);
//                 tmp_clrs[i].push_back(c_info);

//                 std::sort(existed_subkeys.begin(), existed_subkeys.end(), [](key_find &a, key_find &b)
//                           { return a.dist < b.dist; });

//                 bool flag = true;
//                 for (auto val : existed_subkeys)
//                 {
//                     if (val.dist == tmp_clrs[i].size() - 1 && flag)
//                     {
//                         // ocall_get_timeNow(total_time_now);
//                         times_[1] += *total_time_now - total_begin_time;
//                         total_begin_time = *total_time_now;
//                         flag = false;
//                     }
//                     int begin = tmp_clrs[i][val.dist].node.begin_idx;
//                     int end = tmp_clrs[i][val.dist].end;

//                     auto tmpsub1 = val.subkey;
//                     auto its = std::lower_bound(sub_linear_comp[i].begin() + begin, sub_linear_comp[i].begin() + end, tmpsub1, compareFirst_comp2);
//                     if (its != sub_linear_comp[i].end() && (its->sub_key == tmpsub1 || its->length & MASK_INF)) //&& its->sub_key == tmpsub1
//                     {
//                         if (its->sub_key == tmpsub1)
//                             val.max_dist = 0;
//                         // visited_subkeys.insert(its->sub_key); // why must ==? cautious
//                         visited_keys.push_back({tmpsub1, its->skiplen, its->length}); // cautious 9-17
//                     }
//                 }
//                 if (flag)
//                 {
//                     // ocall_get_timeNow(total_time_now);
//                     times_[1] += *total_time_now - total_begin_time;
//                     total_begin_time = *total_time_now;
//                 }
//                 else
//                 {
//                     // ocall_get_timeNow(total_time_now);
//                     times_[2] += *total_time_now - total_begin_time;
//                     total_begin_time = *total_time_now;
//                 }
//             }
//             else
//             {
//                 // ocall_get_timeNow(total_time_now);
//                 total_begin_time = *total_time_now;
//                 uint32_t max_node = 0;
//                 // for (; max_node < tmp_clrs[i].size(); max_node++)
//                 // {
//                 //     if (tmp_clrs[i][max_node].dist > min_dist) // 当min太大，可以省略这比较
//                 //         break;
//                 // }
//                 tmp_dist = min_dist0;
//                 uint32_t begin_dist = 0;
//                 for (int t = 0; t < tmp_clrs[i].size(); t++)
//                 {
//                     if (tmp_clrs[i][t].dist > min_dist) // 当min太大，可以省略这比较
//                         break;
//                     tmp_node = tmp_clrs[i][t].node;
//                     begin_idx = tmp_clrs[i][t].node.begin_idx;
//                     end_idx = tmp_clrs[i][t].end;

//                     if (!tmp_node.is_combined) //*2的位置错了？//有效，但是无法和combkey=50结合起来//这里的find时间不高
//                     {
//                         key_find tmp_key{0, 0, 0};
//                         // continue;
//                         sub_info_comp tmp;
//                         for (int k = begin_idx; k < end_idx; k++) // cautious error in it
//                         {
//                             // if (k >= sub_linear_comp[i].size())
//                             // {
//                             // 	printf("error %d %d %d %d %d\n", k, sub_linear_comp[i].size(), begin_idx, end_idx, tmp_clrs[i][t].dist);
//                             // 	break;
//                             // }
//                             tmp = sub_linear_comp[i][k];
//                             // if(tmp.begin<0){visited_keys.push_back({sub[i],tmp.begin});continue;}// errors

//                             if (popcount(tmp.sub_key ^ sub[i]) <= ham_dist)
//                             {
//                                 // visited_keys.push_back({tmp.sub_key, tmp.skiplen, tmp.length});
//                                 get_cand_knn(tmp_key, {tmp.sub_key, tmp.skiplen, tmp.length}, i, query, &knn_res, KNN_NUM);
//                             }
//                         }
//                         // tmp_clrs[i].erase(tmp_clrs[i].begin() + t);
//                         // t--;
//                     }
//                     else
//                     {
//                         // begin_dist = 0;
//                         // if (tmp_clrs[i][t].dist > (min_dist0 + 2))
//                         // {
//                         // 	begin_dist = ((tmp_clrs[i][t].dist - 1 - min_dist0) >> 1);
//                         // }
//                         for (int j = 0; j < existed_subkeys.size(); j++) // exist-keys 有很多，但是实际上只需要在与它最近的cluster中find
//                         {
//                             auto &val = existed_subkeys[j];
//                             if (val.max_dist == 0)
//                                 continue;

//                             auto &tmpsub1 = val.subkey;
//                             // if (reached_subkey.find(tmpsub1) != reached_subkey.end()) // val.dist <= begin_dist || error
//                             //     continue;
//                             // if (val.dist < dt) // if 的次数太多，能否优化  || visited_subkeys.find(tmpsub1) != visited_subkeys.end()
//                             // 	continue;
//                             uint16_t tmp = popcount(tmp_node.subkey ^ tmpsub1); // 开销很大？？
//                             if (tmp > val.max_dist)                             // find max太大可省略，是不是小于呢？
//                                 continue;
//                             // add_sum++;
//                             val.max_dist = min(tmp, val.max_dist);

//                             auto its = std::lower_bound(sub_linear_comp[i].begin() + begin_idx, sub_linear_comp[i].begin() + end_idx, tmpsub1, compareFirst_comp2);
//                             if (its != sub_linear_comp[i].end() && (its->sub_key == tmpsub1 || its->length & MASK_INF)) //&& its->sub_key == tmpsub1
//                             {
//                                 if (its->sub_key == tmpsub1)
//                                     val.max_dist = 0;
//                                 // 	visited_subkeys.insert(its->sub_key);

//                                 // ++hitliner;
//                                 // visited_keys.push_back({tmpsub1, its->skiplen, its->length}); // cautious 9-17
//                                 get_cand_knn(val, {tmpsub1, its->skiplen, its->length}, i, query, &knn_res, KNN_NUM);

//                                 // begin_ids = its->length;
//                                 // if (begin_ids & MASK_SIM)
//                                 // {
//                                 //     tmp_info = visited_keys.back();
//                                 //     visited_keys.pop_back();
//                                 //     gen_candidate(candidate, tmp_info, visited_keys, tmp_visit, i, sub[i], dt);
//                                 //     for (int t = 0; t < tmp_visit.size(); t++)
//                                 //     {
//                                 //         gen_candidate(candidate, tmp_visit[t], visited_keys, tmp_visit, i, sub[i], dt + 1);
//                                 //     }
//                                 //     tmp_visit.clear();
//                                 // }
//                             }
//                         }
//                     }
//                 }

//                 // ocall_get_timeNow(total_time_now);
//                 times_[1] += *total_time_now - total_begin_time;
//                 total_begin_time = *total_time_now;
//                 // set before clusters
//                 uint32_t dt1 = std::max(dt, (int)(max_dist - min_dist0)); // cautious
//                 if (min_dist0 + ham_dist > max_dist)
//                 {
//                     // min_dist = UINT16_MAX;
//                     uint32_t idx1 = clr[i].size() - 1;
//                     begin_idx = clr[i][idx1].begin_idx;
//                     end_idx = sub_linear_comp[i].size();
//                     // if (begin_idx < end_idx) // cautious for stash==0
//                     {
//                         for (auto &val : existed_subkeys)
//                         {
//                             if (val.max_dist == 0)
//                                 continue;
//                             auto &tmpsub1 = val.subkey;
//                             if (val.dist < dt1 || val.max_dist == 0) //|| visited_subkeys.find(tmpsub1) != visited_subkeys.end()
//                                 continue;
//                             // if (reached_subkey.find(tmpsub1) != reached_subkey.end())
//                             //     continue;

//                             auto its = std::lower_bound(sub_linear_comp[i].begin() + begin_idx, sub_linear_comp[i].begin() + end_idx, tmpsub1, compareFirst_comp2);
//                             if (its != sub_linear_comp[i].end() && (its->sub_key == tmpsub1 || its->length & MASK_INF)) //&& its->sub_key == tmpsub1
//                             {
//                                 if (its->sub_key == tmpsub1)
//                                     val.max_dist = 0;
//                                 // visited_subkeys.insert(its->sub_key); // why must ==? cautious

//                                 // visited_keys.push_back({tmpsub1, its->skiplen, its->length}); // cautious 9-17
//                                 get_cand_knn(val, {tmpsub1, its->skiplen, its->length}, i, query, &knn_res, KNN_NUM);

//                                 // begin_ids = its->length;
//                                 // if (begin_ids & MASK_SIM)
//                                 // {
//                                 //     tmp_info = visited_keys.back();
//                                 //     visited_keys.pop_back();
//                                 //     gen_candidate(candidate, tmp_info, visited_keys, tmp_visit, i, sub[i], dt);
//                                 //     for (int t = 0; t < tmp_visit.size(); t++)
//                                 //     {
//                                 //         gen_candidate(candidate, tmp_visit[t], visited_keys, tmp_visit, i, sub[i], dt + 1);
//                                 //     }
//                                 //     tmp_visit.clear();
//                                 // }
//                             }
//                         }
//                     }
//                 }
//                 // ocall_get_timeNow(total_time_now);
//                 times_[2] += *total_time_now - total_begin_time;
//                 total_begin_time = *total_time_now;
//             }

//         search_end:
//             vector<sub_info_comp> tmpv;
//             std::map<uint32_t, int> tmpm;

//             // // the node finded by linear list or hashmap, to get candidate's id
//             // for (int y = 0; y < visited_keys.size(); y += 1)
//             // {
//             //     gen_candidate(candidate, visited_keys[y], tmp_visit, tmpv, i, sub[i], dt);
//             // }

//             if (knn_res.size() >= KNN_NUM && knn_res.top().first <= (i + ham_dist * SUBINDEX_NUM))
//             {
//                 for (int j = 0; j < KNN_NUM; j++)
//                 {
//                     successful_num++;
//                     candidate.push_back(knn_res.top());
//                     knn_res.pop();
//                 }
//                 return candidate;
//             }
//             visited_keys.clear();
//         }
//         // if (ham_dist > 4)
//         // {
//         //     candidate.push_back(knn_res.size());
//         //     while (knn_res.size() != 0)
//         //     {
//         //         successful_num++;
//         //         candidate.push_back(knn_res.top().second);
//         //         knn_res.pop();
//         //     }
//         //     return candidate;
//         // }
//         pre_dist = ham_dist + 1;
//     }
//     uint32_t successful_num_pre = successful_num;

//     uint64_t tmp_fullkey[2] = {0};
//     uint64_t equal = 0, target = 0;
//     static uint32_t unequal = 0;
//     static uint32_t unequal_n = 0;

//     uint64_t cmp_hamm[2] = {0};
//     uint64_t count = 0;
//     vector<uint32_t> res_id;
//     res_id.reserve(5000);
//     information got_out;
//     // for (auto it = candidate.begin(); it != candidate.end();)
//     // {
//     //     if (*it < full_index.size())
//     //         got_out = full_index[*it];
//     //     if (1)
//     //     {
//     //         get_full_fingerprint32(tmp_fullkey, (uint32_t *)&full_index[*it]);
//     //         cmp_hamm[0] = query[0] ^ (tmp_fullkey[0]);
//     //         cmp_hamm[1] = query[1] ^ (tmp_fullkey[1]);
//     //         // count =__builtin_popcountl(cmp_hamm[0]) + __builtin_popcountl(cmp_hamm[1]);
//     //         count = bitset<64>(cmp_hamm[0]).count() + bitset<64>(cmp_hamm[1]).count();

//     //         candi_num += full_index[*it + fullkey_len].len; // cautious caluate for candidate images
//     //         if (count <= hammdist)
//     //         {
//     //             successful_num += full_index[*it + fullkey_len].len;

//     //             out_tmp = out;
//     //             uint8_t *comp_data = (uint8_t *)&full_index[*it + fullkey_len + 1];
//     //             if (full_index[*it + fullkey_len].len <= COMPRESS_MIN_UNSORT)
//     //             {
//     //                 uint32_t test_target = 0;
//     //                 out_tmp = (uint32_t *)&full_index[*it + fullkey_len + 1];
//     //                 // 测试获取的图片对应的id
//     //                 for (int j = 0; j < full_index[*it + fullkey_len].len; j++)
//     //                     res_id.push_back(out_tmp[j]);
//     //                 // test_target += out_tmp[j];
//     //             }
//     //             else
//     //             {
//     //                 uint32_t test_target = 0;
//     //                 for_uncompress(comp_data, out_tmp, full_index[*it + fullkey_len].len);
//     //                 // 测试获取的图片对应的id
//     //                 for (int j = 0; j < full_index[*it + fullkey_len].len; j++)
//     //                     res_id.push_back(out_tmp[j]);
//     //                 // test_target += out_tmp[j];
//     //             }

//     //             it++;
//     //         }
//     //         else
//     //             it = candidate.erase(it);
//     //     }
//     // }

//     return vector<std::pair<uint32_t, uint32_t>>(); // std::move(res_id);
// }

// void containers::get_cand_knn(key_find &find_val, sub_info_comp comp, uint32_t i, uint64_t *query, void *res, uint32_t KNN_NUM)
// {
//     knn_cand_get++;
//     uint64_t key = ((uint64_t)i << 32) | comp.skiplen;

//     auto val = data_cache.find(key);
//     if (val != data_cache.end())
//     {
//         tmp_ids_block = val->second->ids.data();
//         lru_ids_visit(key, val->second);
//     }
//     else
//     {
//         tmp_ids_block = lru_ids_add(key, i, comp);
//     }
//     // tmp_ids_block = id_point[i] + comp.skiplen;

//     uint32_t tempKey = comp.sub_key;
//     uint32_t tmp_size = 0, count;
//     int tmp_begin = 0;
//     bool is_combined_keys = false;
//     uint64_t tmp_fullkey[2] = {0}, cmp_hamm[2];

//     auto out_tmp = out;
//     // if (tmp_begin < 0) ,some continuous  subkeys are Combined to one biggest subkey in there
//     if (comp.length & MASK_INF)
//     {
//         is_combined_keys = true;
//     }

//     tmp_size = *((uint32_t *)&tmp_ids_block[tmp_begin]);
//     if ((int)tmp_size < 0)
//     {
//         tmp_begin += sizeof(uint32_t);
//         tmp_size = *((uint32_t *)&tmp_ids_block[tmp_begin]);
//     }

//     // 解压，如果多个subkey是被合并后的，is-combine=true；解压的是unsort数组；否则解压产生sorted数组
//     if (!is_combined_keys)
//     {
//         if (tmp_size <= COMPRESS_MIN)
//         {
//             out_tmp = (uint32_t *)(tmp_ids_block + tmp_begin + 4);
//         }
//         else
//         {
//             for_uncompress(tmp_ids_block + tmp_begin + 4, out_tmp, tmp_size); // decompress
//                                                                               //   printf("tmp_size: %u\n", tmp_size);
//         }
//     }
//     else
//     {
//         if (tmp_size <= COMPRESS_MIN_UNSORT)
//             out_tmp = (uint32_t *)(tmp_ids_block + tmp_begin + 4);
//         else
//             for_uncompress(tmp_ids_block + tmp_begin + 4, out_tmp, tmp_size); // decompress
//     }

//     // get the true identifiers of the subkey
//     if (is_combined_keys)
//     {
//         uint32_t lens = 0;

//         // out_tmp结构:[keys_len, subkey0,...,subkeyN,-id0,id1,-id4,id8,...,idm]
//         // keys_len: 这个block里面subkey的数量，subkey：这个block里面包含的subkey，所有subkey在排列在一起
//         // id：前面subkey对应的图片id集合，按照subkey的先后顺序，每个subkey对应一个id序列，这个id序列开头为-id，以表示开始一个新的序列
//         uint32_t keys_len = out_tmp[0];
//         // printf("keys_len %d\n", keys_len);

//         auto x = std::lower_bound(out_tmp + 1, out_tmp + 1 + keys_len, tempKey);
//         if (x != out_tmp + 1 + keys_len && *x == tempKey)
//         {
//             uint32_t times = (x - out_tmp);
//             for (int t = 1 + keys_len; t < tmp_size; t++)
//             {
//                 if ((int)out_tmp[t] < 0)
//                 {
//                     times--;
//                     if (times == 0)
//                     {
//                         knn_hit_cand++;
//                         find_val.max_dist = 0;
//                         if (cand_filters.find(-out_tmp[t]) == cand_filters.end())
//                         {
//                             cand_filters.emplace_hint(cand_filters.begin(), -out_tmp[t]);
//                             get_knn_res(-out_tmp[t], query, res, KNN_NUM);
//                         }
//                         for (int l = t + 1; l < tmp_size; l++)
//                         {
//                             if ((int)out_tmp[l] < 0)
//                                 break;
//                             if (cand_filters.find(out_tmp[l]) == cand_filters.end())
//                             {
//                                 cand_filters.emplace_hint(cand_filters.begin(), out_tmp[l]);
//                                 get_knn_res(out_tmp[l], query, res, KNN_NUM);
//                             }
//                         }
//                         break;
//                     }
//                 }
//             }
//         }
//     }
//     else
//     {
//         find_val.max_dist = 0;
//         knn_hit_cand++;
//         for (int j = 0; j < tmp_size; j++)
//         {
//             if (cand_filters.find(out_tmp[j]) == cand_filters.end())
//             {
//                 cand_filters.emplace_hint(cand_filters.begin(), out_tmp[j]);
//                 get_knn_res(out_tmp[j], query, res, KNN_NUM);
//             }
//         }
//     }
// }

// void containers::get_knn_res(uint32_t fullkey_index, uint64_t *query, void *res, uint32_t KNN_NUM)
// {
//     uint64_t tmp_fullkey[2] = {0}, cmp_hamm[2];
//     uint32_t count;
//     auto compare = [](const std::pair<uint32_t, uint32_t> &lhs, const std::pair<uint32_t, uint32_t> &rhs)
//     {
//         return lhs.first < rhs.first;
//     };
//     auto *knn_res = reinterpret_cast<priority_queue<std::pair<uint32_t, uint32_t>, vector<std::pair<uint32_t, uint32_t>>, decltype(compare)> *>(res);

//     uint32_t *it = &fullkey_index;
//     get_full_fingerprint32(tmp_fullkey, (uint32_t *)&full_index[*it]);
//     cmp_hamm[0] = query[0] ^ (tmp_fullkey[0]);
//     cmp_hamm[1] = query[1] ^ (tmp_fullkey[1]);
//     count = __builtin_popcountl(cmp_hamm[0]) + __builtin_popcountl(cmp_hamm[1]);
//     // count = bitset<64>(cmp_hamm[0]).count() + bitset<64>(cmp_hamm[1]).count();
//     if (count >= max_knn_num)
//         return;
//     uint32_t *tmp_ids = ids_block;
//     uint8_t *comp_data = (uint8_t *)&full_index[*it + 4 + 1];
//     if (full_index[*it + 4].len <= COMPRESS_MIN_UNSORT)
//     {
//         tmp_ids = (uint32_t *)&full_index[*it + 4 + 1];
//         // 测试获取的图片对应的id
//         for (int j = 0; j < full_index[*it + 4].len; j++)
//         {
//             if (knn_res->size() < KNN_NUM)
//             {
//                 knn_res->push({count, tmp_ids[j]});
//             }
//             else
//             {
//                 if (count < knn_res->top().first)
//                 {
//                     knn_res->pop();
//                     knn_res->push({count, tmp_ids[j]});
//                 }
//             }
//         }
//     }
//     else
//     {
//         uint32_t test_target = 0;
//         for_uncompress(comp_data, tmp_ids, full_index[*it + 4].len);
//         // 测试获取的图片对应的id
//         for (int j = 0; j < full_index[*it + 4].len; j++)
//         {
//             if (knn_res->size() < KNN_NUM)
//             {
//                 knn_res->push({count, tmp_ids[j]});
//             }
//             else
//             {
//                 if (count < knn_res->top().first)
//                 {
//                     knn_res->pop();
//                     knn_res->push({count, tmp_ids[j]});
//                 }
//             }
//         }
//     }
// }


std::vector<std::pair<uint32_t, uint32_t>> containers::find_knn(uint64_t query[], int KNN_NUM)
{
    std::vector<std::pair<uint32_t, uint32_t>> candidate;
    return candidate;
}