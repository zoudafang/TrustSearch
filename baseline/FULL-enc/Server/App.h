#ifndef _APP_H_
#define _APP_H_

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string>
#include <vector>
#include <chrono>
#include "../include/constVar.h"
#include "../include/cryptoPrimitive.h"
#include "Container/Container.h"
#include "../include/serverOptThead.h"

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#if defined(__cplusplus)
extern "C"
{
#endif

    // change!!
    void init_after_send_data(std::vector<dataItem> &db, int dataset_flag);
    void init_homo_params();
    vector<dataItem> partEncData(std::vector<uint8_t> &read_data, int dataSet);

    void read_data(std::string file_name, std::vector<std::pair<uint64_t, uint64_t>> &data, std::vector<uint32_t> &data_target, int flag);
    void send_data(std::vector<std::pair<uint64_t, uint64_t>> &data, std::vector<uint32_t> &data_target, int is_query);

    void read_enc_dataset(std::string file_name, std::vector<uint8_t> &read_data, int is_query);
    std::vector<uint32_t> get_randIndex(int range, int k);

    void init_test_query(std::vector<uint8_t> &queries);
    void start_server();

#if defined(__cplusplus)
}
#endif

#endif /* !_APP_H_ */
