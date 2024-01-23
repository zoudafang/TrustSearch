#include "../App.h"
#include "Enclave_u.h"
// #include <vector>

// class Partition_IDs
// {
// private:
//     std::vector<uint8_t> id_index;
//     int tmp[3] = {1, 2, 3};

// public:
//     Partition_IDs(/* args */){};
//     ~Partition_IDs(){};

//     void push(uint8_t *id, uint32_t len)
//     {
//         id_index.insert(id_index.end(), id, id + len);
//     }
//     uint8_t *get_index()
//     {
//         return id_index.data();
//     }
// };

void Partition_IDs::push(uint8_t *id, uint32_t len)
{
    id_index.insert(id_index.end(), id, id + len);
};
uint8_t *Partition_IDs::get_index()
{
    return id_index.data();
};
uint32_t Partition_IDs::get_len()
{
    return id_index.size();
};

uint32_t ocall_write_ids(void *id_index, uint32_t idx, uint8_t *ids, uint32_t len)
{
    Partition_IDs *tmp = (Partition_IDs *)id_index;
    uint32_t res = tmp->get_len();
    tmp->push(ids, len);
    return res;
}

uint8_t *ocall_init_id_point(void *id_index, uint32_t idx)
{
    Partition_IDs *tmp = (Partition_IDs *)id_index;
    return tmp->get_index();
};