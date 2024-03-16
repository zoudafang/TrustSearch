#ifndef CONST_VAR_H
#define CONST_VAR_H
#include <cstdint>
#include <string>
#include <vector>

#define CACHE_SIZE 5000 //
// the type of chunker
enum CHUNKER_TYPE
{
    FIXED_SIZE_CHUNKING = 0,
    FAST_CDC,
    FSL_TRACE,
    UBC_TRACE
};

// for SGX-Search
enum DATA_TYPE_SET
{
    DATA_CHUNK = 0,
    RECIPE_END,
    DATA_SEGMENT_END_FLAG
};
static const char SERVER_CERT[] = "key/server/server.crt";
static const char SERVER_KEY[] = "key/server/server.key";
static const char CLIENT_CERT[] = "../../key/client/client.crt";
static const char CLIENT_KEY[] = "../../key/client/client.key";
static const char CA_CERT[] = "key/ca/ca.crt";              // 注意可执行文件和key文件的相对路径
static const char CA_CERT_CLIENT[] = "../../key/ca/ca.crt"; // 注意可执行文件和key文件的相对路径
static const char SERVER_IP[] = "192.168.5.104";
static const int SERVER_PORT = 8090;
static const uint32_t THREAD_STACK_SIZE = 8 * 1024 * 1024;

static const uint32_t DATA_LEN = 5124668; // 5124668;
static const uint32_t SIFT_LEN = 1000000;

static const uint32_t SEND_BATCH_LEN = 512;
static const uint32_t ENC_BATCH_SIZE_IMG = 100 * (16 + 8); // 按照batch加密img数据集，<feature, target>
static const uint32_t ENC_BATCH_SIZE_SIFT = 100 * 16;      // <feature>

static const uint32_t PAGE_SIZE = 64; // 4 * 4; // 1024*4
static const uint32_t PAGE_SIZE_B = PAGE_SIZE * 4;
static const uint32_t SUBINDEX_NUM = 10; // byte of subkey

static const uint32_t MASK_INF = 0x80000000; // infrequent keys
static const uint32_t MASK_SIM = 0x40000000; // similar keys
static const uint32_t MASK_LEN = 0x3fffffff;

static const uint32_t MAX_CLIENT_NUM = 10000;
static uint32_t CLIENT_NUM = 7;
struct key_find
{
    uint32_t subkey;
    struct
    {
        uint16_t dist;     // 16bit:dist,16bit:max_dist
        uint16_t max_dist; /* data */
    };
    uint32_t clr_idx;
};

typedef struct ids_node // unchanged for ocall page block
{
    uint64_t key;
    ids_node *next;
    ids_node *pre;
    std::vector<uint8_t> ids;
} ids_node;
struct LRU_cache
{
    uint32_t capacity;
    uint32_t len;
    uint32_t remain_size;
    ids_node *index_head;
    ids_node *index_tail;
};

enum QUERY_ETPE
{
    QUERY_ONE = 0,
    QUERY_BATCH,
    SERVER_RUN,
    KILL_SERVER,
    QUERY_KNN,
    MULTI_CLIENT
};
static std::string p = "kl9DWMr4us0PcFeZ";
static uint8_t *const_sessionKey = reinterpret_cast<uint8_t *>(const_cast<char *>(p.c_str()));

static std::string key1 = "cs9DWMr4us0Pc231";
static uint8_t *const_dataKey = reinterpret_cast<uint8_t *>(const_cast<char *>(key1.c_str()));
static const uint32_t QUERY_SIZE = 100000;

enum INDEX_TYPE_SET
{
    OUT_ENCLAVE = 0,
    IN_ENCLAVE,
    EXTREME_BIN,
    SPARSE_INDEX,
    FREQ_INDEX
};
enum ENCRYPT_SET
{
    AES_256_GCM = 0,
    AES_128_GCM = 1,
    AES_256_CFB = 2,
    AES_128_CFB = 3
};
enum HASH_SET
{
    SHA_256 = 0,
    MD5 = 1,
    SHA_1 = 2
};
enum SSL_CONNECTION_TYPE
{
    IN_SERVERSIDE = 0,
    IN_CLIENTSIDE
};

// for network message protocol code
enum PROTCOL_CODE_SET
{
    CLIENT_UPLOAD_CHUNK = 0,
    CLIENT_UPLOAD_RECIPE_END,
    CLIENT_LOGIN_UPLOAD,
    CLIENT_LOGIN_DOWNLOAD,
    CLIENT_RESTORE_READY,
    SERVER_RESTORE_CHUNK,
    SERVER_RESTORE_FINAL,
    SERVER_LOGIN_RESPONSE,
    SERVER_FILE_NON_EXIST,
    SGX_RA_MSG01,
    SGX_RA_MSG2,
    SGX_RA_MSG3,
    SGX_RA_MSG4,
    SGX_RA_NEED,
    SGX_RA_NOT_NEED,
    SGX_RA_NOT_SUPPORT,
    SESSION_KEY_INIT,
    SESSION_KEY_REPLY
};

static const uint32_t CRYPTO_BLOCK_SIZE = 16;
static const uint32_t CHUNK_HASH_SIZE = 32;
static const uint32_t CHUNK_ENCRYPT_KEY_SIZE = 32;
static const uint32_t HASH_TYPE = SHA_256;
static const uint32_t CIPHER_TYPE = AES_256_GCM;

static const uint32_t CHUNK_QUEUE_SIZE = 8192;
static const uint32_t CONTAINER_QUEUE_SIZE = 32;
static const uint32_t CONTAINER_CAPPING_VALUE = 16;

static const uint32_t SGX_PERSISTENCE_BUFFER_SIZE = 2 * 1024 * 1024;

enum TWO_PATH_STATUS
{
    UNIQUE = 0,
    TMP_UNIQUE = 1,
    DUPLICATE = 2,
    TMP_DUPLICATE = 3
};

enum ENCLAVE_TRUST_STATUS
{
    ENCLAVE_TRUSTED = 0,
    ENCLAVE_UNTRUSTED = 1
};

static const uint32_t MAX_SGX_MESSAGE_SIZE = 4 * 1024;

#define ENABLE_SGX_RA 0
#define TEST_IN_CSE 0

static const uint32_t SESSION_KEY_BUFFER_SIZE = 65;

enum OPT_TYPE
{
    UPLOAD_OPT = 0,
    DOWNLOAD_OPT,
    RA_OPT
};

enum LOCK_TYPE
{
    SESSION_LCK_WRITE = 0,
    SESSION_LCK_READ,
    TOP_K_LCK_WRITE,
    TOP_K_LCK_READ
};

#endif