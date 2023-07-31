#ifndef CONST_VAR_H
#define CONST_VAR_H
#include <cstdint>
#include <string>

// the type of chunker
enum CHUNKER_TYPE
{
    FIXED_SIZE_CHUNKING = 0,
    FAST_CDC,
    FSL_TRACE,
    UBC_TRACE
};

// for multi-index
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

static const char SERVER_IP[] = "127.0.0.10"; // server ip
static const int SERVER_PORT = 8082;          // server port
static const uint32_t THREAD_STACK_SIZE = 8 * 1024 * 1024;

static const uint32_t test_data_len = 1001167;  // the test data length
static const uint32_t sendKey_batch_size = 512; // the batch size of sending to enclave

// for DEBE
enum QUERY_ETPE
{
    QUERY_ONE = 0,
    QUERY_BATCH
};
static std::string KEY_STR = "kl9DWMr4us0PcFeZ";
static uint8_t *const_sessionKey = reinterpret_cast<uint8_t *>(const_cast<char *>(KEY_STR.c_str()));
static const uint32_t QUERY_SIZE = 3000;

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