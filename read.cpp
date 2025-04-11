#include <iostream>
#include <fstream>
#include <vector>
#include <utility>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <unordered_set>
#include <algorithm>

const uint32_t FEATURE_SIZE = 16;  // 每个特征值的大小（128位 = 16字节）
const uint32_t QUERY_SIZE = 1000;  // 要选择的查询数量

void read_all_features(const std::string &file_name, std::vector<std::pair<uint64_t, uint64_t>> &features) {
    std::ifstream input(file_name, std::ios::binary);
    if (!input) {
        std::cerr << "Failed to open the file." << std::endl;
        return;
    }

    uint64_t high, low;
    while (input.read(reinterpret_cast<char *>(&high), sizeof(high)) && input.read(reinterpret_cast<char *>(&low), sizeof(low))) {
        features.emplace_back(high, low);
    }

    input.close();
    std::cout << "Total features read: " << features.size() << std::endl;
}

void write_random_queries(const std::string &output_file, const std::vector<std::pair<uint64_t, uint64_t>> &features) {
    if (features.size() < QUERY_SIZE) {
        std::cerr << "Not enough features to select queries." << std::endl;
        return;
    }

    // 生成1000个随机索引
    std::unordered_set<uint32_t> random_indices;
    srand(static_cast<unsigned int>(time(0)));
    while (random_indices.size() < QUERY_SIZE) {
        uint32_t index = rand() % features.size();
        random_indices.insert(index);
    }

    // 打开输出文件
    std::ofstream output(output_file, std::ios::binary);
    if (!output) {
        std::cerr << "Failed to open the output file." << std::endl;
        return;
    }

    // 写入随机选择的特征值
    for (const auto &index : random_indices) {
        const auto &feature = features[index];
        output.write(reinterpret_cast<const char *>(&feature.first), sizeof(feature.first));
        output.write(reinterpret_cast<const char *>(&feature.second), sizeof(feature.second));
    }

    output.close();
    std::cout << "Random queries written to " << output_file << std::endl;
}

int main() {
    std::string input_file = "/root/shield_search/SGX-Search/faceData_10M-5.3.bin";
    std::string output_file = "/root/shield_search/SGX-Search/query_faceData.bin";
    std::vector<std::pair<uint64_t, uint64_t>> features;

    // 读取所有特征值
    read_all_features(input_file, features);

    // 随机选择1000个特征值并写入新文件
    write_random_queries(output_file, features);

    return 0;
}