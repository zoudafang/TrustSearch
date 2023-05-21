#include <fstream>
#include <iostream>
#include <vector>
#include <torch/torch.h>

int main() {
    // 从二进制文件中读取数据
    std::ifstream input("../imagenet_retrieval_code128.t", std::ios::binary);
    std::vector<char> buffer((std::istreambuf_iterator<char>(input)), (std::istreambuf_iterator<char>()));
    torch::Tensor tensor = torch::from_blob(buffer.data(), {255224, 128}, torch::kFloat);
    if (!input.is_open()) {
        std::cout << "Failed to open input file" << std::endl;
        return -1;
    }
    input.close();

    // 将每128位的数据转换为一个 std::pair 对象
    std::vector<std::pair<uint64_t, uint64_t>> pairs;
    for (int i = 0; i < tensor.size(0); i++) {
        uint64_t high = 0,low = 0;
        for (int j = 0; j < tensor.size(1); j++) {
            uint64_t value =( tensor[i][j].item<float>()>0.0?1:0);
            if (j < 64) {
                high |= value << (63 - j); // 从高位到低位依次读取bit位
            } else {
                low |= value  << (127 - j); // 从高位到低位依次读取bit位
            }
        }
        pairs.emplace_back(high, low);
    }

    // 将 std::pair 对象写入到二进制文件中
    std::ofstream output("img_data128.bin", std::ios::binary);
    for (const auto& pair : pairs) {
        output.write(reinterpret_cast<const char*>(&pair.first), sizeof(pair.first));
        output.write(reinterpret_cast<const char*>(&pair.second), sizeof(pair.second));
    }
    output.close();

    return 0;
}
