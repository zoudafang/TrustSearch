#include <fstream>
#include <vector>
#include <iostream>
#include <bitset>
int main() {
    // 从二进制文件中读取数据
    std::ifstream input("../img_code128.bin", std::ios::binary);
    std::vector<std::pair<uint64_t, uint64_t>> pairs;
    uint64_t high, low;
    while (input.read(reinterpret_cast<char*>(&high), sizeof(high)) && input.read(reinterpret_cast<char*>(&low), sizeof(low))) {
        pairs.emplace_back(high, low);
    }
    input.close();
	
    // ... 处理 pairs 中的数据
	std::cout<<pairs.size()<<std::endl;
	for(int i=0;i<100;i++){
		std::cout<<std::bitset<64>(pairs[i].first)<<std::endl;
	}
    return 0;
}
