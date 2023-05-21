
运行前需要把ima*_code.t复制到该文件夹下
读取code中的128位特征值，写入img_code128.bin中

readData.cpp: 读取torch格式数据并写入img_code128.bin中
./readFromCfile/testRead.cpp: 读取二进制格式数据

cd build
cmake -DCMAKE_PREFIX_PATH=/usr/local/libtorch -DCMAKE_CXX_FLAGS="$(python3-config --includes)"  ..
make
./readData


