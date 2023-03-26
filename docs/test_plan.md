## 测试方案  
### 数据结构 
目前我们假设完整特征值为128bit，有4个子索引，即子特征值为32bit  
代码中涉及到的主要数据都存储在以下容器中，包括：  
##### unordered_map  
·full-index，标识符->[完整特征值，存储位置],数据结构为:uint32-t -- [uint64-t[2],uint16-t]；  
·sub-index，特征值段->标识符，结构为：uint32-t -- uint32-t；  
##### vector  
·C-0-TO-subhammdis，存储用于做异或运算的所有数字，结构为uint32-t;  
##### set  
·test-pool，查询的特征值，结构为：pair<uint64-t,uint64-t>  
### 内存占用  
内存的大小主要由两个参数决定：initialize-size和test-size，前者定义了索引中条目的个数，后者定义了查询个数；  
则根据前面数据结构的定义，可以得到内存占用情况：  
initialize_size x(32+64x2+16+64x4)+test_size x128 bit  
例如initialize_size为10000，test-size为10000，则内存占用为：0.67MB  
### 执行时间  
这里的思路就是测量代码中test()部分的运行时间，但是目前没有找到能够在sgx中使用的时间函数，导致只能测量整体时间（包括初始化）  
### 测试计划  
分别设置initialize-size和test-size，每组测试多次，取执行时间的平均值；  
根据已有经验，当enclave中内存占用在90MB左右时，会因为换页开销而倒是性能下降，在查看数据时可以找一下转折点