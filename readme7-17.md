


数据集:1281167，结构为[64bit key,64not key,32bit target]
       5124668，结构为[64bit key,64not key,64bit target]
        图片集合:共1000个类，128w中每个类1300张图片，512w中每个类5200张图片，但是观察到同一个类中的图片
        特征值距离不一定小于8，平均每次查询可以获得2000张相似图片。
        另外：存在部分特征值，数据集中不存在其他特征值与它相似，用它查询只能获得1个结果。（神经网络训练误差？读取数据集错误？）
        
1. 1281167数据在img_code128.bin中，5124668数据在img512.zip中，注意（由于太大，经过zip压缩，使用时需要用命令unzip img512.zip解压）

分支：
    lru_lz4:混合linear和map，采用lru数据迁移，lz4压缩sub-index,包括bloom filter
    lru_for:混合linear和map，采用lru数据迁移，for压缩sub-index,包括bloom filter
    （上面两个是our design最新的实现）
    naive_multiIndex:纯map实现multi-index，包括数据倾斜划分，for压缩，认为是state of the art的MIH

0. 压缩：对于naive_multiIndex，一个key对应多个identifiers，可以压缩vector<identifiers>，
        对于lru，也是压缩identifiers，只是位置不一样，是linear list的identifiers
0.0 现在的方法，压缩之前，需要将数据全部读入enclave中，以[key,identifier]的方式写入tmp_linear_list，然后再进行压缩
    这样的话，峰值内存占用实际上比不用压缩的方式还更高，但是运行find时的内存使用应该会更低

1. lz4和for是两种不同压缩算法，注意到，压缩只有10个int的数据，可能压缩后长度反而增加，所以数据量较少时不会压缩
    1.1 对于naive_multiIndex，压缩可能减少1-2s查询；对于lru，压缩似乎没有太高的提升？0.1左右

lru：
0. 流程：init（初始化bloom filter等），ecall_send（发送全部数据到enclave中），
        init_after_send_data（接收完所有数据后，linear list进行sort，compress；插入sub_map）

1. 分为sub_map和sub_linear, 其中sub_linear又拆分为sub_keys和sub_identifiers两个linear list（这里的sub_keys等 只是一个名称代表，不一定是代码中的name）
    将[key,identifier]结构的linear拆分成sub_keys [keys], sub_identifiers [identifiers]两个linear list
    好处是keys作为查询lienar list，大小更小；多个identifiers只需要存储一份key，减少冗余
    sub_keys [keys]数据结构为{sub_key,begin}, begin是该sub_key对应的sub_identifiers的起始index
    sub_identifiers [identifiers]数据结构为{ [len0,compress(identifiers0)], [len1,compress(identifiers1),...] }
        sub_identifiers除了存储压缩后的identifiers，还会在前面存储一些额外信息，
        for压缩=前面4byte存储压缩前长度len，后面是len长度压缩后的数据；lz4压缩=前面4byte是长度，后面4byte是压缩参数，再后面是压缩后的数据

2. map中同样存储的是sub_keys中的begin，所以map中查找到了，需要到线性表中获取数据，目的是减少lru-add函数的复杂度；
    其他方案：map中存储未压缩的identifiers，map中存储压缩后的identifiers（lru-add时间开销大），linear和map中都不进行压缩，


备注：
1. bloom filter的parameters.false_positive_probability影响filter的大小和查询精确度，在当前lru下，0.3测试是最佳的
2. 倾斜分区似乎用处不大，数据分布相对均匀，就算使用随机划分分区的方法，查询效率变化不大
3. 查询效率对内存敏感，比如information或sub_information增加一个uint32字段，则查询效率会相应降低