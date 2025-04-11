#!/bin/bash

while getopts "t:n:" opt; do
  case $opt in
    t)
      # 获取 -t 参数的值
      value=$OPTARG
      ;;
    n)
      nums=$OPTARG
      ;;
    *)
      echo "Usage: $0 -t <value>"
      exit 1
      ;;
  esac
done


echo "data $((value))" >> res_test5.txt
cmake ..
make

    
    start_time=$(date +%s%6N)
    for((n = 1; n <= (nums-1); n++))
    do
    ./client -t $value  -h 12 >> res_exp2.txt &
    done
    ./client -t $value  -h 12 >> res_exp2.txt

    wait
    end_time=$(date +%s%6N)
    duration=$((end_time - start_time))

    echo "clients of number $((nums)) ----- Duration: $duration us" >> res_exp2.txt  # 将时间差和 times 记录到 res_test5.txt 文件中
    sleep 5

make clean

