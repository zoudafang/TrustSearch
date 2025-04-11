#!/bin/bash

while getopts "t:" opt; do
  case $opt in
    t)
      # 获取 -t 参数的值
      value=$OPTARG
      ;;
    *)
      echo "Usage: $0 -t <value>"
      exit 1
      ;;
  esac
done


for j in {1..6}
do 
    h=$((4+j*4))

    echo "data $((t))" >> res_exp3.txt
    cmake ..
    make
    echo "loop--------data $((value))----hamm--$((h))--" >> res_exp3.txt 

    ./client -t $value -h $h >> res_exp3.txt 

    make clean


done