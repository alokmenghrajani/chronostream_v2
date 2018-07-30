#!/bin/bash

mkdir results
mkdir results/exp1
mkdir results/exp2

for i in `seq 1 50`; do
  java -cp /opt/nfast/java/classes/nCipherKM.jar:./chronostream-2.0.jar org.openjdk.jmh.Main -wi 1 -r 30s -i 4 -f 2 -t $i -rff "results/exp1/throughput_"$i".csv"
  java -cp /opt/nfast/java/classes/nCipherKM.jar:./chronostream-2.0.jar org.openjdk.jmh.Main -wi 1 -r 30s -i 4 -f 2 -t $i -tu ms -bm avgt -rff "results/exp1/latency_"$i".csv"
done

for j in `seq 10 10 120`; do
  java -cp /opt/nfast/java/classes/nCipherKM.jar:./chronostream-2.0.jar org.openjdk.jmh.Main -wi 1 -r $j"s" -i 1 -f 1 -t 20 -rff "results/exp2/throughput_"$j".csv"
  java -cp /opt/nfast/java/classes/nCipherKM.jar:./chronostream-2.0.jar org.openjdk.jmh.Main -wi 1 -r $j"s" -i 1 -f 1 -t 20 -tu ms -bm avgt -rff "results/exp2/latency_"$j".csv"
done
