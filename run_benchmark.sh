#!/bin/bash

for i in `seq 1 50`; do
  for j in `seq 10 10 120`; do
      java -cp /opt/nfast/java/classes/nCipherKM.jar:./chronostream-2.0.jar org.openjdk.jmh.Main -wi 1 -r $j"s" -i 1 -f 1 -t $i -rff "results/throughput_"$i"_"$j".csv"
      java -cp /opt/nfast/java/classes/nCipherKM.jar:./chronostream-2.0.jar org.openjdk.jmh.Main -wi 1 -r $j"s" -i 1 -f 1 -t $i -tu ms -bm avgt -rff "results/latency_"$i"_"$j".csv"
  done
done
