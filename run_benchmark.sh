#!/bin/bash

for i in `seq 1 50`; do
  echo "running $i"
  java -cp /opt/nfast/java/classes/nCipherKM.jar:./chronostream-2.0.jar org.openjdk.jmh.Main -wi 1 -i 2 -f 2 -t $i -rff results/throughput_$i
  java -cp /opt/nfast/java/classes/nCipherKM.jar:./chronostream-2.0.jar org.openjdk.jmh.Main -wi 1 -i 2 -f 2 -tu ms -bm avgt -t $i -rff results/latency_$i
done
