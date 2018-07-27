#!/bin/bash

for i in `seq 1 50`; do
  java -cp /opt/nfast/java/classes/nCipherKM.jar:./chronostream-2.0.jar org.openjdk.jmh.Main -t $i -rff throughput_$i
  java -cp /opt/nfast/java/classes/nCipherKM.jar:./chronostream-2.0.jar org.openjdk.jmh.Main -tu ms -bm avgt -t $i -rff latency_$i
done
