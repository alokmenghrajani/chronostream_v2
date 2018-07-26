# Running

    mvn package
    java -cp /opt/nfast/java/classes/nCipherKM.jar:./chronostream-2.0.jar org.openjdk.jmh.Main -f 1 -t 20 -rff output

# Testing
To quickly run the code:

    mvn package
    java -cp ./ncipherkm-1.0.jar:target/chronostream-2.0.jar org.openjdk.jmh.Main -wi 0 -f 1 -i 1 -r 1