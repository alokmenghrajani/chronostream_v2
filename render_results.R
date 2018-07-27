setwd('results')

threads = 50

# merge all the files
throughputs <- data.frame()
latencies <- data.frame()

for (thread in 1:threads) {
  throughput <- read.table(paste('throughput_', thread, sep=''), header=TRUE, sep=',')
  throughputs <- rbind(throughputs, throughput[c("Benchmark", "Threads", "Score")])

  latency <- read.table(paste('latency_', thread, sep=''), header=TRUE, sep=',')
  latencies <- rbind(latencies, latency[c("Benchmark", "Threads", "Score")])
}

# make per benchmark graphs
throughputs$Benchmark <- sub(".*[.]", "", throughputs$Benchmark)
latencies$Benchmark <- sub(".*[.]", "", latencies$Benchmark)
benchmarks = c("testAesDecryptionJce", "testAesDecryptionNCore", "testHmacJce", "testHmacNcore", "testRsaDecryptionJce", "testRsaDecryptionNCore")
for (benchmark in benchmarks) {
  png(filename=paste(benchmark, ".png", sep=''))
  throughput <- throughputs[which(throughputs$Benchmark == benchmark),]
  latency <- latencies[which(latencies$Benchmark == benchmark),]

  par(mar=c(3, 7, 2, 1))
  yaxis = c(0, max(latency$Score))
  plot(latency$Score, axes=F, ylim=yaxis, xlab='', ylab='', type='l', col='black', main=benchmark, xlim=c(1, threads))
  points(latency$Score, pch=20, col='black')
  axis(2, ylim=yaxis, col='black', lwd=2)
  mtext(2, text='latency [ms]', line=2)

  par(new=T)
  yaxis = c(0, max(throughput$Score))
  plot(throughput$Score, axes=F, ylim=yaxis, xlab='', ylab='', type='l', main='', xlim=c(1, threads), col='blue')
  points(throughput$Score, pch=20, col='blue')
  axis(2, ylim=yaxis, col='blue', lwd=2, line=3.5)
  mtext(2, text='throughput [ops/s]', line=5.5)

  axis(1, pretty(c(1, threads)))
  mtext('threads', side=1, line=2)
  dev.off()
}
