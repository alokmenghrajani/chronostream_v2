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
benchmarks = c("testAesDecryption", "testHmac", "testRsaDecryption")
for (benchmark in benchmarks) {
  jce = paste(benchmark, "Jce", sep='')
  ncore = paste(benchmark, "NCore", sep='')
  png(filename=paste(benchmark, "_throughput.png", sep=''))
  throughput_jce <- throughputs[which(throughputs$Benchmark == jce),]
  throughput_ncore <- throughputs[which(throughputs$Benchmark == ncore),]

  par(mar=c(3, 7, 2, 1))
  yaxis = c(0, max(throughput_jce$Score, throughput_ncore$Score))
  plot(throughput_jce$Score, axes=F, ylim=yaxis, xlab='', ylab='', type='l', main='', xlim=c(1, threads), col='blue')
  points(throughput_jce$Score, pch=20, col='blue')
  axis(2, ylim=yaxis, col='blue', lwd=2, line=3.5)
  mtext(2, text='throughput [ops/s]', line=5.5)
  par(new=T)
  plot(throughput_ncore$Score, axes=F, ylim=yaxis, xlab='', ylab='', type='l', main='', xlim=c(1, threads), col='black')
  points(throughput_ncore$Score, pch=20, col='black')

  axis(1, pretty(c(1, threads)))
  mtext('threads', side=1, line=2)

  legend("topleft", inset=.05, title=benchmark, c("JCE","NCore"), fill=c('blue', 'black'), horiz=TRUE)
  grid()
  dev.off()

  png(filename=paste(benchmark, "_latency.png", sep=''))
  latency_jce <- latencies[which(latencies$Benchmark == jce),]
  latency_ncore <- latencies[which(latencies$Benchmark == ncore),]

  par(mar=c(3, 7, 2, 1))
  yaxis = c(0, max(latency_jce$Score, latency_ncore$Score))
  plot(latency_jce$Score, axes=F, ylim=yaxis, xlab='', ylab='', type='l', main='', xlim=c(1, threads), col='blue')
  points(latency_jce$Score, pch=20, col='blue')
  axis(2, ylim=yaxis, col='blue', lwd=2, line=3.5)
  mtext(2, text='latency [ms]', line=5.5)
  par(new=T)
  plot(latency_ncore$Score, axes=F, ylim=yaxis, xlab='', ylab='', type='l', main='', xlim=c(1, threads), col='black')
  points(latency_ncore$Score, pch=20, col='black')

  axis(1, pretty(c(1, threads)))
  mtext('threads', side=1, line=2)

  legend("topleft", inset=.05, title=benchmark, c("JCE","NCore"), fill=c('blue', 'black'), horiz=TRUE)
  grid()
  dev.off()
}
