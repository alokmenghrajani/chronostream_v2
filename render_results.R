# Experiment 1: measure throughput/latency as the number of threads grows.
# (in the past, we were seeing some perf degradation)

# merge all the files
threads = 50
throughputs <- data.frame()
latencies <- data.frame()

for (thread in 1:threads) {
  throughput <- read.table(paste('results/exp1/throughput_', thread, '.csv', sep=''), header=TRUE, sep=',')
  throughputs <- rbind(throughputs, throughput[c("Benchmark", "Threads", "Score")])

  latency <- read.table(paste('results/exp1/latency_', thread, '.csv', sep=''), header=TRUE, sep=',')
  latencies <- rbind(latencies, latency[c("Benchmark", "Threads", "Score")])
}
throughputs$Benchmark <- sub(".*[.]", "", throughputs$Benchmark)
latencies$Benchmark <- sub(".*[.]", "", latencies$Benchmark)

# make per benchmark graphs
benchmarks = c("testAesDecryption", "testHmac", "testRsaDecryption")
for (benchmark in benchmarks) {
  jce = paste(benchmark, "Jce", sep='')
  ncore = paste(benchmark, "NCore", sep='')
  png(filename=paste('graphs/exp1_', benchmark, "_throughput.png", sep=''))
  throughput_jce <- throughputs[which(throughputs$Benchmark == jce),]
  throughput_ncore <- throughputs[which(throughputs$Benchmark == ncore),]

  par(mar=c(3, 7, 2, 1))
  yaxis = c(0, max(throughput_jce$Score, throughput_ncore$Score))
  plot(throughput_jce$Threads, throughput_jce$Score, axes=F, ylim=yaxis, xlab='', ylab='', type='l', main='', col='blue')
  points(throughput_jce$Threads, throughput_jce$Score, pch=20, col='blue')
  axis(2, ylim=yaxis, col='blue', lwd=2, line=3.5)
  mtext(2, text='throughput [ops/s]', line=5.5)
  par(new=T)
  plot(throughput_ncore$Threads, throughput_ncore$Score, axes=F, ylim=yaxis, xlab='', ylab='', type='l', main='', col='black')
  points(throughput_ncore$Threads, throughput_ncore$Score, pch=20, col='black')

  axis(1, pretty(c(1, threads)))
  mtext('threads', side=1, line=2)

  grid()
  legend("topleft", bg='white', inset=.05, title=benchmark, c("JCE","NCore"), fill=c('blue', 'black'), horiz=TRUE)
  dev.off()

  png(filename=paste('graphs/exp1_', benchmark, "_latency.png", sep=''))
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

  grid()
  legend("topleft", bg='white', inset=.05, title=benchmark, c("JCE","NCore"), fill=c('blue', 'black'), horiz=TRUE)
  dev.off()
}

# Experiment 2: measure throughput/latency as the test runs longer.
# (in the past, we were seeing some perf degradation)

# merge all the files
min_time = 10
max_time = 120
throughputs <- data.frame()
latencies <- data.frame()
for (t in seq(from=min_time, to=max_time, by=10)) {
  throughput <- read.table(paste('results/exp2/throughput_', t, '.csv', sep=''), header=TRUE, sep=',')
  throughput$Time <- t
  throughputs <- rbind(throughputs, throughput[c("Benchmark", "Time", "Score")])

  latency <- read.table(paste('results/exp2/latency_', t, '.csv', sep=''), header=TRUE, sep=',')
  latency$Time <- t
  latencies <- rbind(latencies, latency[c("Benchmark", "Time", "Score")])
}
throughputs$Benchmark <- sub(".*[.]", "", throughputs$Benchmark)
latencies$Benchmark <- sub(".*[.]", "", latencies$Benchmark)

# make per benchmark graphs
benchmarks = c("testAesDecryption", "testHmac", "testRsaDecryption")
for (benchmark in benchmarks) {
  jce = paste(benchmark, "Jce", sep='')
  ncore = paste(benchmark, "NCore", sep='')
  png(filename=paste('graphs/exp2_', benchmark, "_throughput.png", sep=''))
  throughput_jce <- throughputs[which(throughputs$Benchmark == jce),]
  throughput_ncore <- throughputs[which(throughputs$Benchmark == ncore),]

  par(mar=c(3, 7, 2, 1))
  yaxis = c(0, ceiling(max(throughput_jce$Score, throughput_ncore$Score)))
  plot(throughput_jce$Time, throughput_jce$Score, axes=F, ylim=yaxis, xlab='', ylab='', type='l', main='', col='blue')
  points(throughput_jce$Time, throughput_jce$Score, pch=20, col='blue')
  axis(2, ylim=yaxis, col='blue', lwd=2, line=3.5)
  mtext(2, text='throughput [ops/s]', line=5.5)
  par(new=T)
  plot(throughput_ncore$Time, throughput_ncore$Score, axes=F, ylim=yaxis, xlab='', ylab='', type='l', main='', col='black')
  points(throughput_ncore$Time, throughput_ncore$Score, pch=20, col='black')

  axis(1, pretty(c(min_time, max_time)))
  mtext('time [s]', side=1, line=2)

  grid()
  legend("bottomright", bg='white', inset=0.05, title=benchmark, c("JCE","NCore"), fill=c('blue', 'black'), horiz=TRUE)
  dev.off()

  png(filename=paste('graphs/exp2_', benchmark, "_latency.png", sep=''))
  latency_jce <- latencies[which(latencies$Benchmark == jce),]
  latency_ncore <- latencies[which(latencies$Benchmark == ncore),]

  par(mar=c(3, 7, 2, 1))
  yaxis = c(0, ceiling(max(latency_jce$Score, latency_ncore$Score)))
  plot(latency_jce$Time, latency_jce$Score, axes=F, ylim=yaxis, xlab='', ylab='', type='l', main='', col='blue')
  points(latency_jce$Time, latency_jce$Score, pch=20, col='blue')
  axis(2, ylim=yaxis, col='blue', lwd=2, line=3.5)
  mtext(2, text='latency [ms]', line=5.5)
  par(new=T)
  plot(latency_ncore$Time, latency_ncore$Score, axes=F, ylim=yaxis, xlab='', ylab='', type='l', main='', col='black')
  points(latency_ncore$Time, latency_ncore$Score, pch=20, col='black')

  axis(1, pretty(c(min_time, max_time)))
  mtext('time [s]', side=1, line=2)

  grid()
  legend("bottomright", bg='white', inset=.05, title=benchmark, c("JCE","NCore"), fill=c('blue', 'black'), horiz=TRUE)
  dev.off()
}
