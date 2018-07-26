/*
 * Copyright (c) 2014, Oracle America, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  * Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 *  * Neither the name of Oracle nor the names of its contributors may be used
 *    to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

package chronostream;

import com.ncipher.provider.km.nCipherKM;
import java.security.Key;
import java.security.Provider;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;

@State(Scope.Benchmark)
public class Chronostream {

  private Provider provider;
  private Key key;
  private byte[] iv;
  private Map<Integer, byte[]> ciphertexts = new HashMap<>();

  @Setup(Level.Invocation)
  public void setUp() throws Exception {
    // Configure nCipher provider
    provider = new nCipherKM();
    Security.addProvider(provider);

    // Set the softcard. Password is "prout"
    System.setProperty("protect", "softcard:fb1d3e233393838d51eb5c0a911d3056c4155af8");

    // Create a key
    KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", provider);
    keyGenerator.init(256);
    key = keyGenerator.generateKey();

    // Create the ciphertext
    iv = random(16);
    for (int i = 100; i <= 200; i++) {
      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", provider);
      cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
      ciphertexts.put(i, cipher.doFinal(random(i)));
    }
  }

  private byte[] random(int length) {
    byte[] r = new byte[length];
    new Random().nextBytes(r);
    return r;
  }

  @Benchmark
  @BenchmarkMode({Mode.Throughput, Mode.AverageTime})
  public byte[] testAesDecryption() throws Exception {
    int dataSize = (int)(Math.random() * 100 + 100);
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", provider);
    cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
    return cipher.doFinal(ciphertexts.get(dataSize));
  }
}
