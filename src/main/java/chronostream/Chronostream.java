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

import com.ncipher.provider.km.KMHmacSHA256Key;
import com.ncipher.provider.km.KMRijndaelKey;
import com.ncipher.provider.km.nCipherKM;
import java.security.Provider;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;

public class Chronostream {
  private static Object lock = new Object();
  private static Provider provider;

  private static KMRijndaelKey aesKey;
  public static final int AES_MIN = 100;
  public static final int AES_MAX = 200;

  public static final int HMAC_MIN = 3;
  public static final int HMAC_MAX = 151;
  private static KMHmacSHA256Key hmacSHA256Key;



  @State(Scope.Thread)
  public static class ThreadState {
    byte[] aesIv;
    Map<Integer, byte[]> aesCiphertexts = new HashMap<>();
    Map<Integer, byte[]> aesPlaintexts = new HashMap<>();

    Map<Integer, byte[]> hmacPlaintexts = new HashMap();
    Map<Integer, byte[]> hmacResults = new HashMap<>();

    @Setup(Level.Trial)
    public void doSetup() throws Exception {
      synchronized (lock) {
        if (provider == null) {
          // Configure nCipher provider
          provider = new nCipherKM();
          Security.addProvider(provider);

          // Set the softcard. Password is "prout"
          System.setProperty("protect", "softcard:fb1d3e233393838d51eb5c0a911d3056c4155af8");

          // Create keys
          KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", provider);
          keyGenerator.init(256);
          aesKey = (KMRijndaelKey)keyGenerator.generateKey();

          keyGenerator = KeyGenerator.getInstance("HmacSHA256", provider);
          keyGenerator.init(128);
          hmacSHA256Key = (KMHmacSHA256Key)keyGenerator.generateKey();
        }
      }

      // generate plaintext/ciphertexts pairs
      aesIv = random(16);
      for (int i=AES_MIN; i<=AES_MAX; i++) {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", provider);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(aesIv));

        byte[] plaintext = random(i);
        aesPlaintexts.put(i, plaintext);
        aesCiphertexts.put(i, cipher.doFinal(plaintext));
      }

      for (int i=HMAC_MIN; i<=HMAC_MAX; i++) {
        Mac mac = Mac.getInstance("HmacSHA256", provider);
        mac.init(hmacSHA256Key);
        byte[] plaintext = random(i);
        hmacPlaintexts.put(i, plaintext);
        hmacResults.put(i, mac.doFinal(plaintext));
      }
    }
  }

  private static byte[] random(int length) {
    byte[] r = new byte[length];
    new Random().nextBytes(r);
    return r;
  }

  // AES

  @Benchmark
  public byte[] testAesDecryption(ThreadState state) throws Exception {
    return Aes.aesDecryption(provider, aesKey, state);
  }

  @Benchmark
  public byte[] testNativeAesDecryption(ThreadState state) throws Exception {
    return Aes.nativeAesDecryption(aesKey, state);
  }

  // HMAC

  @Benchmark
  public byte[] testHmac(ThreadState state) throws Exception {
    return Hmac.hmac(provider, hmacSHA256Key, state);
  }

  @Benchmark
  public byte[] testNativeHmac(ThreadState state) throws Exception {
    return Hmac.nativeHmac(hmacSHA256Key, state);
  }

}
