package chronostream;

import com.ncipher.provider.km.KMHmacSHA256Key;
import com.ncipher.provider.km.KMRSAPrivateKey;
import com.ncipher.provider.km.KMRijndaelKey;
import com.ncipher.provider.km.nCipherKM;
import java.io.ByteArrayInputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.RSAKeyGenParameterSpec;
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

/**
 * Benchmark, using JCE vs nCore API:
 * AES:
 * - AES-CBC-HMAC encryption (256 bit key)
 * - AES-CBC-HMAC decryption (256 bit key)
 *
 * HMAC:
 * - HmacSha256
 *
 * RSA:
 * - RSA-OAEP decryption (2048 bit key)
 * - RSA-PSS-SHA256 signing (2048 bit key)   (TODO)
 * - RSA-PKCS1-SHA256 signing (2048 bit key) (TODO)
 * - RSA-PKCS1-SHA512 signing (2048 bit key) (TODO)
 */
public class Chronostream {
  public static final String KEYSTORE = "1b0e6e7ded66468082d51dfc29d6e8dcfdc29c4b";
  public static final String PASSWORD = "prout";
  public static final String SOFTCARD = "952c93dfde960d877ea039d805fb2a70b6578460";

  private static Object lock = new Object();
  private static Provider provider;
  private static KeyStore keyStore;

  private static KMRijndaelKey aesKey;
  public static final int AES_MIN = 100;
  public static final int AES_MAX = 200;

  public static final int HMAC_MIN = 3;
  public static final int HMAC_MAX = 151;
  private static KMHmacSHA256Key hmacSHA256Key;

  public static final int RSA_KEY_SIZE = 2048;
  public static final int RSA_MIN = 10;
  public static final int RSA_MAX = 64;
  private static PublicKey rsaPublicKey;
  private static KMRSAPrivateKey rsaPrivateKey;

  @State(Scope.Thread)
  public static class ThreadState {
    byte[] aesIv;
    Map<Integer, byte[]> aesPlaintexts = new HashMap<>();
    Map<Integer, byte[]> aesCiphertexts = new HashMap<>();

    Map<Integer, byte[]> hmacPlaintexts = new HashMap();
    Map<Integer, byte[]> hmacResults = new HashMap<>();

    Map<Integer, byte[]> rsaPlaintexts = new HashMap<>();
    Map<Integer, byte[]> rsaCiphertexts = new HashMap<>();

    @Setup(Level.Trial)
    public void doSetup() throws Exception {
      synchronized (lock) {
        if (provider == null) {
          // Configure nCipher provider
          provider = new nCipherKM();
          Security.addProvider(provider);

          // Set the softcard.
          System.setProperty("protect", String.format("softcard:%s", SOFTCARD));

          // Create keys
          KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", provider);
          keyGenerator.init(256);
          aesKey = (KMRijndaelKey)keyGenerator.generateKey();

          keyGenerator = KeyGenerator.getInstance("HmacSHA256", provider);
          keyGenerator.init(128);
          hmacSHA256Key = (KMHmacSHA256Key)keyGenerator.generateKey();

          KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA", provider);
          RSAKeyGenParameterSpec
              rsaKeyGenParameterSpec = new RSAKeyGenParameterSpec(RSA_KEY_SIZE, RSAKeyGenParameterSpec.F4);
          keyPairGen.initialize(rsaKeyGenParameterSpec);
          KeyPair keyPair = keyPairGen.generateKeyPair();
          rsaPublicKey = keyPair.getPublic();
          rsaPrivateKey = (KMRSAPrivateKey)keyPair.getPrivate();

          keyStore = KeyStore.getInstance("nCipher.sworld");
          ByteArrayInputStream is = new ByteArrayInputStream(KEYSTORE.getBytes());
          keyStore.load(is, PASSWORD.toCharArray());
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

      for (int i=RSA_MIN; i<=RSA_MAX; i++) {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding", provider);
        cipher.init(Cipher.ENCRYPT_MODE, rsaPublicKey);

        byte[] plaintext = random(i);
        rsaPlaintexts.put(i, plaintext);
        rsaCiphertexts.put(i, cipher.doFinal(plaintext));
      }
    }
  }

  private static byte[] random(int length) {
    byte[] r = new byte[length];
    new Random().nextBytes(r);
    return r;
  }

  //// AES

  @Benchmark
  public byte[] testAesDecryptionJce(ThreadState state) throws Exception {
    return Aes.aesDecryptionJce(provider, aesKey, state);
  }

  @Benchmark
  public byte[] testAesDecryptionNCore(ThreadState state) throws Exception {
    return Aes.aesDecryptionNCore(aesKey, state);
  }

  @Benchmark
  public byte[] testAesEncryptionJce(ThreadState state) throws Exception {
    return Aes.aesEncryptionJce(provider, aesKey, state);
  }

  @Benchmark
  public byte[] testAesEncryptionNCore(ThreadState state) throws Exception {
    return Aes.aesEncryptionNCore(aesKey, state);
  }

  // HMAC

  @Benchmark
  public byte[] testHmacJce(ThreadState state) throws Exception {
    return Hmac.hmacJce(provider, hmacSHA256Key, state);
  }

  @Benchmark
  public byte[] testHmacNCore(ThreadState state) throws Exception {
    return Hmac.hmacNCore(hmacSHA256Key, state);
  }

  // RSA

  @Benchmark
  public byte[] testRsaKeyCreationJce(ThreadState state) throws Exception {
    return Rsa.rsaKeyCreationJce(keyStore, provider);
  }

  @Benchmark
  public long testRsaKeyCreationNCore(ThreadState state) throws Exception {
    return Rsa.rsaKeyCreationNCore();
  }

  @Benchmark
  public byte[] testRsaDecryptionJce(ThreadState state) throws Exception {
    return Rsa.rsaDecryptionJce(provider, rsaPrivateKey, state);
  }

  @Benchmark
  public byte[] testRsaDecryptionNCore(ThreadState state) throws Exception {
    return Rsa.rsaDecryptionNCore(rsaPrivateKey, state);
  }
}
