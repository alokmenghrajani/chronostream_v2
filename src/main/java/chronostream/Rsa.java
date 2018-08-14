package chronostream;

import com.ncipher.nfast.NFUtils;
import com.ncipher.nfast.connect.StatusNotOK;
import com.ncipher.nfast.marshall.M_ACL;
import com.ncipher.nfast.marshall.M_Act;
import com.ncipher.nfast.marshall.M_Act_Details_OpPermissions;
import com.ncipher.nfast.marshall.M_Action;
import com.ncipher.nfast.marshall.M_Bignum;
import com.ncipher.nfast.marshall.M_ByteBlock;
import com.ncipher.nfast.marshall.M_CipherText;
import com.ncipher.nfast.marshall.M_Cmd;
import com.ncipher.nfast.marshall.M_Cmd_Args_Decrypt;
import com.ncipher.nfast.marshall.M_Cmd_Args_GenerateKeyPair;
import com.ncipher.nfast.marshall.M_Cmd_Reply_Decrypt;
import com.ncipher.nfast.marshall.M_Cmd_Reply_GenerateKeyPair;
import com.ncipher.nfast.marshall.M_Command;
import com.ncipher.nfast.marshall.M_KeyGenParams;
import com.ncipher.nfast.marshall.M_KeyType;
import com.ncipher.nfast.marshall.M_KeyType_GenParams_RSAPrivate;
import com.ncipher.nfast.marshall.M_Mech;
import com.ncipher.nfast.marshall.M_Mech_Cipher_RSApPKCS1;
import com.ncipher.nfast.marshall.M_Mech_IV_RSApPKCS1OAEP;
import com.ncipher.nfast.marshall.M_ModuleID;
import com.ncipher.nfast.marshall.M_PermissionGroup;
import com.ncipher.nfast.marshall.M_PlainTextType;
import com.ncipher.nfast.marshall.M_PlainTextType_Data_Bytes;
import com.ncipher.nfast.marshall.M_Reply;
import com.ncipher.nfast.marshall.M_Status;
import com.ncipher.nfast.marshall.M_UseLimit;
import com.ncipher.provider.km.KMKey;
import com.ncipher.provider.km.nCipherKM;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Arrays;
import java.util.Date;
import javax.crypto.Cipher;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import sun.security.x509.X509CertImpl;

import static chronostream.Chronostream.KEYSTORE;
import static chronostream.Chronostream.PASSWORD;
import static chronostream.Chronostream.RSA_MAX;
import static chronostream.Chronostream.RSA_MIN;

public class Rsa {
  public static byte[] rsaKeyCreationJce(KeyStore keyStore, Provider provider) throws Exception {
    KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA", provider);
    RSAKeyGenParameterSpec
        rsaKeyGenParameterSpec = new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4);
    keyPairGen.initialize(rsaKeyGenParameterSpec);
    KeyPair keyPair = keyPairGen.generateKeyPair();

    X509Certificate cert = genCert(keyPair);

    KeyStore.PrivateKeyEntry privateKeyEntry = new KeyStore.PrivateKeyEntry(keyPair.getPrivate(), new Certificate[] {cert});
    String fingerprint = ((X509CertImpl) cert).getFingerprint("SHA1").toLowerCase();
    synchronized (keyStore) {
      keyStore.setEntry(fingerprint, privateKeyEntry,
          new KeyStore.PasswordProtection(PASSWORD.toCharArray()));

      ByteArrayOutputStream os = new ByteArrayOutputStream();
      keyStore.store(os, PASSWORD.toCharArray());
      if (!os.toString().equals(KEYSTORE)) {
        throw new IllegalStateException("unexpected keystore");
      }
    }

     return keyPair.getPublic().getEncoded();
  }

  public static X509Certificate genCert(KeyPair keyPair)
      throws OperatorCreationException, CertificateException {
    X500Name name = new X500Name("sn=chronostream");
    SubjectPublicKeyInfo subPubKeyInfo =
        SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
    X509v3CertificateBuilder certGen = new X509v3CertificateBuilder(
        name,
        new BigInteger(64, new SecureRandom()),
        new Date(),
        new Date(new Date().getTime() + 365 * 86400000L),
        name,
        subPubKeyInfo);
    JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA512withRSA");
    ContentSigner contentSigner = contentSignerBuilder.build(keyPair.getPrivate());
    X509CertificateHolder holder = certGen.build(contentSigner);
    return new JcaX509CertificateConverter().getCertificate(holder);
  }

  public static long rsaKeyCreationNCore() throws Exception {
    M_Cmd_Args_GenerateKeyPair args = new M_Cmd_Args_GenerateKeyPair(0, new M_ModuleID(0),
        new M_KeyGenParams(M_KeyType.RSAPrivate, new M_KeyType_GenParams_RSAPrivate(0, 2048)),
        new M_ACL(new M_PermissionGroup[]{
            new M_PermissionGroup(0, new M_UseLimit[0], new M_Action[]{
                new M_Action(M_Act.OpPermissions,
                    new M_Act_Details_OpPermissions(
                        M_Act_Details_OpPermissions.perms_Decrypt))})}),
        new M_ACL(new M_PermissionGroup[]{
            new M_PermissionGroup(0, new M_UseLimit[0], new M_Action[]{
                new M_Action(M_Act.OpPermissions,
                    new M_Act_Details_OpPermissions(
                        M_Act_Details_OpPermissions.perms_Encrypt))})}));

    M_Command cmd = new M_Command(M_Cmd.GenerateKeyPair, 0, args);
    M_Reply rep = nCipherKM.getConnection().transact(cmd);
    if (rep.status != M_Status.OK) {
      throw new StatusNotOK(M_Cmd.toString(cmd.cmd)
          + " command returned status "
          + NFUtils.errorString(rep.status, rep.errorinfo));
    }

    return ((M_Cmd_Reply_GenerateKeyPair)rep.reply).keypub.value;
  }

  public static byte[] rsaDecryptionJce(Provider provider, Key key, Chronostream.ThreadState state) throws Exception {
    int dataSize = (int) (Math.random() * (RSA_MAX - RSA_MIN) + RSA_MIN);
    Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding", provider);
    cipher.init(Cipher.DECRYPT_MODE, key);
    byte[] plaintext = cipher.doFinal(state.rsaCiphertexts.get(dataSize));

    if (!Arrays.equals(plaintext, state.rsaPlaintexts.get(dataSize))) {
      throw new IllegalStateException("rsa decryption failed");
    }

    return plaintext;
  }

  public static byte[] rsaDecryptionNCore(KMKey key, Chronostream.ThreadState state) throws Exception {
    int dataSize = (int) (Math.random() * (RSA_MAX - RSA_MIN) + RSA_MIN);
    M_Command cmd;
    M_Reply rep;

    byte[] ciphertext = state.rsaCiphertexts.get(dataSize);

    // note: the conversion from byte[] to M_Bignum should not be needed per Thales docs...
    M_Bignum num;
    if (ciphertext.length > 0 && (ciphertext[0] & 128) == 128) {
      byte[] t = new byte[ciphertext.length + 1];
      t[0] = 0;
      System.arraycopy(ciphertext, 0, t, 1, ciphertext.length);
      num = new M_Bignum(new BigInteger(t));
    } else {
      num = new M_Bignum(new BigInteger(ciphertext));
    }
    M_Cmd_Args_Decrypt args = new M_Cmd_Args_Decrypt(0, key.getKeyID(), M_Mech.RSApPKCS1OAEP,
        new M_CipherText(M_Mech.RSApPKCS1OAEP,
            new M_Mech_Cipher_RSApPKCS1(num),
            new M_Mech_IV_RSApPKCS1OAEP(new M_ByteBlock(new byte[0]))),
        M_PlainTextType.Bytes);
    cmd = new M_Command(M_Cmd.Decrypt, 0, args);
    rep = nCipherKM.getConnection().transact(cmd);
    if (rep.status != M_Status.OK) {
      throw new StatusNotOK(M_Cmd.toString(cmd.cmd)
          + " command returned status "
          + NFUtils.errorString(rep.status, rep.errorinfo));
    }
    byte[] plaintext = ((M_PlainTextType_Data_Bytes) ((M_Cmd_Reply_Decrypt)rep.reply).plain.data).data.value;

    if (!Arrays.equals(plaintext, state.rsaPlaintexts.get(dataSize))) {
      throw new IllegalStateException("rsa decryption failed");
    }

    return plaintext;
  }
}
