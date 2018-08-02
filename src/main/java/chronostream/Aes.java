package chronostream;

import com.ncipher.nfast.NFUtils;
import com.ncipher.nfast.connect.StatusNotOK;
import com.ncipher.nfast.marshall.M_Block128;
import com.ncipher.nfast.marshall.M_ByteBlock;
import com.ncipher.nfast.marshall.M_CipherText;
import com.ncipher.nfast.marshall.M_Cmd;
import com.ncipher.nfast.marshall.M_Cmd_Args_Decrypt;
import com.ncipher.nfast.marshall.M_Cmd_Args_Encrypt;
import com.ncipher.nfast.marshall.M_Cmd_Reply_Decrypt;
import com.ncipher.nfast.marshall.M_Cmd_Reply_Encrypt;
import com.ncipher.nfast.marshall.M_Command;
import com.ncipher.nfast.marshall.M_IV;
import com.ncipher.nfast.marshall.M_Mech;
import com.ncipher.nfast.marshall.M_Mech_Cipher_Generic128;
import com.ncipher.nfast.marshall.M_Mech_IV_Generic128;
import com.ncipher.nfast.marshall.M_PlainText;
import com.ncipher.nfast.marshall.M_PlainTextType;
import com.ncipher.nfast.marshall.M_PlainTextType_Data_Bytes;
import com.ncipher.nfast.marshall.M_Reply;
import com.ncipher.nfast.marshall.M_Status;
import com.ncipher.provider.km.KMKey;
import com.ncipher.provider.km.nCipherKM;
import java.security.Key;
import java.security.Provider;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

import static chronostream.Chronostream.AES_MAX;
import static chronostream.Chronostream.AES_MIN;

public class Aes {
  public static byte[] aesDecryptionJce(Provider provider, Key key, Chronostream.ThreadState state) throws Exception {
    int dataSize = (int) (Math.random() * (AES_MAX - AES_MIN) + AES_MIN);
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", provider);
    cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(state.aesIv));
    byte[] plaintext = cipher.doFinal(state.aesCiphertexts.get(dataSize));

    if (!Arrays.equals(plaintext, state.aesPlaintexts.get(dataSize))) {
      throw new IllegalStateException("aes decryption failed");
    }

    return plaintext;
  }

  public static byte[] aesDecryptionNCore(KMKey key, Chronostream.ThreadState state) throws Exception {
    int dataSize = (int) (Math.random() * (AES_MAX - AES_MIN) + AES_MIN);
    M_Command cmd;
    M_Reply rep;

    byte[] ciphertext = state.aesCiphertexts.get(dataSize);
    M_Cmd_Args_Decrypt args = new M_Cmd_Args_Decrypt(0, key.getKeyID(), M_Mech.Any,
        new M_CipherText(M_Mech.RijndaelmCBCi128pPKCS5,
            new M_Mech_Cipher_Generic128(new M_ByteBlock(ciphertext)),
            new M_Mech_IV_Generic128(new M_Block128(state.aesIv))),
        M_PlainTextType.Bytes);
    cmd = new M_Command(M_Cmd.Decrypt, 0, args);
    rep = nCipherKM.getConnection().transact(cmd);
    if (rep.status != M_Status.OK) {
      throw new StatusNotOK(M_Cmd.toString(cmd.cmd)
          + " command returned status "
          + NFUtils.errorString(rep.status, rep.errorinfo));
    }
    byte[] plaintext = ((M_PlainTextType_Data_Bytes) ((M_Cmd_Reply_Decrypt)rep.reply).plain.data).data.value;

    if (!Arrays.equals(plaintext, state.aesPlaintexts.get(dataSize))) {
      throw new IllegalStateException("aes decryption failed");
    }

    return plaintext;
  }

  public static byte[] aesEncryptionJce(Provider provider, Key key, Chronostream.ThreadState state) throws Exception {
    int dataSize = (int) (Math.random() * (AES_MAX - AES_MIN) + AES_MIN);
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", provider);
    cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(state.aesIv));
    byte[] ciphertext = cipher.doFinal(state.aesPlaintexts.get(dataSize));

    if (!Arrays.equals(ciphertext, state.aesCiphertexts.get(dataSize))) {
      throw new IllegalStateException("aes encryption failed");
    }

    return ciphertext;
  }

  public static byte[] aesEncryptionNCore(KMKey key, Chronostream.ThreadState state) throws Exception {
    int dataSize = (int) (Math.random() * (AES_MAX - AES_MIN) + AES_MIN);
    M_Command cmd;
    M_Reply rep;

    byte[] plaintext = state.aesPlaintexts.get(dataSize);
    M_Cmd_Args_Encrypt args = new M_Cmd_Args_Encrypt(0, key.getKeyID(), M_Mech.Any,
        new M_PlainText(M_PlainTextType.Bytes, new M_PlainTextType_Data_Bytes(
            new M_ByteBlock(plaintext))));
    args.set_given_iv(new M_IV(M_Mech.RijndaelmCBCi128pPKCS5, new M_Mech_IV_Generic128(new M_Block128(state.aesIv))));
    cmd = new M_Command(M_Cmd.Encrypt, 0, args);
    rep = nCipherKM.getConnection().transact(cmd);
    if (rep.status != M_Status.OK) {
      throw new StatusNotOK(M_Cmd.toString(cmd.cmd)
          + " command returned status "
          + NFUtils.errorString(rep.status, rep.errorinfo));
    }
    byte[] ciphertext = ((M_Mech_Cipher_Generic128) ((M_Cmd_Reply_Encrypt)rep.reply).cipher.data).cipher.value;

    if (!Arrays.equals(ciphertext, state.aesCiphertexts.get(dataSize))) {
      throw new IllegalStateException("aes decryption failed");
    }

    return plaintext;
  }
}
