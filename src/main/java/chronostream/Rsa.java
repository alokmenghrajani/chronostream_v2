package chronostream;

import com.ncipher.nfast.NFUtils;
import com.ncipher.nfast.connect.StatusNotOK;
import com.ncipher.nfast.marshall.M_Bignum;
import com.ncipher.nfast.marshall.M_ByteBlock;
import com.ncipher.nfast.marshall.M_CipherText;
import com.ncipher.nfast.marshall.M_Cmd;
import com.ncipher.nfast.marshall.M_Cmd_Args_Decrypt;
import com.ncipher.nfast.marshall.M_Cmd_Reply_Decrypt;
import com.ncipher.nfast.marshall.M_Command;
import com.ncipher.nfast.marshall.M_Mech;
import com.ncipher.nfast.marshall.M_Mech_Cipher_RSApPKCS1;
import com.ncipher.nfast.marshall.M_Mech_IV_RSApPKCS1OAEP;
import com.ncipher.nfast.marshall.M_PlainTextType;
import com.ncipher.nfast.marshall.M_PlainTextType_Data_Bytes;
import com.ncipher.nfast.marshall.M_Reply;
import com.ncipher.nfast.marshall.M_Status;
import com.ncipher.provider.km.KMKey;
import com.ncipher.provider.km.nCipherKM;
import java.math.BigInteger;
import java.security.Key;
import java.security.Provider;
import java.util.Arrays;
import javax.crypto.Cipher;

import static chronostream.Chronostream.RSA_MAX;
import static chronostream.Chronostream.RSA_MIN;

public class Rsa {
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

    // WARNING: the conversion from byte[] to M_Bignum below might be incorrect. You probably don't
    // want to use this code in production!
    M_Cmd_Args_Decrypt args = new M_Cmd_Args_Decrypt(0, key.getKeyID(), M_Mech.RSApPKCS1OAEP,
        new M_CipherText(M_Mech.RSApPKCS1OAEP,
            new M_Mech_Cipher_RSApPKCS1(new M_Bignum(new BigInteger(ciphertext))),
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
