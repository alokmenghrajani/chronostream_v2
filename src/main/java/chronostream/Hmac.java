package chronostream;

import com.ncipher.nfast.NFUtils;
import com.ncipher.nfast.connect.StatusNotOK;
import com.ncipher.nfast.marshall.M_ByteBlock;
import com.ncipher.nfast.marshall.M_Cmd;
import com.ncipher.nfast.marshall.M_Cmd_Args_Sign;
import com.ncipher.nfast.marshall.M_Cmd_Reply_Sign;
import com.ncipher.nfast.marshall.M_Command;
import com.ncipher.nfast.marshall.M_Mech;
import com.ncipher.nfast.marshall.M_Mech_Cipher_SHA256Hash;
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
import javax.crypto.Mac;

import static chronostream.Chronostream.HMAC_MAX;
import static chronostream.Chronostream.HMAC_MIN;

public class Hmac {
  public static byte[] hmac(Provider provider, Key key, Chronostream.ThreadState state) throws Exception {
    int dataSize = (int) (Math.random() * (HMAC_MAX - HMAC_MIN) + HMAC_MIN);
    Mac mac = Mac.getInstance("HmacSHA256", provider);
    mac.init(key);
    byte[] result = mac.doFinal(state.hmacPlaintexts.get(dataSize));

    if (!Arrays.equals(result, state.hmacResults.get(dataSize))) {
      throw new IllegalStateException("hmac failed");
    }

    return result;
  }

  public static byte[] nativeHmac(KMKey key, Chronostream.ThreadState state) throws Exception {
    int dataSize = (int) (Math.random() * (HMAC_MAX - HMAC_MIN) + HMAC_MIN);
    M_Command cmd;
    M_Reply rep;

    byte[] plaintext = state.hmacPlaintexts.get(dataSize);
    M_Cmd_Args_Sign args = new M_Cmd_Args_Sign(0, key.getKeyID(), M_Mech.HMACSHA256,
        new M_PlainText(M_PlainTextType.Bytes,
            new M_PlainTextType_Data_Bytes(new M_ByteBlock(plaintext))));
    cmd = new M_Command(M_Cmd.Sign, 0, args);
    rep = nCipherKM.getConnection().transact(cmd);
    if (rep.status != M_Status.OK) {
      throw new StatusNotOK(M_Cmd.toString(cmd.cmd)
          + " command returned status "
          + NFUtils.errorString(rep.status, rep.errorinfo));
    }
    byte[] result = ((M_Mech_Cipher_SHA256Hash)((M_Cmd_Reply_Sign)rep.reply).sig.data).h.value;

    if (!Arrays.equals(result, state.hmacResults.get(dataSize))) {
      throw new IllegalStateException("hmac failed");
    }

    return result;
  }
}
