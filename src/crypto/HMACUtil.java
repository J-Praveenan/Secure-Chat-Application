package crypto;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public class HMACUtil {

    public static SecretKey deriveAESKeyFromUUID(SecretKey baseSessionKey, String uuid) throws Exception {
        Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(baseSessionKey);
        byte[] derivedBytes = hmac.doFinal(uuid.getBytes(StandardCharsets.UTF_8));
        // Truncate to 16 bytes (128 bits) for AES
        byte[] aesKeyBytes = new byte[16];
        System.arraycopy(derivedBytes, 0, aesKeyBytes, 0, 16);
        return new SecretKeySpec(aesKeyBytes, "AES");
    }
}
