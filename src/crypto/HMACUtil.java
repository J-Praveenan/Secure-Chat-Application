package crypto;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

/**
 * Utility class for deriving keys using HMAC.
 */
public class HMACUtil {

    /**
     * Derives a 128-bit AES key from a base session key and UUID using HMAC-SHA256.
     * This provides a unique per-message key for use cases like message-level encryption.
     *
     * @param baseSessionKey The shared session key (used as HMAC key)
     * @param uuid           The unique identifier (e.g., message UUID)
     * @return A 128-bit AES key derived via HMAC
     * @throws Exception if HMAC algorithm or key setup fails
     */
    public static SecretKey deriveAESKeyFromUUID(SecretKey baseSessionKey, String uuid) throws Exception {
        Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(baseSessionKey);

        byte[] derivedBytes = hmac.doFinal(uuid.getBytes(StandardCharsets.UTF_8));

        // Truncate to 16 bytes (128 bits) for AES-128
        byte[] aesKeyBytes = new byte[16];
        System.arraycopy(derivedBytes, 0, aesKeyBytes, 0, 16);

        return new SecretKeySpec(aesKeyBytes, "AES");
    }
}
