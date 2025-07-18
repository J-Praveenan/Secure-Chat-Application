package peer;

import crypto.AESUtil;
import crypto.RSAUtil;
import database.AuthLogger;

import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

public class SessionVerifier {

    // ✅ Client Side
    public static void sendVerificationMessage(Socket socket, SecretKey sessionKey,
                                               PrivateKey senderPrivateKey, PublicKey senderPublicKey,
                                               String senderUsername, String receiverUsername) {
        try {
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            DataInputStream in = new DataInputStream(socket.getInputStream());

            String T1 = Instant.now().toString();
            String nonce = UUID.randomUUID().toString();


            // Format: T1||nonce
            String payloadPlainText = T1 + "||" + nonce ;

            byte[] iv = AESUtil.generateIV();
            byte[] encryptedPayload = AESUtil.encrypt(payloadPlainText, sessionKey, iv);
            byte[] signature = RSAUtil.sign(payloadPlainText, senderPrivateKey);

            String message = Base64.getEncoder().encodeToString(iv) + "::" +
                    Base64.getEncoder().encodeToString(encryptedPayload) + "::" +
                    Base64.getEncoder().encodeToString(signature);

            out.writeUTF(message);
            System.out.println("✅ Sent session verification message.");

            String response = in.readUTF();
            System.out.println("📥 Received verification response: " + response);

            AuthLogger.logSessionVerification(senderUsername, receiverUsername, true,
                    "Nonce=" + nonce + ", T1=" + T1);

        } catch (Exception e) {
            System.err.println("❌ Session verification failed: " + e.getMessage());
            AuthLogger.logSessionVerification(senderUsername, receiverUsername, false,
                    "Failed to send session verification: " + e.getMessage());
        }
    }

    // ✅ Server Side
    public static void receiveAndRespondVerification(Socket socket, SecretKey sessionKey, String receiverUsername, String senderUsername) {
        String nonce = null;
        String T1 = null;
        //String senderUsername = null;

        try {
            DataInputStream in = new DataInputStream(socket.getInputStream());
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());

            String message = in.readUTF();
            String[] parts = message.split("::");

            if (parts.length != 3) {
                System.out.println("❌ Invalid message format.");
                AuthLogger.logSessionVerification(receiverUsername, "unknown", false, "Malformed message (3 parts required).");
                return;
            }

            byte[] iv = Base64.getDecoder().decode(parts[0]);
            byte[] encryptedPayload = Base64.getDecoder().decode(parts[1]);
            byte[] signature = Base64.getDecoder().decode(parts[2]);

            String decryptedPlainText = AESUtil.decrypt(encryptedPayload, sessionKey, iv);
            String[] split = decryptedPlainText.split("\\|\\|");

            if (split.length != 2) {
                System.out.println("❌ Invalid decrypted format.");
                AuthLogger.logSessionVerification(receiverUsername, "unknown", false, "Malformed decrypted payload.");
                return;
            }

            T1 = split[0];  // Timestamp
            nonce = split[1];


            System.out.println("🕒 T1: " + T1);
            System.out.println("🔑 Nonce: " + nonce);

            Instant t1Instant = Instant.parse(T1);
            if (Instant.now().minusSeconds(30).isAfter(t1Instant)) {
                System.err.println("❌ T1 is too old!");
                return;
            }

            // Prepare and send response
            String T2_response = Instant.now().toString();
            String responsePlain = nonce + "||" + T2_response;

            byte[] responseIV = AESUtil.generateIV();
            byte[] encryptedResponse = AESUtil.encrypt(responsePlain, sessionKey, responseIV);

            String response = Base64.getEncoder().encodeToString(responseIV) + "::" +
                    Base64.getEncoder().encodeToString(encryptedResponse);

            out.writeUTF(response);
            System.out.println("✅ Sent session verification response with T2: " + T2_response);

            AuthLogger.logSessionVerification(receiverUsername, senderUsername, true,
                    "Nonce=" + nonce + ", T1=" + T1);

        } catch (Exception e) {
            System.err.println("❌ Failed during session verification exchange: " + e.getMessage());
            AuthLogger.logSessionVerification(receiverUsername,
                    senderUsername != null ? senderUsername : "unknown", false,
                    "Exception: " + e.getMessage() +
                            (nonce != null ? ", Nonce=" + nonce : ""));
        }
    }
}
