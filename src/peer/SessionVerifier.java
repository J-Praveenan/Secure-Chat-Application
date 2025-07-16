package peer;

import crypto.AESUtil;
import crypto.RSAUtil;

import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

public class SessionVerifier {

    // Client Side
    public static void sendVerificationMessage(String host, int port, SecretKey sessionKey,
                                               PrivateKey senderPrivateKey, PublicKey senderPublicKey,
                                               String originalT1) {
        try (Socket socket = new Socket(host, port);
             DataOutputStream out = new DataOutputStream(socket.getOutputStream());
             DataInputStream in = new DataInputStream(socket.getInputStream())) {

            String T2 = Instant.now().toString();
            String nonce = UUID.randomUUID().toString();

            // Construct plaintext: T1||nonce||T2
            String payloadPlainText = originalT1 + "||" + nonce + "||" + T2;

            // Encrypt payload with AES session key and IV
            byte[] iv = AESUtil.generateIV();
            byte[] encryptedPayload = AESUtil.encrypt(payloadPlainText, sessionKey, iv);

            // Sign the plain payload
            byte[] signature = RSAUtil.sign(payloadPlainText, senderPrivateKey);

            // Construct message: IV::encrypted::signature
            String message = Base64.getEncoder().encodeToString(iv) + "::" +
                    Base64.getEncoder().encodeToString(encryptedPayload) + "::" +
                    Base64.getEncoder().encodeToString(signature);

            out.writeUTF(message);
            System.out.println("✅ Sent session verification message.");


            String response = in.readUTF();
            System.out.println("📥 Received verification response: " + response);

        } catch (Exception e) {
            System.err.println("❌ Session verification failed: " + e.getMessage());
        }
    }

    // Server Side
    public static void receiveAndRespondVerification(Socket socket, SecretKey sessionKey) {
        try (DataInputStream in = new DataInputStream(socket.getInputStream());
             DataOutputStream out = new DataOutputStream(socket.getOutputStream())) {

            String message = in.readUTF();
            String[] parts = message.split("::");

            if (parts.length != 3) {
                System.out.println("❌ Invalid message format.");
                return;
            }

            byte[] iv = Base64.getDecoder().decode(parts[0]);
            byte[] encryptedPayload = Base64.getDecoder().decode(parts[1]);
            byte[] signature = Base64.getDecoder().decode(parts[2]);

            String decryptedPlainText = AESUtil.decrypt(encryptedPayload, sessionKey, iv);
            String[] split = decryptedPlainText.split("\\|\\|");

            if (split.length != 3) {
                System.out.println("❌ Invalid decrypted format.");
                return;
            }

            String T1 = split[0];
            String nonce = split[1];
            String T2 = split[2];

            System.out.println("🕒 T1: " + T1);
            System.out.println("🔑 Nonce: " + nonce);
            System.out.println("📥 T2: " + T2);

            // Prepare response: nonce||T2_new
            String T2_response = Instant.now().toString();
            String responsePlain = nonce + "||" + T2_response;

            byte[] responseIV = AESUtil.generateIV();
            byte[] encryptedResponse = AESUtil.encrypt(responsePlain, sessionKey, responseIV);

            String response = Base64.getEncoder().encodeToString(responseIV) + "::" +
                    Base64.getEncoder().encodeToString(encryptedResponse);

            out.writeUTF(response);
            System.out.println("✅ Sent session verification response with T2: " + T2_response);

        } catch (Exception e) {
            System.err.println("❌ Failed during session verification exchange: " + e.getMessage());
        }
    }
}
