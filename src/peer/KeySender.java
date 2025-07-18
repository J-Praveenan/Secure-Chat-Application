package peer;

import color.ConsoleColors;
import crypto.AESUtil;
import crypto.DHUtil;
import crypto.RSAUtil;
import database.AuthLogger;

import javax.crypto.SecretKey;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.UUID;

public class KeySender {

  public static SecretKey sessionKey;

  /**
   * Initiates a mutual authentication and DH key exchange with the peer.
   * Performs nonce exchange, RSA + AES wrapping, signature verification, and computes the shared session key.
   */
  public static void sendKeyToPeer(String host, int port, String senderUsername,
                                   String receiverUsername,
                                   PrivateKey senderPrivateKey, PublicKey receiverRSAPublicKey) {
    try (Socket socket = new Socket(host, port);
         DataOutputStream out = new DataOutputStream(socket.getOutputStream());
         DataInputStream in = new DataInputStream(socket.getInputStream())) {

      // === Step 1: Initiator sends username and nonce RA ===
      String nonceA = UUID.randomUUID().toString();
      out.writeUTF(senderUsername);
      out.writeUTF(nonceA);
      out.flush();

      System.out.println(ConsoleColors.PURPLE + "\n─────── Sender Info ───────" + ConsoleColors.RESET);
      System.out.println("🕵️ Identity  : " + senderUsername);
      System.out.println("📥 Sent RA   : " + nonceA);

      // === Step 2: Receive encrypted response from peer (RB, encrypted DH pub key, signature) ===
      String nonceB = in.readUTF();
      byte[] encryptedAESKey = Base64.getDecoder().decode(in.readUTF());
      byte[] ciphertext = Base64.getDecoder().decode(in.readUTF());
      byte[] iv = Base64.getDecoder().decode(in.readUTF());

      System.out.println(ConsoleColors.PURPLE + "\n─────── Received Response ───────" + ConsoleColors.RESET);
      System.out.println("📤 Received:");
      System.out.println("   🔹 RB               : " + nonceB);
      System.out.println("   🔹 EncryptedAESKey  : " + Base64.getEncoder().encodeToString(encryptedAESKey));
      System.out.println("   🔹 Ciphertext       : " + Base64.getEncoder().encodeToString(ciphertext));
      System.out.println("   🔹 IV               : " + Base64.getEncoder().encodeToString(iv));

      // === Step 3: Decrypt AES key using sender's private RSA key ===
      SecretKey aesKey = AESUtil.keyFromBytes(RSAUtil.decryptRSA(encryptedAESKey, senderPrivateKey));
      String decrypted = AESUtil.decrypt(ciphertext, aesKey, iv);

      System.out.println(ConsoleColors.YELLOW + "\n🔑  Decrypted Message: " + decrypted + ConsoleColors.RESET);

      // Format: RA||bobDHPubKey||signature
      String[] parts = decrypted.split("\\|\\|");
      if (parts.length != 3) throw new IllegalArgumentException("Invalid decrypted message format");

      String receivedRA = parts[0];
      String bobDHPubKeyBase64 = parts[1];
      byte[] signature = Base64.getDecoder().decode(parts[2]);

      // === Step 4: Verify digital signature of Bob using their RSA public key ===
      System.out.println(ConsoleColors.PURPLE + "\n─────── Signature Verification ───────" + ConsoleColors.RESET);
      if (!DHUtil.verifyWithPublicKey((receivedRA + "||" + bobDHPubKeyBase64).getBytes(), signature, receiverRSAPublicKey)) {
        System.out.println("❌ Signature from " + receiverUsername + " invalid. Aborting.");
        AuthLogger.logDHExchange(senderUsername, receiverUsername, false, "Signature verification failed.");
        return;
      }
      System.out.println(ConsoleColors.CYAN + "✅ Signature from " + receiverUsername + " verified successfully." + ConsoleColors.RESET);

      // === Step 5: Verify nonce ===
      System.out.println(ConsoleColors.PURPLE + "\n─────── Nonce Verification ───────" + ConsoleColors.RESET);
      if (!receivedRA.equals(nonceA)) {
        System.out.println("❌ NonceA mismatch. Aborting.");
        AuthLogger.logDHExchange(senderUsername, receiverUsername, false, "Nonce mismatch.");
        return;
      }

      System.out.println("🔐 Sent RA     : " + nonceA);
      System.out.println("🔐 Received RA : " + receivedRA);
      System.out.println(ConsoleColors.BLUE + "✅ Nonce matching. Verified successfully!" + ConsoleColors.RESET);

      // === Step 6: Generate DH key pair and prepare response ===
      KeyPair aliceKeyPair = DHUtil.generateDHKeyPair();
      String aliceDHPubKeyBase64 = Base64.getEncoder().encodeToString(DHUtil.encodePublicKey(aliceKeyPair.getPublic()));
      String messageToSign = nonceB + "||" + aliceDHPubKeyBase64;

      byte[] signature2 = DHUtil.signWithPrivateKey(messageToSign.getBytes(), senderPrivateKey);
      String combinedMessage = messageToSign + "||" + Base64.getEncoder().encodeToString(signature2);

      // Encrypt the signed message using a new AES key and wrap it with receiver's RSA key
      SecretKey aesKey2 = AESUtil.generateAESKey();
      byte[] iv2 = AESUtil.generateIV();
      byte[] ciphertext2 = AESUtil.encrypt(combinedMessage, aesKey2, iv2);
      byte[] encryptedAESKey2 = RSAUtil.encryptRSA(aesKey2.getEncoded(), receiverRSAPublicKey);

      // === Step 7: Send encrypted response (RB verification and Alice's DH key) ===
      out.writeUTF(Base64.getEncoder().encodeToString(encryptedAESKey2));
      out.writeUTF(Base64.getEncoder().encodeToString(ciphertext2));
      out.writeUTF(Base64.getEncoder().encodeToString(iv2));
      out.flush();

      System.out.println(ConsoleColors.PURPLE + "\n─────── Sent Response ───────" + ConsoleColors.RESET);
      System.out.println("📤 Sent:");
      System.out.println("   🔹 EncryptedAESKey      : " + Base64.getEncoder().encodeToString(encryptedAESKey2));
      System.out.println("   🔹 Ciphertext (embedded): " + Base64.getEncoder().encodeToString(ciphertext2));
      System.out.println("   🔹 IV                   : " + Base64.getEncoder().encodeToString(iv2));
      System.out.println("   🔹 Signature (embedded) : " + Base64.getEncoder().encodeToString(signature2));

      // === Step 8: Compute shared session key using Bob's DH public key ===
      PublicKey bobDHPubKey = DHUtil.decodePublicKey(Base64.getDecoder().decode(bobDHPubKeyBase64));
      sessionKey = DHUtil.computeSharedSecret(aliceKeyPair.getPrivate(), bobDHPubKey);

      AuthLogger.logDHExchange(senderUsername, receiverUsername, true, "DH key exchange completed. Session key established.");

      System.out.println(ConsoleColors.CYAN + "\n─────── Session Symmetric Key Shared Successfully! ───────" + ConsoleColors.RESET);
      System.out.println("🔑 Shared Symmetric Key: " + Base64.getEncoder().encodeToString(sessionKey.getEncoded()));
      System.out.println(ConsoleColors.YELLOW + "\n🛡️ Session Secured. Begin Chatting!\n" + ConsoleColors.RESET);

      // === Final Step: Optional verification to confirm freshness and intent ===
      SessionVerifier.sendVerificationMessage(socket, sessionKey, senderPrivateKey,
              aliceKeyPair.getPublic(), senderUsername, receiverUsername);

    } catch (Exception e) {
      System.err.println("❌ KeySender DH exchange failed: " + e.getMessage());
      e.printStackTrace();
      AuthLogger.logDHExchange(senderUsername, receiverUsername, false, "Exception: " + e.getMessage());
    }
  }
}
