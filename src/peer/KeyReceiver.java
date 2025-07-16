package peer;

import color.ConsoleColors;
import crypto.AESUtil;
import crypto.DHUtil;
import crypto.RSAUtil;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.UUID;
import javax.crypto.SecretKey;

public class KeyReceiver {

  public static SecretKey sessionKey;

  public static String startServer(PrivateKey receiverPrivateKey, PublicKey receiverPublicKey) {

    try (ServerSocket serverSocket = new ServerSocket(5000)) {
      System.out.println("🖥 Waiting for peer to connect...");

      try (Socket client = serverSocket.accept();
           DataOutputStream out = new DataOutputStream(client.getOutputStream());
           DataInputStream in = new DataInputStream(client.getInputStream())) {

        System.out.println("🔗 Peer connected. Starting authentication...");

        // Step 1: Receive sender ID and RA
        String senderIdentity = in.readUTF();
        String RA = in.readUTF();

        System.out.println(ConsoleColors.PURPLE + "\n──────── Received Sender Info ────────" + ConsoleColors.RESET);
        System.out.println("🕵️ Sender        : " + senderIdentity);
        System.out.println("📥 Received RA   : " + RA);

        // Step 2: Generate RB and DH key pair
        String RB = UUID.randomUUID().toString();
        KeyPair bobKeyPair = DHUtil.generateDHKeyPair();
        String bobDHPubKeyBase64 = Base64.getEncoder().encodeToString(
                DHUtil.encodePublicKey(bobKeyPair.getPublic()));

        // Step 3: Sign and encrypt (RA || g^b mod p)
        String messageToSign = RA + "||" + bobDHPubKeyBase64;
        byte[] signature = DHUtil.signWithPrivateKey(messageToSign.getBytes(), receiverPrivateKey);
        String combinedMessage = messageToSign + "||" + Base64.getEncoder().encodeToString(signature);

        SecretKey aesKey = AESUtil.generateAESKey();
        byte[] iv = AESUtil.generateIV();
        byte[] ciphertext = AESUtil.encrypt(combinedMessage, aesKey, iv);

        PublicKey aliceRSAPubKey = RSAUtil.getPublicKeyFromBase64(
                database.UserAuthManager.getPublicKey(senderIdentity));
        byte[] encryptedAESKey = RSAUtil.encryptRSA(aesKey.getEncoded(), aliceRSAPubKey);

        // Step 4: Send RB, encrypted AES key, encrypted message, and IV
        out.writeUTF(RB);
        out.writeUTF(Base64.getEncoder().encodeToString(encryptedAESKey));
        out.writeUTF(Base64.getEncoder().encodeToString(ciphertext));
        out.writeUTF(Base64.getEncoder().encodeToString(iv));
        out.flush();

        System.out.println(ConsoleColors.PURPLE + "\n──────── Generated Response ─────────" + ConsoleColors.RESET);
        System.out.println("📤 Sent:");
        System.out.println("   🔹 RB               : " + RB);
        System.out.println("   🔹 EncryptedAESKey  : " + Base64.getEncoder().encodeToString(encryptedAESKey));
        System.out.println("   🔹 Ciphertext       : " + Base64.getEncoder().encodeToString(ciphertext));
        System.out.println("   🔹 Signature (embedded) : " + Base64.getEncoder().encodeToString(signature));
        System.out.println("   🔹 IV               : " + Base64.getEncoder().encodeToString(iv));

        // Step 5: Receive encrypted response from Alice
        byte[] encryptedAESKey2 = Base64.getDecoder().decode(in.readUTF());
        byte[] ciphertext2 = Base64.getDecoder().decode(in.readUTF());
        byte[] iv2 = Base64.getDecoder().decode(in.readUTF());

        System.out.println(ConsoleColors.PURPLE + "\n──────── Received Response ─────────" + ConsoleColors.RESET);
        System.out.println("📤 Received:");
        System.out.println("   🔹 EncryptedAESKey  : " + Base64.getEncoder().encodeToString(encryptedAESKey2));
        System.out.println("   🔹 Ciphertext       : " + Base64.getEncoder().encodeToString(ciphertext2));
        System.out.println("   🔹 IV               : " + Base64.getEncoder().encodeToString(iv2));

        // Step 6: Decrypt Alice's response and verify signature
        SecretKey aesKey2 = AESUtil.keyFromBytes(
                RSAUtil.decryptRSA(encryptedAESKey2, receiverPrivateKey));

        String decryptedMessage = AESUtil.decrypt(ciphertext2, aesKey2, iv2);
        System.out.println(ConsoleColors.YELLOW + "\n🗝️  Decrypted Message: " + decryptedMessage + ConsoleColors.RESET);

        String[] parts = decryptedMessage.split("\\|\\|");
        if (parts.length != 3) {
          throw new IllegalArgumentException("Decrypted message structure invalid! Expected 3 parts.");
        }

        String receivedRB = parts[0];
        String aliceDHPubKeyBase64 = parts[1];
        byte[] signature2 = Base64.getDecoder().decode(parts[2]);

        System.out.println("📥 Extracted:");
        System.out.println("   🔹 RB                  : " + receivedRB);
        System.out.println("   🔹 Alice's DH Pub Key  : " + aliceDHPubKeyBase64);
        System.out.println("   🔹 Signature           : " + Base64.getEncoder().encodeToString(signature2));

        String messageToVerify = receivedRB + "||" + aliceDHPubKeyBase64;

        System.out.println(ConsoleColors.PURPLE + "\n──────── Signature Verification   ────────" + ConsoleColors.RESET);
        if (DHUtil.verifyWithPublicKey(messageToVerify.getBytes(), signature2, aliceRSAPubKey)) {
          System.out.println(ConsoleColors.CYAN + "✅ Signature from receiver verified Successfully." + ConsoleColors.RESET);
        } else {
          System.out.println("❌ Signature verification failed! Aborting.");
          return null;
        }

        // Step 7: Verify RB (nonce)
        System.out.println(ConsoleColors.PURPLE + "\n──────── Nonce Verification   ────────" + ConsoleColors.RESET);
        if (receivedRB.equals(RB)) {
          System.out.println("🔐 Sent RB     : " + RB);
          System.out.println("🔐 Received RB : " + receivedRB);
          System.out.println(ConsoleColors.BLUE + "✅ Nonce matching. Verified Successfully!" + ConsoleColors.RESET);
        } else {
          System.out.println("❌ NonceB mismatch. Aborting.");
          return null;
        }

        // Step 8: Compute shared key
        PublicKey aliceDHPubKey = DHUtil.decodePublicKey(
                Base64.getDecoder().decode(aliceDHPubKeyBase64));
        sessionKey = DHUtil.computeSharedSecret(bobKeyPair.getPrivate(), aliceDHPubKey);

        System.out.println("\n" + ConsoleColors.CYAN + "──────── Session Symmetric Key Shared Successfully! ────────" + ConsoleColors.RESET);
        System.out.println("🔑 Shared Symmetric Key: " + Base64.getEncoder().encodeToString(sessionKey.getEncoded()));
        System.out.println("\n" + ConsoleColors.YELLOW + "🛡️ Session Secured. Begin Chatting!\n" + ConsoleColors.RESET);

        return senderIdentity;
      }
    } catch (Exception e) {
      System.err.println("❌ Error during DH exchange: " + e.getMessage());
      e.printStackTrace();
      return null;
    }
  }
}
