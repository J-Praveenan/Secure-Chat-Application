
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

        // Receive Alice’s identity and RA
        String senderIdentity = in.readUTF();
        String RA = in.readUTF();
        System.out.println(ConsoleColors.PURPLE + "\n──────── Received Sender Info ────────"
            + ConsoleColors.RESET);
        System.out.println("🕵️ Sender        : " + senderIdentity);
        System.out.println("📥 Received RA   : " + RA);

        // Generate RB and DH key pair
        String RB = UUID.randomUUID().toString();
        KeyPair bobKeyPair = DHUtil.generateDHKeyPair();
        String bobDHPubKeyBase64 = Base64.getEncoder()
            .encodeToString(DHUtil.encodePublicKey(bobKeyPair.getPublic()));
        String messageToEncrypt = RA + "||" + bobDHPubKeyBase64;

        PublicKey aliceRSAPubKey = RSAUtil.getPublicKeyFromBase64(
            database.UserAuthManager.getPublicKey(senderIdentity));

        SecretKey aesKey = AESUtil.generateAESKey();
        byte[] iv = AESUtil.generateIV();
        byte[] ciphertext = AESUtil.encrypt(messageToEncrypt, aesKey, iv);
        byte[] signature = DHUtil.signWithPrivateKey(ciphertext, receiverPrivateKey);
        byte[] encryptedAESKey = RSAUtil.encryptRSA(aesKey.getEncoded(), aliceRSAPubKey);

        out.writeUTF(RB);
        out.writeUTF(Base64.getEncoder().encodeToString(encryptedAESKey));
        out.writeUTF(Base64.getEncoder().encodeToString(ciphertext));
        out.writeUTF(Base64.getEncoder().encodeToString(signature));
        out.writeUTF(Base64.getEncoder().encodeToString(iv));
        out.flush();

        System.out.println(
            ConsoleColors.PURPLE + "\n──────── Generated Response ─────────" + ConsoleColors.RESET);
        System.out.println("📤 Sent:");
        System.out.println("   🔹 RB               : " + RB);
        System.out.println(
            "   🔹 EncryptedAESKey  : " + Base64.getEncoder().encodeToString(encryptedAESKey));
        System.out.println(
            "   🔹 Ciphertext       : " + Base64.getEncoder().encodeToString(ciphertext));
        System.out.println(
            "   🔹 Signature        : " + Base64.getEncoder().encodeToString(signature));
        System.out.println("   🔹 IV               : " + Base64.getEncoder().encodeToString(iv));

        // Receive encrypted response from Alice
        byte[] encryptedAESKey2 = Base64.getDecoder().decode(in.readUTF());
        byte[] ciphertext2 = Base64.getDecoder().decode(in.readUTF());
        byte[] signature2 = Base64.getDecoder().decode(in.readUTF());
        byte[] iv2 = Base64.getDecoder().decode(in.readUTF());

        System.out.println(
            ConsoleColors.PURPLE + "\n──────── Received Response ─────────" + ConsoleColors.RESET);
        System.out.println("📤 Received:");
        System.out.println(
            "   🔹 EncryptedAESKey  : " + Base64.getEncoder().encodeToString(encryptedAESKey2));
        System.out.println(
            "   🔹 Ciphertext       : " + Base64.getEncoder().encodeToString(ciphertext2));
        System.out.println(
            "   🔹 Signature        : " + Base64.getEncoder().encodeToString(signature2));
        System.out.println("   🔹 IV               : " + Base64.getEncoder().encodeToString(iv2));

        SecretKey aesKey2 = AESUtil.keyFromBytes(
            RSAUtil.decryptRSA(encryptedAESKey2, receiverPrivateKey));

        System.out.println(ConsoleColors.PURPLE + "\n──────── Signature Verification   ────────"
            + ConsoleColors.RESET);
        if (DHUtil.verifyWithPublicKey(ciphertext2, signature2, aliceRSAPubKey)) {
          System.out.println(ConsoleColors.CYAN + "✅ Signature from receiver verified Successfully."
              + ConsoleColors.RESET);
        } else {
          System.out.println("❌ Signature verification failed! Aborting.");
        }

        String decryptedMessage = AESUtil.decrypt(ciphertext2, aesKey2, iv2);
        String[] parts = decryptedMessage.split("\\|\\|");
        String receivedRB = parts[0];
        String aliceDHPubKeyBase64 = parts[1];

        System.out.println(ConsoleColors.PURPLE + "\n──────── Nonce Verification   ────────"
            + ConsoleColors.RESET);
        if (receivedRB.equals(RB)) {
          System.out.println("🔐 Sent RB     : " + RB);
          System.out.println("🔐 Received RB : " + receivedRB);
          System.out.println(
              ConsoleColors.BLUE + "✅ Nonce matching. Verified Succeed!" + ConsoleColors.RESET);
        } else {
          System.out.println("❌ NonceB mismatch. Aborting.");
        }

        PublicKey aliceDHPubKey = DHUtil.decodePublicKey(
            Base64.getDecoder().decode(aliceDHPubKeyBase64));
        sessionKey = DHUtil.computeSharedSecret(bobKeyPair.getPrivate(), aliceDHPubKey);

        System.out.println("\n" + ConsoleColors.CYAN
            + "──────── Session Symmetric Key Shared Successfully! ────────" + ConsoleColors.RESET);
        System.out.println("🔑 Shared Symmetric Key: " + Base64.getEncoder()
            .encodeToString(sessionKey.getEncoded()));
        System.out.println("\n" + ConsoleColors.YELLOW + "🛡️ Session Secured. Begin Chatting!\n"
            + ConsoleColors.RESET);

        return senderIdentity;
      }
    } catch (Exception e) {
      System.err.println("❌ Error during DH exchange: " + e.getMessage());
      e.printStackTrace();
      return null;
    }

  }

}
