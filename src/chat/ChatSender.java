package chat;

import color.ConsoleColors;
import crypto.AESUtil;
import crypto.HMACUtil;
import database.AuthLogger;

import java.io.DataOutputStream;
import java.net.Socket;
import java.util.Scanner;
import java.util.UUID;
import javax.crypto.SecretKey;

/**
 * Handles sending encrypted messages over a secure socket connection.
 * Messages are encrypted with per-message AES keys derived from a session key and UUID.
 */
public class ChatSender {

  /**
   * Starts the chat sender which reads user input, encrypts messages, and sends them to the peer.
   *
   * @param host         IP address or hostname of the peer
   * @param port         Port to connect to
   * @param sessionKey   Shared symmetric session key from DH exchange
   * @param senderName   This peer's username
   * @param receiverName Remote peer's username
   */
  public static void start(String host, int port, SecretKey sessionKey, String senderName, String receiverName) {
    try (Socket socket = new Socket(host, port);
         DataOutputStream out = new DataOutputStream(socket.getOutputStream());
         Scanner scanner = new Scanner(System.in)) {

      System.out.println("📝 Start typing messages (type 'exit' to quit):");

      while (true) {
        // === Step 1: Read message from user ===
        System.out.print("🗨️" + ConsoleColors.AQUAMARINE3 + " [" + senderName + "] : " + ConsoleColors.RESET);
        String message = scanner.nextLine();
        if (message.equalsIgnoreCase("exit")) break;

        // === Step 2: Generate unique message UUID for replay protection ===
        String uuid = UUID.randomUUID().toString();

        // === Step 3: Derive a unique AES key per message using HMAC(sessionKey, UUID) ===
        SecretKey derivedKey = HMACUtil.deriveAESKeyFromUUID(sessionKey, uuid);

        // === Step 4: Encrypt message using AES-GCM ===
        byte[] iv = AESUtil.generateIV();
        byte[] encrypted = AESUtil.encrypt(message, derivedKey, iv);

        // === Step 5: Send UUID, IV, and ciphertext (all Base64 encoded) ===
        out.writeUTF(uuid);
        out.writeUTF(AESUtil.encodeBase64(iv));
        out.writeUTF(AESUtil.encodeBase64(encrypted));
        out.flush();

        // === Step 6: Log message transmission event ===
        AuthLogger.logMessageSent(senderName, receiverName, uuid);
      }

    } catch (Exception e) {
      System.err.println("❌ Error sending message: " + e.getMessage());
    }
  }
}
