package chat;

import color.ConsoleColors;
import crypto.AESUtil;
import crypto.HMACUtil;
import database.AuthLogger;

import java.io.DataInputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashSet;
import java.util.Set;
import javax.crypto.SecretKey;

/**
 * Handles incoming encrypted chat messages using a secure session key.
 * Provides replay protection via UUID tracking and logs message reception.
 */
public class ChatReceiver {

  // Tracks UUIDs of received messages to detect and ignore replayed messages
  private static final Set<String> seenMessages = new HashSet<>();

  /**
   * Starts a secure chat receiver server on the given port.
   * Accepts one incoming client and continuously receives encrypted messages.
   *
   * @param port         Port to listen on
   * @param sessionKey   Shared session key established via DH
   * @param senderName   Expected sender username (for display and logging)
   * @param receiverName This peer's username
   */
  public static void start(int port, SecretKey sessionKey, String senderName, String receiverName) {
    try (ServerSocket serverSocket = new ServerSocket(port)) {
      System.out.println("\n📥 ChatReceiver waiting on port " + port + "...");

      try (Socket client = serverSocket.accept();
           DataInputStream in = new DataInputStream(client.getInputStream())) {

        System.out.println("🔗 Connected. Listening for messages...");

        while (true) {
          // === Step 1: Receive message metadata and content ===
          String uuid = in.readUTF();            // Unique identifier to prevent replay
          String ivBase64 = in.readUTF();        // IV in base64
          String encryptedBase64 = in.readUTF(); // Encrypted message in base64

          // === Step 2: Detect and block replayed messages ===
          if (seenMessages.contains(uuid)) {
            System.out.println(ConsoleColors.PURPLE + "\n⚠️ Replayed message detected. Ignored." + ConsoleColors.RESET);
            AuthLogger.logReplayDetected(receiverName, senderName, "Duplicate UUID: " + uuid);
            continue;
          }
          seenMessages.add(uuid);

          // === Step 3: Derive per-message AES key using HMAC(sessionKey, UUID) ===
          SecretKey derivedKey = HMACUtil.deriveAESKeyFromUUID(sessionKey, uuid);

          // === Step 4: Decode and decrypt message ===
          byte[] iv = AESUtil.decodeBase64(ivBase64);
          byte[] encrypted = AESUtil.decodeBase64(encryptedBase64);
          String decrypted = AESUtil.decrypt(encrypted, derivedKey, iv);

          // === Step 5: Display message and prompt for reply ===
          System.out.println("\n🗨️" + ConsoleColors.PLUM2 + " [" + senderName + "] : " + decrypted + ConsoleColors.RESET);
          System.out.print("🗨️" + ConsoleColors.AQUAMARINE3 + " [" + receiverName + "] : " + ConsoleColors.RESET);
          System.out.flush();

          // === Step 6: Log successful reception ===
          AuthLogger.logMessageReceived(receiverName, senderName, uuid);
        }
      }

    } catch (Exception e) {
      System.err.println("❌ Error receiving message: " + e.getMessage());
    }
  }
}
