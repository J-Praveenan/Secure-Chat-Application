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

public class ChatReceiver {

  private static final Set<String> seenMessages = new HashSet<>();

  public static void start(int port, SecretKey sessionKey, String senderName, String receiverName) {
    try (ServerSocket serverSocket = new ServerSocket(port)) {
      System.out.println("\n📥 ChatReceiver waiting on port " + port + "...");

      try (Socket client = serverSocket.accept();
           DataInputStream in = new DataInputStream(client.getInputStream())) {

        System.out.println("🔗 Connected. Listening for messages...");

        while (true) {
          String uuid = in.readUTF();
          String ivBase64 = in.readUTF();
          String encryptedBase64 = in.readUTF();

          if (seenMessages.contains(uuid)) {
            System.out.println(ConsoleColors.PURPLE + "\n⚠️ Replayed message detected. Ignored." + ConsoleColors.RESET);
            AuthLogger.logReplayDetected(receiverName, senderName, "Duplicate UUID: " + uuid);
            continue;
          }
          seenMessages.add(uuid);

          SecretKey derivedKey = HMACUtil.deriveAESKeyFromUUID(sessionKey, uuid);

          byte[] iv = AESUtil.decodeBase64(ivBase64);
          byte[] encrypted = AESUtil.decodeBase64(encryptedBase64);

          String decrypted = AESUtil.decrypt(encrypted, derivedKey, iv);

          System.out.println("\n🗨️" + ConsoleColors.PLUM2 + " [" + senderName + "] : " + decrypted + ConsoleColors.RESET);
          System.out.print("🗨️" + ConsoleColors.AQUAMARINE3 + " [" + receiverName + "] : " + ConsoleColors.RESET);
          System.out.flush();

          // ✅ Log message reception
          AuthLogger.logMessageReceived(receiverName, senderName, uuid);
        }
      }

    } catch (Exception e) {
      System.err.println("❌ Error receiving message: " + e.getMessage());
    }
  }
}
