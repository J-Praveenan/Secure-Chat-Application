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

public class ChatSender {

  public static void start(String host, int port, SecretKey sessionKey, String senderName, String receiverName) {
    try (Socket socket = new Socket(host, port);
         DataOutputStream out = new DataOutputStream(socket.getOutputStream());
         Scanner scanner = new Scanner(System.in)) {

      System.out.println("📝 Start typing messages (type 'exit' to quit):");

      while (true) {
        System.out.print("🗨️" + ConsoleColors.AQUAMARINE3 + " [" + senderName + "] : " + ConsoleColors.RESET);
        String message = scanner.nextLine();
        if (message.equalsIgnoreCase("exit")) break;

        String uuid = UUID.randomUUID().toString();

        // Derive per-message AES key using HMAC(sessionKey, UUID)
        SecretKey derivedKey = HMACUtil.deriveAESKeyFromUUID(sessionKey, uuid);

        byte[] iv = AESUtil.generateIV();
        byte[] encrypted = AESUtil.encrypt(message, derivedKey, iv);

        // Send: UUID, IV, Ciphertext
        out.writeUTF(uuid);
        out.writeUTF(AESUtil.encodeBase64(iv));
        out.writeUTF(AESUtil.encodeBase64(encrypted));
        out.flush();

        // ✅ Log message sent
        AuthLogger.logMessageSent(senderName, receiverName, uuid);
      }

    } catch (Exception e) {
      System.err.println("❌ Error sending message: " + e.getMessage());
    }
  }
}
