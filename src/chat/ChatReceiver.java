package chat;

import color.ConsoleColors;
import crypto.AESUtil;
import java.io.DataInputStream;
import java.net.ServerSocket;
import java.net.Socket;
import javax.crypto.SecretKey;

public class ChatReceiver {

  public static void start(int port, SecretKey sessionKey, String senderName, String receiverName) {
    try (ServerSocket serverSocket = new ServerSocket(port)) {
      System.out.println("\n📥 ChatReceiver waiting on port " + port + "...");

      try (Socket client = serverSocket.accept();
          DataInputStream in = new DataInputStream(client.getInputStream())) {

        System.out.println("🔗 Connected. Listening for messages...");

        while (true) {
          String ivBase64 = in.readUTF();
          String encryptedBase64 = in.readUTF();

          byte[] iv = AESUtil.decodeBase64(ivBase64);
          byte[] encrypted = AESUtil.decodeBase64(encryptedBase64);

          String decrypted = AESUtil.decrypt(encrypted, sessionKey, iv);
          System.out.println("\n🗨️" + ConsoleColors.PLUM2 + " [" + senderName + "] : " + decrypted
              + ConsoleColors.RESET);
          System.out.print("🗨️" + ConsoleColors.AQUAMARINE3 + " [" + receiverName + "] : "
              + ConsoleColors.RESET);
          System.out.flush();

        }

      }
    } catch (Exception e) {
      System.err.println("❌ Error receiving message: " + e.getMessage());
    }
  }
}
