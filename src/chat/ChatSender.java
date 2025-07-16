package chat;

import color.ConsoleColors;
import crypto.AESUtil;
import java.io.DataOutputStream;
import java.net.Socket;
import java.util.Scanner;
import javax.crypto.SecretKey;

public class ChatSender {

  public static void start(String host, int port, SecretKey sessionKey, String senderName) {
    try (Socket socket = new Socket(host, port);
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());
        Scanner scanner = new Scanner(System.in)) {

      System.out.println("📝 Start typing messages (type 'exit' to quit):");

      while (true) {
        System.out.print(
            "🗨️" + ConsoleColors.AQUAMARINE3 + " [" + senderName + "] : " + ConsoleColors.RESET);
        String message = scanner.nextLine();
        if (message.equalsIgnoreCase("exit")) {
          break;
        }

        byte[] iv = AESUtil.generateIV();
        byte[] encrypted = AESUtil.encrypt(message, sessionKey, iv);

        out.writeUTF(AESUtil.encodeBase64(iv));
        out.writeUTF(AESUtil.encodeBase64(encrypted));
        out.flush();
      }

    } catch (Exception e) {
      System.err.println("❌ Error sending message: " + e.getMessage());
    }
  }
}
