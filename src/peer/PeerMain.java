package peer;

import chat.ChatReceiver;
import chat.ChatSender;
import color.ConsoleColors;
import crypto.RSAUtil;
import database.DBHelper;
import database.UserAuthManager;

import javax.crypto.SecretKey;
import java.io.FileWriter;
import java.io.IOException;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Scanner;

public class PeerMain {

  private static PublicKey sessionPublicKey;
  private static PrivateKey sessionPrivateKey;
  private static String loggedInUsername;

  public static void main(String[] args) throws IOException {
    Scanner scanner = new Scanner(System.in);
    DBHelper.initDatabase();

    System.out.println(ConsoleColors.YELLOW + "\n🔐================ SECURE CHAT APPLICATION =================" + ConsoleColors.RESET);
    System.out.print("Choose action " + ConsoleColors.BLUE + " (register/login): " + ConsoleColors.RESET);
    String action = scanner.nextLine().trim().toLowerCase();

    if (action.equals("register")) {
      System.out.println(ConsoleColors.BLUE + "\n📝================ REGISTER USER ================" + ConsoleColors.RESET);
      System.out.print("👤 Enter Username: ");
      String username = scanner.nextLine();

      System.out.print("🔑 Enter password: ");
      String password = scanner.nextLine();

      KeyPair keyPair = RSAUtil.generateKeyPair();
      PublicKey pubKey = keyPair.getPublic();
      PrivateKey privKey = keyPair.getPrivate();

      String pubKeyStr = RSAUtil.getBase64PublicKey(pubKey);
      boolean success = UserAuthManager.registerUser(username, password, pubKeyStr);

      if (success) {
        System.out.println(ConsoleColors.GREEN + "✅ Registration successful!" + ConsoleColors.RESET);
        try (FileWriter writer = new FileWriter(username + "_private.key")) {
          writer.write(RSAUtil.getBase64PrivateKey(privKey));
          System.out.println("🔐 Private key saved to: " + username + "_private.key");
        } catch (IOException e) {
          System.err.println("❌ Failed to save private key: " + e.getMessage());
        }
      } else {
        System.out.println("❌ Username already exists or error occurred.");
      }

    } else if (action.equals("login")) {
      System.out.println(ConsoleColors.BLUE + "\n🔓================ LOGIN ================" + ConsoleColors.RESET);
      System.out.print("👤 Username: ");
      String username = scanner.nextLine();

      System.out.print("🔑 Password: ");
      String password = scanner.nextLine();

      String publicKeyStr = UserAuthManager.login(username, password);
      if (publicKeyStr == null) {
        System.out.println("❌ Login failed. Invalid username/password.");
        return;
      }
      System.out.println(ConsoleColors.CYAN + "✅ Login successful!" + ConsoleColors.RESET);

      sessionPublicKey = RSAUtil.getPublicKeyFromBase64(publicKeyStr);
      loggedInUsername = username;

      try {
        String privateKeyStr = new String(Files.readAllBytes(Paths.get(username + "_private.key")));
        sessionPrivateKey = RSAUtil.getPrivateKeyFromBase64(privateKeyStr);
      } catch (IOException e) {
        System.err.println("❌ Could not load private key from file.");
        return;
      }

      System.out.println(ConsoleColors.BLUE + "\n🎭================ SELECT ROLE ================" + ConsoleColors.RESET);
      System.out.print("Choose role " + ConsoleColors.BLUE + "(host/connect): " + ConsoleColors.RESET);
      String role = scanner.nextLine().trim().toLowerCase();

      String peerUsername;
      SecretKey sharedKey;

      if (role.equals("host")) {
        peerUsername = KeyReceiver.startServer(sessionPrivateKey, sessionPublicKey);
        sharedKey = KeyReceiver.sessionKey;

        new Thread(() -> ChatReceiver.start(6000, sharedKey, peerUsername, loggedInUsername)).start();
        // ✅ Add delay to ensure receiver is ready
        try { Thread.sleep(1000); } catch (InterruptedException ignored) {}
        new Thread(() -> ChatSender.start("127.0.0.1", 6003, sharedKey, loggedInUsername, peerUsername)).start();

      } else if (role.equals("connect")) {
        System.out.print("🌐 Enter peer IP " + ConsoleColors.BLUE + "(e.g., 127.0.0.1): " + ConsoleColors.RESET);
        String peerIP = scanner.nextLine();

        System.out.print("🔌 Enter peer port" + ConsoleColors.BLUE + " (e.g., 5000): " + ConsoleColors.RESET);
        int port = Integer.parseInt(scanner.nextLine());

        System.out.print("👤 Enter peer username: ");
        peerUsername = scanner.nextLine();

        String peerPublicKeyStr = UserAuthManager.getPublicKey(peerUsername);
        if (peerPublicKeyStr == null) {
          System.out.println("❌ Could not find public key for user: " + peerUsername);
          return;
        }

        PublicKey peerPublicKey = RSAUtil.getPublicKeyFromBase64(peerPublicKeyStr);
        KeySender.sendKeyToPeer(peerIP, port, loggedInUsername, peerUsername, sessionPrivateKey, peerPublicKey);
        sharedKey = KeySender.sessionKey;

        new Thread(() -> ChatReceiver.start(6001, sharedKey, peerUsername, loggedInUsername)).start();
        // ✅ Add delay
        try { Thread.sleep(1000); } catch (InterruptedException ignored) {}
        new Thread(() -> ChatSender.start(peerIP, 6002, sharedKey, loggedInUsername, peerUsername)).start();

      } else {
        System.out.println("❌ Unknown role. Type 'host' or 'connect'.");
      }

    } else {
      System.out.println("❌ Unknown action. Type 'register' or 'login'.");
    }
  }
}