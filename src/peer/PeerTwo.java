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
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Scanner;

public class PeerTwo {

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
      // ==== User Registration ====
      System.out.println(ConsoleColors.BLUE + "\n📝================ REGISTER USER ================" + ConsoleColors.RESET);
      System.out.print("👤 Enter Username: ");
      String username = scanner.nextLine();

      System.out.print("🔑 Enter password: ");
      String password = scanner.nextLine();

      // Generate RSA key pair for the new user
      KeyPair keyPair = RSAUtil.generateKeyPair();
      PublicKey pubKey = keyPair.getPublic();
      PrivateKey privKey = keyPair.getPrivate();

      String pubKeyStr = RSAUtil.getBase64PublicKey(pubKey);
      boolean success = UserAuthManager.registerUser(username, password, pubKeyStr);

      if (success) {
        System.out.println(ConsoleColors.GREEN + "✅ Registration successful!" + ConsoleColors.RESET);
        // Save the private key locally
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
      // ==== User Login ====
      System.out.println(ConsoleColors.BLUE + "\n🔓================ LOGIN ================" + ConsoleColors.RESET);
      System.out.print("👤 Username: ");
      String username = scanner.nextLine();

      System.out.print("🔑 Password: ");
      String password = scanner.nextLine();

      // Attempt login and retrieve public key from DB
      String publicKeyStr = UserAuthManager.login(username, password);
      if (publicKeyStr == null) {
        System.out.println("❌ Login failed. Invalid username/password.");
        return;
      }

      System.out.println(ConsoleColors.CYAN + "✅ Login successful!" + ConsoleColors.RESET);
      sessionPublicKey = RSAUtil.getPublicKeyFromBase64(publicKeyStr);
      loggedInUsername = username;

      // Load private key from file
      try {
        String privateKeyStr = new String(Files.readAllBytes(Paths.get(username + "_private.key")));
        sessionPrivateKey = RSAUtil.getPrivateKeyFromBase64(privateKeyStr);
      } catch (IOException e) {
        System.err.println("❌ Could not load private key from file.");
        return;
      }

      // ==== Role Selection (Host or Connect) ====
      System.out.println(ConsoleColors.BLUE + "\n🎯================ SELECT ROLE ================" + ConsoleColors.RESET);
      System.out.print("Choose role " + ConsoleColors.BLUE + "(host/connect): " + ConsoleColors.RESET);
      String role = scanner.nextLine().trim().toLowerCase();

      String peerUsername;

      if (role.equals("host")) {
        // Host acts as server and waits for incoming key exchange
        System.out.println("🖥 Waiting for peer to connect...");
        peerUsername = KeyReceiver.startServer(sessionPrivateKey, sessionPublicKey);
        SecretKey sharedKey = KeyReceiver.sessionKey;

        // Start ChatReceiver on port 6002
        new Thread(() -> ChatReceiver.start(6002, sharedKey, peerUsername, loggedInUsername)).start();

        // Delay to ensure receiver is ready
        try { Thread.sleep(1000); } catch (InterruptedException ignored) {}

        // Start ChatSender to send messages to peer on port 6001
        new Thread(() -> ChatSender.start("127.0.0.1", 6001, sharedKey, loggedInUsername, peerUsername)).start();

      } else if (role.equals("connect")) {
        // Client connects to the host and initiates key exchange
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

        // Initiate session key exchange
        KeySender.sendKeyToPeer(peerIP, port, loggedInUsername, peerUsername, sessionPrivateKey, peerPublicKey);
        SecretKey sharedKey = KeySender.sessionKey;

        // Start ChatReceiver on port 6001
        new Thread(() -> ChatReceiver.start(6001, sharedKey, peerUsername, loggedInUsername)).start();

        // Delay to ensure receiver is ready
        try { Thread.sleep(1000); } catch (InterruptedException ignored) {}

        // Start ChatSender on port 6000
        new Thread(() -> ChatSender.start(peerIP, 6000, sharedKey, loggedInUsername, peerUsername)).start();

      } else {
        System.out.println("❌ Invalid role.");
      }

    } else {
      System.out.println("❌ Unknown action. Type 'register' or 'login'.");
    }
  }
}
