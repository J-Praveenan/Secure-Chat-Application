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

public class PeerOne {

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

      // Generate RSA key pair
      KeyPair keyPair = RSAUtil.generateKeyPair();
      PublicKey pubKey = keyPair.getPublic();
      PrivateKey privKey = keyPair.getPrivate();

      String pubKeyStr = RSAUtil.getBase64PublicKey(pubKey);
      boolean success = UserAuthManager.registerUser(username, password, pubKeyStr);

      if (success) {
        System.out.println(ConsoleColors.GREEN + "✅ Registration successful!" + ConsoleColors.RESET);
        // Save private key locally
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

      String publicKeyStr = UserAuthManager.login(username, password);
      if (publicKeyStr == null) {
        System.out.println("❌ Login failed. Invalid username/password.");
        return;
      }

      System.out.println(ConsoleColors.CYAN + "✅ Login successful!" + ConsoleColors.RESET);
      sessionPublicKey = RSAUtil.getPublicKeyFromBase64(publicKeyStr);
      loggedInUsername = username;

      // Load private key from local file
      try {
        String privateKeyStr = new String(Files.readAllBytes(Paths.get(username + "_private.key")));
        sessionPrivateKey = RSAUtil.getPrivateKeyFromBase64(privateKeyStr);
      } catch (IOException e) {
        System.err.println("❌ Could not load private key from file.");
        return;
      }

      // ==== Role Selection (host or connect) ====
      System.out.println(ConsoleColors.BLUE + "\n🎭================ SELECT ROLE ================" + ConsoleColors.RESET);
      System.out.print("Choose role " + ConsoleColors.BLUE + "(host/connect): " + ConsoleColors.RESET);
      String role = scanner.nextLine().trim().toLowerCase();

      String peerUsername;
      SecretKey sharedKey;

      if (role.equals("host")) {
        // Start server and wait for key exchange from peer
        peerUsername = KeyReceiver.startServer(sessionPrivateKey, sessionPublicKey);
        sharedKey = KeyReceiver.sessionKey;

        // Start chat receiver on port 6000
        new Thread(() -> ChatReceiver.start(6000, sharedKey, peerUsername, loggedInUsername)).start();

        // Allow receiver to start before sending
        try { Thread.sleep(1000); } catch (InterruptedException ignored) {}

        // Start chat sender on port 6001
        new Thread(() -> ChatSender.start("127.0.0.1", 6001, sharedKey, loggedInUsername, peerUsername)).start();

      } else if (role.equals("connect")) {
        // Initiate connection to remote peer
        System.out.print("🌐 Enter peer IP " + ConsoleColors.BLUE + "(e.g., 127.0.0.1): " + ConsoleColors.RESET);
        String peerIP = scanner.nextLine();

        System.out.print("🔌 Enter peer port" + ConsoleColors.BLUE + " (e.g., 5000): " + ConsoleColors.RESET);
        int port = Integer.parseInt(scanner.nextLine());

        System.out.print("👤 Enter peer username: ");
        peerUsername = scanner.nextLine();

        // Retrieve peer's public key
        String peerPublicKeyStr = UserAuthManager.getPublicKey(peerUsername);
        if (peerPublicKeyStr == null) {
          System.out.println("❌ Could not find public key for user: " + peerUsername);
          return;
        }

        PublicKey peerPublicKey = RSAUtil.getPublicKeyFromBase64(peerPublicKeyStr);

        // Perform session key exchange
        KeySender.sendKeyToPeer(peerIP, port, loggedInUsername, peerUsername, sessionPrivateKey, peerPublicKey);
        sharedKey = KeySender.sessionKey;

        // Start chat receiver on port 6001
        new Thread(() -> ChatReceiver.start(6001, sharedKey, peerUsername, loggedInUsername)).start();

        try { Thread.sleep(1000); } catch (InterruptedException ignored) {}

        // Start chat sender on port 6002
        new Thread(() -> ChatSender.start(peerIP, 6002, sharedKey, loggedInUsername, peerUsername)).start();

      } else {
        System.out.println("❌ Unknown role. Type 'host' or 'connect'.");
      }

    } else {
      System.out.println("❌ Unknown action. Type 'register' or 'login'.");
    }
  }
}
