package database;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import org.mindrot.jbcrypt.BCrypt;

public class UserAuthManager {

  // Stores the currently logged-in username in memory
  private static String currentLoggedInUser = null;

  /**
   * Registers a new user with hashed password and RSA public key.
   * @param username Username
   * @param password Raw password
   * @param publicKey RSA public key in base64
   * @return true if registration succeeded, false otherwise
   */
  public static boolean registerUser(String username, String password, String publicKey) {
    String hash = hashPassword(password);
    String sql = "INSERT INTO users (username, password_hash, public_key) VALUES (?, ?, ?)";

    try (Connection conn = DBHelper.connect();
         PreparedStatement pstmt = conn.prepareStatement(sql)) {
      pstmt.setString(1, username);
      pstmt.setString(2, hash);
      pstmt.setString(3, publicKey);
      pstmt.executeUpdate();
      AuthLogger.log("REGISTER_SUCCESS", username, null, "User registered successfully");
      return true;
    } catch (SQLException e) {
      System.err.println("Registration Failed: " + e.getMessage());
      AuthLogger.log("REGISTER_FAIL", username, null, "Registration error: " + e.getMessage());
      return false;
    }
  }

  /**
   * Retrieves the stored public key for a given username.
   * @param username Target user
   * @return Base64 public key string, or null if user not found or error
   */
  public static String getPublicKey(String username) {
    String sql = "SELECT public_key FROM users WHERE username = ?";

    try (Connection conn = DBHelper.connect();
         PreparedStatement pstmt = conn.prepareStatement(sql)) {
      pstmt.setString(1, username);
      ResultSet rs = pstmt.executeQuery();
      if (rs.next()) {
        return rs.getString("public_key");
      } else {
        return null;
      }
    } catch (SQLException e) {
      System.err.println("Public Key Retrieval Failed: " + e.getMessage());
      return null;
    }
  }

  /**
   * Logs in a user by verifying the password against the stored hash.
   * If successful, stores the user in memory and returns their public key.
   * @param username Input username
   * @param password Input password
   * @return Base64 public key if login succeeds, null otherwise
   */
  public static String login(String username, String password) {
    String sql = "SELECT password_hash, public_key FROM users WHERE username = ?";

    try (Connection conn = DBHelper.connect();
         PreparedStatement pstmt = conn.prepareStatement(sql)) {
      pstmt.setString(1, username);
      ResultSet rs = pstmt.executeQuery();
      if (rs.next()) {
        String storedHash = rs.getString("password_hash");
        if (BCrypt.checkpw(password, storedHash)) {
          AuthLogger.logLoginSuccess(username);
          currentLoggedInUser = username;  // Set user session
          return rs.getString("public_key");
        } else {
          AuthLogger.logLoginFailure(username, "Incorrect password");
        }
      } else {
        AuthLogger.logLoginFailure(username, "Incorrect password");
      }
    } catch (SQLException e) {
      System.err.println("Login Failed: " + e.getMessage());
      AuthLogger.log("LOGIN_FAIL", username, null, "Login SQL error: " + e.getMessage());
    }
    return null;
  }

  /**
   * Returns the username of the currently logged-in user.
   */
  public static String getCurrentLoggedInUser() {
    return currentLoggedInUser;
  }

  /**
   * Logs out the current user by clearing the session.
   */
  public static void logout() {
    currentLoggedInUser = null;
  }

  /**
   * Generates a bcrypt hash of the given password.
   * @param password Raw password
   * @return Hashed password string
   */
  public static String hashPassword(String password) {
    return BCrypt.hashpw(password, BCrypt.gensalt(12));
  }
}
