package database;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import org.mindrot.jbcrypt.BCrypt;

public class UserAuthManager {
  private static String currentLoggedInUser = null;
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
          currentLoggedInUser = username;  // ✅ Set current user
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

  public static String getCurrentLoggedInUser() {
    return currentLoggedInUser;
  }

  public static void logout() {
    currentLoggedInUser = null;
  }

  public static String hashPassword(String password) {
    return BCrypt.hashpw(password, BCrypt.gensalt(12));
  }
}

