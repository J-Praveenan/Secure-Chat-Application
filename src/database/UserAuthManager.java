package database;

import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class UserAuthManager {

  public static boolean registerUser(String username, String password, String publicKey) {
    String hash = hashPassword(password);
    String sql = "INSERT INTO users (username, password_hash, public_key) VALUES (?, ?, ?)";

    try (Connection conn = DBHelper.connect();
        PreparedStatement pstmt = conn.prepareStatement(sql)) {
      pstmt.setString(1, username);
      pstmt.setString(2, hash);
      pstmt.setString(3, publicKey);
      pstmt.executeUpdate();
      return true;
    } catch (SQLException e) {
      System.err.println("Registration Failed: " + e.getMessage());
      return false;
    }
  }

  public static boolean authenticate(String username, String password) {
    String hash = hashPassword(password);
    String sql = "SELECT * FROM users WHERE username = ? AND password_hash = ?";

    try (Connection conn = DBHelper.connect();
        PreparedStatement pstmt = conn.prepareStatement(sql)) {
      pstmt.setString(1, username);
      pstmt.setString(2, hash);
      ResultSet rs = pstmt.executeQuery();
      return rs.next();
    } catch (SQLException e) {
      System.err.println("Authentication Failed: " + e.getMessage());
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
    String hash = hashPassword(password);
    String sql = "SELECT public_key FROM users WHERE username = ? AND password_hash = ?";

    try (Connection conn = DBHelper.connect();
        PreparedStatement pstmt = conn.prepareStatement(sql)) {
      pstmt.setString(1, username);
      pstmt.setString(2, hash);
      ResultSet rs = pstmt.executeQuery();
      if (rs.next()) {
        return rs.getString("public_key");
      }
    } catch (SQLException e) {
      System.err.println("Login Failed: " + e.getMessage());
    }
    return null;
  }

  public static String hashPassword(String password) {
    try {
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      byte[] hashed = md.digest(password.getBytes("UTF-8"));
      StringBuilder sb = new StringBuilder();
        for (byte b : hashed) {
            sb.append(String.format("%02x", b));
        }
      return sb.toString();
    } catch (Exception e) {
      throw new RuntimeException("Hashing Error", e);
    }
  }
}
