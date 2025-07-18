package database;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.time.Instant;

public class AuthLogger {

    /**
     * Logs an authentication or messaging event into the database.
     * Retries if the database is temporarily locked (due to SQLite concurrency limits).
     * @param eventType  Type of event (e.g., LOGIN_SUCCESS, MESSAGE_SENT)
     * @param user       Initiating user
     * @param peer       Peer user (can be null)
     * @param details    Additional context (timestamp, UUID, reason, etc.)
     */
    public static synchronized void log(String eventType, String user, String peer, String details) {
        String sql = "INSERT INTO logs (event_type, user, peer, timestamp, details) VALUES (?, ?, ?, ?, ?)";
        int retries = 10;
        int delay = 300; // ms

        for (int i = 0; i < retries; i++) {
            try (Connection conn = DBHelper.connect();
                 PreparedStatement pstmt = conn.prepareStatement(sql)) {

                pstmt.setString(1, eventType);
                pstmt.setString(2, user);
                pstmt.setString(3, peer);
                pstmt.setString(4, Instant.now().toString());
                pstmt.setString(5, details);
                pstmt.executeUpdate();
                return;

            } catch (SQLException e) {
                if (e.getMessage().toLowerCase().contains("database is locked")) {
                    // Retry after short delay with jitter to avoid collision storms
                    try {
                        Thread.sleep(delay + (int)(Math.random() * 100));
                    } catch (InterruptedException ignored) {}
                } else {
                    System.err.println("❌ Failed to log authentication event: " + e.getMessage());
                    break;
                }
            }
        }

        // Final failure log after all retry attempts
        System.err.println("❌ All retries failed: could not log event [" + eventType + "] for user=" + user);
    }

    // ==== Specialized Logging Helpers ====

    /** Logs a Diffie-Hellman key exchange result. */
    public static void logDHExchange(String user, String peer, boolean success, String details) {
        String eventType = success ? "DH_EXCHANGE_SUCCESS" : "DH_EXCHANGE_FAILURE";
        log(eventType, user, peer, details);
    }

    /** Logs the result of a session verification check. */
    public static void logSessionVerification(String user, String peer, boolean success, String details) {
        String eventType = success ? "SESSION_VERIFICATION_SUCCESS" : "SESSION_VERIFICATION_FAILURE";
        log(eventType, user, peer, details);
    }

    /** Logs when a replay attack attempt is detected. */
    public static void logReplayDetected(String user, String peer, String details) {
        log("REPLAY_ATTACK_DETECTED", user, peer, details);
    }

    /** Logs successful login. */
    public static void logLoginSuccess(String user) {
        log("LOGIN_SUCCESS", user, null, "User logged in successfully.");
    }

    /** Logs failed login attempt with reason. */
    public static void logLoginFailure(String user, String reason) {
        log("LOGIN_FAILURE", user, null, "Login failed: " + reason);
    }

    /** Logs successful user registration. */
    public static void logRegisterSuccess(String user) {
        log("REGISTER_SUCCESS", user, null, "New user registered.");
    }

    /** Logs when a message is sent. */
    public static void logMessageSent(String sender, String receiver, String uuid) {
        log("MESSAGE_SENT", sender, receiver, "UUID=" + uuid);
    }

    /** Logs when a message is received. */
    public static void logMessageReceived(String receiver, String sender, String uuid) {
        log("MESSAGE_RECEIVED", receiver, sender, "UUID=" + uuid);
    }
}
