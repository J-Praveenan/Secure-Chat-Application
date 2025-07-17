package database;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

public class DBHelper {
    private static final String DB_URL = "jdbc:sqlite:chat.db";


    public static Connection connect() {
        try {
            Connection conn = DriverManager.getConnection("jdbc:sqlite:chat.db");

            // ✅ Enable WAL for concurrent write safety
            try (Statement stmt = conn.createStatement()) {
                stmt.execute("PRAGMA journal_mode=WAL;");
            }

            return conn;
        } catch (SQLException e) {
            System.err.println("DB Connection Failed: " + e.getMessage());
            return null;
        }
    }


    // Initializes the users and logs tables if not present
    public static void initDatabase() {
        String usersTable = """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                public_key TEXT NOT NULL
            );
        """;

        String logsTable = """
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT,
                user TEXT,
                peer TEXT,
                timestamp TEXT,
                details TEXT
            );
        """;

        try (Connection conn = connect()) {
            if (conn != null) {
                try (Statement stmt = conn.createStatement()) {
                    stmt.execute(usersTable);
                    stmt.execute(logsTable);
                    System.out.println("✅ Database and tables initialized.");
                }
            } else {
                System.err.println("❌ Database connection was null during initialization.");
            }
        } catch (SQLException e) {
            System.err.println("❌ Database Initialization Error: " + e.getMessage());
        }
    }
}
