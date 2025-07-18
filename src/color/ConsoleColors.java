package color;

/**
 * ANSI escape codes for coloring console output.
 * Supports basic and 24-bit RGB terminal colors.
 */
public class ConsoleColors {

  // Resets the console color to default
  public static final String RESET = "\033[0m";

  // Standard ANSI color codes
  public static final String GREEN = "\033[0;32m";
  public static final String YELLOW = "\033[0;33m";
  public static final String BLUE = "\033[0;34m";
  public static final String CYAN = "\033[0;36m";
  public static final String PURPLE = "\033[0;35m";

  // Extended 24-bit RGB colors (may not work on all terminals)
  public static final String PLUM2 = "\033[38;2;215;175;255m";      // Light purple
  public static final String AQUAMARINE3 = "\033[38;2;95;215;175m"; // Light teal
}
