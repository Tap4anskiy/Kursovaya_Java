import java.io.Serializable;

/**
 * Represents an object that includes a login and password. Implements the Serializable interface.
 */
public class PasswordEntry implements Serializable {
    private String username;  // Login
    private String password;  // Password

    /**
     * Constructor of the PasswordEntry class.
     *
     * @param username Login
     * @param password Password
     */
    public PasswordEntry(String username, String password) {
        this.username = username;
        this.password = password;
    }

    /**
     * Gets the login from the entry.
     *
     * @return Login
     */
    public String getUsername() {
        return username;
    }

    /**
     * Gets the password from the entry.
     *
     * @return Password
     */
    public String getPassword() {
        return password;
    }
}