/**
 * Exception indicating an error in password input.
 */
public class InvalidPasswordException extends Exception {
    public InvalidPasswordException(String message) {
        super(message); // Вызов конструктора суперкласса (Exception) с переданным сообщением об ошибке
    }
}
