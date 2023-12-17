import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.logging.*;

/**
 * PasswordManager - a simple password management application with a console interface.
 * The application provides functions for adding, viewing, editing, and deleting password entries.
 * Passwords are encrypted and stored in a file using the AES encryption algorithm with a randomly generated salt.
 */
public class PasswordManager {
    /**
     * File path for storing passwords.
     */
    private static final String FILE_PATH = "passwords.dat";

    /**
     * Logger for the PasswordManager class.
     */
    private static final Logger LOGGER = Logger.getLogger(PasswordManager.class.getName());

    /**
     * Map to store password entries.
     */
    private static Map<String, PasswordEntry> passwordEntries = new HashMap<>();

    /**
     * Main method that initializes logging, loads passwords from a file.
     *
     * @param args Command-line arguments (not used).
     */
    public static void main(String[] args) {
        // Настройка вывода логов в файл
        try {
            // Создать объект FileHandler для записи логов в файл "password_manager.log".
            FileHandler fileHandler = new FileHandler("password_manager.log", true);
            SimpleFormatter formatter = new SimpleFormatter();
            fileHandler.setFormatter(formatter);
            // Добавить FileHandler в логгер (LOGGER) для записи логов в файл.
            LOGGER.addHandler(fileHandler);
        } catch (IOException e) {
            // В случае ошибки при настройке логирования, вывести информацию об ошибке.
            e.printStackTrace();
        }

        // Метод загрузки паролей из файла
        loadPasswordsFromFile();

        // Основной цикл обработки пользовательских действий
        Scanner scanner = new Scanner(System.in);
        try {
            while (true) {
                // Вывести меню выбора пользовательских действий
                System.out.println("1. Добавить запись");
                System.out.println("2. Просмотреть записи");
                System.out.println("3. Редактировать запись");
                System.out.println("4. Удалить запись");
                System.out.println("5. Выйти");

                // Прочитать выбор пользователя
                int choice = scanner.nextInt();

                // Обработать выбор пользователя
                switch (choice) {
                    case 1:
                        addPasswordEntry();
                        break;
                    case 2:
                        viewPasswordEntries();
                        break;
                    case 3:
                        editPasswordEntry();
                        break;
                    case 4:
                        deletePasswordEntry();
                        break;
                    case 5:
                        savePasswordsToFile();
                        // Завершить выполнение программы после сохранения паролей и выхода
                        System.exit(0);
                    default:
                        System.out.println("Неверный выбор. Пожалуйста, выберите из списка:");
                }
            }
        } catch (InputMismatchException e) {
            // В случае ошибки ввода, вывести сообщение и зарегистрировать ошибку в логах.
            System.out.println("Ошибка ввода. Введите число от 1 до 5.");
            LOGGER.log(Level.SEVERE, "Ошибка ввода", e);
        }
    }

    /**
     * Method to add a new password entry to the passwordEntries map.
     */
    private static void addPasswordEntry() {
        Scanner scanner = new Scanner(System.in);
        // Запрос имени сервиса
        System.out.print("Введите название сервиса: ");
        String serviceName = scanner.nextLine();
        // Запрос имени пользователя (логина)
        System.out.print("Введите имя пользователя: ");
        String username = scanner.nextLine();
        // Запрос пароля
        System.out.print("Введите пароль: ");
        String password = scanner.nextLine();
        // Создание объекта PasswordEntry
        PasswordEntry entry = new PasswordEntry(username, password);
        // Добавление записи в карту passwordEntries
        passwordEntries.put(serviceName, entry);
        // Вывод сообщения об успешном добавлении записи
        System.out.println("Запись успешно добавлена.");
    }

    /**
     * Method to display all password entries in the passwordEntries map.
     */
    private static void viewPasswordEntries() {
        // Вывод всех записей карты
        for (Map.Entry<String, PasswordEntry> entry : passwordEntries.entrySet()) {
            System.out.println("Сервис: " + entry.getKey());
            System.out.println("Логин: " + entry.getValue().getUsername());
            System.out.println("Пароль: " + entry.getValue().getPassword());
            System.out.println("-----------");
        }
    }

    /**
     * Method to edit a password entry.
     */
    private static void editPasswordEntry() {
        Scanner scanner = new Scanner(System.in);

        // Запрос имени сервиса для редактирования
        System.out.print("Введите название сервиса для редактирования: ");
        String serviceName = scanner.nextLine();

        // Проверка существования записи
        if (passwordEntries.containsKey(serviceName)) {
            // Редактирование существующей записи
            System.out.print("Введите новое имя пользователя: ");
            String newUsername = scanner.nextLine();

            System.out.print("Введите новый пароль: ");
            String newPassword = scanner.nextLine();

            // Создание нового объекта PasswordEntry с новыми данными
            PasswordEntry entry = new PasswordEntry(newUsername, newPassword);

            // Замена существующей записи в карте passwordEntries новым объектом
            passwordEntries.put(serviceName, entry);

            // Вывод сообщения об успешном редактировании записи
            System.out.println("Запись успешно отредактирована.");
        } else {
            // Вывод сообщения о том, что запись не найдена
            System.out.println("Запись с указанным сервисом не найдена.");
        }
    }

    /**
     * Method to delete an entry.
     */
    private static void deletePasswordEntry() {
        Scanner scanner = new Scanner(System.in);

        // Запрос имени сервиса для удаления
        System.out.print("Введите название сервиса для удаления: ");
        String serviceName = scanner.nextLine();

        // Проверка существования записи
        if (passwordEntries.containsKey(serviceName)) {
            // Удаление существующей записи
            passwordEntries.remove(serviceName);

            // Вывод сообщения об успешном удалении записи
            System.out.println("Запись успешно удалена.");
        } else {
            // Вывод сообщения о том, что запись не найдена
            System.out.println("Запись с указанным сервисом не найдена.");
        }
    }

    /**
     * Method to load entries from a file.
     */
    private static void loadPasswordsFromFile() {
        Scanner scanner = new Scanner(System.in);

        // Вывод меню выбора
        System.out.println("Выберите опцию:");
        System.out.println("1. Создать новый файл паролей");
        System.out.println("2. Ввести существующий пароль");

        try {
            // Запрос выбора пользователя
            int choice = scanner.nextInt();
            scanner.nextLine(); // Прочитать лишний символ новой строки

            //Обработка выбора пользователя
            switch (choice) {
                case 1:
                    // Создание нового файла паролей
                    createNewPasswordFile();
                    break;
                case 2:
                    // Ввод существующего пароля
                    enterExistingPassword();
                    break;
                default:
                    // Вывод сообщения об ошибке и завершение программы
                    System.out.println("Некорректный выбор. Завершение программы.");
                    System.exit(0);
            }
        } catch (InputMismatchException e) {
            // Обработка ошибки ввода и логирование
            System.out.println("Ошибка ввода. Введите число от 1 до 2.");
            LOGGER.log(Level.SEVERE, "Ошибка ввода", e);
        }
    }

    /**
     * Method to create a new password file.
     */
    private static void createNewPasswordFile() {
        Scanner scanner = new Scanner(System.in);

        // Вывод меню выбора
        System.out.println("Выберите опцию:");
        System.out.println("1. Ввести ключ для шифрования самостоятельно");
        System.out.println("2. Сгенерировать надежный ключ");

        String password = "";
        try {
            // Запрос выбора пользователя
            int choice = scanner.nextInt();
            scanner.nextLine(); // Прочитать лишний символ новой строки

            // Обработка выбора пользователя
            switch (choice) {
                case 1:
                    // Ввод нового пароля для шифрования
                    System.out.print("Введите новый пароль для шифрования: ");
                    password = scanner.nextLine();
                    break;
                case 2:
                    // Генерация надежного ключа
                    password = generateStrongPassword();
                    System.out.println("Сгенерирован сильный ключ: " + password);
                    System.out.println("Обязательно сохраните его, иначе вы потеряете свои данные!");
                    break;
                default:
                    // Вывод сообщения об ошибке и завершение программы
                    System.out.println("Некорректный выбор. Завершение программы.");
                    System.exit(0);
            }
        } catch (InputMismatchException e) {
            // Обработка ошибки ввода и логирование
            System.out.println("Ошибка ввода. Введите число от 1 до 2.");
            LOGGER.log(Level.SEVERE, "Ошибка ввода", e);
        }


        // Вывод сообщения о успешном создании нового файла паролей
        System.out.println("Новый файл паролей создан успешно.");
    }

    /**
     * Method to generate a strong key.
     *
     * @return A strong key.
     */
    private static String generateStrongPassword() {
        // Создание нового объект SecureRandom для генерации случайных байтов.
        SecureRandom random = new SecureRandom();
        // Создание массива байтов длиной 16 для хранения сгенерированного пароля.
        byte[] passwordBytes = new byte[16];
        // Заполнение массива случайными байтами с использованием объекта SecureRandom.
        random.nextBytes(passwordBytes);
        // Преобразование массива байтов в строку Base64 и возвращение результата.
        return Base64.getEncoder().encodeToString(passwordBytes);
    }

    /**
     * Method to enter an existing password.
     */
    private static void enterExistingPassword() {
        System.out.print("Введите ключ от существующего файла: ");

        // Считывание введенного пароля из консоли
        String enteredPassword = new Scanner(System.in).nextLine();

        try {
            // Попытка загрузить и расшифровать пароли, используя введенный пароль
            loadAndDecryptPasswords(enteredPassword);

            // Вывод сообщения об успешной загрузке файла с паролями
            System.out.println("Файл загружен успешно.");
        } catch (InvalidPasswordException e) {
            // В случае ошибки InvalidPasswordException, вывод сообщения о неверном пароле
            // и запись ошибки в лог
            System.out.println("Неверный пароль. Завершение работы.");
            LOGGER.log(Level.SEVERE, "Ошибка загрузки и расшифровки", e);

            // Завершение программы
            System.exit(0);
        }
    }

    /**
     * Method to initialize password entries.
     *
     * @param password Password for encryption.
     */
    private static void initializePasswordEntries(String password) {
        // Создание нового экземпляра HashMap для хранения паролей
        // (перезапись переменной passwordEntries)
        passwordEntries = new HashMap<>();
    }

    /**
     * Method to load and decrypt passwords from a file.
     *
     * @param password Password for decryption.
     * @throws InvalidPasswordException If the password is incorrect.
     */
    private static void loadAndDecryptPasswords(String password) throws InvalidPasswordException {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(FILE_PATH))) {
            byte[] salt = (byte[]) ois.readObject();  // Чтение соли из файла
            SecretKey secretKey = generateSecretKey(password, salt);

            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);

            // Расшифровка
            byte[] encryptedData = (byte[]) ois.readObject();
            byte[] decryptedData = cipher.doFinal(encryptedData);

            // Десериализация расшифрованных данных и сохранение в passwordEntries
            passwordEntries = (Map<String, PasswordEntry>) deserialize(decryptedData);
        } catch (FileNotFoundException e) {
            // Если файл с паролями не найден, создаем новую структуру данных
            // инициализируем ее с использованием введенного пароля
            System.out.println("Файл паролей не найден. Создание нового файла.");
            initializePasswordEntries(password);
        } catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | InvalidKeySpecException |
                 NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
            // Логирование ошибки и выброс исключения, если произошла ошибка при расшифровке
            LOGGER.log(Level.SEVERE, "Ошибка загрузки и расшифровки", e);
            throw new InvalidPasswordException("Неверный пароль.");
        }
    }

    /**
     * Method to save entries to a file.
     *
     */
    private static void savePasswordsToFile() {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(FILE_PATH))) {
            byte[] salt = generateSalt(); // Генерация случайной соли
            SecretKey secretKey = generateSecretKey(getUserEnteredPassword(), salt); // Генерация ключа на основе введенного пользователем пароля и соли

            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey); // Установка шифра в режим шифрования с использованием сгенерированного ключа

            byte[] serializedData = serialize(passwordEntries); // Сериализация паролей в байтовый массив
            byte[] encryptedData = cipher.doFinal(serializedData); // Шифрование данных

            oos.writeObject(salt);  // Сохранение соли в файл
            oos.writeObject(encryptedData); // Сохранение зашифрованных данных в файл

            System.out.println("Данные сохранены.");
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException |
                 InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
            LOGGER.log(Level.SEVERE, "Ошибка сохранения.", e); // Логирование ошибки сохранения паролей
        }
    }

    /**
     * Method to get the user-entered password.
     *
     * @return User-entered password.
     */
    private static String getUserEnteredPassword() {
        Scanner scanner = new Scanner(System.in); // Создание объекта Scanner для ввода с клавиатуры
        System.out.print("Введите ключ для шифрования: ");
        return scanner.nextLine(); // Считывание введенного пользователем пароля и возвращение его
    }

    /**
     * Method to generate a secret key.
     *
     * @param secret Secret (password).
     * @param salt   Salt for strengthening.
     * @return Secret key.
     * @throws NoSuchAlgorithmException If the specified algorithm is not available.
     * @throws InvalidKeySpecException  If the specified key specification is inappropriate for the given algorithm.
     */
    private static SecretKey generateSecretKey(String secret, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // Создание экземпляра PBEKeySpec с паролем, солью и параметрами итераций и длины ключа
        KeySpec spec = new PBEKeySpec(secret.toCharArray(), salt, 65536, 256);
        // Создание экземпляра SecretKeyFactory с использованием алгоритма PBKDF2
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        // Генерация байтов ключа с использованием SecretKeyFactory
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        // Создание экземпляра SecretKeySpec для представления секретного ключа
        return new SecretKeySpec(keyBytes, "AES");
    }

    /**
     * Method to generate a salt.
     *
     * @return Generated salt.
     */
    private static byte[] generateSalt() {
        // Создание экземпляра SecureRandom для генерации случайной соли
        SecureRandom random = new SecureRandom();
        // Создание байтового массива для хранения соли длиной 16 байт
        byte[] salt = new byte[16];
        // Заполнение массива случайными байтами с использованием SecureRandom
        random.nextBytes(salt);
        // Возврат сгенерированной соли
        return salt;
    }

    /**
     * Method to serialize an object into a byte array.
     *
     * @param obj Object to serialize.
     * @return Byte array.
     * @throws IOException
     */
    private static byte[] serialize(Object obj) throws IOException {
        // Создание ByteArrayOutputStream для записи сериализованных данных
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             // Создание ObjectOutput для записи объекта в ByteArrayOutputStream
             ObjectOutput out = new ObjectOutputStream(bos)) {
            // Запись объекта в ByteArrayOutputStream
            out.writeObject(obj);

            // Возврат массива байт, содержащего сериализованные данные
            return bos.toByteArray();
        }
    }

    /**
     * Method to deserialize an object from a byte array.
     *
     * @param data Byte array.
     * @return Deserialized object.
     * @throws IOException
     * @throws ClassNotFoundException
     */
    private static Object deserialize(byte[] data) throws IOException, ClassNotFoundException {
        // Создание ByteArrayInputStream для чтения сериализованных данных
        try (ByteArrayInputStream bis = new ByteArrayInputStream(data);
             // Создание ObjectInput для чтения объекта из ByteArrayInputStream
             ObjectInput in = new ObjectInputStream(bis)) {
            // Чтение объекта из ByteArrayInputStream и возврат
            return in.readObject();
        }
    }
}
