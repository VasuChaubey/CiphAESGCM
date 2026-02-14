import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.Scanner;

public class CiphAESGCM {

    // ===== File format =====
    private static final String MAGIC = "AESGCM01";
    private static final byte VERSION = 1;

    // ===== Crypto params =====
    private static final int SALT_SIZE = 16;
    private static final int IV_SIZE = 12;
    private static final int KEY_SIZE = 256;
    private static final int ITERATIONS = 100_000;
    private static final int BUFFER_SIZE = 64 * 1024; // 64 KB

    // ===== Key derivation =====
    private static SecretKey deriveKey(char[] password, byte[] salt) throws Exception {
        SecretKeyFactory factory =
                SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        PBEKeySpec spec =
                new PBEKeySpec(password, salt, ITERATIONS, KEY_SIZE);
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    }

    // ===== Encrypt =====
    private static void encrypt(File input, File output, String password) throws Exception {

        SecureRandom random = SecureRandom.getInstanceStrong();
        byte[] salt = new byte[SALT_SIZE];
        byte[] iv = new byte[IV_SIZE];
        random.nextBytes(salt);
        random.nextBytes(iv);

        SecretKey key = deriveKey(password.toCharArray(), salt);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));

        try (
            FileInputStream fis = new FileInputStream(input);
            FileOutputStream fos = new FileOutputStream(output);
            BufferedOutputStream bos = new BufferedOutputStream(fos);
            CipherOutputStream cos = new CipherOutputStream(bos, cipher)
        ) {
            // Header
            bos.write(MAGIC.getBytes(StandardCharsets.US_ASCII));
            bos.write(VERSION);
            bos.write(salt);
            bos.write(iv);

            // Stream encryption
            byte[] buffer = new byte[BUFFER_SIZE];
            int read;
            while ((read = fis.read(buffer)) != -1) {
                cos.write(buffer, 0, read);
            }
        }
    }

    // ===== Decrypt =====
    private static void decrypt(File input, File output, String password) throws Exception {

        try (
            FileInputStream fis = new FileInputStream(input);
            BufferedInputStream bis = new BufferedInputStream(fis)
        ) {
            byte[] magic = bis.readNBytes(8);
            if (!MAGIC.equals(new String(magic, StandardCharsets.US_ASCII))) {
                throw new SecurityException("Invalid encrypted file format");
            }

            int version = bis.read();
            if (version != VERSION) {
                throw new SecurityException("Unsupported version");
            }

            byte[] salt = bis.readNBytes(SALT_SIZE);
            byte[] iv = bis.readNBytes(IV_SIZE);

            SecretKey key = deriveKey(password.toCharArray(), salt);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));

            try (
                CipherInputStream cis = new CipherInputStream(bis, cipher);
                FileOutputStream fos = new FileOutputStream(output)
            ) {
                byte[] buffer = new byte[BUFFER_SIZE];
                int read;
                while ((read = cis.read(buffer)) != -1) {
                    fos.write(buffer, 0, read);
                }
            }
        }
    }

    // ===== CLI =====
    public static void main(String[] args) {

        try (Scanner sc = new Scanner(System.in)) {

            System.out.print("Encrypt or Decrypt (e/d): ");
            String mode = sc.nextLine().trim().toLowerCase();

            System.out.print("Enter full file path: ");
            File input = new File(sc.nextLine().trim());

            if (!input.exists()) {
                System.out.println("File not found.");
                return;
            }

            System.out.print("Enter password: ");
            String password = sc.nextLine();

            File output;

            if (mode.equals("e")) {
                output = new File(input.getParent(),
                        input.getName() + ".ciph");
                encrypt(input, output, password);
                System.out.println("Encrypted file saved as:");
                System.out.println(output.getAbsolutePath());

            } else if (mode.equals("d")) {
                String name = input.getName();
                if (name.endsWith(".ciph")) {
                    name = name.substring(0, name.length() - 5);
                } else {
                    name = name + ".dec";
                }
                output = new File(input.getParent(), name);
                decrypt(input, output, password);
                System.out.println("Decrypted file saved as:");
                System.out.println(output.getAbsolutePath());

            } else {
                System.out.println("Invalid option.");
            }
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }
    }
}
