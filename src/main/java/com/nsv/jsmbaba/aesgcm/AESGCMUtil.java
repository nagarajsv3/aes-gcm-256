package com.nsv.jsmbaba.aesgcm;

import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

@Slf4j
public class AESGCMUtil {

    private static final String ENCRYPT_ALGO = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128;
    private static final int IV_LENGTH_BYTE = 12;
    private static final int SALT_LENGTH_BYTE = 16;
    private static final Charset UTF_8 = StandardCharsets.UTF_8;

    public static byte[] getRandomNonce(int numberOfBytes) {
        byte[] randomNonce = new byte[numberOfBytes];
        new SecureRandom().nextBytes(randomNonce);
        return randomNonce;
    }

    /**
     * The AES secret key, either AES-128 or AES-256.
     * In Java, we can use KeyGenerator to generate the AES secret key.
     * 256 bits AES secret key
     *
     * @return
     * @throws NoSuchAlgorithmException
     */
    // 256 bits AES secret key
    public static SecretKey getAESKey(int numberOfBits) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(numberOfBits, SecureRandom.getInstanceStrong());
        return keyGenerator.generateKey();
    }

    /**
     * The AES secret key that derived from a given password.
     * In Java, we can use the SecretKeyFactory and PBKDF2WithHmacSHA256 to generate an AES key from a given password.
     *
     * @return
     * @throws NoSuchAlgorithmException
     */
    // AES key derived from a password
    public static SecretKey getAESKeyFromPassword(char[] password, byte[] salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        // iterationCount = 65536
        // keyLength = 256
        KeySpec spec = new PBEKeySpec(password, salt, 65536, 256);
        SecretKey secret = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
        return secret;
    }

    // hex representation
    public static String hex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }

    // print hex with block size split
    public static String hexWithBlockSize(byte[] bytes, int blockSize) {

        String hex = hex(bytes);

        // one hex = 2 chars
        blockSize = blockSize * 2;

        // better idea how to print this?
        List<String> result = new ArrayList<>();
        int index = 0;
        while (index < hex.length()) {
            result.add(hex.substring(index, Math.min(index + blockSize, hex.length())));
            index += blockSize;
        }

        return result.toString();

    }

    // AES-GCM needs GCMParameterSpec
    public static byte[] encrypt(byte[] pText, SecretKey secret, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, secret, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
        byte[] encryptedText = cipher.doFinal(pText);
        return encryptedText;
    }

    public static byte[] encrypt(byte[] pText, String password, byte[] salt, byte[] iv) throws Exception {
        return encrypt(pText,getAESKeyFromPassword(password.toCharArray(), salt),iv);
    }

    public static byte[] encrypt(String fromFile, String toFile, String password, byte[] iv, byte[] salt) throws Exception {

        // read a normal txt file
        Path readPath = Paths.get(ClassLoader.getSystemResource(fromFile).toURI());
        byte[] fileContent = Files.readAllBytes(readPath);

        // encrypt with a password
        byte[] encryptedText = AESGCMUtil.encrypt(fileContent, password, iv, salt);

        // save a file
        Path writePath = Paths.get(toFile);
        Files.write(writePath, encryptedText);

        return encryptedText;

    }

    // return a base64 encoded AES encrypted text
    public static String encryptAndEncode(byte[] pText, String password, byte[] salt, byte[] iv) throws Exception {
        // string representation, base64, send this string to other for decryption.
        return Base64.getEncoder().encodeToString(encrypt(pText, password, salt, iv));
    }


    // prefix IV length + IV bytes to cipher text
    public static byte[] encryptWithPrefixIV(byte[] pText, SecretKey secret, byte[] iv) throws Exception {

        byte[] cipherText = encrypt(pText, secret, iv);

        byte[] cipherTextWithIv = ByteBuffer.allocate(iv.length + cipherText.length)
                .put(iv)
                .put(cipherText)
                .array();
        return cipherTextWithIv;

    }

    // return a base64 encoded AES encrypted text
    public static String encryptWithPasswordKeyPrefixIvAndSaltBase64Ecoded(byte[] pText, String password, byte[] iv, byte[] salt) throws Exception {
        // string representation, base64, send this string to other for decryption.
        return Base64.getEncoder().encodeToString(encryptWithPasswordKeyPrefixIvAndSalt(pText, password, iv, salt));

    }


    public static byte[] encryptWithPasswordKeyPrefixIvAndSalt(byte[] pText, String password, byte[] iv, byte[] salt) throws Exception {

        // secret key from password
        SecretKey aesKeyFromPassword = getAESKeyFromPassword(password.toCharArray(), salt);

        byte[] cipherText = encrypt(pText, aesKeyFromPassword, iv);

        // prefix IV and Salt to cipher text
        byte[] cipherTextWithIvSalt = ByteBuffer.allocate(iv.length + salt.length + cipherText.length)
                .put(iv)
                .put(salt)
                .put(cipherText)
                .array();

        // it works, even if we save the based64 encoded string into a file.
        // return Base64.getEncoder().encodeToString(cipherTextWithIvSalt);

        // we save the byte[] into a file.
        return cipherTextWithIvSalt;

    }


    public static byte[] decrypt(byte[] cText, SecretKey secret, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
        cipher.init(Cipher.DECRYPT_MODE, secret, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
        byte[] plainText = cipher.doFinal(cText);
        return plainText;
    }

    public static byte[] decrypt(String cipherText, SecretKey secret, byte[] iv) throws Exception {
        return decrypt(cipherText.getBytes(), secret, iv);
    }


    public static byte[] decryptWithPrefixIV(byte[] cText, SecretKey secret) throws Exception {
        ByteBuffer bb = ByteBuffer.wrap(cText);

        byte[] iv = new byte[IV_LENGTH_BYTE];
        bb.get(iv);
        //bb.get(iv, 0, iv.length);

        byte[] cipherText = new byte[bb.remaining()];
        bb.get(cipherText);

        return decrypt(cipherText, secret, iv);

    }

    // we need the same password, salt and iv to decrypt it
    public static byte[] decryptBase64Encoded(String base64EncodedCipherText, String password, byte[] salt, byte[] iv) throws Exception {

        byte[] decode = Base64.getDecoder().decode(base64EncodedCipherText.getBytes(UTF_8));

        ByteBuffer bb = ByteBuffer.wrap(decode);

        byte[] cipherText = new byte[bb.remaining()];
        bb.get(cipherText);

        // get back the aes key from the same password and salt
        SecretKey aesKeyFromPassword = getAESKeyFromPassword(password.toCharArray(), salt);

        return decrypt(cipherText, aesKeyFromPassword, iv);

    }


    public static byte[] decryptFromFile(String fromEncryptedFile, String password, byte[] salt, byte[] iv) throws Exception {
        // read a file
        byte[] fileContent = Files.readAllBytes(Paths.get(fromEncryptedFile));
        return AESGCMUtil.decrypt(fileContent, password, salt,  iv);
    }

    public static byte[] decrypt(byte[] encryptedData, String password, byte[] salt, byte[] iv) throws Exception {
        // get back the aes key from the same password and salt
        SecretKey aesKeyFromPassword = getAESKeyFromPassword(password.toCharArray(), salt);
        return decrypt(encryptedData, aesKeyFromPassword, iv);
    }


    // we need the same password, salt and iv to decrypt it
    public static byte[] decryptWithPasswordKeyPrefixIvAndSaltBase64Encoded(String cText, String password) throws Exception {

        byte[] decode = Base64.getDecoder().decode(cText.getBytes(UTF_8));

        // get back the iv and salt from the cipher text
        ByteBuffer bb = ByteBuffer.wrap(decode);

        byte[] iv = new byte[IV_LENGTH_BYTE];
        bb.get(iv);

        byte[] salt = new byte[SALT_LENGTH_BYTE];
        bb.get(salt);

        byte[] cipherText = new byte[bb.remaining()];
        bb.get(cipherText);

        // get back the aes key from the same password and salt
        SecretKey aesKeyFromPassword = getAESKeyFromPassword(password.toCharArray(), salt);

        return decrypt(cipherText, aesKeyFromPassword, iv);

    }

}
