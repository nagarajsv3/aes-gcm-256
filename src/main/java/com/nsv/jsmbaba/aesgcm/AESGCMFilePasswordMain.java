package com.nsv.jsmbaba.aesgcm;

import lombok.extern.slf4j.Slf4j;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

@Slf4j
public class AESGCMFilePasswordMain {

    private static final int AES_KEY_BIT = 256;
    private static final int IV_LENGTH_BYTE = 12;
    private static final int SALT_LENGTH_BYTE = 16;
    private static final Charset UTF_8 = StandardCharsets.UTF_8;


    public static void main(String[] args) throws Exception{
        String password = "password123";
        String fromFile = "readme.txt"; // from resources folder
        String toFile = "c:\\nagaraj\\enc\\readme.encrypted.txt";

        byte[] iv = AESGCMUtil.getRandomNonce(IV_LENGTH_BYTE);
        log.info("IV ; Size={} ; Value={}; String Value={}", iv.length, iv, iv.toString());
        log.info("Input iv(hex)={}", AESGCMUtil.hex(iv));

        byte[] salt = AESGCMUtil.getRandomNonce(SALT_LENGTH_BYTE);
        log.info("SALT ; Size={} ; Value={}; String Value={}", salt.length, salt, salt.toString());
        log.info("Input salt(hex)={}", AESGCMUtil.hex(salt));

        byte[] encrypt = AESGCMUtil.encrypt(fromFile, toFile, password, iv, salt);

        byte[] decrypt = AESGCMUtil.decrypt(encrypt, password, iv, salt);
        log.info("Decrypted Data = {}",new String(decrypt));

        byte[] bytes = AESGCMUtil.decryptFromFile(toFile, password, iv, salt);
        log.info("Decrypted Data from file = {}",new String(bytes));

    }
}
