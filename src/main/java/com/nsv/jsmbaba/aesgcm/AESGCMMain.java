package com.nsv.jsmbaba.aesgcm;

import lombok.extern.slf4j.Slf4j;

import javax.crypto.SecretKey;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;

@Slf4j
public class AESGCMMain {

    private static final int AES_KEY_BIT = 256;
    private static final int IV_LENGTH_BYTE = 12;
    private static final Charset UTF_8 = StandardCharsets.UTF_8;

    public static void main(String[] args) throws NoSuchAlgorithmException, Exception {

        log.info("*****AES GCM Encryption*****");

        //Person jsmbaba = new Person("jsmbaba", "I dont have Identity", "Whole Universe");
        //String pText = JsonUtils.getJsonMessageFromObject(jsmbaba);

        String pText = "Jsmbaba...";

        log.info("Input Text={}", pText.toString());

        log.info("********Generate Random IV using SecureRandom - 12 / 16 bytes********");
        // encrypt and decrypt need the same IV.
        // AES-GCM needs IV 96-bit (12 bytes)
        byte[] iv = AESGCMUtil.getRandomNonce(IV_LENGTH_BYTE);
        log.info("IV ; Size={} ; Value={}; String Value={}", iv.length, iv, iv.toString());
        log.info("Input iv(hex)={}", AESGCMUtil.hex(iv));

        log.info("********Generate SecretKey 256*********");
        // encrypt and decrypt need the same key.
        // get AES 256 bits (32 bytes) key
        SecretKey aesKey = AESGCMUtil.getAESKey(AES_KEY_BIT);
        log.info("AES SecretKey ; Size={} bytes, Secret Key= {} ; Algorithm={} ; Format={}", aesKey.getEncoded().length, aesKey.getEncoded(), aesKey.getAlgorithm(), aesKey.getFormat());
        log.info("Input Secret Key(hex)={}", AESGCMUtil.hex(aesKey.getEncoded()));


        byte[] encryptedData = AESGCMUtil.encrypt(pText.getBytes(UTF_8), aesKey, iv);
        log.info("encrypted data={}", encryptedData);
        log.info("encrypted data(hex)={}", AESGCMUtil.hex(encryptedData));
        log.info("encrypted data Block 16 (hex)={}", AESGCMUtil.hexWithBlockSize(encryptedData, 16));


        log.info("***********AES Decryption***********");
        log.info("Input Secret Key(hex)={}", AESGCMUtil.hex(aesKey.getEncoded()));
        log.info("Input iv(hex)={}", AESGCMUtil.hex(iv));
        log.info("encrypted data(hex)={}", AESGCMUtil.hex(encryptedData));
        byte[] decrypt = AESGCMUtil.decrypt(encryptedData, aesKey, iv);
        log.info("decrypted data={}", new String(decrypt));


        log.info("\n\n");
        log.info("*******AES GCM Encryption-Prefix with IV************");
        byte[] encryptedDataWithPrefixedIv = AESGCMUtil.encryptWithPrefixIV(pText.getBytes(), aesKey, iv);
        log.info("encrypted data prefixed iv={}", encryptedDataWithPrefixedIv);
        log.info("encrypted data prefixed iv(hex)={}", AESGCMUtil.hex(encryptedDataWithPrefixedIv));
        log.info("encrypted data prefixed iv Block 16 (hex)={}", AESGCMUtil.hexWithBlockSize(encryptedDataWithPrefixedIv, 16));

        log.info("Input Secret Key(hex)={}", AESGCMUtil.hex(aesKey.getEncoded()));
        log.info("Input iv(hex)={}", AESGCMUtil.hex(iv));
        log.info("encrypted data(hex)={}", AESGCMUtil.hex(encryptedDataWithPrefixedIv));
        log.info("decrypted data={}", new String(AESGCMUtil.decryptWithPrefixIV(encryptedDataWithPrefixedIv, aesKey)));

    }

}