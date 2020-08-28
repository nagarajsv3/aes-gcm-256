package com.nsv.jsmbaba.aesgcm;

import lombok.extern.slf4j.Slf4j;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

@Slf4j
public class AESGCMPasswordMain {


    private static final int AES_KEY_BIT = 256;
    private static final int IV_LENGTH_BYTE = 12;
    private static final int SALT_LENGTH_BYTE = 16;
    private static final Charset UTF_8 = StandardCharsets.UTF_8;


    public static void main(String[] args) throws Exception{

        String pText = "Hi... Jsmbaba... How are you...";
        log.info("Plain Text={}",pText);

        String password = "Partha";

        byte[] iv = AESGCMUtil.getRandomNonce(IV_LENGTH_BYTE);
        log.info("IV ; Size={} ; Value={}; String Value={}", iv.length, iv, iv.toString());
        log.info("Input iv(hex)={}", AESGCMUtil.hex(iv));


        byte[] salt = AESGCMUtil.getRandomNonce(SALT_LENGTH_BYTE);
        log.info("SALT ; Size={} ; Value={}; String Value={}", salt.length, salt, salt.toString());
        log.info("Input salt(hex)={}", AESGCMUtil.hex(salt));

        String cipherText = AESGCMUtil.encryptAndEncode(pText.getBytes(), password, iv, salt);
        log.info("encrypted data Base64 Encoded={}", cipherText);

        log.info("Decrypted Text = {}",new String(AESGCMUtil.decryptBase64Encoded(cipherText, password, iv, salt)));

        String cipherTextPrefixedWithIvAndSalt = AESGCMUtil.encryptWithPasswordKeyPrefixIvAndSaltBase64Ecoded(pText.getBytes(), password, iv, salt);
        log.info("encrypted data PrefixedWithIvAndSalt Base64 Encoded={}", cipherTextPrefixedWithIvAndSalt);

        log.info("Decrypted Text = {}",new String(AESGCMUtil.decryptWithPasswordKeyPrefixIvAndSaltBase64Encoded(cipherTextPrefixedWithIvAndSalt, password)));

    }
}
