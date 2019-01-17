package com.biometric.sample.enc;

import android.util.Base64;

import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

/**
 * This class wraps [Cipher] class apis with some additional possibilities.
 */
public class CipherWrapper {

    public static final String TRANSFORMATION_ASYMMETRIC = "RSA/ECB/PKCS1Padding";
    public static final String TRANSFORMATION_SYMMETRIC = "AES/CBC/PKCS7Padding";
    private static final String IV_SEPARATOR = "]";

    private Cipher cipher;

    private boolean useIV = true;

    public CipherWrapper(String transformation) throws Throwable {
        cipher = Cipher.getInstance(transformation);
    }

    public String encrypt(String data, Key key) throws Throwable {
        cipher.init(Cipher.ENCRYPT_MODE, key);

        String result = "";
        if (useIV) {
            byte[] iv = cipher.getIV();
            String ivString = Base64.encodeToString(iv, Base64.DEFAULT);
            result = ivString + IV_SEPARATOR;
        }

        byte[] bytes = cipher.doFinal(data.getBytes());
        result += Base64.encodeToString(bytes, Base64.DEFAULT);

        return result;
    }

    public String decrypt(String data, Key key) throws Throwable {
        String encodedString;

        if (useIV) {
            String[] split = data.split(IV_SEPARATOR);
            if (split.length != 2) {
                throw new IllegalArgumentException("Passed data is incorrect. There was no IV specified with it.");
            }

            String ivString = split[0];
            encodedString = split[1];
            IvParameterSpec ivSpec = new IvParameterSpec(Base64.decode(ivString, Base64.DEFAULT));
            cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        } else {
            encodedString = data;
            cipher.init(Cipher.DECRYPT_MODE, key);
        }

        byte[] encryptedData = Base64.decode(encodedString, Base64.DEFAULT);
        byte[] decodedData = cipher.doFinal(encryptedData);
        return new String(decodedData);
    }

    public String wrapKey(Key keyToBeWrapped, Key keyToWrapWith) throws Throwable {
        cipher.init(Cipher.WRAP_MODE, keyToWrapWith);
        byte[] decodedData = cipher.wrap(keyToBeWrapped);
        return Base64.encodeToString(decodedData, Base64.DEFAULT);
    }

    public Key unWrapKey(String wrappedKeyData, String algorithm, int wrappedKeyType, Key keyToUnWrapWith) throws Throwable {
        byte[] encryptedKeyData = Base64.decode(wrappedKeyData, Base64.DEFAULT);
        cipher.init(Cipher.UNWRAP_MODE, keyToUnWrapWith);
        return cipher.unwrap(encryptedKeyData, algorithm, wrappedKeyType);
    }
}
