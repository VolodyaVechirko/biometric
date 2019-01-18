package com.biometric.sample.enc;

import android.content.Context;
import android.os.Build;

import java.security.KeyPair;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public class EncryptionServices {

    private static final String MASTER_KEY = "MASTER_KEY";
    public static final String ALGORITHM_AES = "AES";
    public static final String ALGORITHM_RSA = "RSA";

    public static boolean hasApi23() {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.M;
    }

    public static boolean hasApi18() {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR2;
    }

    private Storage storage;
    private KeyStoreWrapper keyStoreWrapper;

    public EncryptionServices(Context context) throws Throwable {
        storage = new Storage(context);
        keyStoreWrapper = new KeyStoreWrapper(context);
    }

    /*
     * Encryption Stage
     */

    public void createMasterKey() throws Throwable {
        if (hasApi23()) createAndroidSymmetricKey();
        else if (hasApi18()) createDefaultSymmetricKey();
        else { /* Not supported */ }
    }

    public boolean hasEncryptionKey() throws Throwable {
        if (hasApi23()) return keyStoreWrapper.hasEncryptionKey(MASTER_KEY);
        else if (hasApi18()) return storage.hasEncryptionKey();
        else return false; // Not supported
    }

    public void removeMasterKey() throws Throwable {
        keyStoreWrapper.removeAndroidKeyStoreKey(MASTER_KEY);
    }

    public String encrypt(String data) throws Throwable {
        createMasterKey();

        if (hasApi23()) return encryptWithAndroidSymmetricKey(data);
        else if (hasApi18()) return encryptWithDefaultSymmetricKey(data);
        else return data; // Not supported
    }

    public String decrypt(String data) throws Throwable {
        if (hasApi23()) return decryptWithAndroidSymmetricKey(data);
        else if (hasApi18()) return decryptWithDefaultSymmetricKey(data);
        else return data; // Not supported
    }

    private void createAndroidSymmetricKey() throws Throwable {
        keyStoreWrapper.createAndroidKeyStoreSymmetricKey(MASTER_KEY);
    }

    private String encryptWithAndroidSymmetricKey(String data) throws Throwable {
        SecretKey masterKey = keyStoreWrapper.getAndroidKeyStoreSymmetricKey(MASTER_KEY);
        return new CipherWrapper(CipherWrapper.TRANSFORMATION_SYMMETRIC).encrypt(data, masterKey);
    }

    private String decryptWithAndroidSymmetricKey(String data) throws Throwable {
        SecretKey masterKey = keyStoreWrapper.getAndroidKeyStoreSymmetricKey(MASTER_KEY);
        return new CipherWrapper(CipherWrapper.TRANSFORMATION_SYMMETRIC).decrypt(data, masterKey);
    }

    private void createDefaultSymmetricKey() throws Throwable {
        SecretKey symmetricKey = keyStoreWrapper.generateDefaultSymmetricKey();
        KeyPair masterKey = keyStoreWrapper.createAndroidKeyStoreAsymmetricKey(MASTER_KEY);
        String encryptedSymmetricKey = new CipherWrapper(CipherWrapper.TRANSFORMATION_ASYMMETRIC)
                .wrapKey(symmetricKey, masterKey.getPublic());
        storage.saveEncryptionKey(encryptedSymmetricKey);
    }

    private SecretKey getDefaultSymmetricKey() throws Throwable {
        KeyPair masterKey = keyStoreWrapper.getAndroidKeyStoreAsymmetricKeyPair(MASTER_KEY);
        String encryptionKey = storage.getEncryptionKey();
        return (SecretKey) new CipherWrapper(CipherWrapper.TRANSFORMATION_ASYMMETRIC)
                .unWrapKey(encryptionKey, ALGORITHM_AES, Cipher.SECRET_KEY, masterKey.getPrivate());
    }

    private String encryptWithDefaultSymmetricKey(String data) throws Throwable {
        SecretKey symmetricKey = getDefaultSymmetricKey();
        return new CipherWrapper(CipherWrapper.TRANSFORMATION_SYMMETRIC).encrypt(data, symmetricKey);
    }

    private String decryptWithDefaultSymmetricKey(String data) throws Throwable {
        SecretKey symmetricKey = getDefaultSymmetricKey();
        return new CipherWrapper(CipherWrapper.TRANSFORMATION_SYMMETRIC).decrypt(data, symmetricKey);
    }
}