package com.biometric.sample.enc;

import android.annotation.TargetApi;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class AesEncryption {

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private static final String AES_KEY_ALIAS = "MyAESSecretKey123";

    private static final String PREFS_NAME = "MyTestPrefs";
    private static final String SECRET = "secret";
    private static final String IV = "iv";

    private KeyStore keyStore;
    private SharedPreferences prefs;

    public AesEncryption(Context context) throws Throwable {
        prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
        keyStore.load(null);
    }

    @TargetApi(Build.VERSION_CODES.KITKAT)
    public String encrypt(final String input) throws Throwable {
        if (!keyStore.containsAlias(AES_KEY_ALIAS)) {
            generateSecretKey(AES_KEY_ALIAS);
        }

        final Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, getSecretKey(AES_KEY_ALIAS));

        byte[] encryption = cipher.doFinal(input.getBytes(StandardCharsets.UTF_8));
        String encrypted = Base64.encodeToString(encryption, Base64.NO_PADDING);
        String iv = Base64.encodeToString(cipher.getIV(), Base64.NO_PADDING);

        prefs.edit()
                .putString(SECRET, encrypted)
                .putString(IV, iv)
                .apply();

        return encrypted;
    }

    @TargetApi(Build.VERSION_CODES.KITKAT)
    public String decrypt() throws Throwable {
        byte[] encrypted = Base64.decode(prefs.getString(SECRET, null), Base64.NO_PADDING);
        byte[] iv = Base64.decode(prefs.getString(IV, null), Base64.NO_PADDING);

        final Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        final GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, getSecretKey(AES_KEY_ALIAS), spec);

        return new String(cipher.doFinal(encrypted), StandardCharsets.UTF_8);
    }

    private SecretKey getSecretKey(final String alias) throws Throwable {
        return ((KeyStore.SecretKeyEntry) keyStore.getEntry(alias, null)).getSecretKey();
    }

    @TargetApi(Build.VERSION_CODES.M)
    private SecretKey generateSecretKey(final String alias) throws Throwable {
        final KeyGenerator keyGenerator = KeyGenerator
                .getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE);

        keyGenerator.init(new KeyGenParameterSpec.Builder(alias,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .build()
        );

        return keyGenerator.generateKey();
    }
}
