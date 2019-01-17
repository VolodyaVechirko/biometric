package com.biometric.sample.enc;

import android.annotation.TargetApi;
import android.content.Context;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Calendar;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.security.auth.x500.X500Principal;

import androidx.annotation.Nullable;

public class KeyStoreWrapper {

    private static final String KEYSTORE_PROVIDER = "AndroidKeyStore";

    private KeyStore keyStore;
    private Context context;

    public KeyStoreWrapper(Context context) throws Throwable {
        this.context = context;
        keyStore = createAndroidKeyStore();
    }

    /**
     * @return symmetric key from Android Key Store or null if any key with given alias exists
     */
    @Nullable
    public SecretKey getAndroidKeyStoreSymmetricKey(String alias) throws Throwable {
        return (SecretKey) keyStore.getKey(alias, null);
    }

    /**
     * @return asymmetric keypair from Android Key Store or null if any key with given alias exists
     */
    @Nullable
    public KeyPair getAndroidKeyStoreAsymmetricKeyPair(String alias) throws Throwable {
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, null);
        PublicKey publicKey = keyStore.getCertificate(alias).getPublicKey();

        if (privateKey != null && publicKey != null) {
            return new KeyPair(publicKey, privateKey);
        } else {
            return null;
        }
    }

    @TargetApi(Build.VERSION_CODES.M)
    public SecretKey createAndroidKeyStoreSymmetricKey(String alias) throws Throwable {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER);
        keyGenerator.init(new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                .build()
        );
        return keyGenerator.generateKey();
    }

    public void removeAndroidKeyStoreKey(String alias) throws Throwable {
        keyStore.deleteEntry(alias);
    }

    public KeyPair createAndroidKeyStoreAsymmetricKey(String alias) throws Throwable {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(EncryptionServices.ALGORITHM_RSA, KEYSTORE_PROVIDER);

        if (EncryptionServices.hasApi23()) {
            initGeneratorWithKeyGenParameterSpec(generator, alias);
        } else {
            initGeneratorWithKeyPairGeneratorSpec(generator, alias);
        }

        return generator.generateKeyPair();
    }

    public SecretKey generateDefaultSymmetricKey() throws Throwable {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(EncryptionServices.ALGORITHM_AES);
        return keyGenerator.generateKey();
    }

    @TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR2)
    private void initGeneratorWithKeyPairGeneratorSpec(KeyPairGenerator generator, String alias) throws InvalidAlgorithmParameterException {
        Calendar startDate = Calendar.getInstance();
        Calendar endDate = Calendar.getInstance();
        endDate.add(Calendar.YEAR, 20);

        generator.initialize(new KeyPairGeneratorSpec.Builder(context)
                .setAlias(alias)
                .setSerialNumber(BigInteger.ONE)
                .setSubject(new X500Principal("CN=${alias} CA Certificate"))
                .setStartDate(startDate.getTime())
                .setEndDate(endDate.getTime()).build()
        );
    }

    @TargetApi(Build.VERSION_CODES.M)
    private void initGeneratorWithKeyGenParameterSpec(KeyPairGenerator generator, String alias) throws InvalidAlgorithmParameterException {
        generator.initialize(new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                .build()
        );
    }

    private KeyStore createAndroidKeyStore() throws Throwable {
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
        keyStore.load(null);
        return keyStore;
    }
}