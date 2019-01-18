package com.biometric.sample.enc;

import android.content.Context;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Calendar;

import javax.crypto.Cipher;
import javax.security.auth.x500.X500Principal;

public class RsaEncryption {

    private static final String TRANSFORMATION = "RSA/ECB/PKCS1Padding";
    private static final String TRANSFORMATION_2 = "RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING";
    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private static final String RSA_KEY_ALIAS = "MyRSAKeyPair123";

    private static final String TAG = "RsaEncryption";
    private static final String UTF_8 = "UTF-8";

    private KeyStore keyStore;

    public RsaEncryption(Context context) throws Throwable {
        keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
        keyStore.load(null);

//        if (!keyStore.containsAlias(RSA_KEY_ALIAS)) {
        generateKeyPair(context, RSA_KEY_ALIAS);
//        }
    }

//    public void testEncryptData(String dataToEncrypt) throws Throwable {
//        // generate a new public/private key pair to test with (note. you should only do this once and keep them!)
//        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
//        kpg.initialize(2048);
//        KeyPair kp = kpg.generateKeyPair();
//
//        PublicKey publicKey = kp.getPublic();
//        byte[] publicKeyBytes = publicKey.getEncoded();
//        String publicKeyBytesBase64 = Base64.encodeToString(publicKeyBytes, Base64.DEFAULT);
//
//        PrivateKey privateKey = kp.getPrivate();
//        byte[] privateKeyBytes = privateKey.getEncoded();
//        String privateKeyBytesBase64 = Base64.encodeToString(privateKeyBytes, Base64.DEFAULT);
//
//        // test encryption
//        String encrypted = encryptRSA(dataToEncrypt, publicKeyBytesBase64, true);
//
//        // test decryption
//        String decrypted = decryptRSA(encrypted, privateKeyBytesBase64, false);
//    }

    public PrivateKey generatePrivate(String privateKey) throws Throwable {
        KeyFactory keyFac = KeyFactory.getInstance("RSA");
        KeySpec keySpec = new PKCS8EncodedKeySpec(Base64.decode(privateKey, Base64.DEFAULT));
        return keyFac.generatePrivate(keySpec);
    }

    public PublicKey generatePublic(String publicKey) throws Throwable {
        KeyFactory keyFac = KeyFactory.getInstance("RSA");
        KeySpec keySpec = new X509EncodedKeySpec(Base64.decode(publicKey, Base64.DEFAULT));
        return keyFac.generatePublic(keySpec);
    }

    public String encryptRSA(String plainText, String rsaKey, boolean isPublic) throws Throwable {
        Key key = isPublic ? generatePublic(rsaKey) : generatePrivate(rsaKey);

        final Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes("UTF-8"));

        String str = Base64.encodeToString(encryptedBytes, Base64.DEFAULT);
        Log.d(TAG, "Encrypted " + str);
        return str;
    }

    public String decryptRSA(String encryptedBase64, String rsaKey, boolean isPublic) throws Throwable {
        Key key = isPublic ? generatePublic(rsaKey) : generatePrivate(rsaKey);

        final Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] encryptedBytes = Base64.decode(encryptedBase64, Base64.DEFAULT);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        String str = new String(decryptedBytes, UTF_8);
        Log.d(TAG, "Decrypted " + str);
        return str;
    }

    public String encrypt(final String input) throws Throwable {
        final Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, getKeyPair(RSA_KEY_ALIAS).getPublic());

        byte[] encrypted = cipher.doFinal(input.getBytes(UTF_8));

        String str = Base64.encodeToString(encrypted, Base64.DEFAULT);
        Log.d(TAG, "Encrypted " + str);
        return str;
    }

    public String decrypt(final String input) throws Throwable {
        byte[] encrypted = Base64.decode(input, Base64.DEFAULT);
        final Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, getKeyPair(RSA_KEY_ALIAS).getPrivate());
        byte[] decrypted = cipher.doFinal(encrypted);

        String str = new String(decrypted, UTF_8);
        Log.d(TAG, "Decrypted " + str);
        return str;
    }

    private KeyPair getKeyPair(final String alias) throws Throwable {
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, null);
        PublicKey publicKey = keyStore.getCertificate(alias).getPublicKey();

        if (privateKey != null && publicKey != null) {
            return new KeyPair(publicKey, privateKey);
        } else {
            throw new GeneralSecurityException("Private or PublicKey is null");
        }
    }

    private KeyPair generateKeyPair(Context context, final String alias) throws Throwable {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(EncryptionServices.ALGORITHM_RSA, ANDROID_KEY_STORE);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            generator.initialize(new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                    .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                    .build()
            );
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
            Calendar startDate = Calendar.getInstance();
            Calendar endDate = Calendar.getInstance();
            endDate.add(Calendar.YEAR, 20);

            generator.initialize(new KeyPairGeneratorSpec.Builder(context)
                    .setAlias(alias)
                    .setSerialNumber(BigInteger.ONE)
                    .setSubject(new X500Principal("CN=" + alias + " CA Certificate"))
                    .setStartDate(startDate.getTime())
                    .setEndDate(endDate.getTime())
                    .build()
            );
        }

        KeyPair keyPair = generator.generateKeyPair();

        Log.d(TAG, "KeyPair generated" +
                "\nPublickey: " + Base64.encodeToString(keyPair.getPublic().getEncoded(), Base64.DEFAULT) +
                "\nsize: " + keyPair.getPublic().getEncoded().length
        );

        return keyPair;
    }
}