package com.biometric.sample.auth;

import android.Manifest;
import android.annotation.TargetApi;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.os.CancellationSignal;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import com.biometric.sample.aes.FingerPrintAuthHelper;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;
import androidx.core.app.ActivityCompat;

import static android.content.Context.FINGERPRINT_SERVICE;
import static android.content.Context.KEYGUARD_SERVICE;
import static android.content.Context.MODE_PRIVATE;

public class FingerprintHelper {

    private static final String FINGER_PRINT_HELPER = "FingerPrintAuthHelper";
    private static final String ENCRYPTED_PASS_SHARED_PREF_KEY = "ENCRYPTED_PASS_SHARED_PREF_KEY";
    private static final String LAST_USED_IV_SHARED_PREF_KEY = "LAST_USED_IV_SHARED_PREF_KEY";
    private static final String KEY_ALIAS = "KEY_ALIAS";

    private KeyguardManager keyguardManager;
    private FingerprintManager fingerprintManager;

    private final Context context;
    private KeyStore keyStore;
    private KeyPairGenerator keyGenerator;

    private SharedPreferences prefs;
    private String lastError;

    public interface Callback {
        void onSuccess(String savedPass);

        void onFailure(String message);

        void onHelp(int helpCode, String helpString);
    }

    public FingerprintHelper(Context context) {
        this.context = context;
        prefs = context.getSharedPreferences("MyPrefs", MODE_PRIVATE);
    }

    public String getLastError() {
        return lastError;
    }


    @TargetApi(Build.VERSION_CODES.M)
    public boolean init() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            setError("This Android version does not support fingerprint authentication");
            return false;
        }

        keyguardManager = (KeyguardManager) context.getSystemService(KEYGUARD_SERVICE);
        fingerprintManager = (FingerprintManager) context.getSystemService(FINGERPRINT_SERVICE);

        if (!keyguardManager.isKeyguardSecure()) {
            setError("User hasn't enabled Lock Screen");
            return false;
        }

        if (!hasPermission()) {
            setError("User hasn't granted permission to use Fingerprint");
            return false;
        }

        if (!fingerprintManager.hasEnrolledFingerprints()) {
            setError("User hasn't registered any fingerprints");
            return false;
        }

        if (!initKeyStore()) {
            return false;
        }
        return false;
    }

    @Nullable
    @RequiresApi(api = Build.VERSION_CODES.M)
    private Cipher createCipher(int mode) {
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");

            if (mode == Cipher.ENCRYPT_MODE) {
                PublicKey key = keyStore.getCertificate(KEY_ALIAS).getPublicKey();

                // workaround for using public key
                PublicKey unrestricted = KeyFactory.getInstance(key.getAlgorithm()).generatePublic(new X509EncodedKeySpec(key.getEncoded()));
                OAEPParameterSpec spec = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT);

                cipher.init(mode, unrestricted, spec);
            } else {
                PrivateKey key = (PrivateKey) keyStore.getKey(KEY_ALIAS, null);
                cipher.init(mode, key);
            }

            return cipher;
        } catch (KeyPermanentlyInvalidatedException exception) {
            deleteInvalidKey();
        } catch (Throwable t) {
            setError("Failed init of cipher: " + t.getMessage());
        }

        return null;
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private boolean initKeyStore() {
        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyGenerator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
            keyStore.load(null);

            keyGenerator.initialize(new KeyGenParameterSpec.Builder(KEY_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                    .setUserAuthenticationRequired(true)
                    .build()
            );
            keyGenerator.generateKeyPair();
        } catch (Throwable t) {
            setError("Failed init of keyStore & keyGenerator: " + t.getMessage());
            return false;
        }
        return true;
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private void authenticate(CancellationSignal cancellationSignal, AuthenticationListener authListener, int mode) {
        try {
            if (hasPermission()) {
                Cipher cipher = createCipher(mode);
                FingerprintManager.CryptoObject crypto = new FingerprintManager.CryptoObject(cipher);
                fingerprintManager.authenticate(crypto, cancellationSignal, 0, authListener, null);
            } else {
                authListener.getCallback().onFailure("User hasn't granted permission to use Fingerprint");
            }
        } catch (Throwable t) {
            authListener.getCallback().onFailure("An error occurred: " + t.getMessage());
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private boolean hasPermission() {
        return ActivityCompat.checkSelfPermission(context, Manifest.permission.USE_FINGERPRINT) == PackageManager.PERMISSION_GRANTED;
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public void savePassword(@NonNull String password, CancellationSignal cancellationSignal, FingerPrintAuthHelper.Callback callback) {
        authenticate(cancellationSignal, new FingerPrintEncryptPasswordListener(callback, password), Cipher.ENCRYPT_MODE);
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public void getPassword(CancellationSignal cancellationSignal, FingerPrintAuthHelper.Callback callback) {
        authenticate(cancellationSignal, new FingerPrintDecryptPasswordListener(callback), Cipher.DECRYPT_MODE);
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public boolean encrypt(Cipher cipher, String password) {
        try {
            if (password.isEmpty()) {
                setError("Password is empty");
                return false;
            }

//            if (cipher == null) {
//                setError("Could not create cipher");
//                return false;
//            }

            byte[] bytes = cipher.doFinal(password.getBytes());
            String encoded = Base64.encodeToString(bytes, Base64.NO_WRAP);

            prefs.edit().putString(ENCRYPTED_PASS_SHARED_PREF_KEY, encoded).apply();
        } catch (Throwable t) {
            setError("Encryption failed " + t.getMessage());
            return false;
        }

        return true;
    }

    @Nullable
    public String decrypt(Cipher cipher) {
        String password = null;
        try {
            String encoded = prefs.getString(ENCRYPTED_PASS_SHARED_PREF_KEY, null);

            byte[] bytes = Base64.decode(encoded, Base64.NO_WRAP);
            password = new String(cipher.doFinal(bytes));
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
            return null;
        }

        return password;
    }

    public void deleteInvalidKey() {
        if (keyStore != null) {
            try {
                keyStore.deleteEntry(KEY_ALIAS);
            } catch (KeyStoreException e) {
                e.printStackTrace();
            }
        }
    }

    @RequiresApi(Build.VERSION_CODES.M)
    protected class AuthenticationListener extends FingerprintManager.AuthenticationCallback {

        protected final FingerPrintAuthHelper.Callback callback;

        public AuthenticationListener(@NonNull FingerPrintAuthHelper.Callback callback) {
            this.callback = callback;
        }

        public void onAuthenticationError(int errorCode, CharSequence errString) {
            callback.onFailure("Authentication error [" + errorCode + "] " + errString);
        }

        /**
         * Called when a recoverable error has been encountered during authentication. The help
         * string is provided to give the user guidance for what went wrong, such as
         * "Sensor dirty, please clean it."
         *
         * @param helpCode   An integer identifying the error message
         * @param helpString A human-readable string that can be shown in UI
         */
        public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
            callback.onHelp(helpCode, helpString.toString());
        }

        /**
         * Called when a fingerprint is recognized.
         *
         * @param result An object containing authentication-related data
         */
        public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
        }

        /**
         * Called when a fingerprint is valid but not recognized.
         */
        public void onAuthenticationFailed() {
            callback.onFailure("Authentication failed");
        }

        public @NonNull
        FingerPrintAuthHelper.Callback getCallback() {
            return callback;
        }

    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private class FingerPrintEncryptPasswordListener extends AuthenticationListener {

        private final String password;

        public FingerPrintEncryptPasswordListener(FingerPrintAuthHelper.Callback callback, String password) {
            super(callback);
            this.password = password;
        }

        public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
            Cipher cipher = result.getCryptoObject().getCipher();
            try {
                if (encrypt(cipher, password)) {
                    callback.onSuccess("Encrypted");
                } else {
                    callback.onFailure("Encryption failed");
                }

            } catch (Exception e) {
                callback.onFailure("Encryption failed " + e.getMessage());
            }
        }
    }

    @RequiresApi(Build.VERSION_CODES.M)
    protected class FingerPrintDecryptPasswordListener extends AuthenticationListener {

        public FingerPrintDecryptPasswordListener(@NonNull FingerPrintAuthHelper.Callback callback) {
            super(callback);
        }

        public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
            Cipher cipher = result.getCryptoObject().getCipher();
            try {
                String savedPass = decrypt(cipher);
                if (savedPass != null) {
                    callback.onSuccess(savedPass);
                } else {
                    callback.onFailure("Failed deciphering");
                }

            } catch (Exception e) {
                callback.onFailure("Deciphering failed " + e.getMessage());
            }
        }
    }

    private void setError(String error) {
        lastError = error;
        Log.w(FINGER_PRINT_HELPER, lastError);
    }
}
