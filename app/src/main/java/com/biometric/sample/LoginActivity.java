package com.biometric.sample;

import android.annotation.TargetApi;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import com.biometric.sample.R;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.hardware.fingerprint.FingerprintManagerCompat;
import androidx.core.os.CancellationSignal;

public class LoginActivity extends AppCompatActivity {

    private EditText loginEt;
    private EditText passwordEt;
    private Button loginBtn;

    private boolean isAuthenticationRequired = true;
    private static final String keystoreAlias = "MyKeyAlias";
    private static final String provider = "AndroidKeyStore";

    private KeyStore keyStore;
    private Cipher cipher;

    private SharedPreferences prefs;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_login);

        loginEt = findViewById(R.id.loginEt);
        passwordEt = findViewById(R.id.passwordEt);
        loginBtn = findViewById(R.id.loginBtn);

        prefs = getSharedPreferences("MyPrefs", MODE_PRIVATE);
        initKeyStore();

        loginBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (prefs.contains("login")) {
                    login2();
                } else {
                    login1();
                }
            }
        });
    }

    private void login1() {
        String login = loginEt.getText().toString();
        String pass = passwordEt.getText().toString();

        String encoded = encrypt(pass);
        prefs.edit()
                .putString("login", login)
                .putString("pass", encoded)
                .apply();

        showToast("Password encrypted login " + login + " pass " + pass);

        startListening();
    }

    private void login2() {
        String login = prefs.getString("login", null);
        String encodedPass = prefs.getString("pass", null);

        String pass = decrypt(encodedPass);

        showToast("Password decrypted login " + login + " pass " + pass);
    }

    @TargetApi(Build.VERSION_CODES.JELLY_BEAN)
    public void startListening() {
        FingerprintManagerCompat manager = FingerprintManagerCompat.from(this);

//        if (!isFingerprintAuthAvailable()) {
//            return;
//        }

        FingerprintManagerCompat.CryptoObject cryptoObject = new FingerprintManagerCompat.CryptoObject(cipher);
        FingerprintManagerCompat.AuthenticationCallback authenticationCallback = new FingerprintManagerCompat.AuthenticationCallback() {
            @Override
            public void onAuthenticationError(int errMsgId, CharSequence errString) {
                showToast("onAuthenticationError " + errString);
            }

            @Override
            public void onAuthenticationFailed() {
                showToast("onAuthenticationFailed");
            }

            @Override
            public void onAuthenticationHelp(int helpMsgId, CharSequence helpString) {
                showToast("onAuthenticationHelp " + helpString);
            }

            @Override
            public void onAuthenticationSucceeded(FingerprintManagerCompat.AuthenticationResult result) {
                showToast("onAuthenticationSucceeded");

                login2();
            }
        };

        CancellationSignal cancellationSignal = new CancellationSignal();
        manager.authenticate(cryptoObject, 0, cancellationSignal, authenticationCallback, null);
    }

    @TargetApi(Build.VERSION_CODES.M)
    private void initKeyStore() {
        try {
            keyStore = KeyStore.getInstance(provider);
            keyStore.load(null);

            KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_RSA, provider);

            keyGenerator.initialize(new KeyGenParameterSpec.Builder(keystoreAlias,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                    .setUserAuthenticationRequired(isAuthenticationRequired)
                    .build()
            );
            keyGenerator.generateKeyPair();

            cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        } catch (GeneralSecurityException | IOException e) {
            e.printStackTrace();
        }
    }

    @TargetApi(Build.VERSION_CODES.M)
    private String encrypt(String input) {
        try {
            PublicKey key = keyStore.getCertificate(keystoreAlias).getPublicKey();
            PublicKey unrestrictedPublicKey = KeyFactory.getInstance(key.getAlgorithm())
                    .generatePublic(new X509EncodedKeySpec(key.getEncoded()));
            OAEPParameterSpec spec = new OAEPParameterSpec("SHA-256", "MGF1",
                    MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT);

            cipher.init(Cipher.ENCRYPT_MODE, unrestrictedPublicKey, spec);

            byte[] bytes = cipher.doFinal(input.getBytes());
            String encoded = Base64.encodeToString(bytes, Base64.NO_WRAP);
            return encoded;
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
            return null;
        }
    }

    @TargetApi(Build.VERSION_CODES.M)
    private String decrypt(String encoded) {
        try {
            PrivateKey key = (PrivateKey) keyStore.getKey(keystoreAlias, null);
            cipher.init(Cipher.DECRYPT_MODE, key);

            byte[] bytes = Base64.decode(encoded, Base64.NO_WRAP);
            String decoded = new String(cipher.doFinal(bytes));
            return decoded;
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
            return null;
        }
    }

    private void showToast(String s) {
        Toast.makeText(this, s, Toast.LENGTH_LONG).show();
    }
}
