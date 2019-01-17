package com.biometric.sample.auth;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.os.Handler;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import com.biometric.sample.R;

import javax.crypto.Cipher;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.hardware.fingerprint.FingerprintManagerCompat;
import androidx.core.os.CancellationSignal;

public class AuthActivity extends AppCompatActivity {

    public static final String PREFS = "MyPrefs";
    public static final String LOGIN = "login";
    public static final String PASSWORD = "pass";

    private EditText loginEt;
    private EditText passwordEt;
    private Button loginBtn;
    private TextView errorTv;

    private SharedPreferences prefs;
    private FingerprintHelper fingerprintHelper;

    private Dialog dialog;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_login);

        loginEt = findViewById(R.id.loginEt);
        passwordEt = findViewById(R.id.passwordEt);
        loginBtn = findViewById(R.id.loginBtn);
        errorTv = findViewById(R.id.errorTv);

        loginBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                loginClick();
            }
        });

        prefs = getSharedPreferences(PREFS, MODE_PRIVATE);
    }

    @Override
    protected void onStart() {
        super.onStart();
        if (prefs.contains(LOGIN)) {
            String login = prefs.getString(LOGIN, null);
            loginEt.setText(login);
            loginEt.setSelection(loginEt.getText().length());
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (prefs.contains(PASSWORD)) {
            prepareSensor();

            dialog = new Dialog();
            dialog.show(getSupportFragmentManager(), null);
        }
    }

    @Override
    protected void onStop() {
        super.onStop();
        if (fingerprintHelper != null) {
            fingerprintHelper.cancel();

            if (dialog != null) {
                dialog.dismiss();
            }
        }
    }

    private void prepareSensor() {
        if (FingerprintUtils.isSensorStateAt(FingerprintUtils.SensorState.READY, this)) {
            FingerprintManagerCompat.CryptoObject cryptoObject = FingerprintUtils.getCryptoObject();
            if (cryptoObject != null) {
                Toast.makeText(this, "use fingerprint to login", Toast.LENGTH_LONG).show();
                fingerprintHelper = new FingerprintHelper(this);
                fingerprintHelper.startAuth(cryptoObject);
            } else {
                prefs.edit().remove(PASSWORD).apply();
                Toast.makeText(this, "new fingerprint enrolled. enter pin again", Toast.LENGTH_SHORT).show();
            }

        }
    }

    private void loginClick() {
        String login = loginEt.getText().toString();
        String pass = passwordEt.getText().toString();

        if (login.isEmpty() || pass.isEmpty()) {
            Toast.makeText(this, "login or pass is empty", Toast.LENGTH_SHORT).show();
            return;
        }

        prefs.edit().putString(LOGIN, login).apply();
        startActivity(new Intent(AuthActivity.this, AppActivity.class));
    }


    public class FingerprintHelper extends FingerprintManagerCompat.AuthenticationCallback {
        private Context mContext;
        private CancellationSignal mCancellationSignal;

        FingerprintHelper(Context context) {
            mContext = context;
        }

        void startAuth(FingerprintManagerCompat.CryptoObject cryptoObject) {
            mCancellationSignal = new CancellationSignal();
            FingerprintManagerCompat manager = FingerprintManagerCompat.from(mContext);
            manager.authenticate(cryptoObject, 0, mCancellationSignal, this, null);
        }

        void cancel() {
            if (mCancellationSignal != null) {
                mCancellationSignal.cancel();
            }
        }

        @Override
        public void onAuthenticationError(int errMsgId, CharSequence errString) {
            Toast.makeText(mContext, errString, Toast.LENGTH_SHORT).show();

            if (dialog != null) {
                dialog.onAuthenticationError(errString);
            }
        }

        @Override
        public void onAuthenticationHelp(int helpMsgId, CharSequence helpString) {
            Toast.makeText(mContext, helpString, Toast.LENGTH_SHORT).show();

            if (dialog != null) {
                dialog.onAuthenticationHelp(helpString);
            }
        }

        @Override
        public void onAuthenticationSucceeded(FingerprintManagerCompat.AuthenticationResult result) {
            Cipher cipher = result.getCryptoObject().getCipher();
            String encoded = prefs.getString(PASSWORD, null);
            String decoded = FingerprintUtils.decode(encoded, cipher);
            passwordEt.setText(decoded);
            passwordEt.setSelection(passwordEt.getText().length());

            Toast.makeText(mContext, "success", Toast.LENGTH_SHORT).show();

            if (dialog != null) {
                dialog.onAuthenticationSucceeded();
            }

            new Handler().postDelayed(new Runnable() {
                @Override
                public void run() {
                    loginClick();
                }
            }, 1500);
        }

        @Override
        public void onAuthenticationFailed() {
            Toast.makeText(mContext, "try again", Toast.LENGTH_SHORT).show();

            if (dialog != null) {
                dialog.onAuthenticationFailed();
            }
        }
    }
}
