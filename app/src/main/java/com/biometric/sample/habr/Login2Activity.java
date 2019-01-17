package com.biometric.sample.habr;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.view.View;
import android.widget.EditText;
import android.widget.Toast;

import com.biometric.sample.R;
import com.biometric.sample.MainActivity;

import javax.crypto.Cipher;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.hardware.fingerprint.FingerprintManagerCompat;
import androidx.core.os.CancellationSignal;

public class Login2Activity extends AppCompatActivity {

    private static final String PIN = "pin";
    private EditText mEditText;
    private SharedPreferences mPreferences;
    private FingerprintHelper mFingerprintHelper;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_login_ololo);

        mPreferences = PreferenceManager.getDefaultSharedPreferences(this);
        mEditText = (EditText) findViewById(R.id.editText);

        findViewById(R.id.button).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                prepareLogin();
            }
        });

    }

    @Override
    protected void onResume() {
        super.onResume();
        if (mPreferences.contains(PIN)) {
            prepareSensor();
        }
    }

    @Override
    protected void onStop() {
        super.onStop();
        if (mFingerprintHelper != null) {
            mFingerprintHelper.cancel();
        }
    }

    private void prepareLogin() {

        final String pin = mEditText.getText().toString();
        if (pin.length() > 0) {
            savePin(pin);
            startActivity(new Intent(this, MainActivity.class));
        } else {
            Toast.makeText(this, "pin is empty", Toast.LENGTH_SHORT).show();
        }
    }

    private void savePin(String pin) {
        if (FingerprintUtils.isSensorStateAt(FingerprintUtils.SensorState.READY, this)) {
            String encoded = CryptoUtils.encode(pin);
            mPreferences.edit().putString(PIN, encoded).apply();
        }
    }

    private void prepareSensor() {
        if (FingerprintUtils.isSensorStateAt(FingerprintUtils.SensorState.READY, this)) {
            FingerprintManagerCompat.CryptoObject cryptoObject = CryptoUtils.getCryptoObject();
            if (cryptoObject != null) {
                Toast.makeText(this, "use fingerprint to login", Toast.LENGTH_LONG).show();
                mFingerprintHelper = new FingerprintHelper(this);
                mFingerprintHelper.startAuth(cryptoObject);
            } else {
                mPreferences.edit().remove(PIN).apply();
                Toast.makeText(this, "new fingerprint enrolled. enter pin again", Toast.LENGTH_SHORT).show();
            }

        }
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
        }

        @Override
        public void onAuthenticationHelp(int helpMsgId, CharSequence helpString) {
            Toast.makeText(mContext, helpString, Toast.LENGTH_SHORT).show();
        }

        @Override
        public void onAuthenticationSucceeded(FingerprintManagerCompat.AuthenticationResult result) {
            Cipher cipher = result.getCryptoObject().getCipher();
            String encoded = mPreferences.getString(PIN, null);
            String decoded = CryptoUtils.decode(encoded, cipher);
            mEditText.setText(decoded);
            Toast.makeText(mContext, "success", Toast.LENGTH_SHORT).show();
        }

        @Override
        public void onAuthenticationFailed() {
            Toast.makeText(mContext, "try again", Toast.LENGTH_SHORT).show();
        }

    }
}
