package com.biometric.sample.aes;

import android.os.Build;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;

import com.biometric.sample.R;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;

public class AesTestActivity extends AppCompatActivity {

    private EditText passwordTextView;
    private TextView errorTextView;
    private FingerPrintAuthHelper fingerPrintAuthHelper;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_aes_test);
        passwordTextView = findViewById(R.id.passwordEt);
        errorTextView = findViewById(R.id.errorTv);

        findViewById(R.id.setPass).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    fingerPrintAuthHelper.savePassword(passwordTextView.getText().toString(), new CancellationSignal(), getAuthListener(false));
                }
            }
        });

        findViewById(R.id.getPass).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    fingerPrintAuthHelper.getPassword(new CancellationSignal(), getAuthListener(true));
                }
            }
        });

        findViewById(R.id.lock).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                    startActivityForResult(fingerPrintAuthHelper.confirmCredential(), 0);
                }
            }
        });

        startFingerPrintAuthHelper();
    }

    // Start the finger print helper. In case this fails show error to user
    private void startFingerPrintAuthHelper() {
        fingerPrintAuthHelper = new FingerPrintAuthHelper(this);
        if (!fingerPrintAuthHelper.init()) {
            errorTextView.setText(fingerPrintAuthHelper.getLastError());
        }
    }

    @NonNull
    private FingerPrintAuthHelper.Callback getAuthListener(final boolean isGetPass) {
        return new FingerPrintAuthHelper.Callback() {
            @Override
            public void onSuccess(String result) {
                if (isGetPass) {
                    errorTextView.setText("Success!!! Pass = " + result);
                } else {
                    errorTextView.setText("Encrypted pass = " + result);
                }
            }

            @Override
            public void onFailure(String message) {
                errorTextView.setText("Failed - " + message);
            }

            @Override
            public void onHelp(int helpCode, String helpString) {
                errorTextView.setText("Help needed - " + helpString);
            }
        };
    }
}
