package com.biometric.sample;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;

import com.biometric.sample.R;
import com.biometric.sample.aes.AesTestActivity;
import com.biometric.sample.auth.AuthActivity;
import com.biometric.sample.enc.EncryptActivity;
import com.biometric.sample.habr.Login2Activity;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;

public class SplashActivity extends AppCompatActivity {

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_splash);

        findViewById(R.id.aes_fingerprint).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                startActivity(new Intent(SplashActivity.this, AesTestActivity.class));
            }
        });

        findViewById(R.id.rsa_fingerprint).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                startActivity(new Intent(SplashActivity.this, Login2Activity.class));
            }
        });

        findViewById(R.id.biometric_manager).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                startActivity(new Intent(SplashActivity.this, MainActivity.class));
            }
        });

        findViewById(R.id.btn_authenticate).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                startActivity(new Intent(SplashActivity.this, LoginActivity.class));
            }
        });

        findViewById(R.id.auth_test).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                startActivity(new Intent(SplashActivity.this, AuthActivity.class));
            }
        });

        findViewById(R.id.encryption).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                startActivity(new Intent(SplashActivity.this, EncryptActivity.class));
            }
        });
    }
}
