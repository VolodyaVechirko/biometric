package com.biometric.sample.enc;

import android.content.SharedPreferences;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import com.biometric.sample.R;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;

public class EncryptActivity extends AppCompatActivity {

    private EditText editText;
    private Button encrypt;
    private TextView textView;
    private Button decrypt;
    private TextView status;

    private EncryptionServices encryptionServices;
    private SharedPreferences prefs;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_encryption);

        prefs = getSharedPreferences("Test", MODE_PRIVATE);

        editText = findViewById(R.id.editText);
        encrypt = findViewById(R.id.encrypt);
        textView = findViewById(R.id.textView);
        decrypt = findViewById(R.id.decrypt);
        status = findViewById(R.id.status);

        try {
            encryptionServices = new EncryptionServices(this);
        } catch (Throwable e) {
            e.printStackTrace();
            status.setText("Error \n" + e.getMessage());
        }

        encrypt.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                try {
                    String data = editText.getText().toString();
                    String encrypted = encryptionServices.encrypt(data);

                    prefs.edit().putString("pass", encrypted).apply();
                    status.setText("Encrypted \n" + encrypted);
                } catch (Throwable e) {
                    e.printStackTrace();
                    status.setText("Error \n" + e.getMessage());
                }
            }
        });

        decrypt.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                try {
                    String encrypted = prefs.getString("pass", null);
                    String data = encryptionServices.decrypt(encrypted);

                    textView.setText(data);
                    status.setText("Decryptes \n" + data);
                } catch (Throwable e) {
                    e.printStackTrace();
                    status.setText("Error \n" + e.getMessage());
                }
            }
        });
    }
}
