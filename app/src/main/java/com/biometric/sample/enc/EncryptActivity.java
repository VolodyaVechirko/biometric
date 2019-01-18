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

//    private EncryptionServices encryptionServices;
    private SharedPreferences prefs;

    private RsaSignature rsaSignature;
    private RsaEncryption rsaEncryption;
//    private AesEncryption aesEncryption;

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
//            encryptionServices = new EncryptionServices(this);
            rsaSignature = new RsaSignature(this);
            rsaEncryption = new RsaEncryption(this);
//            aesEncryption = new AesEncryption(this);
            rsaSignature.printPublicKey();
        } catch (Throwable e) {
            e.printStackTrace();
            status.setText("Error \n" + e.getMessage());
        }

        encrypt.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                try {
                    String data = editText.getText().toString();
                    String encrypted = rsaEncryption.encrypt(data);
//                    String encrypted = encryptionServices.encrypt(data);
//                    String encrypted = aesEncryption.encrypt(data);

                    String sign = rsaSignature.sign(encrypted);
                    prefs.edit().putString("pass", encrypted).apply();
                    prefs.edit().putString("sign", sign).apply();

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
                    String data = rsaEncryption.decrypt(encrypted);
//                    String data = encryptionServices.decrypt(encrypted);
//                    String data = aesEncryption.decrypt();

                    String signature = prefs.getString("sign", null);
                    boolean verify = rsaSignature.verify(encrypted, signature);

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
