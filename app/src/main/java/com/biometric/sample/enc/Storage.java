package com.biometric.sample.enc;

import android.content.Context;
import android.content.SharedPreferences;

public class Storage {

    private static final String STORAGE_SECRETS = "secrets";
    private static final String ENCRYPTION_KEY = "encryption_key";

    private SharedPreferences secrets;

    public Storage(Context context) {
        secrets = context.getSharedPreferences(STORAGE_SECRETS, android.content.Context.MODE_PRIVATE);
    }

    public void saveEncryptionKey(String key) {
        secrets.edit().putString(ENCRYPTION_KEY, key).apply();
    }

    public String getEncryptionKey() {
        return secrets.getString(ENCRYPTION_KEY, "");
    }
}
