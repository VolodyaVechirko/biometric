package com.biometric.sample.auth;

import android.app.Fragment;
import android.content.Context;
import android.content.DialogInterface;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.preference.CheckBoxPreference;
import android.preference.PreferenceFragment;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.Toast;

import com.biometric.sample.R;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;

public class AppActivity extends AppCompatActivity {

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Display the fragment as the main content.
        getFragmentManager().beginTransaction().replace(android.R.id.content,
                new MainFragment()).commit();
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        int id = item.getItemId();

        if (id == R.id.action_settings) {
            getFragmentManager().beginTransaction().replace(android.R.id.content,
                    new SettingsFragment()).commit();
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    /**
     * Fragment for settings.
     */
    public static class SettingsFragment extends PreferenceFragment
            implements SharedPreferences.OnSharedPreferenceChangeListener {

        @Override
        public void onCreate(Bundle savedInstanceState) {
            super.onCreate(savedInstanceState);
            addPreferencesFromResource(R.xml.preferences);
        }

        @Override
        public void onStart() {
            super.onStart();
            getPreferenceScreen().getSharedPreferences().registerOnSharedPreferenceChangeListener(this);
        }

        @Override
        public void onStop() {
            super.onStop();
            getPreferenceScreen().getSharedPreferences().unregisterOnSharedPreferenceChangeListener(this);
        }

        @Override
        public void onSharedPreferenceChanged(SharedPreferences sharedPreferences, String key) {
            CheckBoxPreference pref = (CheckBoxPreference)
                    findPreference(getString(R.string.use_fingerprint_to_authenticate_key));

            if (pref.isChecked()) {
                showDialog(getActivity());
            }
        }

        void onPassEntered(String pass) {
            Toast.makeText(getActivity(), pass, Toast.LENGTH_SHORT).show();
            if (FingerprintUtils.isSensorStateAt(FingerprintUtils.SensorState.READY, getActivity())) {
                String encoded = FingerprintUtils.encode(pass);
                getActivity().getSharedPreferences(AuthActivity.PREFS, MODE_PRIVATE)
                        .edit().putString(AuthActivity.PASSWORD, encoded).apply();
            }
        }

        private void showDialog(Context context) {
            final EditText edittext = new EditText(context);
            new AlertDialog.Builder(context)
                    .setTitle("Password")
                    .setView(edittext)
                    .setPositiveButton("Ok", new DialogInterface.OnClickListener() {
                        @Override
                        public void onClick(DialogInterface dialog, int which) {
                            String pass = edittext.getText().toString();
                            onPassEntered(pass);
                        }
                    })
                    .setNegativeButton("Cancel", null)
                    .show();
        }
    }

    public static class MainFragment extends Fragment {

        @Nullable
        @Override
        public View onCreateView(LayoutInflater inflater, @Nullable ViewGroup container, Bundle savedInstanceState) {
            return inflater.inflate(R.layout.fragment_main, container, false);
        }
    }
}
