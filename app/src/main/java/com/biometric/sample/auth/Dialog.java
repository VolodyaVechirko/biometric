package com.biometric.sample.auth;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.TextView;

import com.biometric.sample.R;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.DialogFragment;

public class Dialog extends DialogFragment {

    private static final long ERROR_TIMEOUT_MILLIS = 1600;
    private static final long SUCCESS_DELAY_MILLIS = 1300;

    private Button cancelButton;
    private ImageView mIcon;
    private TextView mErrorTextView;

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        View v = inflater.inflate(R.layout.fingerprint_dialog_container, container, false);
        cancelButton = v.findViewById(R.id.cancel_button);
        cancelButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                dismiss();
            }
        });

        mIcon = v.findViewById(R.id.fingerprint_icon);
        mErrorTextView = v.findViewById(R.id.fingerprint_status);

        return v;
    }

    @Override
    public void onStart() {
        super.onStart();
        mIcon.setImageResource(R.drawable.ic_fp_40px);
    }

    private void showError(CharSequence error) {
        if (!isAdded()) {
            return;
        }

        mIcon.setImageResource(R.drawable.ic_fingerprint_error);
        mErrorTextView.setText(error);
        mErrorTextView.setTextColor(ContextCompat.getColor(getActivity(), R.color.warning_color));
        mErrorTextView.removeCallbacks(mResetErrorTextRunnable);
        mErrorTextView.postDelayed(mResetErrorTextRunnable, ERROR_TIMEOUT_MILLIS);
    }

    private Runnable mResetErrorTextRunnable = new Runnable() {
        @Override
        public void run() {
            mErrorTextView.setTextColor(ContextCompat.getColor(getActivity(), R.color.hint_color));
            mErrorTextView.setText(
                    mErrorTextView.getResources().getString(R.string.fingerprint_hint));
            mIcon.setImageResource(R.drawable.ic_fp_40px);
        }
    };

    public void onAuthenticationError(CharSequence errString) {
//        if (!mSelfCancelled) {
        showError(errString);
//            mIcon.postDelayed(new Runnable() {
//                @Override
//                public void run() {
//                    mCallback.onError();
//                }
//            }, ERROR_TIMEOUT_MILLIS);
//        }
    }

    public void onAuthenticationHelp(CharSequence helpString) {
        showError(helpString);
    }

    public void onAuthenticationFailed() {
        showError(mIcon.getResources().getString(R.string.fingerprint_not_recognized));
    }

    public void onAuthenticationSucceeded() {
        mErrorTextView.removeCallbacks(mResetErrorTextRunnable);
        mIcon.setImageResource(R.drawable.ic_fingerprint_success);
        mErrorTextView.setTextColor(
                ContextCompat.getColor(getActivity(), R.color.success_color));
        mErrorTextView.setText(
                mErrorTextView.getResources().getString(R.string.fingerprint_success));
        mIcon.postDelayed(new Runnable() {
            @Override
            public void run() {
                dismiss();
            }
        }, SUCCESS_DELAY_MILLIS);
    }

}
