package com.ali.glovebox;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.webkit.JavascriptInterface;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import androidx.annotation.NonNull;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.FragmentActivity;
import androidx.webkit.WebViewAssetLoader;

import org.json.JSONObject;

import java.security.KeyStore;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class MainActivity extends FragmentActivity {
    private WebView webView;
    private static final String KEY_ALIAS = "glovebox_bio";
    private static final String PREFS = "glovebox_native";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        webView = new WebView(this);
        WebSettings s = webView.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);

        final WebViewAssetLoader loader = new WebViewAssetLoader.Builder()
                .addPathHandler("/assets/", new WebViewAssetLoader.AssetsPathHandler(this))
                .build();

        webView.setWebViewClient(new WebViewClient() {
            @Override
            public WebResourceResponse shouldInterceptRequest(WebView view, WebResourceRequest request) {
                return loader.shouldInterceptRequest(request.getUrl());
            }
        });

        webView.addJavascriptInterface(new Bridge(), "AndroidBridge");

        webView.loadUrl("https://appassets.androidplatform.net/assets/vault.html");
        setContentView(webView);
    }

    private boolean bioAvailable() {
        BiometricManager bm = BiometricManager.from(this);
        return bm.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_WEAK)
                == BiometricManager.BIOMETRIC_SUCCESS;
    }

    private SecretKey getOrCreateKey() throws Exception {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        KeyStore.Entry entry = ks.getEntry(KEY_ALIAS, null);
        if (entry instanceof KeyStore.SecretKeyEntry) {
            return ((KeyStore.SecretKeyEntry) entry).getSecretKey();
        }
        KeyGenerator kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        kg.init(new KeyGenParameterSpec.Builder(KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(false)
                .build());
        return kg.generateKey();
    }

    private SharedPreferences prefs() {
        return getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    private boolean storeMaster(String master) {
        try {
            SecretKey key = getOrCreateKey();
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, key);
            byte[] iv = c.getIV();
            byte[] ct = c.doFinal(master.getBytes("UTF-8"));
            prefs().edit()
                    .putString("bio_iv", Base64.encodeToString(iv, Base64.NO_WRAP))
                    .putString("bio_ct", Base64.encodeToString(ct, Base64.NO_WRAP))
                    .apply();
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private String readMaster() {
        try {
            String ivS = prefs().getString("bio_iv", null);
            String ctS = prefs().getString("bio_ct", null);
            if (ivS == null || ctS == null) return null;
            SecretKey key = getOrCreateKey();
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, Base64.decode(ivS, Base64.NO_WRAP)));
            byte[] pt = c.doFinal(Base64.decode(ctS, Base64.NO_WRAP));
            return new String(pt, "UTF-8");
        } catch (Exception e) {
            return null;
        }
    }

    private class Bridge {

        @JavascriptInterface
        public boolean isBioEnabled() {
            return bioAvailable()
                    && prefs().contains("bio_ct")
                    && prefs().getBoolean("bio_on", false);
        }

        @JavascriptInterface
        public boolean enableBio(String master) {
            if (!bioAvailable()) return false;
            boolean ok = storeMaster(master);
            if (ok) prefs().edit().putBoolean("bio_on", true).apply();
            return ok;
        }

        @JavascriptInterface
        public void disableBio() {
            prefs().edit().remove("bio_iv").remove("bio_ct").putBoolean("bio_on", false).apply();
        }

        @JavascriptInterface
        public void copy(String text) {
            runOnUiThread(() -> {
                android.content.ClipboardManager cm =
                        (android.content.ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
                if (cm != null && text != null) {
                    cm.setPrimaryClip(android.content.ClipData.newPlainText("GLOVEBOX", text));
                }
            });
        }

        @JavascriptInterface
        public void bioUnlock() {
            runOnUiThread(() -> {
                if (!isBioEnabled()) return;
                BiometricPrompt prompt = new BiometricPrompt(MainActivity.this,
                        ContextCompat.getMainExecutor(MainActivity.this),
                        new BiometricPrompt.AuthenticationCallback() {
                            @Override
                            public void onAuthenticationSucceeded(
                                    @NonNull BiometricPrompt.AuthenticationResult result) {
                                String master = readMaster();
                                if (master != null && webView != null) {
                                    webView.evaluateJavascript(
                                            "bioUnlockWithPassword(" + JSONObject.quote(master) + ")", null);
                                }
                            }
                        });
                prompt.authenticate(new BiometricPrompt.PromptInfo.Builder()
                        .setTitle("Unlock GLOVEBOX")
                        .setNegativeButtonText("Use password")
                        .build());
            });
        }
    }

    @Override
    public void onBackPressed() {
        if (webView != null && webView.canGoBack()) {
            webView.goBack();
        } else {
            super.onBackPressed();
        }
    }
}
