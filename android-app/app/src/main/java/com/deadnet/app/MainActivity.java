package com.deadnet.app;

import android.app.Activity;
import android.app.AlertDialog;
import android.os.Bundle;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.webkit.WebChromeClient;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.ProgressBar;
import android.widget.Toast;
import java.io.File;

public class MainActivity extends Activity {
    private WebView webView;
    private ProgressBar progressBar;
    private static final String SERVER_URL = "http://127.0.0.1:5000";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        
        // Fullscreen
        requestWindowFeature(Window.FEATURE_NO_TITLE);
        getWindow().setFlags(
            WindowManager.LayoutParams.FLAG_FULLSCREEN,
            WindowManager.LayoutParams.FLAG_FULLSCREEN
        );
        
        // Check root first
        if (!isRooted()) {
            showRootRequiredDialog();
            return;
        }
        
        setContentView(R.layout.activity_main);
        
        webView = findViewById(R.id.webView);
        progressBar = findViewById(R.id.progressBar);
        
        setupWebView();
        loadServer();
    }
    
    private boolean isRooted() {
        // Check common root paths
        String[] paths = {
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su",
            "/su/bin/su",
            "/data/adb/magisk",
            "/data/adb/ksu"
        };
        
        for (String path : paths) {
            if (new File(path).exists()) {
                return true;
            }
        }
        
        // Try executing su
        try {
            Process process = Runtime.getRuntime().exec(new String[]{"su", "-c", "id"});
            process.waitFor();
            return process.exitValue() == 0;
        } catch (Exception e) {
            return false;
        }
    }
    
    private void showRootRequiredDialog() {
        new AlertDialog.Builder(this)
            .setTitle("Root Required")
            .setMessage("DeadNet requires root access for network attacks.\n\nPlease root your device using Magisk or KernelSU.")
            .setPositiveButton("OK", (d, w) -> finish())
            .setCancelable(false)
            .show();
    }

    private void setupWebView() {
        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        settings.setAllowFileAccess(true);
        settings.setCacheMode(WebSettings.LOAD_NO_CACHE);
        
        webView.setWebViewClient(new WebViewClient() {
            @Override
            public void onReceivedError(WebView view, int errorCode, String description, String failingUrl) {
                showConnectionError();
            }
            
            @Override
            public void onPageFinished(WebView view, String url) {
                progressBar.setVisibility(View.GONE);
                webView.setVisibility(View.VISIBLE);
            }
        });
        
        webView.setWebChromeClient(new WebChromeClient() {
            @Override
            public void onProgressChanged(WebView view, int newProgress) {
                progressBar.setProgress(newProgress);
            }
        });
    }

    private void loadServer() {
        progressBar.setVisibility(View.VISIBLE);
        webView.setVisibility(View.GONE);
        webView.loadUrl(SERVER_URL);
    }

    private void showConnectionError() {
        new AlertDialog.Builder(this)
            .setTitle("Connection Error")
            .setMessage("Cannot connect to DeadNet server.\n\nMake sure you run 'deadnet' in Termux first!")
            .setPositiveButton("Retry", (d, w) -> loadServer())
            .setNegativeButton("Exit", (d, w) -> finish())
            .setCancelable(false)
            .show();
    }

    @Override
    public void onBackPressed() {
        if (webView.canGoBack()) {
            webView.goBack();
        } else {
            new AlertDialog.Builder(this)
                .setTitle("Exit DeadNet?")
                .setMessage("Server will keep running in Termux.")
                .setPositiveButton("Exit", (d, w) -> finish())
                .setNegativeButton("Cancel", null)
                .show();
        }
    }
}
