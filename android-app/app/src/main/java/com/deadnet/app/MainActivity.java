package com.deadnet.app;

import android.app.Activity;
import android.app.AlertDialog;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.webkit.WebChromeClient;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.ProgressBar;
import android.widget.TextView;
import java.io.File;

import com.chaquo.python.Python;
import com.chaquo.python.android.AndroidPlatform;

public class MainActivity extends Activity {
    private WebView webView;
    private ProgressBar progressBar;
    private TextView statusText;
    private static final String SERVER_URL = "http://127.0.0.1:5000";
    private static final int SERVER_PORT = 5000;
    private Thread serverThread;
    private boolean serverRunning = false;

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
        statusText = findViewById(R.id.statusText);
        
        // Initialize Python
        if (!Python.isStarted()) {
            Python.start(new AndroidPlatform(this));
        }
        
        setupWebView();
        startServer();
    }
    
    private boolean isRooted() {
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
                // Retry after delay
                new Handler(Looper.getMainLooper()).postDelayed(() -> loadServer(), 1000);
            }
            
            @Override
            public void onPageFinished(WebView view, String url) {
                progressBar.setVisibility(View.GONE);
                statusText.setVisibility(View.GONE);
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
    
    private void startServer() {
        statusText.setText("Starting DeadNet server...");
        
        serverThread = new Thread(() -> {
            try {
                Python py = Python.getInstance();
                py.getModule("deadnet_server").callAttr("start_server", SERVER_PORT);
                serverRunning = true;
            } catch (Exception e) {
                e.printStackTrace();
                runOnUiThread(() -> {
                    statusText.setText("Server error: " + e.getMessage());
                });
            }
        });
        serverThread.start();
        
        // Wait for server to start, then load WebView
        new Handler(Looper.getMainLooper()).postDelayed(() -> {
            statusText.setText("Loading interface...");
            loadServer();
        }, 2000);
    }

    private void loadServer() {
        webView.loadUrl(SERVER_URL);
    }

    @Override
    public void onBackPressed() {
        if (webView.canGoBack()) {
            webView.goBack();
        } else {
            new AlertDialog.Builder(this)
                .setTitle("Exit DeadNet?")
                .setMessage("This will stop the server.")
                .setPositiveButton("Exit", (d, w) -> {
                    stopServer();
                    finish();
                })
                .setNegativeButton("Cancel", null)
                .show();
        }
    }
    
    private void stopServer() {
        try {
            Python py = Python.getInstance();
            py.getModule("deadnet_server").callAttr("stop_server");
        } catch (Exception e) {
            e.printStackTrace();
        }
        serverRunning = false;
    }
    
    @Override
    protected void onDestroy() {
        stopServer();
        super.onDestroy();
    }
}
