package com.deadnet.app;

import android.app.Activity;
import android.app.AlertDialog;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.widget.*;
import androidx.core.content.ContextCompat;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.chaquo.python.PyObject;
import com.chaquo.python.Python;
import com.chaquo.python.android.AndroidPlatform;

public class MainActivity extends Activity {
    private Python py;
    private PyObject backend;
    
    // UI Elements
    private View statusDot;
    private TextView statusText;
    private Button tabAttacker, tabDefender;
    private View attackerView, defenderView;
    
    // Attacker UI
    private TextView statCycles, statPackets, statDuration, txtLogs;
    private Spinner spinnerInterface, spinnerIntensity;
    private CheckBox checkArp, checkIpv6, checkDeadRouter;
    private Button btnAttack;
    
    // Defender UI
    private TextView defStatPackets, defStatSuspicious, txtAlerts;
    private Spinner defSpinnerInterface;
    private Button btnDefend;
    
    // State
    private boolean attackActive = false;
    private boolean defendActive = false;
    private Handler handler = new Handler(Looper.getMainLooper());
    private List<String> interfaces = new ArrayList<>();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        
        requestWindowFeature(Window.FEATURE_NO_TITLE);
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_FULLSCREEN,
                           WindowManager.LayoutParams.FLAG_FULLSCREEN);
        
        if (!isRooted()) {
            showRootDialog();
            return;
        }
        
        setContentView(R.layout.activity_main);
        initPython();
        initViews();
        loadInterfaces();
        startPolling();
    }
    
    private boolean isRooted() {
        String[] paths = {"/sbin/su", "/system/bin/su", "/system/xbin/su", 
                         "/data/adb/magisk", "/data/adb/ksu"};
        for (String p : paths) {
            if (new File(p).exists()) return true;
        }
        return false;
    }
    
    private void showRootDialog() {
        new AlertDialog.Builder(this)
            .setTitle("Root Required")
            .setMessage("DeadNet needs root for network attacks.")
            .setPositiveButton("OK", (d, w) -> finish())
            .setCancelable(false).show();
    }
    
    private void initPython() {
        if (!Python.isStarted()) {
            Python.start(new AndroidPlatform(this));
        }
        py = Python.getInstance();
        backend = py.getModule("deadnet_backend");
    }
    
    private void initViews() {
        statusDot = findViewById(R.id.statusDot);
        statusText = findViewById(R.id.statusText);
        tabAttacker = findViewById(R.id.tabAttacker);
        tabDefender = findViewById(R.id.tabDefender);
        attackerView = findViewById(R.id.attackerView);
        defenderView = findViewById(R.id.defenderView);
        
        // Attacker
        statCycles = findViewById(R.id.statCycles);
        statPackets = findViewById(R.id.statPackets);
        statDuration = findViewById(R.id.statDuration);
        txtLogs = findViewById(R.id.txtLogs);
        spinnerInterface = findViewById(R.id.spinnerInterface);
        spinnerIntensity = findViewById(R.id.spinnerIntensity);
        checkArp = findViewById(R.id.checkArp);
        checkIpv6 = findViewById(R.id.checkIpv6);
        checkDeadRouter = findViewById(R.id.checkDeadRouter);
        btnAttack = findViewById(R.id.btnAttack);
        
        // Defender
        defStatPackets = findViewById(R.id.defStatPackets);
        defStatSuspicious = findViewById(R.id.defStatSuspicious);
        txtAlerts = findViewById(R.id.txtAlerts);
        defSpinnerInterface = findViewById(R.id.defSpinnerInterface);
        btnDefend = findViewById(R.id.btnDefend);
        
        // Tab switching
        tabAttacker.setOnClickListener(v -> showTab(true));
        tabDefender.setOnClickListener(v -> showTab(false));
        
        // Intensity spinner
        String[] intensities = {"Slow (10s)", "Medium (5s)", "Fast (2s)", "Maximum (1s)"};
        spinnerIntensity.setAdapter(new ArrayAdapter<>(this, 
            android.R.layout.simple_spinner_dropdown_item, intensities));
        spinnerIntensity.setSelection(1);
        
        // Buttons
        btnAttack.setOnClickListener(v -> toggleAttack());
        btnDefend.setOnClickListener(v -> toggleDefend());
    }
    
    private void showTab(boolean attacker) {
        attackerView.setVisibility(attacker ? View.VISIBLE : View.GONE);
        defenderView.setVisibility(attacker ? View.GONE : View.VISIBLE);
        tabAttacker.setTextColor(attacker ? 0xFF00FF00 : 0xFF888888);
        tabDefender.setTextColor(attacker ? 0xFF888888 : 0xFF3B82F6);
        tabAttacker.setBackgroundColor(attacker ? 0xFF1A1A1A : 0xFF111111);
        tabDefender.setBackgroundColor(attacker ? 0xFF111111 : 0xFF1A1A1A);
    }
    
    private void loadInterfaces() {
        new Thread(() -> {
            try {
                PyObject result = backend.callAttr("get_interfaces");
                List<PyObject> ifaces = result.asList();
                interfaces.clear();
                List<String> names = new ArrayList<>();
                for (PyObject iface : ifaces) {
                    Map<PyObject, PyObject> map = iface.asMap();
                    String name = map.get(py.builtins().callAttr("str", "name")).toString();
                    String ip = map.get(py.builtins().callAttr("str", "ip")).toString();
                    interfaces.add(name);
                    names.add(name + " (" + ip + ")");
                }
                runOnUiThread(() -> {
                    ArrayAdapter<String> adapter = new ArrayAdapter<>(this,
                        android.R.layout.simple_spinner_dropdown_item, names);
                    spinnerInterface.setAdapter(adapter);
                    defSpinnerInterface.setAdapter(adapter);
                });
            } catch (Exception e) {
                e.printStackTrace();
            }
        }).start();
    }
    
    private int getInterval() {
        int[] intervals = {10, 5, 2, 1};
        return intervals[spinnerIntensity.getSelectedItemPosition()];
    }
    
    private void toggleAttack() {
        if (attackActive) {
            stopAttack();
        } else {
            startAttack();
        }
    }
    
    private void startAttack() {
        if (interfaces.isEmpty()) {
            toast("No interface selected");
            return;
        }
        String iface = interfaces.get(spinnerInterface.getSelectedItemPosition());
        int interval = getInterval();
        
        new Thread(() -> {
            try {
                backend.callAttr("start_attack", iface, interval,
                    checkArp.isChecked(), checkIpv6.isChecked(), checkDeadRouter.isChecked());
                attackActive = true;
                runOnUiThread(() -> updateAttackUI());
            } catch (Exception e) {
                runOnUiThread(() -> toast("Error: " + e.getMessage()));
            }
        }).start();
    }
    
    private void stopAttack() {
        new Thread(() -> {
            try {
                backend.callAttr("stop_attack");
                attackActive = false;
                runOnUiThread(() -> updateAttackUI());
            } catch (Exception e) {
                e.printStackTrace();
            }
        }).start();
    }
    
    private void toggleDefend() {
        if (defendActive) {
            stopDefend();
        } else {
            startDefend();
        }
    }
    
    private void startDefend() {
        if (interfaces.isEmpty()) {
            toast("No interface selected");
            return;
        }
        String iface = interfaces.get(defSpinnerInterface.getSelectedItemPosition());
        
        new Thread(() -> {
            try {
                backend.callAttr("start_defend", iface);
                defendActive = true;
                runOnUiThread(() -> updateDefendUI());
            } catch (Exception e) {
                runOnUiThread(() -> toast("Error: " + e.getMessage()));
            }
        }).start();
    }
    
    private void stopDefend() {
        new Thread(() -> {
            try {
                backend.callAttr("stop_defend");
                defendActive = false;
                runOnUiThread(() -> updateDefendUI());
            } catch (Exception e) {
                e.printStackTrace();
            }
        }).start();
    }
    
    private void updateAttackUI() {
        Drawable icon;
        if (attackActive) {
            btnAttack.setText("STOP ATTACK");
            btnAttack.setBackgroundColor(0xFF16A34A);
            icon = ContextCompat.getDrawable(this, R.drawable.ic_stop);
            statusDot.setBackgroundResource(R.drawable.status_dot_active);
            statusText.setText("Attacking");
        } else {
            btnAttack.setText("START ATTACK");
            btnAttack.setBackgroundColor(0xFFDC2626);
            icon = ContextCompat.getDrawable(this, R.drawable.ic_play);
            statusDot.setBackgroundResource(R.drawable.status_dot_inactive);
            statusText.setText("Inactive");
        }
        btnAttack.setCompoundDrawablesWithIntrinsicBounds(icon, null, null, null);
    }
    
    private void updateDefendUI() {
        Drawable icon;
        if (defendActive) {
            btnDefend.setText("STOP MONITORING");
            btnDefend.setBackgroundColor(0xFFDC2626);
            icon = ContextCompat.getDrawable(this, R.drawable.ic_stop);
        } else {
            btnDefend.setText("START MONITORING");
            btnDefend.setBackgroundColor(0xFF16A34A);
            icon = ContextCompat.getDrawable(this, R.drawable.ic_play);
        }
        btnDefend.setCompoundDrawablesWithIntrinsicBounds(icon, null, null, null);
    }
    
    private void startPolling() {
        handler.postDelayed(new Runnable() {
            @Override
            public void run() {
                pollStatus();
                handler.postDelayed(this, 1000);
            }
        }, 1000);
    }
    
    private void pollStatus() {
        new Thread(() -> {
            try {
                PyObject status = backend.callAttr("get_status");
                Map<PyObject, PyObject> map = status.asMap();
                
                int cycles = map.get(py.builtins().callAttr("str", "cycles")).toInt();
                int packets = map.get(py.builtins().callAttr("str", "packets")).toInt();
                int duration = map.get(py.builtins().callAttr("str", "duration")).toInt();
                String logs = map.get(py.builtins().callAttr("str", "logs")).toString();
                boolean active = map.get(py.builtins().callAttr("str", "active")).toBoolean();
                
                runOnUiThread(() -> {
                    statCycles.setText(String.valueOf(cycles));
                    statPackets.setText(String.valueOf(packets));
                    statDuration.setText(duration + "ms");
                    txtLogs.setText(logs);
                    
                    if (active != attackActive) {
                        attackActive = active;
                        updateAttackUI();
                    }
                });
            } catch (Exception e) {
                // Ignore polling errors
            }
        }).start();
    }
    
    private void toast(String msg) {
        Toast.makeText(this, msg, Toast.LENGTH_SHORT).show();
    }
    
    @Override
    protected void onDestroy() {
        if (attackActive) stopAttack();
        if (defendActive) stopDefend();
        super.onDestroy();
    }
}
