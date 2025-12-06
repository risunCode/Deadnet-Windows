# DeadNet Android WebView App

Simple WebView wrapper that connects to DeadNet server running in Termux.

## Requirements
- DeadNet installed in Termux
- Server running (`deadnet` command)

## Build APK

### Option 1: Android Studio
1. Open this folder in Android Studio
2. Build > Build Bundle(s) / APK(s) > Build APK(s)
3. APK will be in `app/build/outputs/apk/`

### Option 2: Command Line (requires Android SDK)
```bash
cd android-app
./gradlew assembleRelease
```

## Usage
1. Run `deadnet` in Termux first
2. Open DeadNet app
3. App will connect to `http://127.0.0.1:5000`

## Note
This app is just a WebView wrapper. The actual DeadNet server runs in Termux.
Make sure Termux is running with `deadnet` command before opening the app.
