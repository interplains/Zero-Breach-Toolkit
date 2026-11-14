# Checking an Android TV or Google TV

Android TV and Google TV (Sony, Philips, TCL, Hisense, Xiaomi, Nvidia Shield, Chromecast with Google TV and
many TV boxes) run Android, so Zero Breach's Android check can read them the same way as a phone: you make a
collection with AndroidQF, then check it. Samsung (Tizen), LG (webOS) and Roku TVs are not Android and cannot be
checked this way; the home network check (`--home-network`) can still tell you which doors they leave open.

TV menus differ by maker and version. If a step does not match your TV, the menu names below are what to look for.
We have not been able to try every model: please tell us (an issue on GitHub) how it went on yours.

## 1. Turn on debugging on the TV

1. **Settings > System > About** (or **Device Preferences > About**). Select **Android TV OS build** (or **Build**)
   seven times until it says you are a developer.
2. Go back to **System** (or **Device Preferences**) > **Developer options** and turn on **USB debugging**.
   Some TVs call it **ADB debugging** or **Network debugging**; turn that on as well if you see it.
3. Note the TV's address: **Settings > Network & Internet > (your network)** shows an IP address such as
   `192.168.1.40`.

## 2. Connect from the computer

You need Google's `adb` tool (Android "platform-tools", free from developer.android.com) on a computer on the same
Wi-Fi as the TV:

```
adb connect 192.168.1.40:5555
```

The TV asks **Allow USB debugging?**: choose **Allow**. `adb devices` should now list the TV.
Newer Google TV models use **Wireless debugging** instead: open it on the TV, choose **Pair device with pairing
code**, and run `adb pair <address:port shown on the TV>` and then `adb connect <address:port>`.

## 3. Collect and check

Run AndroidQF (the Zero Breach program's **A phone > Collect from an Android phone** downloads and verifies it for
you) while the TV is connected, then check the collection like a phone's:

```
python scan/zero-breach-toolkit.py --phone "PATH TO THE COLLECTION FOLDER"
```

The collection holds private information about the TV and its accounts: keep it on your computer.

## 4. Turn debugging off again

While network debugging is on, **anyone on your Wi-Fi can install apps on the TV and control it**. When you are
done: `adb disconnect`, then turn off **USB debugging** / **Network debugging** in Developer options.
Zero Breach's home network check warns about any device that still has this door open.
