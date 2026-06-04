# ⚡ ErFlasherTools

<p align="center">
  <img src="https://img.shields.io/badge/version-2.1.0-00e5ff?style=for-the-badge" />
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-00e5ff?style=for-the-badge" />
  <img src="https://img.shields.io/badge/license-MIT-00e5ff?style=for-the-badge" />
  <img src="https://img.shields.io/github/downloads/Erzambayu/hacktiv8/total?color=00e5ff&style=for-the-badge" />
</p>

**ErFlasherTools** is a one-click cross-platform iOS activation bypass tool for **legacy Apple devices** (A5/A6 chips). It exploits the iTunes Store daemon (`itunesstored`) sandbox escape vulnerability to bypass the iOS activation lock — **no jailbreak required**.

> formerly known as hacktiv8 / A5_Bypass_OSS

## 📱 Supported Devices

| iOS | Devices |
|---|---|
| **10.3.3 / 10.3.4** | iPhone 5, iPhone 5c, iPad 4 |
| **9.3.5 / 9.3.6** | iPhone 4S, iPad 2, iPad 3, iPad mini, iPod touch 5 |
| **8.4.1** | iPad 2, iPad 3, iPad mini (WiFi), iPod touch 5 |

All A5 and A6 devices. See the full list in [`main.py`](main.py#L21).

## ⚙️ How It Works

1. **Detect** — polls for a connected iOS device via USB
2. **Build payload** — crafts a SQLite database mimicking an iTunes Store download
3. **Push** — sends the payload to the device via AFC (Apple File Conduit)
4. **Exploit** — `itunesstored` processes the fake download, fetches a patched `MobileGestalt.plist` from the backend, and writes it to the system cache
5. **Bypassed** — the device is activated without any jailbreak or kernel modification

```
┌──────────────┐     USB (AFC)      ┌─────────────┐     HTTP      ┌──────────────┐
│  ErFlasher   │ ─── push SQLite ──→│  iOS Device  │─── fetch ───→│  PHP Backend │
│  Tools GUI   │     payload        │ (itunesstored)│  plist      │ (server.php) │
└──────────────┘                    └─────────────┘              └──────────────┘
```

## 📥 Download

Pre-built binaries are available on the [Releases page](https://github.com/Erzambayu/hacktiv8/releases):

| Platform | File |
|---|---|
| 🪟 Windows | `ErFlasherTools_windows.exe` |
| 🐧 Linux | `ErFlasherTools_linux` |
| 🍎 macOS (ARM) | `ErFlasherTools_macos_arm64.dmg` |
| 🍎 macOS (Intel) | `ErFlasherTools_macos_intel.dmg` |

## 🔨 Build from Source

```bash
# requirements
pip install PyQt5 pymobiledevice3==7.8.3 pyinstaller
# Windows only
pip install pywin32

# build
pyinstaller --noconfirm --onefile --windowed \
  --name ErFlasherTools \
  --add-data "payload.sql;." \
  --hidden-import "pymobiledevice3" \
  --hidden-import "win32security" \
  --hidden-import "win32api" \
  --hidden-import "win32file" \
  --hidden-import "win32con" \
  --hidden-import "pywintypes" \
  --hidden-import "win32com" \
  main.py
```

## 🌐 Backend

The tool relies on a lightweight PHP backend that serves patched `MobileGestalt.plist` files. The default backend URL is configured in [`main.py`](main.py#L19).

> ⚠️ Legacy iOS devices don't trust modern certificate authorities (e.g., Let's Encrypt). The backend **must use HTTP** or serve an SSL certificate chained to a root CA trusted by legacy iOS.

## ⚠️ Disclaimer

This project is for **research and educational purposes only**. It is not intended for unlawful use. The authors take no responsibility for misuse or damage.

## 👤 Credits

- [**Erzambayu**](https://github.com/Erzambayu) — project maintainer, GUI redesign & features
- [pkkf5673](https://github.com/bablaerrr)
- [bl_sbx](https://github.com/hanakim3945/bl_sbx)
- [pymobiledevice3](https://github.com/doronz88/pymobiledevice3)

## 📄 License

MIT © 2025 [Erzambayu](https://github.com/Erzambayu). See [LICENSE](LICENSE) for details.
