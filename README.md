# 🔐 Password Gatekeeper Pro

Password Gatekeeper Pro is a lightweight password manager that pairs a **browser extension** with a **Flask API** for encrypted sync. The goal is simple: keep passwords private, searchable, and convenient without sacrificing security or clarity.

## Why this project

I wanted something that feels practical for day‑to‑day use but is also a solid reference for **OOP + DSA concepts** in a real product‑style build. Everything is intentionally kept framework‑light so it’s easy to read and extend.

## ✨ What you get

### Browser extension
- 🔒 **AES‑256‑GCM encryption** for all stored secrets
- 🔑 **Password generator** with secure random output
- 📊 **Strength analyzer** with entropy scoring
- 🔍 **Breach checker** support (HaveIBeenPwned)
- 📝 **Auto‑fill** for login forms
- ☁️ **Encrypted sync** with the Flask API
- 📤 **Export/Import** for vault backups

### Engineering highlights

#### OOP (JavaScript)
- `PasswordEntry` – data model with encapsulation
- `PasswordValidator` – strength checks + entropy
- `PasswordGenerator` – configurable generation rules
- `CryptoService` – AES‑GCM encrypt/decrypt helpers
- `StorageService` – Chrome Storage wrapper
- `SyncService` – JWT‑authenticated sync
- `PasswordManager` – main controller (Facade pattern)

#### DSA
- **Trie** – fast website autocomplete
- **HashMap** – $O(1)$ lookup by domain
- **Binary Search** – search sorted lists
- **QuickSort/MergeSort** – sorting entries
- **Levenshtein Distance** – detect similar/reused passwords

#### Python backend (OOP)
- `User`, `PasswordEntry`, `SyncLog`
- `CryptoUtils` – server‑side crypto utilities
- `Database` – SQLite access layer
- `AuthService` – JWT auth

## 📁 Project structure

```
password_gatekeeper/
├── app.py
├── requirements.txt
├── api/
│   ├── __init__.py
│   ├── models.py
│   ├── crypto_utils.py
│   ├── database.py
│   ├── auth.py
│   └── routes.py
├── extension/
│   ├── manifest.json
│   ├── popup/
│   │   ├── popup.html
│   │   ├── popup.css
│   │   └── popup.js
│   ├── js/
│   │   ├── classes/
│   │   ├── dsa/
│   │   └── services/
│   ├── background/
│   ├── content/
│   └── icons/
├── templates/
│   ├── index.html
│   └── extension.html
└── static/
    └── styles.css
```

## 🚀 Quick start

### 1) Install Python deps
```bash
pip install -r requirements.txt
```

### 2) Run the API
```bash
python app.py
```

Server runs at $http://localhost:5000$.

### 3) Load the extension
1. Open Chrome → $chrome://extensions$
2. Enable **Developer mode**
3. Click **Load unpacked**
4. Select the `extension/` folder
5. Pin the extension in the toolbar

## 🔧 API endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/register` | Create account |
| POST | `/api/auth/login` | Login + JWT |
| POST | `/api/auth/refresh` | Refresh token |
| GET | `/api/passwords` | List passwords |
| POST | `/api/passwords` | Create password |
| PUT | `/api/passwords/:id` | Update password |
| DELETE | `/api/passwords/:id` | Delete password |
| POST | `/api/passwords/sync` | Sync vault |
| POST | `/api/password/check` | Check strength |

## 🛡️ Security notes
- Master password is **never stored**; it derives the key.
- AES‑256‑GCM encryption happens **client‑side**.
- PBKDF2 (100,000 iterations) for key derivation.
- Server stores **encrypted blobs only**.

## 📦 Dependencies

**Python**
- Flask
- flask-cors
- cryptography

**Extension**
- Plain JavaScript
- Web Crypto API

## ✅ Roadmap ideas
- End‑to‑end export with optional passphrase
- Vault search filters and tags
- Full sync conflict resolution

## 🤝 Contribution
Contributions are welcome and appreciated.

### How to contribute
1. Fork the repository
2. Create a new branch (`feat/your-change` or `fix/your-change`)
3. Make your changes and test locally
4. Commit with a clear message
5. Push your branch and open a Pull Request

### Contributors
- [@urstrulyPrateeK](https://github.com/urstrulyPrateeK) - Project author
- [@Chhavi001](https://github.com/Chhavi001) - Documentation updates

## 📄 License
Open‑source for personal and educational use.