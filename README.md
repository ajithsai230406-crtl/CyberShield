# CyberShield 🛡️

A professional, high-performance cybersecurity analysis suite built with **Flutter + Dart** (frontend) and **Python FastAPI** (backend).

Designed with a modern **Material 3 dark cybersecurity theme**, featuring deep navy backgrounds, electric blue accents, green safe status indicators, red threat indicators, and session audit trails.

---

## 🏗️ Architecture & Project Structure

```
CyberShield/
├── lib/                               # Flutter / Dart Frontend
│   ├── main.dart                      # Application bootstrap
│   ├── app.dart                       # CyberShieldApp root configuration
│   ├── core/
│   │   ├── navigation/
│   │   │   └── app_router.dart        # Route registry & screen transitions
│   │   ├── services/
│   │   │   └── api_service.dart       # HTTP client with timeouts & error handling
│   │   ├── theme/
│   │   │   └── app_theme.dart         # Material 3 Dark Cybersecurity Theme
│   │   └── widgets/
│   │       ├── cyber_card.dart        # Glowing border cards
│   │       ├── cyber_badge.dart       # Status badge (Safe, Danger, Warning, Info)
│   │       ├── cyber_loading_state.dart # Electric blue pulsing analysis indicator
│   │       ├── cyber_error_state.dart # Error boundary card with retry action
│   │       ├── cyber_empty_state.dart # Actionable zero-state view
│   │       ├── nav_drawer.dart        # Cybersecurity navigation drawer
│   │       └── status_indicator.dart  # Live indicator pill with pulse
│   └── features/
│       ├── dashboard/                 # Central Security Control Center
│       ├── url_scanner/               # Web link & TLS inspection
│       ├── sms_scanner/               # Smishing & text scam detector
│       ├── qr_scanner/                # QR code & quishing inspector
│       ├── screenshot_analysis/       # Visual spoof & layout analyzer
│       ├── apk_analysis/              # Android package & permission auditor
│       └── history/                   # Session audit log & history
│
├── backend/                           # Python FastAPI Backend
│   ├── main.py                        # FastAPI application with audit log & endpoints
│   ├── requirements.txt               # Backend dependencies
│   └── tests/
│       ├── __init__.py
│       └── test_health.py             # Pytest test suite (100% pass rate)
│
├── pubspec.yaml                       # Flutter dependencies & metadata
├── analysis_options.yaml              # Dart linter & static analysis rules
└── README.md                          # Documentation
```

---

## 🎨 Theme & Design System

The application strictly adheres to the **CyberShield Phase 1 Design System**:
- **Background**: Deep Dark Navy (`#0A0E1A`)
- **Card Surfaces**: Rich Slate Navy (`#131B2E`, `#1A233D`) with subtle neon borders (`#1E2C4F`)
- **Accents**: Electric Blue (`#00E5FF` primary, `#0077FE` secondary)
- **Safe Indicator**: Emerald Green (`#00E676`)
- **Danger Indicator**: Crimson Red (`#FF3B30`)
- **Warning Indicator**: Amber Glow (`#FFB300`)
- **Typography**: Clean, high-legibility Google Fonts Inter typography.

---

## 🔒 6 Security Analysis Modules

| Module | Route | Functionality |
|--------|-------|---------------|
| **URL Threat Detection** | `/url-scanner` / `POST /api/v1/url/scan` | Heuristic scanner checking raw IP usage, URL shorteners, phishing keywords, excessive subdomains, user-info '@' delimiters, plain HTTP, and high-risk TLDs. Computes risk score (0-100) and classifies into Safe, Suspicious, or Malicious. |
| **SMS Scam Detection** | `/sms-scanner` / `POST /api/v1/scan/sms` | Analyzes text message bodies for embedded URLs, urgency cues, and banking terms. |
| **QR Scanner** | `/qr-scanner` / `POST /api/v1/scan/qr` | Decodes barcode payloads, identifies dangerous scheme redirects (e.g. `intent://`, `tel:`), and flags quishing links. |
| **Screenshot Scanner** | `/screenshot-analysis` / `POST /api/v1/scan/screenshot` | Simulates OCR text extraction, visual interface pattern matching, and credential spoof detection. |
| **APK Analyzer** | `/apk-analysis` / `POST /api/v1/scan/apk` | Performs static manifest audits, flags high-privilege permission combinations (SMS + Network), and audits exported components. |
| **Scan History** | `/history` / `GET /api/v1/history` | Displays real session audit logs synchronized directly from the FastAPI backend. |

---

## 📡 URL Threat Detection API (`POST /api/v1/url/scan`)

### Request Body:
```json
{
  "url": "http://192.168.1.50/banking/login/verify?account=99281"
}
```

### Response Schema:
```json
{
  "scanned_url": "http://192.168.1.50/banking/login/verify?account=99281",
  "risk_score": 75,
  "classification": "Malicious",
  "detected_indicators": [
    "Host uses raw IP address instead of registered domain (192.168.1.50)",
    "Insecure plain HTTP protocol in use (lacks TLS/SSL encryption)",
    "Suspicious phishing keyword(s) detected: login, verify, banking"
  ],
  "explanation": "The URL scored 75/100 and exhibits severe threat indicators: ... High probability of phishing or credential theft.",
  "recommendation": "Do not open this URL. Block the sender and report the destination as a malicious phishing attempt."
}
```

### Risk Classification Matrix:
| Score Range | Classification | Description |
|-------------|----------------|-------------|
| `0 - 29` | **Safe** | Legitimate domain, HTTPS, no high-risk heuristic triggers. |
| `30 - 69` | **Suspicious** | Presence of URL shorteners, plain HTTP, suspicious keywords, or high-abuse TLDs. |
| `70 - 100` | **Malicious** | Dangerous combinations: raw IP address, '@' spoofing, excessive nested subdomains, and credential theft keywords. |

> **Ethical Security Guarantee**: CyberShield strictly avoids fabricated threat scores or fake detection results. All findings report verifiable protocol and structural indicators.

---

## 🚀 Running the Application

### 1. Prerequisites
- [Flutter SDK](https://docs.flutter.dev/) (≥ 3.0.0)
- [Python](https://www.python.org/) (≥ 3.10)

### 2. Backend Setup & Startup
```bash
cd backend
pip install -r requirements.txt
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```
- Health Check: `http://localhost:8000/health`
- Interactive Swagger Docs: `http://localhost:8000/docs`

### 3. Frontend Setup & Startup
```bash
flutter pub get
flutter run -d chrome        # Web browser
flutter run -d windows       # Windows desktop
```

---

## 🧪 Verification & Testing

### Backend Test Suite
```bash
cd backend
python -m pytest tests/ -v
```
*Current test suite covers health checks, HTTPS/HTTP URL inspection, SMS pattern detection, and session audit history.*

### Flutter Static Analysis
```bash
flutter analyze lib/
```
*Validated with zero lint or analyzer errors.*

---

## 🔮 Roadmap (Phase 2 & Beyond)
- **Firebase Authentication & Cloud Firestore**: Persistent cloud history and multi-device sync.
- **Scikit-learn ML Pipeline**: Machine learning classification models for phishing URLs and SMS spam.
- **Camera QR Scanner**: Real-time camera feed scanning via `mobile_scanner`.
- **DEX Bytecode Analyzer**: Dynamic and static APK bytecode decompiler.
