# CyberShield 🛡️

A professional cybersecurity analysis suite built with **Flutter** (frontend) and **Python FastAPI** (backend).

## 🏗️ Architecture

```
CyberShield/
├── lib/                          # Flutter/Dart frontend
│   ├── main.dart                 # App entry point
│   ├── app.dart                  # MaterialApp configuration
│   ├── core/
│   │   ├── theme/                # Dark cybersecurity theme
│   │   ├── navigation/           # Named route configuration
│   │   ├── services/             # API client service
│   │   └── widgets/              # Reusable UI components
│   └── features/
│       ├── dashboard/            # Main security dashboard
│       ├── url_scanner/          # URL threat analysis
│       ├── sms_scanner/          # SMS phishing detection
│       ├── qr_scanner/           # QR code analysis
│       ├── screenshot_analysis/  # Screenshot threat detection
│       ├── apk_analysis/         # Android APK inspection
│       └── history/              # Scan history viewer
├── backend/                      # Python FastAPI backend
│   ├── main.py                   # API server with endpoints
│   ├── requirements.txt          # Python dependencies
│   └── tests/                    # Backend test suite
├── pubspec.yaml                  # Flutter dependencies
└── analysis_options.yaml         # Dart linter configuration
```

## 🚀 Getting Started

### Prerequisites

- [Flutter SDK](https://docs.flutter.dev/get-started/install) (≥ 3.0.0)
- [Python](https://www.python.org/downloads/) (≥ 3.10)
- [pip](https://pip.pypa.io/en/stable/)

### Backend Setup

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

The API will be available at `http://localhost:8000`.
Health check: `http://localhost:8000/health`

### Frontend Setup

```bash
flutter pub get
flutter run -d chrome     # Web
flutter run -d windows    # Windows desktop
flutter run               # Connected device
```

### Running Tests

```bash
# Backend tests
cd backend
python -m pytest tests/ -v

# Flutter analysis
flutter analyze
```

## 🔒 Security Tools

| Tool | Description | Endpoint |
|------|-------------|----------|
| URL Scanner | Analyze URLs for phishing and malware | `POST /api/v1/scan/url` |
| SMS Scanner | Detect fraudulent text messages | `POST /api/v1/scan/sms` |
| QR Scanner | Scan QR codes for hidden threats | `POST /api/v1/scan/qr` |
| Screenshot Analysis | Analyze screenshots for suspicious content | `POST /api/v1/scan/screenshot` |
| APK Analysis | Inspect Android packages for threats | `POST /api/v1/scan/apk` |
| Scan History | View past scan results | `GET /api/v1/history` |

## 🛠️ Tech Stack

- **Frontend:** Flutter + Dart (Material Design 3)
- **Backend:** Python FastAPI + Uvicorn
- **Database:** Firebase *(planned integration)*
- **Theme:** Custom dark cybersecurity theme

## 📋 API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Server health check |
| `POST` | `/api/v1/scan/url` | Submit URL for analysis |
| `POST` | `/api/v1/scan/sms` | Submit SMS for analysis |
| `POST` | `/api/v1/scan/qr` | Submit QR code image |
| `POST` | `/api/v1/scan/screenshot` | Submit screenshot |
| `POST` | `/api/v1/scan/apk` | Submit APK file |
| `GET` | `/api/v1/history` | Retrieve scan history |

## 📝 Notes

- All scan endpoints currently return `not_implemented` status — real detection engines will be integrated.
- Firebase integration is planned for authentication, cloud storage, and real-time data.
- No fake security detection is used — all responses honestly indicate implementation status.

## 📄 License

MIT License

