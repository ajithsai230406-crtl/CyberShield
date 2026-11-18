"""APK Security Analyzer — static metadata inspection for Android packages."""

from __future__ import annotations

import io
import zipfile
from dataclasses import dataclass, field
from typing import Any, Dict, List


# ---------------------------------------------------------------------------
# Known dangerous permissions with risk weights and explanations
# ---------------------------------------------------------------------------

_DANGEROUS_PERMISSIONS: Dict[str, Dict[str, Any]] = {
    # SMS / Telephony
    "android.permission.READ_SMS": {
        "weight": 20,
        "category": "SMS Access",
        "explanation": (
            "Allows the app to read SMS messages. "
            "This capability is frequently abused by banking trojans to intercept OTP codes."
        ),
    },
    "android.permission.RECEIVE_SMS": {
        "weight": 20,
        "category": "SMS Access",
        "explanation": (
            "Allows the app to receive incoming SMS messages. "
            "Malicious apps exploit this to silently capture authentication codes."
        ),
    },
    "android.permission.SEND_SMS": {
        "weight": 20,
        "category": "SMS Access",
        "explanation": (
            "Allows the app to send SMS messages without user interaction. "
            "This can be used for premium-rate SMS fraud."
        ),
    },
    "android.permission.RECEIVE_MMS": {
        "weight": 10,
        "category": "SMS Access",
        "explanation": "Allows the app to receive MMS messages.",
    },
    # Contacts
    "android.permission.READ_CONTACTS": {
        "weight": 15,
        "category": "Contact Harvesting",
        "explanation": (
            "Allows the app to read the device contact list. "
            "Spyware uses this to harvest personal data."
        ),
    },
    "android.permission.WRITE_CONTACTS": {
        "weight": 10,
        "category": "Contact Harvesting",
        "explanation": "Allows the app to modify contact records.",
    },
    # Location
    "android.permission.ACCESS_FINE_LOCATION": {
        "weight": 15,
        "category": "Location Tracking",
        "explanation": (
            "Allows the app to access precise GPS location. "
            "Stalkerware routinely requests this permission."
        ),
    },
    "android.permission.ACCESS_COARSE_LOCATION": {
        "weight": 10,
        "category": "Location Tracking",
        "explanation": "Allows approximate location access via cell towers and Wi-Fi.",
    },
    "android.permission.ACCESS_BACKGROUND_LOCATION": {
        "weight": 20,
        "category": "Location Tracking",
        "explanation": (
            "Allows location access even when the app is not in use. "
            "This is a strong indicator of covert tracking."
        ),
    },
    # Accessibility
    "android.permission.BIND_ACCESSIBILITY_SERVICE": {
        "weight": 25,
        "category": "Accessibility Abuse",
        "explanation": (
            "Grants control over the screen reader/accessibility service. "
            "Overlay attack malware and banking trojans heavily exploit this to "
            "log keystrokes and interact with other apps."
        ),
    },
    # Microphone / Camera
    "android.permission.RECORD_AUDIO": {
        "weight": 15,
        "category": "Microphone Access",
        "explanation": "Allows the app to record audio using the device microphone.",
    },
    "android.permission.CAMERA": {
        "weight": 10,
        "category": "Camera Access",
        "explanation": "Allows the app to access the device camera.",
    },
    # Call interception
    "android.permission.READ_CALL_LOG": {
        "weight": 20,
        "category": "Call Log Access",
        "explanation": "Allows reading the call history, useful for profiling user behaviour.",
    },
    "android.permission.WRITE_CALL_LOG": {
        "weight": 15,
        "category": "Call Log Access",
        "explanation": "Allows modifying the call history.",
    },
    "android.permission.PROCESS_OUTGOING_CALLS": {
        "weight": 15,
        "category": "Call Interception",
        "explanation": "Allows the app to intercept outgoing calls and redirect them.",
    },
    # Device identity
    "android.permission.READ_PHONE_STATE": {
        "weight": 15,
        "category": "Device Identity",
        "explanation": (
            "Allows reading the IMEI, phone number, and current call state. "
            "Used for device fingerprinting."
        ),
    },
    "android.permission.READ_PHONE_NUMBERS": {
        "weight": 10,
        "category": "Device Identity",
        "explanation": "Allows reading phone numbers associated with the device.",
    },
    # Persistence
    "android.permission.RECEIVE_BOOT_COMPLETED": {
        "weight": 15,
        "category": "Auto-Start Persistence",
        "explanation": (
            "Allows the app to start automatically after the device reboots, "
            "a common persistence mechanism used by malware."
        ),
    },
    # Overlay attacks
    "android.permission.SYSTEM_ALERT_WINDOW": {
        "weight": 20,
        "category": "Overlay Attacks",
        "explanation": (
            "Allows drawing overlays on top of other apps. "
            "This is a key capability for phishing overlay attacks that capture credentials."
        ),
    },
    # Dropper behaviour
    "android.permission.REQUEST_INSTALL_PACKAGES": {
        "weight": 25,
        "category": "Package Installation",
        "explanation": (
            "Allows the app to install other APK packages silently. "
            "Dropper malware uses this to install secondary payloads."
        ),
    },
    # System settings
    "android.permission.WRITE_SETTINGS": {
        "weight": 10,
        "category": "System Modification",
        "explanation": "Allows modifying global system settings.",
    },
    "android.permission.WRITE_SECURE_SETTINGS": {
        "weight": 20,
        "category": "System Modification",
        "explanation": "Allows modifying secure system settings - extremely privileged.",
    },
    # Account harvesting
    "android.permission.GET_ACCOUNTS": {
        "weight": 15,
        "category": "Account Harvesting",
        "explanation": (
            "Allows listing all accounts registered on the device, "
            "including Google and banking accounts."
        ),
    },
    # Storage
    "android.permission.MANAGE_EXTERNAL_STORAGE": {
        "weight": 15,
        "category": "Broad Storage Access",
        "explanation": (
            "Grants unrestricted access to all external storage. "
            "This exceeds what most legitimate apps require."
        ),
    },
    "android.permission.READ_EXTERNAL_STORAGE": {
        "weight": 5,
        "category": "Storage Access",
        "explanation": "Allows reading files from external storage.",
    },
    "android.permission.WRITE_EXTERNAL_STORAGE": {
        "weight": 8,
        "category": "Storage Access",
        "explanation": "Allows writing files to external storage.",
    },
    # Network
    "android.permission.CHANGE_NETWORK_STATE": {
        "weight": 5,
        "category": "Network Control",
        "explanation": "Allows modifying network connectivity state.",
    },
    "android.permission.CHANGE_WIFI_STATE": {
        "weight": 5,
        "category": "Network Control",
        "explanation": "Allows changing Wi-Fi connectivity settings.",
    },
}

# Dangerous permission category combinations that amplify risk
_HIGH_RISK_COMBOS: List[Dict[str, Any]] = [
    {
        "name": "SMS + Accessibility Combo",
        "perms": {"android.permission.READ_SMS", "android.permission.BIND_ACCESSIBILITY_SERVICE"},
        "bonus": 20,
        "note": (
            "Combining SMS access with Accessibility Service is a hallmark of banking trojans "
            "capable of stealing OTPs and overlaying fake login screens."
        ),
    },
    {
        "name": "SMS + Overlay Combo",
        "perms": {"android.permission.READ_SMS", "android.permission.SYSTEM_ALERT_WINDOW"},
        "bonus": 15,
        "note": "SMS access with overlay capability enables credential phishing attacks.",
    },
    {
        "name": "Dropper + Accessibility Combo",
        "perms": {
            "android.permission.REQUEST_INSTALL_PACKAGES",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
        },
        "bonus": 20,
        "note": (
            "Package installation combined with Accessibility Service enables "
            "silent dropper behaviour."
        ),
    },
    {
        "name": "Microphone + Location Combo",
        "perms": {
            "android.permission.RECORD_AUDIO",
            "android.permission.ACCESS_FINE_LOCATION",
        },
        "bonus": 10,
        "note": "Microphone and location together is a common stalkerware profile.",
    },
    {
        "name": "Background Location + Boot Persistence",
        "perms": {
            "android.permission.ACCESS_BACKGROUND_LOCATION",
            "android.permission.RECEIVE_BOOT_COMPLETED",
        },
        "bonus": 10,
        "note": "Persistent background location tracking.",
    },
]


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass
class APKAnalysisResult:
    """Structured result of an APK security inspection."""

    filename: str
    package_name: str
    app_name: str
    version_name: str
    version_code: str
    min_sdk: int
    target_sdk: int
    permissions: List[str]
    dangerous_permissions: List[str]
    risk_score: int
    classification: str
    findings: List[str]
    detected_indicators: List[str]
    explanation: str
    finding_explanations: List[Dict[str, Any]]
    recommendation: str
    metadata: Dict[str, Any]
    combo_findings: List[str] = field(default_factory=list)
    engine_status: str = "apk_security_inspector_active"


# ---------------------------------------------------------------------------
# APK security analyser
# ---------------------------------------------------------------------------


class APKSecurityAnalyzer:
    """Static APK metadata inspector using pyaxmlparser and stdlib zipfile."""

    MAX_SIZE_BYTES: int = 52_428_800  # 50 MB

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze_bytes(self, apk_bytes: bytes, filename: str) -> APKAnalysisResult:
        """Analyse raw APK bytes and return a structured security assessment."""
        # Step 1: validate ZIP structure
        self._validate_zip(apk_bytes, filename)

        # Step 2: Parse manifest via pyaxmlparser
        parsed = self._parse_manifest(apk_bytes, filename)

        # Step 3: Score and classify
        return self._score(parsed, filename, apk_bytes)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _validate_zip(self, data: bytes, filename: str) -> None:
        """Raise ValueError if data is not a valid ZIP / APK structure."""
        if not zipfile.is_zipfile(io.BytesIO(data)):
            raise ValueError("The uploaded file is not a valid APK (ZIP) archive.")

        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = set(zf.namelist())
            if "AndroidManifest.xml" not in names:
                raise ValueError(
                    "The archive does not contain AndroidManifest.xml "
                    "and is not a valid APK file."
                )

    def _parse_manifest(self, apk_bytes: bytes, filename: str) -> Dict[str, Any]:
        """Parse AndroidManifest.xml via pyaxmlparser; fall back gracefully."""
        meta: Dict[str, Any] = {
            "package_name": "unknown",
            "app_name": filename.removesuffix(".apk"),
            "version_name": "unknown",
            "version_code": "unknown",
            "min_sdk": 0,
            "target_sdk": 0,
            "permissions": [],
            "dex_count": 0,
            "has_native_libs": False,
            "file_count": 0,
            "parse_error": None,
        }

        # Count files in the ZIP
        try:
            with zipfile.ZipFile(io.BytesIO(apk_bytes)) as zf:
                names = zf.namelist()
                meta["file_count"] = len(names)
                meta["dex_count"] = sum(
                    1 for n in names if n.endswith(".dex") and "/" not in n
                )
                meta["has_native_libs"] = any(n.startswith("lib/") for n in names)
        except Exception:
            pass

        # Try pyaxmlparser
        try:
            import contextlib
            from pyaxmlparser import APK  # type: ignore[import]

            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                apk = APK(apk_bytes, raw=True)
                meta["package_name"] = apk.get_package() or "unknown"
                meta["app_name"] = apk.get_app_name() or meta["app_name"]
                meta["version_name"] = apk.get_androidversion_name() or "unknown"
                meta["version_code"] = str(apk.get_androidversion_code() or "unknown")
                meta["permissions"] = list(apk.get_permissions() or [])

                # SDK versions
                min_sdk_raw = apk.get_min_sdk_version()
                target_sdk_raw = apk.get_target_sdk_version()
                meta["min_sdk"] = int(min_sdk_raw) if min_sdk_raw else 0
                meta["target_sdk"] = int(target_sdk_raw) if target_sdk_raw else 0

        except Exception as exc:
            meta["parse_error"] = str(exc)
            # Fallback: extract permissions from raw bytes via regex
            meta["permissions"] = self._extract_permissions_raw(apk_bytes)

        return meta

    @staticmethod
    def _extract_permissions_raw(apk_bytes: bytes) -> List[str]:
        """Best-effort permission extraction from raw binary AXML bytes."""
        import re

        pattern = re.compile(
            rb"android\.permission\.([A-Z_]{2,50})",
            re.IGNORECASE,
        )
        raw_perms: set[str] = set()
        with zipfile.ZipFile(io.BytesIO(apk_bytes)) as zf:
            try:
                manifest_bytes = zf.read("AndroidManifest.xml")
                for m in pattern.finditer(manifest_bytes):
                    raw_perms.add("android.permission." + m.group(1).decode("utf-8", errors="replace"))
            except Exception:
                pass
        return list(raw_perms)

    def _score(
        self,
        meta: Dict[str, Any],
        filename: str,
        apk_bytes: bytes,
    ) -> APKAnalysisResult:
        """Build findings, risk score and final classification."""
        permissions: List[str] = meta["permissions"]
        perm_set = set(permissions)

        dangerous: List[str] = []
        findings: List[str] = []
        indicators: List[str] = []
        finding_explanations: List[Dict[str, Any]] = []
        raw_score = 0

        # --- dangerous permission analysis ---
        for perm, info in _DANGEROUS_PERMISSIONS.items():
            if perm in perm_set:
                dangerous.append(perm)
                short = perm.replace("android.permission.", "")
                findings.append(f"Dangerous permission: {short}")
                indicators.append(short)
                raw_score += info["weight"]
                finding_explanations.append(
                    {
                        "indicator": short,
                        "category": info["category"],
                        "explanation": info["explanation"],
                    }
                )

        # --- combination bonuses ---
        combo_findings: List[str] = []
        for combo in _HIGH_RISK_COMBOS:
            if combo["perms"].issubset(perm_set):
                raw_score += combo["bonus"]
                combo_findings.append(combo["name"])
                findings.append(f"High-risk permission combination: {combo['name']}")
                finding_explanations.append(
                    {
                        "indicator": combo["name"],
                        "category": "Permission Combination",
                        "explanation": combo["note"],
                    }
                )

        # --- old SDK target ---
        min_sdk: int = meta["min_sdk"]
        if 0 < min_sdk < 21:
            raw_score += 10
            findings.append(
                f"Legacy minimum SDK target: API {min_sdk} "
                "(Android 5.0 and below - outdated security model)"
            )
            finding_explanations.append(
                {
                    "indicator": f"Min SDK {min_sdk}",
                    "category": "Legacy SDK",
                    "explanation": (
                        "Targeting very old Android versions may bypass modern security "
                        "restrictions such as scoped storage and runtime permissions."
                    ),
                }
            )

        # --- multiple DEX files (obfuscation hint) ---
        dex_count: int = meta.get("dex_count", 0)
        if dex_count > 2:
            raw_score += 5
            findings.append(
                f"Multiple DEX files detected ({dex_count}). "
                "This may indicate obfuscation or a large third-party SDK footprint."
            )

        # --- parse error note ---
        if meta.get("parse_error"):
            findings.append(
                "AndroidManifest.xml could not be fully parsed - "
                "some metadata may be incomplete."
            )

        # Clamp score
        risk_score = min(100, max(0, raw_score))

        # --- classification ---
        if risk_score >= 60:
            classification = "High Risk"
        elif risk_score >= 30:
            classification = "Suspicious"
        else:
            classification = "Safe"

        # --- explanation ---
        if classification == "High Risk":
            explanation = (
                f"This APK requests {len(dangerous)} potentially dangerous permission(s) "
                f"and has a computed risk score of {risk_score}/100. "
                "The permission profile is consistent with apps that perform intrusive data "
                "collection or that exhibit characteristics commonly seen in high-risk software. "
                "This does NOT constitute a confirmed malware detection - legitimate apps may "
                "request some of these permissions - but the combination warrants careful review "
                "before installation."
            )
        elif classification == "Suspicious":
            explanation = (
                f"This APK requests {len(dangerous)} elevated-risk permission(s) "
                f"with a risk score of {risk_score}/100. "
                "Some permissions may be legitimate depending on the app's purpose, "
                "but the profile merits closer scrutiny."
            )
        else:
            n_total = len(permissions)
            explanation = (
                f"No high-risk permissions detected. "
                f"The app requests {n_total} permission(s) in total, "
                f"with a risk score of {risk_score}/100. "
                "The permission profile appears normal for a typical Android application."
            )

        # --- recommendation ---
        if classification == "High Risk":
            recommendation = (
                "⚠️ Exercise extreme caution. Do not install this APK unless you fully trust "
                "the source and understand why these permissions are needed. "
                "Consider scanning the file with a reputable antivirus tool, "
                "and only install from the official Google Play Store or trusted developer channels."
            )
        elif classification == "Suspicious":
            recommendation = (
                "🔍 Review the app's privacy policy and verify its origin before installation. "
                "Grant only the permissions it actively needs, and monitor for unusual behaviour "
                "such as unexpected data usage or battery drain."
            )
        else:
            recommendation = (
                "✅ The permission profile appears normal. "
                "Always install apps from trusted sources such as Google Play, "
                "and keep your device updated with the latest security patches."
            )

        return APKAnalysisResult(
            filename=filename,
            package_name=meta["package_name"],
            app_name=meta["app_name"],
            version_name=meta["version_name"],
            version_code=meta["version_code"],
            min_sdk=meta["min_sdk"],
            target_sdk=meta["target_sdk"],
            permissions=permissions,
            dangerous_permissions=dangerous,
            risk_score=risk_score,
            classification=classification,
            findings=findings,
            detected_indicators=indicators,
            explanation=explanation,
            finding_explanations=finding_explanations,
            recommendation=recommendation,
            combo_findings=combo_findings,
            metadata={
                "file_count": meta.get("file_count", 0),
                "dex_count": meta.get("dex_count", 0),
                "has_native_libs": meta.get("has_native_libs", False),
                "parse_error": meta.get("parse_error"),
            },
            engine_status="apk_security_inspector_active",
        )

