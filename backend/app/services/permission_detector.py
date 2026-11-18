"""CyberShield Permission Analyzer - In-depth Android permission and combination analysis."""

from __future__ import annotations

import io
import re
import zipfile
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


# ---------------------------------------------------------------------------
# Comprehensive Android Permission Knowledge Base
# ---------------------------------------------------------------------------

KNOWN_PERMISSIONS: Dict[str, Dict[str, Any]] = {
    # SMS / Telephony
    "android.permission.READ_SMS": {
        "weight": 20,
        "category": "SMS Interception",
        "danger_level": "Dangerous",
        "explanation": (
            "Allows the app to read incoming and stored SMS messages. "
            "Frequently exploited by banking trojans to intercept one-time passwords (OTP) and 2FA codes."
        ),
    },
    "android.permission.RECEIVE_SMS": {
        "weight": 20,
        "category": "SMS Interception",
        "danger_level": "Dangerous",
        "explanation": (
            "Allows the app to intercept incoming SMS messages in the background before the user sees them. "
            "Commonly abused for silent credential interception."
        ),
    },
    "android.permission.SEND_SMS": {
        "weight": 20,
        "category": "SMS Fraud",
        "danger_level": "Dangerous",
        "explanation": (
            "Allows sending SMS messages without user consent. "
            "Can cause financial loss via unauthorized subscriptions to premium-rate shortcodes."
        ),
    },
    "android.permission.RECEIVE_MMS": {
        "weight": 10,
        "category": "MMS Interception",
        "danger_level": "Dangerous",
        "explanation": "Allows monitoring and intercepting incoming multimedia (MMS) messages.",
    },

    # Contacts & Accounts
    "android.permission.READ_CONTACTS": {
        "weight": 15,
        "category": "Contact Harvesting",
        "danger_level": "Dangerous",
        "explanation": (
            "Allows reading the entire device contact list. "
            "Spyware and phishing actors harvest contacts for identity theft and social engineering attacks."
        ),
    },
    "android.permission.WRITE_CONTACTS": {
        "weight": 10,
        "category": "Contact Tampering",
        "danger_level": "Dangerous",
        "explanation": "Allows adding, altering, or deleting contact entries stored on the device.",
    },
    "android.permission.GET_ACCOUNTS": {
        "weight": 15,
        "category": "Account Harvesting",
        "danger_level": "Dangerous",
        "explanation": (
            "Allows querying the list of Google, corporate, and banking accounts registered on the device. "
            "Enables targeted credential phishing."
        ),
    },

    # Location
    "android.permission.ACCESS_FINE_LOCATION": {
        "weight": 15,
        "category": "GPS Tracking",
        "danger_level": "Dangerous",
        "explanation": (
            "Allows accessing high-precision GPS coordinates. "
            "Enables precise geographic surveillance and movement profiling."
        ),
    },
    "android.permission.ACCESS_COARSE_LOCATION": {
        "weight": 10,
        "category": "Cellular/Wi-Fi Location",
        "danger_level": "Dangerous",
        "explanation": "Allows estimating the device position using cellular tower and Wi-Fi access point data.",
    },
    "android.permission.ACCESS_BACKGROUND_LOCATION": {
        "weight": 25,
        "category": "Covert Location Surveillance",
        "danger_level": "Dangerous",
        "explanation": (
            "Allows continuous location tracking even when the user is not actively interacting with the app. "
            "A hallmark indicator of stalkerware."
        ),
    },

    # Accessibility & Overlay
    "android.permission.BIND_ACCESSIBILITY_SERVICE": {
        "weight": 30,
        "category": "Accessibility Abuse",
        "danger_level": "Privileged / Critical",
        "explanation": (
            "Grants absolute control over the device display: screen reading, keylogging, and simulated touch taps. "
            "Android banking trojans heavily abuse this to bypass MFA and steal credentials."
        ),
    },
    "android.permission.SYSTEM_ALERT_WINDOW": {
        "weight": 20,
        "category": "Overlay Injection",
        "danger_level": "Dangerous",
        "explanation": (
            "Allows drawing floating windows on top of all other running applications. "
            "Primary mechanism used in overlay attacks to spoof banking and social login screens."
        ),
    },
    "android.permission.PACKAGE_USAGE_STATS": {
        "weight": 15,
        "category": "Application Surveillance",
        "danger_level": "Privileged",
        "explanation": (
            "Allows monitoring which apps the user opens, duration of use, and network activity. "
            "Used by trojans to trigger fake overlays when banking apps launch."
        ),
    },

    # Audio, Video & Camera
    "android.permission.RECORD_AUDIO": {
        "weight": 15,
        "category": "Microphone Eavesdropping",
        "danger_level": "Dangerous",
        "explanation": "Allows recording ambient audio from the device microphone without visible notification.",
    },
    "android.permission.CAMERA": {
        "weight": 15,
        "category": "Visual Surveillance",
        "danger_level": "Dangerous",
        "explanation": "Allows capturing photos and video streams from front and rear cameras.",
    },

    # Telephony & Calls
    "android.permission.READ_PHONE_STATE": {
        "weight": 15,
        "category": "Device Fingerprinting",
        "danger_level": "Dangerous",
        "explanation": (
            "Allows reading device IMEI, IMSI, cellular network state, and phone number. "
            "Widely utilized to fingerprint devices across app uninstalls."
        ),
    },
    "android.permission.READ_PHONE_NUMBERS": {
        "weight": 10,
        "category": "Phone Identity",
        "danger_level": "Dangerous",
        "explanation": "Allows retrieving the phone number assigned to the SIM card.",
    },
    "android.permission.READ_CALL_LOG": {
        "weight": 20,
        "category": "Call Log Harvesting",
        "danger_level": "Dangerous",
        "explanation": "Allows reading historical call records, timestamps, caller IDs, and call durations.",
    },
    "android.permission.WRITE_CALL_LOG": {
        "weight": 15,
        "category": "Call History Tampering",
        "danger_level": "Dangerous",
        "explanation": "Allows altering or deleting call history records to conceal unauthorized telephone activity.",
    },
    "android.permission.PROCESS_OUTGOING_CALLS": {
        "weight": 15,
        "category": "Call Interception",
        "danger_level": "Dangerous",
        "explanation": "Allows intercepting, redirecting, or terminating outgoing telephone calls.",
    },

    # Persistence & Droppers
    "android.permission.REQUEST_INSTALL_PACKAGES": {
        "weight": 25,
        "category": "Package Dropper",
        "danger_level": "Dangerous",
        "explanation": (
            "Allows requesting the installation of auxiliary APK files. "
            "Commonly exploited by dropper malware to silently download secondary payloads."
        ),
    },
    "android.permission.RECEIVE_BOOT_COMPLETED": {
        "weight": 15,
        "category": "Reboot Persistence",
        "danger_level": "Elevated",
        "explanation": (
            "Allows starting background services automatically every time the device powers on. "
            "Used by persistent malware to ensure survivability."
        ),
    },

    # Storage Access
    "android.permission.MANAGE_EXTERNAL_STORAGE": {
        "weight": 20,
        "category": "Unrestricted Storage Access",
        "danger_level": "Dangerous",
        "explanation": (
            "Bypasses Android scoped storage to access all files, documents, downloads, and photos. "
            "Excessive for standard consumer applications."
        ),
    },
    "android.permission.READ_EXTERNAL_STORAGE": {
        "weight": 8,
        "category": "Storage Reading",
        "danger_level": "Dangerous",
        "explanation": "Allows reading user files and photos stored on external storage.",
    },
    "android.permission.WRITE_EXTERNAL_STORAGE": {
        "weight": 10,
        "category": "Storage Modification",
        "danger_level": "Dangerous",
        "explanation": "Allows writing, modifying, and deleting files on external storage.",
    },

    # System Modification
    "android.permission.WRITE_SETTINGS": {
        "weight": 10,
        "category": "System Configuration",
        "danger_level": "Privileged",
        "explanation": "Allows altering global operating system settings.",
    },
    "android.permission.WRITE_SECURE_SETTINGS": {
        "weight": 25,
        "category": "Privileged Security Modification",
        "danger_level": "Privileged",
        "explanation": "Allows modifying protected Android system security configuration.",
    },

    # Network & Connectivity
    "android.permission.INTERNET": {
        "weight": 0,
        "category": "Network Operations",
        "danger_level": "Normal",
        "explanation": "Allows the app to open network sockets and transmit data over the Internet.",
    },
    "android.permission.ACCESS_NETWORK_STATE": {
        "weight": 0,
        "category": "Network Status",
        "danger_level": "Normal",
        "explanation": "Allows viewing information about active network connections.",
    },
    "android.permission.CHANGE_NETWORK_STATE": {
        "weight": 5,
        "category": "Network Modification",
        "danger_level": "Elevated",
        "explanation": "Allows changing network connectivity state.",
    },
    "android.permission.CHANGE_WIFI_STATE": {
        "weight": 5,
        "category": "Wi-Fi Modification",
        "danger_level": "Elevated",
        "explanation": "Allows connecting, disconnecting, and modifying Wi-Fi networks.",
    },
}

# ---------------------------------------------------------------------------
# High-Risk & Suspicious Permission Combinations
# ---------------------------------------------------------------------------

DANGEROUS_COMBOS: List[Dict[str, Any]] = [
    {
        "name": "Banking Trojan Signature (SMS + Accessibility)",
        "perms": {"android.permission.READ_SMS", "android.permission.BIND_ACCESSIBILITY_SERVICE"},
        "bonus": 25,
        "severity": "Critical",
        "explanation": (
            "Combining SMS access with Accessibility Service allows an application to "
            "read incoming OTP verification codes while simultaneously controlling the screen. "
            "This is the definitive signature of automated banking fraud."
        ),
    },
    {
        "name": "Overlay Phishing Attack (SMS + Overlay)",
        "perms": {"android.permission.READ_SMS", "android.permission.SYSTEM_ALERT_WINDOW"},
        "bonus": 20,
        "severity": "High",
        "explanation": (
            "SMS reading paired with System Alert Window permits injecting deceptive login overlays "
            "over legitimate banking apps and capturing the incoming two-factor authorization SMS."
        ),
    },
    {
        "name": "Silent Dropper Pipeline (Install Packages + Accessibility)",
        "perms": {"android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.BIND_ACCESSIBILITY_SERVICE"},
        "bonus": 25,
        "severity": "Critical",
        "explanation": (
            "Requesting package installation alongside Accessibility Service enables "
            "unattended, automated installation of secondary malware payloads without user confirmation."
        ),
    },
    {
        "name": "Surveillance & Wiretapping Suite (Microphone + Location)",
        "perms": {"android.permission.RECORD_AUDIO", "android.permission.ACCESS_FINE_LOCATION"},
        "bonus": 15,
        "severity": "High",
        "explanation": (
            "Continuous location tracking combined with ambient microphone recording "
            "constitutes an extensive physical surveillance profile commonly seen in stalkerware."
        ),
    },
    {
        "name": "Full Covert Wiretapping (Camera + Mic + Background Location)",
        "perms": {
            "android.permission.RECORD_AUDIO",
            "android.permission.CAMERA",
            "android.permission.ACCESS_BACKGROUND_LOCATION",
        },
        "bonus": 25,
        "severity": "Critical",
        "explanation": (
            "Simultaneous background location tracking, camera access, and microphone recording "
            "provides total audio-visual and physical tracking capability."
        ),
    },
    {
        "name": "Persistent Tracking (Background Location + Reboot Persistence)",
        "perms": {"android.permission.ACCESS_BACKGROUND_LOCATION", "android.permission.RECEIVE_BOOT_COMPLETED"},
        "bonus": 15,
        "severity": "High",
        "explanation": (
            "Ensures the application starts immediately on device boot and tracks location silently in the background."
        ),
    },
    {
        "name": "Identity & Financial 2FA Theft (Contacts + SMS + Phone State)",
        "perms": {
            "android.permission.READ_CONTACTS",
            "android.permission.READ_SMS",
            "android.permission.READ_PHONE_STATE",
        },
        "bonus": 20,
        "severity": "High",
        "explanation": (
            "Allows scraping user contacts, intercepting SMS messages, and collecting unique hardware/SIM identifiers."
        ),
    },
    {
        "name": "Ransomware / Dropper Profile (Manage Storage + Install Packages)",
        "perms": {
            "android.permission.MANAGE_EXTERNAL_STORAGE",
            "android.permission.REQUEST_INSTALL_PACKAGES",
        },
        "bonus": 20,
        "severity": "High",
        "explanation": (
            "Unrestricted file storage access combined with APK installation capability "
            "is consistent with ransomware droppers and destructive payloads."
        ),
    },
    {
        "name": "Call Interception & Profiling (Outgoing Calls + Call Log + Phone State)",
        "perms": {
            "android.permission.PROCESS_OUTGOING_CALLS",
            "android.permission.READ_CALL_LOG",
            "android.permission.READ_PHONE_STATE",
        },
        "bonus": 15,
        "severity": "High",
        "explanation": (
            "Complete telephony interception: can redirect phone calls, inspect call logs, and read SIM identity."
        ),
    },
]


# ---------------------------------------------------------------------------
# Structured Result Models
# ---------------------------------------------------------------------------

@dataclass
class PermissionAnalysisResult:
    """Structured assessment of Android permissions and risk profile."""
    package_name: str
    app_name: str
    version_name: str
    version_code: str
    min_sdk: int
    target_sdk: int
    total_permissions_count: int
    dangerous_permissions_count: int
    permissions: List[str]
    dangerous_permissions: List[str]
    risk_score: int
    classification: str  # "Safe", "Suspicious", "High Risk", "Critical"
    findings: List[str]
    detected_indicators: List[str]
    combo_findings: List[str]
    finding_explanations: List[Dict[str, Any]]
    explanation: str
    recommendation: str
    recommendations: List[str]
    metadata: Dict[str, Any]
    engine_status: str = "permission_analyzer_active"


# ---------------------------------------------------------------------------
# Permission Analyzer Engine
# ---------------------------------------------------------------------------

class PermissionAnalyzer:
    """Evaluates Android permissions, dangerous combinations, and assigns risk scores."""

    MAX_FILE_SIZE: int = 52_428_800  # 50 MB

    def analyze_apk_bytes(self, apk_bytes: bytes, filename: str) -> PermissionAnalysisResult:
        """Analyze an APK archive by extracting AndroidManifest.xml and scoring its permissions."""
        self._validate_apk_zip(apk_bytes, filename)
        meta = self._extract_manifest_metadata(apk_bytes, filename)
        return self._score_permissions(meta, filename)

    def analyze_permissions_list(
        self,
        permissions: List[str],
        app_name: str = "Android Application",
        package_name: str = "unknown.package",
        min_sdk: int = 0,
        target_sdk: int = 0,
        version_name: str = "1.0",
        version_code: str = "1",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> PermissionAnalysisResult:
        """Analyze an arbitrary list of Android permission strings (e.g. from an installed app)."""
        # Normalize permission names (ensure 'android.permission.' prefix where appropriate)
        normalized_perms: List[str] = []
        for p in permissions:
            cleaned = p.strip()
            if not cleaned:
                continue
            if not cleaned.startswith("android.permission.") and "." not in cleaned:
                cleaned = f"android.permission.{cleaned}"
            normalized_perms.append(cleaned)

        meta: Dict[str, Any] = {
            "app_name": app_name,
            "package_name": package_name,
            "version_name": version_name,
            "version_code": version_code,
            "min_sdk": min_sdk,
            "target_sdk": target_sdk,
            "permissions": list(dict.fromkeys(normalized_perms)),
            "metadata": metadata or {},
        }
        return self._score_permissions(meta, filename=f"{package_name}.apk")

    # -----------------------------------------------------------------------
    # Manifest Extraction Helpers
    # -----------------------------------------------------------------------

    def _validate_apk_zip(self, data: bytes, filename: str) -> None:
        """Validate that bytes represent a valid ZIP archive containing AndroidManifest.xml."""
        if not data:
            raise ValueError("The uploaded APK file is empty.")

        if not filename.lower().endswith(".apk"):
            raise ValueError(f"Invalid file extension for '{filename}'. Only .apk packages are supported.")

        if not zipfile.is_zipfile(io.BytesIO(data)):
            raise ValueError("The uploaded file is not a valid APK (ZIP) archive.")

        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = set(zf.namelist())
            if "AndroidManifest.xml" not in names:
                raise ValueError("The archive does not contain AndroidManifest.xml and is not a valid APK.")

    def _extract_manifest_metadata(self, apk_bytes: bytes, filename: str) -> Dict[str, Any]:
        """Extract package details and permissions using pyaxmlparser with binary fallback."""
        meta: Dict[str, Any] = {
            "app_name": filename.removesuffix(".apk").replace("_", " ").title(),
            "package_name": "unknown.package",
            "version_name": "1.0",
            "version_code": "1",
            "min_sdk": 0,
            "target_sdk": 0,
            "permissions": [],
            "parse_error": None,
        }

        # Attempt pyaxmlparser parsing
        try:
            import contextlib
            from pyaxmlparser import APK  # type: ignore[import]

            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                apk = APK(apk_bytes, raw=True)
                if apk.get_package():
                    meta["package_name"] = apk.get_package()
                if apk.get_app_name():
                    meta["app_name"] = apk.get_app_name()
                if apk.get_androidversion_name():
                    meta["version_name"] = apk.get_androidversion_name()
                if apk.get_androidversion_code():
                    meta["version_code"] = str(apk.get_androidversion_code())
                if apk.get_permissions():
                    meta["permissions"] = list(apk.get_permissions())

                min_sdk_raw = apk.get_min_sdk_version()
                target_sdk_raw = apk.get_target_sdk_version()
                if min_sdk_raw:
                    try:
                        meta["min_sdk"] = int(min_sdk_raw)
                    except (ValueError, TypeError):
                        pass
                if target_sdk_raw:
                    try:
                        meta["target_sdk"] = int(target_sdk_raw)
                    except (ValueError, TypeError):
                        pass
        except Exception as exc:
            meta["parse_error"] = str(exc)

        # Fallback regex extraction if permissions list is empty
        if not meta["permissions"]:
            meta["permissions"] = self._extract_permissions_raw_regex(apk_bytes)

        return meta

    @staticmethod
    def _extract_permissions_raw_regex(apk_bytes: bytes) -> List[str]:
        """Regex-based extraction from binary AndroidManifest.xml."""
        pattern = re.compile(rb"android\.permission\.([A-Z_]{2,60})", re.IGNORECASE)
        perms: Set[str] = set()
        try:
            with zipfile.ZipFile(io.BytesIO(apk_bytes)) as zf:
                manifest_bytes = zf.read("AndroidManifest.xml")
                for match in pattern.finditer(manifest_bytes):
                    suffix = match.group(1).decode("utf-8", errors="replace")
                    perms.add(f"android.permission.{suffix}")
        except Exception:
            pass
        return sorted(list(perms))

    # -----------------------------------------------------------------------
    # Risk Scoring & Classification
    # -----------------------------------------------------------------------

    def _score_permissions(self, meta: Dict[str, Any], filename: str) -> PermissionAnalysisResult:
        permissions: List[str] = meta["permissions"]
        perm_set = set(permissions)

        dangerous_perms: List[str] = []
        findings: List[str] = []
        indicators: List[str] = []
        combo_findings: List[str] = []
        finding_explanations: List[Dict[str, Any]] = []
        recommendations: List[str] = []
        raw_score = 0
        has_critical_combo = False

        # 1. Analyze dangerous permissions individually
        for perm, info in KNOWN_PERMISSIONS.items():
            if perm in perm_set:
                short_name = perm.replace("android.permission.", "")
                weight = info["weight"]

                if weight > 0:
                    dangerous_perms.append(perm)
                    raw_score += weight
                    findings.append(f"Dangerous permission requested: {short_name}")
                    indicators.append(short_name)
                    finding_explanations.append({
                        "indicator": short_name,
                        "permission": perm,
                        "category": info["category"],
                        "danger_level": info["danger_level"],
                        "risk_points": weight,
                        "explanation": info["explanation"],
                    })

        # 2. Analyze dangerous permission combinations
        for combo in DANGEROUS_COMBOS:
            if combo["perms"].issubset(perm_set):
                bonus = combo["bonus"]
                raw_score += bonus
                combo_name = combo["name"]
                combo_findings.append(combo_name)
                findings.append(f"High-risk permission combination: {combo_name} (+{bonus} pts)")
                if combo.get("severity") == "Critical":
                    has_critical_combo = True

                finding_explanations.append({
                    "indicator": combo_name,
                    "permission": ", ".join([p.replace("android.permission.", "") for p in combo["perms"]]),
                    "category": "Permission Combination",
                    "danger_level": combo.get("severity", "High"),
                    "risk_points": bonus,
                    "explanation": combo["explanation"],
                })

        # 3. Excessive permission volume penalty
        if len(dangerous_perms) >= 8:
            raw_score += 15
            findings.append(f"Excessive dangerous permissions requested ({len(dangerous_perms)} sensitive privileges)")
        elif len(dangerous_perms) >= 4:
            raw_score += 8
            findings.append(f"Multiple dangerous permissions requested ({len(dangerous_perms)} sensitive privileges)")

        # 4. Outdated Target / Min SDK Penalty
        min_sdk: int = meta.get("min_sdk", 0)
        target_sdk: int = meta.get("target_sdk", 0)
        if 0 < min_sdk < 21:
            raw_score += 10
            findings.append(f"Outdated minimum SDK target (API {min_sdk} / Android 5.0). Bypasses runtime permission protections.")

        # Clamp risk score
        risk_score = min(100, max(0, raw_score))

        # 5. Four-tier classification: Safe, Suspicious, High Risk, Critical
        if has_critical_combo or risk_score >= 80:
            classification = "Critical"
        elif risk_score >= 60:
            classification = "High Risk"
        elif risk_score >= 30:
            classification = "Suspicious"
        else:
            classification = "Safe"

        # 6. Actionable recommendations & explanations
        if classification == "Critical":
            explanation = (
                f"Critical permission exposure detected with a computed risk score of {risk_score}/100. "
                f"The application requests {len(dangerous_perms)} sensitive permissions including dangerous "
                "privilege combinations commonly associated with banking trojans or surveillance software. "
                "While legitimate apps may request some sensitive permissions, this combination warrants extreme caution."
            )
            recommendations = [
                "Do not grant Accessibility Service permission unless you verified the developer directly.",
                "Review Android Settings > Apps > Permissions to restrict background location and SMS access.",
                "Verify whether this application was installed from the official Google Play Store.",
                "If this app does not legitimately require banking or SMS operations, consider uninstalling it.",
            ]
            recommendation = recommendations[0]

        elif classification == "High Risk":
            explanation = (
                f"Elevated risk score of {risk_score}/100 with {len(dangerous_perms)} sensitive permissions requested. "
                "The requested capabilities significantly expand the device's attack surface and allow access to "
                "private user data such as location, contacts, or storage."
            )
            recommendations = [
                "Inspect granted permissions in Android Settings > Apps > [App Name] > Permissions.",
                "Set location access to 'Allow only while using the app' rather than 'Always allow'.",
                "Deny access to Contacts and Phone State if unrelated to core app features.",
                "Ensure Play Protect is enabled on your device.",
            ]
            recommendation = recommendations[0]

        elif classification == "Suspicious":
            explanation = (
                f"Moderate permission profile with a risk score of {risk_score}/100. "
                f"Requests {len(dangerous_perms)} elevated permissions. "
                "Assess whether the permissions match the advertised features of the application."
            )
            recommendations = [
                "Review if the application's functionality justifies each requested permission.",
                "Keep the application updated to the latest available version.",
                "Monitor for unexpected data usage or battery consumption.",
            ]
            recommendation = recommendations[0]

        else:
            explanation = (
                f"Normal permission footprint with a low risk score of {risk_score}/100. "
                f"Total permissions requested: {len(permissions)} ({len(dangerous_perms)} sensitive). "
                "No dangerous combinations or anomalous permission structures detected."
            )
            recommendations = [
                "The application's permission footprint appears normal.",
                "Always verify app authenticity and install exclusively from trusted app stores.",
            ]
            recommendation = recommendations[0]

        return PermissionAnalysisResult(
            package_name=meta.get("package_name", "unknown.package"),
            app_name=meta.get("app_name", filename.removesuffix(".apk")),
            version_name=meta.get("version_name", "1.0"),
            version_code=meta.get("version_code", "1"),
            min_sdk=meta.get("min_sdk", 0),
            target_sdk=meta.get("target_sdk", 0),
            total_permissions_count=len(permissions),
            dangerous_permissions_count=len(dangerous_perms),
            permissions=permissions,
            dangerous_permissions=dangerous_perms,
            risk_score=risk_score,
            classification=classification,
            findings=findings,
            detected_indicators=indicators,
            combo_findings=combo_findings,
            finding_explanations=finding_explanations,
            explanation=explanation,
            recommendation=recommendation,
            recommendations=recommendations,
            metadata={
                "parse_error": meta.get("parse_error"),
                "has_critical_combo": has_critical_combo,
                "custom_metadata": meta.get("metadata", {}),
            },
            engine_status="permission_analyzer_active",
        )

