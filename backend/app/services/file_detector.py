"""CyberShield Static File Threat Detection Engine.

Performs static heuristic analysis of uploaded files without execution:
- Magic bytes / file signature validation vs file extension
- Mismatched file type detection (e.g. Windows PE disguised as PDF/JPG)
- Dangerous extensions (executable binaries, scripts, installers)
- Double-extension deception (e.g. invoice.pdf.exe)
- Safe archive inspection (Zip Slip / path traversal, zip bombs, hidden executables)
- Script & document heuristic inspection (PowerShell hidden windows, webclient downloads, VBS shells, PDF JS/Launch)
- Strictly static inspection: NEVER executes uploaded files
"""

from __future__ import annotations

import hashlib
import io
import os
import re
import tarfile
import zipfile
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Magic Byte Signatures & Known Mappings
# ---------------------------------------------------------------------------

MAGIC_SIGNATURES: List[Tuple[bytes, str, str, List[str]]] = [
    # (Magic prefix, Formal Type, Category, Typical Extensions)
    (b"MZ", "Windows Portable Executable (PE)", "Executable", [".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx"]),
    (b"\x7fELF", "Linux ELF Executable", "Executable", [".elf", ".bin", ".so", ""]),
    (b"\xca\xfe\xba\xbe", "Java Class / Mach-O Fat Binary", "Executable", [".class", ""]),
    (b"PK\x03\x04", "ZIP Compressed Archive / Office Open XML", "Archive / Document", [".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk", ".epub"]),
    (b"PK\x05\x06", "Empty ZIP Archive", "Archive", [".zip"]),
    (b"Rar!\x1a\x07", "RAR Compressed Archive", "Archive", [".rar"]),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip Compressed Archive", "Archive", [".7z"]),
    (b"\x1f\x8b", "GZIP Compressed File", "Archive", [".gz", ".tgz"]),
    (b"BZh", "BZIP2 Compressed File", "Archive", [".bz2"]),
    (b"%PDF-", "PDF Document", "Document", [".pdf"]),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE2 Compound Document", "Legacy Office", [".doc", ".xls", ".ppt", ".msi"]),
    (b"\xff\xd8\xff", "JPEG Image", "Image", [".jpg", ".jpeg"]),
    (b"\x89PNG\r\n\x1a\n", "PNG Image", "Image", [".png"]),
    (b"GIF87a", "GIF Image", "Image", [".gif"]),
    (b"GIF89a", "GIF Image", "Image", [".gif"]),
    (b"RIFF", "Resource Interchange File Format (WAV/AVI/WEBP)", "Media", [".wav", ".avi", ".webp"]),
]

DANGEROUS_EXTENSIONS: Dict[str, Tuple[str, int, str]] = {
    # (Category, Risk Weight, Explanation)
    ".exe": ("Executable Binary", 35, "Directly executable Windows binary; can execute arbitrary code."),
    ".scr": ("Screensaver Executable", 35, "Standard PE executable file frequently abused for phishing malware delivery."),
    ".pif": ("Program Information File", 35, "Legacy executable format commonly abused in email malware campaigns."),
    ".dll": ("Dynamic Link Library", 30, "Shared library binary that can be loaded to execute code via DLL side-loading."),
    ".bat": ("Batch Script", 25, "Command shell script capable of executing system-level operations."),
    ".cmd": ("Command Script", 25, "Windows command interpreter script capable of invoking system commands."),
    ".ps1": ("PowerShell Script", 30, "PowerShell script with extensive access to Windows internals, WMI, and network sockets."),
    ".psm1": ("PowerShell Module", 30, "PowerShell script module capable of loading automation payloads."),
    ".vbs": ("VBScript Script", 30, "Visual Basic script engine widely exploited by loaders and banking downloaders."),
    ".vbe": ("Encoded VBScript", 35, "Obfuscated / encoded VBScript designed to evade basic text signature scanning."),
    ".js": ("JavaScript Script", 25, "Standalone Windows Script Host (WSH) JavaScript file."),
    ".jse": ("Encoded JavaScript", 30, "Encoded Windows Script Host file hiding underlying commands."),
    ".wsf": ("Windows Script File", 30, "XML-based script capable of executing multiple scripting languages."),
    ".hta": ("HTML Application", 35, "Runs outside browser security sandbox with full administrative privileges."),
    ".cpl": ("Control Panel Item", 30, "Specialized DLL format executed automatically by Windows Explorer."),
    ".msc": ("Management Console Snap-in", 25, "Windows Management Console document capable of launching system tools."),
    ".iso": ("Disk Image", 20, "Virtual disk container often used to bypass Mark-of-the-Web (MOTW) protections."),
    ".img": ("Disk Image", 20, "Disk image file used to deliver multi-stage payloads."),
    ".vhd": ("Virtual Hard Disk", 20, "Virtual disk container used for evasion."),
    ".jar": ("Java Archive", 25, "Java executable archive capable of cross-platform execution."),
    ".lnk": ("Windows Shortcut", 25, "Windows shell shortcut commonly weaponized with hidden PowerShell command-line arguments."),
    ".reg": ("Registry Script", 25, "Directly modifies Windows Registry keys and persistence settings."),
}

SCRIPT_EXTENSIONS: Set[str] = {
    ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".sh", ".bash", ".py", ".hta"
}


@dataclass
class FileFindingDetail:
    indicator: str
    title: str
    risk_level: str
    explanation: str

    def to_dict(self) -> Dict[str, str]:
        return {
            "indicator": self.indicator,
            "title": self.title,
            "risk_level": self.risk_level,
            "explanation": self.explanation,
        }


@dataclass
class FileAnalysisResult:
    filename: str
    file_size_bytes: int
    detected_mime: str
    file_extension: str
    is_archive: bool
    risk_score: int
    classification: str  # Safe, Suspicious, High Risk, Critical
    threat_categories: List[str] = field(default_factory=list)
    detected_indicators: List[str] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)
    finding_explanations: List[Dict[str, str]] = field(default_factory=list)
    explanation: str = ""
    recommendation: str = ""
    recommendations: List[str] = field(default_factory=list)
    archive_contents: List[str] = field(default_factory=list)
    md5: str = ""
    sha1: str = ""
    sha256: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    engine_status: str = "file_threat_detector_active"


class FileThreatDetector:
    """Static heuristic file threat detector with zero execution guarantees."""

    MAX_FILE_SIZE: int = 26_214_400  # 25 MB

    def analyze_bytes(
        self,
        file_bytes: bytes,
        filename: str,
        content_type: Optional[str] = None,
    ) -> FileAnalysisResult:
        """Analyze file bytes for deceptive extensions, magic bytes mismatches, and script indicators."""
        clean_filename = os.path.basename(filename.strip())
        if not clean_filename:
            raise ValueError("Filename must be provided.")

        file_size = len(file_bytes)
        if file_size == 0:
            raise ValueError("Uploaded file is empty (0 bytes).")

        if file_size > self.MAX_FILE_SIZE:
            raise ValueError(f"File size exceeds maximum supported limit of {self.MAX_FILE_SIZE // (1024 * 1024)}MB.")

        raw_score = 0
        categories: Set[str] = set()
        indicators: List[str] = []
        findings: List[str] = []
        finding_details: List[FileFindingDetail] = []
        archive_members: List[str] = []
        is_archive = False

        # Extract file extension
        _, ext = os.path.splitext(clean_filename.lower())

        # 1. Inspect Magic Bytes
        detected_type, detected_category = self._identify_magic_bytes(file_bytes)

        # 2. Detect Mismatched Signatures (e.g. Executable disguised as PDF or Image)
        if detected_type == "Windows Portable Executable (PE)":
            if ext not in [".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx"]:
                raw_score += 85
                categories.add("Deceptive Executable Disguise")
                indicators.append("Disguised Windows PE Executable")
                findings.append(
                    f"CRITICAL: File possesses Windows PE executable magic bytes (MZ), but uses a non-executable extension '{ext}'."
                )
                finding_details.append(
                    FileFindingDetail(
                        indicator="Disguised PE Executable",
                        title="Executable Header Mismatch",
                        risk_level="Critical",
                        explanation="The file is a compiled Windows binary disguised with an innocuous extension (such as PDF or image). This is a high-confidence malware delivery technique.",
                    )
                )

        if detected_type == "Linux ELF Executable":
            if ext not in [".elf", ".bin", ".so", ""]:
                raw_score += 40
                categories.add("Deceptive Executable Disguise")
                indicators.append("Disguised Linux ELF")
                findings.append(f"File has Linux ELF executable header but uses extension '{ext}'.")

        # 3. Detect Double Extensions (e.g., invoice.pdf.exe)
        name_parts = clean_filename.lower().split(".")
        if len(name_parts) >= 3:
            penultimate_ext = f".{name_parts[-2]}"
            final_ext = f".{name_parts[-1]}"
            if penultimate_ext in [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".png", ".txt"]:
                if final_ext in DANGEROUS_EXTENSIONS:
                    raw_score += 45
                    categories.add("Double Extension Deception")
                    indicators.append("Double Extension Trick")
                    findings.append(
                        f"Deceptive double extension detected: '{clean_filename}'. Attacker poses as '{penultimate_ext}' document while executing as '{final_ext}' binary."
                    )
                    finding_details.append(
                        FileFindingDetail(
                            indicator=f"Double Extension: {penultimate_ext}{final_ext}",
                            title="Camouflaged Executable Name",
                            risk_level="Critical",
                            explanation="Exploits Windows default 'hide known file extensions' setting to make an executable look like an ordinary document.",
                        )
                    )

        # 4. Dangerous Extension Direct Assessment
        if ext in DANGEROUS_EXTENSIONS:
            cat_name, weight, expl = DANGEROUS_EXTENSIONS[ext]
            raw_score += weight
            categories.add(cat_name)
            indicators.append(f"Dangerous Ext {ext}")
            findings.append(f"Dangerous file extension: {ext} ({cat_name})")
            finding_details.append(
                FileFindingDetail(
                    indicator=ext,
                    title=cat_name,
                    risk_level="High" if weight >= 30 else "Medium",
                    explanation=expl,
                )
            )

        # 5. Safe In-Memory Archive Inspection
        if detected_type and "ZIP" in detected_type or ext == ".zip":
            is_archive = True
            archive_score, members = self._inspect_zip_archive(
                file_bytes, categories, indicators, findings, finding_details
            )
            raw_score += archive_score
            archive_members.extend(members)

        elif ext in [".tar", ".tgz", ".tar.gz"] or file_bytes.startswith(b"\x1f\x8b"):
            is_archive = True
            archive_score, members = self._inspect_tar_archive(
                file_bytes, categories, indicators, findings, finding_details
            )
            raw_score += archive_score
            archive_members.extend(members)

        # 6. Text / Script Heuristics (if text or script)
        if ext in SCRIPT_EXTENSIONS or detected_category in ["Script", "Document"]:
            script_score = self._inspect_script_text(
                file_bytes, categories, indicators, findings, finding_details
            )
            raw_score += script_score

        # 7. Document Specific Checks (PDF)
        if ext == ".pdf" or detected_type == "PDF Document":
            pdf_score = self._inspect_pdf_indicators(
                file_bytes, categories, indicators, findings, finding_details
            )
            raw_score += pdf_score

        # Clamp Risk Score
        risk_score = min(100, max(0, raw_score))

        # 8. Four-Tier Classification
        if risk_score >= 80 or "Deceptive Executable Disguise" in categories or "Zip Slip Path Traversal" in categories:
            classification = "Critical"
        elif risk_score >= 60:
            classification = "High Risk"
        elif risk_score >= 30:
            classification = "Suspicious"
        else:
            classification = "Safe"

        # 9. Cryptographic Hash Generation (Forensics & Intelligence)
        md5_hash = hashlib.md5(file_bytes).hexdigest()
        sha1_hash = hashlib.sha1(file_bytes).hexdigest()
        sha256_hash = hashlib.sha256(file_bytes).hexdigest()

        # 10. Recommendations & Context
        explanation, recommendation, recommendations = self._generate_advice(
            classification, risk_score, clean_filename, detected_type, findings, categories
        )

        return FileAnalysisResult(
            filename=clean_filename,
            file_size_bytes=file_size,
            detected_mime=detected_type,
            file_extension=ext or "none",
            is_archive=is_archive,
            risk_score=risk_score,
            classification=classification,
            threat_categories=sorted(list(categories)),
            detected_indicators=indicators,
            findings=findings,
            finding_explanations=[d.to_dict() for d in finding_details],
            explanation=explanation,
            recommendation=recommendation,
            recommendations=recommendations,
            archive_contents=archive_members[:50],  # Limit to 50 entries
            md5=md5_hash,
            sha1=sha1_hash,
            sha256=sha256_hash,
            metadata={
                "detected_type": detected_type,
                "detected_category": detected_category,
                "archive_member_count": len(archive_members),
                "md5": md5_hash,
                "sha1": sha1_hash,
                "sha256": sha256_hash,
            },
            engine_status="file_threat_detector_active",
        )

    # -----------------------------------------------------------------------
    # Internal Helpers
    # -----------------------------------------------------------------------

    def _identify_magic_bytes(self, data: bytes) -> Tuple[str, str]:
        """Examine initial bytes for standardized magic signatures."""
        for magic, name, category, _ in MAGIC_SIGNATURES:
            if data.startswith(magic):
                return name, category
        return "Unknown Binary / Plain Text", "Generic"

    def _inspect_zip_archive(
        self,
        data: bytes,
        categories: Set[str],
        indicators: List[str],
        findings: List[str],
        details: List[FileFindingDetail],
    ) -> Tuple[int, List[str]]:
        score = 0
        members: List[str] = []

        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                infolist = zf.infolist()
                total_uncompressed = 0
                has_hidden_exec = False
                has_path_traversal = False

                for info in infolist:
                    filename = info.filename
                    members.append(filename)
                    total_uncompressed += info.file_size

                    # Check for Path Traversal / Zip Slip
                    if ".." in filename or filename.startswith("/") or filename.startswith("\\") or (len(filename) > 2 and filename[1] == ":"):
                        has_path_traversal = True

                    # Check for hidden dangerous files inside archive
                    _, inner_ext = os.path.splitext(filename.lower())
                    if inner_ext in DANGEROUS_EXTENSIONS:
                        has_hidden_exec = True

                # Evaluate Path Traversal
                if has_path_traversal:
                    score += 85
                    categories.add("Zip Slip Path Traversal")
                    indicators.append("Path Traversal in Archive")
                    findings.append("Archive contains directory traversal entries ('..' or absolute paths). Exploits Zip Slip vulnerability.")
                    details.append(
                        FileFindingDetail(
                            indicator="Zip Slip Traversal",
                            title="Arbitrary File Overwrite Risk",
                            risk_level="Critical",
                            explanation="The archive attempts to extract files outside the destination directory using '../' sequences.",
                        )
                    )

                # Evaluate Hidden Executable
                if has_hidden_exec:
                    score += 30
                    categories.add("Embedded Executable in Archive")
                    indicators.append("Archive Executable Member")
                    findings.append("Archive contains executable files or scripts (.exe, .bat, .ps1, .vbs).")
                    details.append(
                        FileFindingDetail(
                            indicator="Executable Inside Archive",
                            title="Executable Payload Inside Compressed Archive",
                            risk_level="High",
                            explanation="Malware distributors frequently pack executables inside ZIP archives to evade email gateway filters.",
                        )
                    )

                # Check for Zip Bomb compression ratio (> 80:1 and > 20MB)
                compressed_size = len(data)
                if compressed_size > 0:
                    ratio = total_uncompressed / compressed_size
                    if ratio > 80 and total_uncompressed > 20_000_000:
                        score += 35
                        categories.add("Potential Zip Bomb (Decompression Bomb)")
                        indicators.append("Anomalous Compression Ratio")
                        findings.append(f"Extreme compression ratio ({ratio:.1f}:1). Potential decompression bomb designed to exhaust resources.")
                        details.append(
                            FileFindingDetail(
                                indicator=f"Compression Ratio {ratio:.1f}:1",
                                title="Resource Exhaustion Risk",
                                risk_level="High",
                                explanation="Massive uncompressed file size compressed into a small file is characteristic of a denial-of-service zip bomb.",
                            )
                        )

        except zipfile.BadZipFile:
            findings.append("Archive is corrupted or malformed ZIP.")
        except Exception as e:
            findings.append(f"Error inspecting archive members: {e}")

        return score, members

    def _inspect_tar_archive(
        self,
        data: bytes,
        categories: Set[str],
        indicators: List[str],
        findings: List[str],
        details: List[FileFindingDetail],
    ) -> Tuple[int, List[str]]:
        score = 0
        members: List[str] = []
        try:
            with tarfile.open(fileobj=io.BytesIO(data)) as tf:
                for member in tf.getmembers():
                    members.append(member.name)
                    if ".." in member.name or member.name.startswith("/"):
                        score += 40
                        categories.add("Zip Slip Path Traversal")
                        findings.append(f"Tar archive contains path traversal member: '{member.name}'.")
        except Exception:
            pass
        return score, members

    def _inspect_script_text(
        self,
        data: bytes,
        categories: Set[str],
        indicators: List[str],
        findings: List[str],
        details: List[FileFindingDetail],
    ) -> int:
        score = 0
        try:
            text = data[:100_000].decode("utf-8", errors="ignore")  # Inspect first 100KB of text
        except Exception:
            return 0

        # Suspicious PowerShell patterns
        ps_patterns = [
            (re.compile(r"-(?:WindowStyle|w)\s+(?:Hidden|1)", re.I), "PowerShell Hidden Window", 25, "Hides execution console window from user view."),
            (re.compile(r"-(?:ExecutionPolicy|ep)\s+(?:Bypass|Unrestricted)", re.I), "Execution Policy Bypass", 20, "Bypasses system PowerShell execution restrictions."),
            (re.compile(r"\b(?:DownloadString|DownloadFile|Net\.WebClient|Invoke-WebRequest|curl\s+-s)\b", re.I), "Remote Payload Download", 20, "Initiates background download of secondary code."),
            (re.compile(r"\b(?:Invoke-Expression|IEX)\b", re.I), "Dynamic Code Execution (IEX)", 20, "Executes dynamically downloaded or de-obfuscated script text."),
            (re.compile(r"\[System\.Convert\]::FromBase64String", re.I), "Base64 Payload Decoding", 15, "Decodes obfuscated base64 encoded strings in memory."),
            (re.compile(r"\b(?:WScript\.Shell|CreateObject\([\"']WScript\.Shell[\"']\))", re.I), "WScript Shell Invocation", 20, "Launches Windows command interpreter from script."),
        ]

        for pattern, name, weight, expl in ps_patterns:
            if pattern.search(text):
                score += weight
                categories.add(name)
                indicators.append(name)
                findings.append(f"Detected suspicious script pattern: {name}")
                details.append(
                    FileFindingDetail(
                        indicator=name,
                        title="Suspicious Script Indicator",
                        risk_level="Medium" if weight < 25 else "High",
                        explanation=expl,
                    )
                )

        return score

    def _inspect_pdf_indicators(
        self,
        data: bytes,
        categories: Set[str],
        indicators: List[str],
        findings: List[str],
        details: List[FileFindingDetail],
    ) -> int:
        score = 0
        # Search for weaponized PDF tags in raw bytes
        pdf_tags = [
            (b"/JavaScript", "Embedded PDF JavaScript", 20, "PDF contains embedded JavaScript code that runs upon document opening."),
            (b"/JS", "Embedded PDF JS Action", 15, "PDF invokes internal JS scripting engine."),
            (b"/Launch", "PDF Application Launch Action", 30, "PDF attempts to launch an external executable program."),
            (b"/OpenAction", "Automatic PDF Trigger", 10, "Executes script actions automatically when opened."),
        ]

        for tag, name, weight, expl in pdf_tags:
            if tag in data:
                score += weight
                categories.add(name)
                indicators.append(name)
                findings.append(f"Suspicious PDF object tag detected: {name}")
                details.append(
                    FileFindingDetail(
                        indicator=name,
                        title="Weaponized PDF Indicator",
                        risk_level="High" if weight >= 20 else "Medium",
                        explanation=expl,
                    )
                )

        return score

    def _generate_advice(
        self,
        classification: str,
        score: int,
        filename: str,
        detected_type: str,
        findings: List[str],
        categories: Set[str],
    ) -> Tuple[str, str, List[str]]:
        if classification == "Critical":
            explanation = (
                f"Critical file threat detected (Risk Score: {score}/100). "
                f"The file '{filename}' displays characteristics heavily consistent with malware distribution, "
                "such as disguised executable signatures, deceptive double extensions, or Zip Slip path traversal. "
                "Do NOT execute or open this file."
            )
            recs = [
                "Do NOT run, double-click, or execute this file.",
                "Delete or quarantine the file immediately.",
                "If received via email or untrusted download, do not trust the source.",
                "Scan your device with full endpoint antivirus protection.",
            ]
            recommendation = recs[0]

        elif classification == "High Risk":
            explanation = (
                f"High-risk file profile detected (Risk Score: {score}/100). "
                f"The file exhibits {len(findings)} dangerous heuristic indicator(s) including executable capabilities, "
                "hidden archive payloads, or stealth script invocation commands."
            )
            recs = [
                "Verify file integrity and developer signature before opening.",
                "Inspect the file in an isolated sandbox environment if analysis is required.",
                "Avoid executing scripts from unverified or unknown senders.",
            ]
            recommendation = recs[0]

        elif classification == "Suspicious":
            explanation = (
                f"Suspicious file attributes detected (Risk Score: {score}/100). "
                "The file contains elevated features such as embedded script tags or atypical compression ratios. "
                "Verify legitimacy before opening."
            )
            recs = [
                "Review the source of this file and confirm why it was provided.",
                "Check file extension visibility in Windows File Explorer.",
            ]
            recommendation = recs[0]

        else:
            explanation = (
                f"No dangerous executable signatures, disguised headers, or known threat patterns detected (Risk Score: {score}/100). "
                f"File signature identifies as: {detected_type}."
            )
            recs = [
                "File structure appears consistent with standard format specifications.",
                "Always ensure files originate from trusted sources.",
            ]
            recommendation = recs[0]

        return explanation, recommendation, recs
