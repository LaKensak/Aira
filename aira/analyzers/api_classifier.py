"""Classifie les imports par comportement (injection, réseau, crypto, anti-debug…)."""
from __future__ import annotations

from typing import Dict, List

# ── Dictionnaire des catégories comportementales ────────────────────────────
CATEGORIES: Dict[str, dict] = {
    "anti_debug": {
        "label":  "Anti-Debug",
        "color":  "#f85149",
        "risk":   "high",
        "apis": {
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess", "NtSetInformationThread",
            "OutputDebugStringA", "OutputDebugStringW",
            "FindWindowA", "FindWindowW", "FindWindowExA", "FindWindowExW",
            "DebugBreak", "DebugActiveProcess", "DebugSetProcessKillOnExit",
            "SetUnhandledExceptionFilter", "UnhandledExceptionFilter",
            "RaiseException", "GetTickCount", "GetTickCount64",
            "QueryPerformanceCounter", "QueryPerformanceFrequency",
            "NtQuerySystemInformation", "NtQueryObject",
            "ZwQueryInformationProcess", "NtClose",
        },
    },
    "anti_vm": {
        "label":  "Anti-VM / Anti-Sandbox",
        "color":  "#d29922",
        "risk":   "high",
        "apis": {
            "GetSystemInfo", "GlobalMemoryStatusEx", "GlobalMemoryStatus",
            "GetSystemMetrics", "EnumDisplayDevices", "EnumDisplayMonitors",
            "GetAdaptersInfo", "GetAdaptersAddresses",
            "RegOpenKeyExA", "RegOpenKeyExW",
            "GetFileAttributesA", "GetFileAttributesW",
            "DeviceIoControl", "CreateFileA", "CreateFileW",
            "NtQuerySystemInformation", "GetCursorPos",
            "GetForegroundWindow", "GetLastInputInfo",
            "SetTimer", "timeGetTime",
        },
    },
    "process_injection": {
        "label":  "Injection de processus",
        "color":  "#ff7b72",
        "risk":   "critical",
        "apis": {
            "VirtualAllocEx", "WriteProcessMemory", "ReadProcessMemory",
            "CreateRemoteThread", "CreateRemoteThreadEx",
            "NtCreateThreadEx", "RtlCreateUserThread",
            "QueueUserAPC", "NtQueueApcThread",
            "SetThreadContext", "GetThreadContext",
            "SuspendThread", "ResumeThread", "NtSuspendThread",
            "OpenProcess", "NtOpenProcess",
            "NtUnmapViewOfSection", "NtMapViewOfSection", "ZwMapViewOfSection",
            "NtWriteVirtualMemory", "NtAllocateVirtualMemory",
        },
    },
    "code_execution": {
        "label":  "Exécution de code / Shellcode",
        "color":  "#ffa657",
        "risk":   "critical",
        "apis": {
            "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
            "HeapCreate", "HeapAlloc",
            "FlushInstructionCache",
            "RtlMoveMemory", "RtlCopyMemory",
            "CreateThread", "NtCreateThread", "NtCreateProcess",
            "CreateProcessA", "CreateProcessW", "CreateProcessWithTokenW",
            "WinExec", "ShellExecuteA", "ShellExecuteW",
            "ShellExecuteExA", "ShellExecuteExW",
            "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
            "GetProcAddress", "LdrLoadDll",
        },
    },
    "network": {
        "label":  "Réseau / C2",
        "color":  "#79c0ff",
        "risk":   "high",
        "apis": {
            "InternetOpenA", "InternetOpenW",
            "InternetConnectA", "InternetConnectW",
            "HttpOpenRequestA", "HttpOpenRequestW",
            "HttpSendRequestA", "HttpSendRequestW",
            "InternetReadFile", "InternetWriteFile",
            "URLDownloadToFileA", "URLDownloadToFileW",
            "URLDownloadToCacheFileA", "URLDownloadToCacheFileW",
            "WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest",
            "WinHttpReceiveResponse", "WinHttpQueryDataAvailable",
            "WSAStartup", "WSACleanup", "WSAConnect",
            "socket", "connect", "send", "recv", "sendto", "recvfrom",
            "bind", "listen", "accept", "closesocket", "select",
            "getaddrinfo", "gethostbyname", "gethostbyaddr",
            "inet_addr", "inet_ntoa", "inet_ntop", "inet_pton",
            "getsockopt", "setsockopt", "ioctlsocket",
        },
    },
    "crypto": {
        "label":  "Cryptographie",
        "color":  "#a5d6ff",
        "risk":   "medium",
        "apis": {
            "CryptAcquireContextA", "CryptAcquireContextW",
            "CryptCreateHash", "CryptHashData", "CryptGetHashParam",
            "CryptEncrypt", "CryptDecrypt",
            "CryptImportKey", "CryptExportKey", "CryptDeriveKey",
            "CryptGenRandom", "CryptGenKey",
            "CryptDestroyKey", "CryptDestroyHash",
            "BCryptOpenAlgorithmProvider", "BCryptCloseAlgorithmProvider",
            "BCryptEncrypt", "BCryptDecrypt",
            "BCryptGenRandom", "BCryptCreateHash",
            "NCryptEncrypt", "NCryptDecrypt",
            "CertOpenStore", "CertOpenSystemStoreA",
        },
    },
    "persistence": {
        "label":  "Persistance",
        "color":  "#7ee787",
        "risk":   "high",
        "apis": {
            "RegSetValueExA", "RegSetValueExW",
            "RegCreateKeyExA", "RegCreateKeyExW",
            "RegDeleteValueA", "RegDeleteValueW",
            "CreateServiceA", "CreateServiceW",
            "OpenServiceA", "OpenServiceW",
            "StartServiceA", "StartServiceW",
            "ChangeServiceConfigA", "ChangeServiceConfigW",
            "SHGetFolderPathA", "SHGetFolderPathW",
            "SHGetSpecialFolderPathA", "SHGetSpecialFolderPathW",
            "CoCreateInstance",  # COM persistence
        },
    },
    "privileges": {
        "label":  "Élévation de privilèges / Token",
        "color":  "#e3b341",
        "risk":   "high",
        "apis": {
            "AdjustTokenPrivileges", "OpenProcessToken", "OpenThreadToken",
            "LookupPrivilegeValueA", "LookupPrivilegeValueW",
            "LookupPrivilegeNameA", "LookupPrivilegeNameW",
            "ImpersonateLoggedOnUser", "ImpersonateNamedPipeClient",
            "DuplicateToken", "DuplicateTokenEx",
            "SetTokenInformation", "CreateProcessWithTokenW",
            "CreateProcessAsUserA", "CreateProcessAsUserW",
        },
    },
    "keylog_spy": {
        "label":  "Keylogging / Espionnage",
        "color":  "#f97316",
        "risk":   "critical",
        "apis": {
            "SetWindowsHookExA", "SetWindowsHookExW",
            "GetAsyncKeyState", "GetKeyState", "GetKeyboardState",
            "GetClipboardData", "SetClipboardData",
            "OpenClipboard", "EmptyClipboard",
            "PrintWindow", "GetDC", "GetDCEx",
            "BitBlt", "StretchBlt",  # screenshots
            "GetForegroundWindow", "GetWindowText",
            "AttachThreadInput",
        },
    },
    "file_ops": {
        "label":  "Opérations fichiers (sensibles)",
        "color":  "#94a3b8",
        "risk":   "medium",
        "apis": {
            "DeleteFileA", "DeleteFileW",
            "MoveFileExA", "MoveFileExW",
            "CopyFileA", "CopyFileW",
            "FindFirstFileA", "FindFirstFileW",
            "FindNextFileA", "FindNextFileW",
            "GetTempPathA", "GetTempPathW",
            "GetTempFileNameA", "GetTempFileNameW",
            "SetFileAttributesA", "SetFileAttributesW",
            "SHFileOperationA", "SHFileOperationW",
        },
    },
    "process_enum": {
        "label":  "Énumération système",
        "color":  "#b0b8c8",
        "risk":   "low",
        "apis": {
            "CreateToolhelp32Snapshot",
            "Process32First", "Process32FirstW",
            "Process32Next",  "Process32NextW",
            "Module32First",  "Module32FirstW",
            "Module32Next",   "Module32NextW",
            "Thread32First",  "Thread32Next",
            "EnumProcesses",  "EnumProcessModules",
            "EnumWindows", "EnumChildWindows",
            "GetComputerNameA", "GetComputerNameW",
            "GetUserNameA", "GetUserNameW",
        },
    },
    "defense_evasion": {
        "label":  "Évasion de défense",
        "color":  "#d946ef",
        "risk":   "critical",
        "apis": {
            "NtSetInformationProcess",  # DEP bypass
            "SetProcessDEPPolicy",
            "IsWow64Process",           # architecture detection
            "Wow64DisableWow64FsRedirection",
            "Wow64RevertWow64FsRedirection",
            "NtSetSystemInformation",   # DKOM
            "NtQueryDirectoryFile",     # rootkit hide files
            "ZwSetSystemInformation",
            "RtlAdjustPrivilege",
            "EraseCommitteFile",        # log tampering
        },
    },
}


def classify_apis(imports: list[dict]) -> dict:
    """
    Prend la liste des imports (comme retourné par static_analysis)
    et retourne les catégories comportementales détectées.

    Returns:
        {
          "categories": {
            "anti_debug": { "label", "color", "risk", "matched": [...] },
            ...
          },
          "risk_score": 0-100,
          "summary": "High risk — process injection, anti-debug detected"
        }
    """
    symbols = {imp.get("symbol", "") for imp in imports if imp.get("symbol")}

    matched_categories: dict[str, dict] = {}
    risk_points = 0

    risk_weights = {"critical": 30, "high": 15, "medium": 8, "low": 3}

    for cat_id, cat_info in CATEGORIES.items():
        matched = sorted(symbols & cat_info["apis"])
        if matched:
            matched_categories[cat_id] = {
                "label":   cat_info["label"],
                "color":   cat_info["color"],
                "risk":    cat_info["risk"],
                "matched": matched,
                "count":   len(matched),
            }
            risk_points += risk_weights.get(cat_info["risk"], 0) * min(len(matched), 3)

    # Risk score 0-100
    risk_score = min(100, risk_points)

    # Summary
    if risk_score >= 70:
        level = "CRITIQUE"
    elif risk_score >= 40:
        level = "ÉLEVÉ"
    elif risk_score >= 20:
        level = "MOYEN"
    elif risk_score > 0:
        level = "FAIBLE"
    else:
        level = "AUCUN"

    top_cats = [v["label"] for v in matched_categories.values() if v["risk"] in ("critical", "high")]
    summary_parts = top_cats[:4]
    summary = f"Risque {level}"
    if summary_parts:
        summary += f" — {', '.join(summary_parts)}"

    return {
        "categories":  matched_categories,
        "risk_score":  risk_score,
        "risk_level":  level,
        "summary":     summary,
    }
