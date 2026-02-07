// https://github.com/seaemperorleviathan/FantaLib
// Compiled at 1770474663 using MSVC
// Latest Git branch: main (14 commits ahead of branch 'master')
#pragma once

#include <Windows.h>
#include <winternl.h>
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <fstream>
#include <TlHelp32.h>

// Define missing structures if not present
#ifndef PROCESSINFOCLASS
typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation = 0,
    ProcessDebugPort = 7,
    ProcessWow64Information = 26,
    ProcessImageFileName = 27,
    ProcessBreakOnTermination = 29
} PROCESSINFOCLASS;
#endif

#ifndef MEMORY_INFORMATION_CLASS
typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation,
    MemoryWorkingSetInformation,
    MemoryMappedFilenameInformation,
    MemoryRegionInformation,
    MemoryWorkingSetExInformation
} MEMORY_INFORMATION_CLASS;
#endif

#ifndef PROCESS_BASIC_INFORMATION
typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;
#endif

#ifndef CLIENT_ID
typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;
#endif

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
    (p)->RootDirectory = r; \
    (p)->Attributes = a; \
    (p)->ObjectName = n; \
    (p)->SecurityDescriptor = s; \
    (p)->SecurityQualityOfService = NULL; \
}
#endif



namespace Fanta {

    // === INTERNAL STATE ===
    namespace Internal {
        inline HANDLE hProcess = NULL;
        inline DWORD processId = 0;
        inline HMODULE ntdll = NULL;

        // NT Function pointers
        typedef NTSTATUS(NTAPI* pNtReadVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
        typedef NTSTATUS(NTAPI* pNtWriteVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
        typedef NTSTATUS(NTAPI* pNtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
        typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
        typedef NTSTATUS(NTAPI* pNtFreeVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG);
        typedef NTSTATUS(NTAPI* pNtQueryVirtualMemory)(HANDLE, PVOID, MEMORY_INFORMATION_CLASS, PVOID, SIZE_T, PSIZE_T);
        typedef NTSTATUS(NTAPI* pNtOpenProcess)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
        typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
        typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

        inline pNtReadVirtualMemory _NtReadVirtualMemory = nullptr;
        inline pNtWriteVirtualMemory _NtWriteVirtualMemory = nullptr;
        inline pNtProtectVirtualMemory _NtProtectVirtualMemory = nullptr;
        inline pNtAllocateVirtualMemory _NtAllocateVirtualMemory = nullptr;
        inline pNtFreeVirtualMemory _NtFreeVirtualMemory = nullptr;
        inline pNtQueryVirtualMemory _NtQueryVirtualMemory = nullptr;
        inline pNtOpenProcess _NtOpenProcess = nullptr;
        inline pNtQueryInformationProcess _NtQueryInformationProcess = nullptr;
        inline pNtCreateThreadEx _NtCreateThreadEx = nullptr;

        inline bool initialized = false;
    }

    // === INITIALIZATION ===

    inline bool Initialize() {
        if (Internal::initialized) return true;

        Internal::ntdll = GetModuleHandleA("ntdll.dll");
        if (!Internal::ntdll) return false;

        Internal::_NtReadVirtualMemory = (Internal::pNtReadVirtualMemory)GetProcAddress(Internal::ntdll, "NtReadVirtualMemory");
        Internal::_NtWriteVirtualMemory = (Internal::pNtWriteVirtualMemory)GetProcAddress(Internal::ntdll, "NtWriteVirtualMemory");
        Internal::_NtProtectVirtualMemory = (Internal::pNtProtectVirtualMemory)GetProcAddress(Internal::ntdll, "NtProtectVirtualMemory");
        Internal::_NtAllocateVirtualMemory = (Internal::pNtAllocateVirtualMemory)GetProcAddress(Internal::ntdll, "NtAllocateVirtualMemory");
        Internal::_NtFreeVirtualMemory = (Internal::pNtFreeVirtualMemory)GetProcAddress(Internal::ntdll, "NtFreeVirtualMemory");
        Internal::_NtQueryVirtualMemory = (Internal::pNtQueryVirtualMemory)GetProcAddress(Internal::ntdll, "NtQueryVirtualMemory");
        Internal::_NtOpenProcess = (Internal::pNtOpenProcess)GetProcAddress(Internal::ntdll, "NtOpenProcess");
        Internal::_NtQueryInformationProcess = (Internal::pNtQueryInformationProcess)GetProcAddress(Internal::ntdll, "NtQueryInformationProcess");
        Internal::_NtCreateThreadEx = (Internal::pNtCreateThreadEx)GetProcAddress(Internal::ntdll, "NtCreateThreadEx");

        if (!Internal::_NtReadVirtualMemory || !Internal::_NtWriteVirtualMemory || !Internal::_NtProtectVirtualMemory ||
            !Internal::_NtAllocateVirtualMemory || !Internal::_NtFreeVirtualMemory || !Internal::_NtQueryVirtualMemory ||
            !Internal::_NtOpenProcess || !Internal::_NtQueryInformationProcess || !Internal::_NtCreateThreadEx) {
            return false;
        }

        Internal::initialized = true;
        return true;
    }

    inline void Cleanup() {
        if (Internal::hProcess && Internal::hProcess != INVALID_HANDLE_VALUE) {
            CloseHandle(Internal::hProcess);
            Internal::hProcess = NULL;
        }
        Internal::processId = 0;
    }

    // === PROCESS FUNCTIONS ===

    inline bool OpenProcess(DWORD pid, ACCESS_MASK access = PROCESS_ALL_ACCESS) {
        if (!Initialize()) return false;

        if (Internal::hProcess && Internal::hProcess != INVALID_HANDLE_VALUE) {
            CloseHandle(Internal::hProcess);
        }

        OBJECT_ATTRIBUTES objAttr = { 0 };
        objAttr.Length = sizeof(OBJECT_ATTRIBUTES);

        CLIENT_ID clientId = { 0 };
        clientId.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
        clientId.UniqueThread = NULL;

        NTSTATUS status = Internal::_NtOpenProcess(&Internal::hProcess, access, &objAttr, &clientId);

        if (NT_SUCCESS(status)) {
            Internal::processId = pid;
            return true;
        }
        return false;
    }

    inline DWORD GetProcessIdByName(const std::string& processName) {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return 0;

        PROCESSENTRY32 entry = { 0 };
        entry.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(snapshot, &entry)) {
            do {
                std::string exeFile(entry.szExeFile);
                if (exeFile == processName) {
                    CloseHandle(snapshot);
                    return entry.th32ProcessID;
                }
            } while (Process32Next(snapshot, &entry));
        }

        CloseHandle(snapshot);
        return 0;
    }

    inline bool OpenProcessByName(const std::string& processName, ACCESS_MASK access = PROCESS_ALL_ACCESS) {
        DWORD pid = GetProcessIdByName(processName);
        if (pid == 0) return false;
        return OpenProcess(pid, access);
    }

    inline HANDLE GetProcessHandle() {
        return Internal::hProcess;
    }

    inline DWORD GetProcessId() {
        return Internal::processId;
    }

    inline uintptr_t GetModuleBaseAddress(const std::string& moduleName = "") {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, Internal::processId);
        if (snapshot == INVALID_HANDLE_VALUE) return 0;

        MODULEENTRY32 entry = { 0 };
        entry.dwSize = sizeof(MODULEENTRY32);

        if (Module32First(snapshot, &entry)) {
            do {
                if (moduleName.empty()) {
                    CloseHandle(snapshot);
                    return (uintptr_t)entry.modBaseAddr;
                }

                std::string modName(entry.szModule);
                if (modName == moduleName) {
                    CloseHandle(snapshot);
                    return (uintptr_t)entry.modBaseAddr;
                }
            } while (Module32Next(snapshot, &entry));
        }

        CloseHandle(snapshot);
        return 0;
    }

    inline SIZE_T GetModuleSize(const std::string& moduleName = "") {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, Internal::processId);
        if (snapshot == INVALID_HANDLE_VALUE) return 0;

        MODULEENTRY32 entry = { 0 };
        entry.dwSize = sizeof(MODULEENTRY32);

        if (Module32First(snapshot, &entry)) {
            do {
                if (moduleName.empty()) {
                    CloseHandle(snapshot);
                    return entry.modBaseSize;
                }

                std::string modName(entry.szModule);
                if (modName == moduleName) {
                    CloseHandle(snapshot);
                    return entry.modBaseSize;
                }
            } while (Module32Next(snapshot, &entry));
        }

        CloseHandle(snapshot);
        return 0;
    }

    inline std::vector<std::pair<std::string, uintptr_t>> EnumerateModules() {
        std::vector<std::pair<std::string, uintptr_t>> modules;

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, Internal::processId);
        if (snapshot == INVALID_HANDLE_VALUE) return modules;

        MODULEENTRY32 entry = { 0 };
        entry.dwSize = sizeof(MODULEENTRY32);

        if (Module32First(snapshot, &entry)) {
            do {
                modules.push_back(std::make_pair(std::string(entry.szModule), (uintptr_t)entry.modBaseAddr));
            } while (Module32Next(snapshot, &entry));
        }

        CloseHandle(snapshot);
        return modules;
    }

    inline uintptr_t GetPEBAddress() {
        if (!Internal::hProcess) return 0;

        PROCESS_BASIC_INFORMATION pbi = { 0 };
        ULONG returnLength = 0;

        NTSTATUS status = Internal::_NtQueryInformationProcess(
            Internal::hProcess,
            ProcessBasicInformation,
            &pbi,
            sizeof(pbi),
            &returnLength
        );

        if (NT_SUCCESS(status)) {
            return (uintptr_t)pbi.PebBaseAddress;
        }
        return 0;
    }

    // === MEMORY FUNCTIONS ===

    template<typename T>
    inline T Read(uintptr_t address) {
        if (!Internal::hProcess) return T();

        T buffer = { 0 };
        SIZE_T bytesRead = 0;

        NTSTATUS status = Internal::_NtReadVirtualMemory(
            Internal::hProcess,
            (PVOID)address,
            &buffer,
            sizeof(T),
            &bytesRead
        );

        if (NT_SUCCESS(status) && bytesRead == sizeof(T)) {
            return buffer;
        }
        return T();
    }

    inline bool ReadBuffer(uintptr_t address, void* buffer, SIZE_T size) {
        if (!Internal::hProcess) return false;

        SIZE_T bytesRead = 0;

        NTSTATUS status = Internal::_NtReadVirtualMemory(
            Internal::hProcess,
            (PVOID)address,
            buffer,
            size,
            &bytesRead
        );

        return NT_SUCCESS(status) && bytesRead == size;
    }

    inline std::string ReadString(uintptr_t address, SIZE_T maxLength = 256) {
        std::vector<char> buffer(maxLength, 0);
        SIZE_T bytesRead = 0;

        NTSTATUS status = Internal::_NtReadVirtualMemory(
            Internal::hProcess,
            (PVOID)address,
            buffer.data(),
            maxLength,
            &bytesRead
        );

        if (NT_SUCCESS(status)) {
            return std::string(buffer.data());
        }
        return "";
    }

    template<typename T>
    inline bool Write(uintptr_t address, T value) {
        if (!Internal::hProcess) return false;

        SIZE_T bytesWritten = 0;

        NTSTATUS status = Internal::_NtWriteVirtualMemory(
            Internal::hProcess,
            (PVOID)address,
            &value,
            sizeof(T),
            &bytesWritten
        );

        return NT_SUCCESS(status) && bytesWritten == sizeof(T);
    }

    inline bool WriteBuffer(uintptr_t address, const void* buffer, SIZE_T size) {
        if (!Internal::hProcess) return false;

        SIZE_T bytesWritten = 0;

        NTSTATUS status = Internal::_NtWriteVirtualMemory(
            Internal::hProcess,
            (PVOID)address,
            (PVOID)buffer,
            size,
            &bytesWritten
        );

        return NT_SUCCESS(status) && bytesWritten == size;
    }

    inline bool WriteString(uintptr_t address, const std::string& str) {
        return WriteBuffer(address, str.c_str(), str.length() + 1);
    }

    inline bool Protect(uintptr_t address, SIZE_T size, ULONG newProtection, ULONG* oldProtection = nullptr) {
        if (!Internal::hProcess) return false;

        PVOID baseAddr = (PVOID)address;
        SIZE_T regionSize = size;
        ULONG oldProt = 0;

        NTSTATUS status = Internal::_NtProtectVirtualMemory(
            Internal::hProcess,
            &baseAddr,
            &regionSize,
            newProtection,
            &oldProt
        );

        if (oldProtection) {
            *oldProtection = oldProt;
        }

        return NT_SUCCESS(status);
    }

    inline uintptr_t Allocate(SIZE_T size, ULONG protection = PAGE_EXECUTE_READWRITE, ULONG allocationType = MEM_COMMIT | MEM_RESERVE) {
        if (!Internal::hProcess) return 0;

        PVOID baseAddr = NULL;
        SIZE_T regionSize = size;

        NTSTATUS status = Internal::_NtAllocateVirtualMemory(
            Internal::hProcess,
            &baseAddr,
            0,
            &regionSize,
            allocationType,
            protection
        );

        if (NT_SUCCESS(status)) {
            return (uintptr_t)baseAddr;
        }
        return 0;
    }

    inline bool Free(uintptr_t address, SIZE_T size = 0) {
        if (!Internal::hProcess) return false;

        PVOID baseAddr = (PVOID)address;
        SIZE_T regionSize = size;

        NTSTATUS status = Internal::_NtFreeVirtualMemory(
            Internal::hProcess,
            &baseAddr,
            &regionSize,
            MEM_RELEASE
        );

        return NT_SUCCESS(status);
    }

    inline bool QueryMemory(uintptr_t address, MEMORY_BASIC_INFORMATION* mbi) {
        if (!Internal::hProcess) return false;

        SIZE_T returnLength = 0;

        NTSTATUS status = Internal::_NtQueryVirtualMemory(
            Internal::hProcess,
            (PVOID)address,
            MemoryBasicInformation,
            mbi,
            sizeof(MEMORY_BASIC_INFORMATION),
            &returnLength
        );

        return NT_SUCCESS(status);
    }

    inline uintptr_t PatternScan(uintptr_t startAddress, SIZE_T scanSize, const char* pattern, const char* mask) {
        SIZE_T patternLength = strlen(mask);
        std::vector<BYTE> buffer(scanSize, 0);

        if (!ReadBuffer(startAddress, buffer.data(), scanSize)) {
            return 0;
        }

        for (SIZE_T i = 0; i < scanSize - patternLength; i++) {
            bool found = true;
            for (SIZE_T j = 0; j < patternLength; j++) {
                if (mask[j] != '?' && buffer[i + j] != (BYTE)pattern[j]) {
                    found = false;
                    break;
                }
            }
            if (found) {
                return startAddress + i;
            }
        }

        return 0;
    }

    inline uintptr_t PatternScanModule(const std::string& moduleName, const char* pattern, const char* mask) {
        uintptr_t baseAddress = GetModuleBaseAddress(moduleName);
        SIZE_T moduleSize = GetModuleSize(moduleName);

        if (baseAddress == 0 || moduleSize == 0) {
            return 0;
        }

        return PatternScan(baseAddress, moduleSize, pattern, mask);
    }

    inline uintptr_t AOBScan(uintptr_t startAddress, SIZE_T scanSize, const std::string& pattern) {
        std::vector<int> patternBytes;
        std::istringstream iss(pattern);
        std::string byte;

        while (iss >> byte) {
            if (byte == "?") {
                patternBytes.push_back(-1);
            }
            else {
                patternBytes.push_back(std::stoi(byte, nullptr, 16));
            }
        }

        std::vector<BYTE> buffer(scanSize, 0);
        if (!ReadBuffer(startAddress, buffer.data(), scanSize)) {
            return 0;
        }

        for (SIZE_T i = 0; i < scanSize - patternBytes.size(); i++) {
            bool found = true;
            for (SIZE_T j = 0; j < patternBytes.size(); j++) {
                if (patternBytes[j] != -1 && buffer[i + j] != (BYTE)patternBytes[j]) {
                    found = false;
                    break;
                }
            }
            if (found) {
                return startAddress + i;
            }
        }

        return 0;
    }

    inline uintptr_t AOBScanModule(const std::string& moduleName, const std::string& pattern) {
        uintptr_t baseAddress = GetModuleBaseAddress(moduleName);
        SIZE_T moduleSize = GetModuleSize(moduleName);

        if (baseAddress == 0 || moduleSize == 0) {
            return 0;
        }

        return AOBScan(baseAddress, moduleSize, pattern);
    }

    inline uintptr_t ResolvePointerChain(uintptr_t baseAddress, const std::vector<uintptr_t>& offsets) {
        uintptr_t address = baseAddress;

        for (size_t i = 0; i < offsets.size(); i++) {
            if (i == offsets.size() - 1) {
                address += offsets[i];
            }
            else {
                address = Read<uintptr_t>(address + offsets[i]);
                if (address == 0) return 0;
            }
        }

        return address;
    }

    // === DLL INJECTION ===

    inline bool InjectDLL(const std::string& dllPath) {
        if (!Internal::hProcess) return false;

        SIZE_T pathSize = dllPath.length() + 1;
        uintptr_t pathAddr = Allocate(pathSize, PAGE_READWRITE);

        if (pathAddr == 0) return false;

        if (!WriteString(pathAddr, dllPath)) {
            Free(pathAddr);
            return false;
        }

        HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
        FARPROC loadLibAddr = GetProcAddress(kernel32, "LoadLibraryA");

        if (!loadLibAddr) {
            Free(pathAddr);
            return false;
        }

        HANDLE hThread = NULL;
        OBJECT_ATTRIBUTES objAttr = { 0 };
        objAttr.Length = sizeof(OBJECT_ATTRIBUTES);

        NTSTATUS status = Internal::_NtCreateThreadEx(
            &hThread,
            THREAD_ALL_ACCESS,
            &objAttr,
            Internal::hProcess,
            loadLibAddr,
            (PVOID)pathAddr,
            0,
            0,
            0,
            0,
            NULL
        );

        if (!NT_SUCCESS(status)) {
            Free(pathAddr);
            return false;
        }

        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
        Free(pathAddr);

        return true;
    }

    inline bool ExecuteShellcode(const void* shellcode, SIZE_T shellcodeSize) {
        if (!Internal::hProcess) return false;

        uintptr_t shellcodeAddr = Allocate(shellcodeSize, PAGE_EXECUTE_READWRITE);

        if (shellcodeAddr == 0) return false;

        if (!WriteBuffer(shellcodeAddr, shellcode, shellcodeSize)) {
            Free(shellcodeAddr);
            return false;
        }

        HANDLE hThread = NULL;
        OBJECT_ATTRIBUTES objAttr = { 0 };
        objAttr.Length = sizeof(OBJECT_ATTRIBUTES);

        NTSTATUS status = Internal::_NtCreateThreadEx(
            &hThread,
            THREAD_ALL_ACCESS,
            &objAttr,
            Internal::hProcess,
            (PVOID)shellcodeAddr,
            NULL,
            0,
            0,
            0,
            0,
            NULL
        );

        if (!NT_SUCCESS(status)) {
            Free(shellcodeAddr);
            return false;
        }

        CloseHandle(hThread);
        return true;
    }

    // === UTILITY FUNCTIONS ===

    inline bool DumpMemory(uintptr_t address, SIZE_T size, const std::string& outputFile) {
        std::vector<BYTE> buffer(size, 0);

        if (!ReadBuffer(address, buffer.data(), size)) {
            return false;
        }

        std::ofstream file(outputFile, std::ios::binary);
        if (!file.is_open()) return false;

        file.write((char*)buffer.data(), size);
        file.close();

        return true;
    }

    inline std::vector<MEMORY_BASIC_INFORMATION> FindMemoryRegions(DWORD protection) {
        std::vector<MEMORY_BASIC_INFORMATION> regions;
        uintptr_t address = 0;
        MEMORY_BASIC_INFORMATION mbi = { 0 };

        while (address < 0x7FFFFFFF0000) {
            if (QueryMemory(address, &mbi)) {
                if (mbi.Protect == protection && mbi.State == MEM_COMMIT) {
                    regions.push_back(mbi);
                }
                address = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
            }
            else {
                address += 0x1000;
            }
        }

        return regions;
    }

    inline void FreezeValue(uintptr_t address, const void* value, SIZE_T size, bool* shouldStop) {
        while (!*shouldStop) {
            WriteBuffer(address, value, size);
            Sleep(10);
        }
    }

    inline bool NOP(uintptr_t address, SIZE_T count) {
        std::vector<BYTE> nops(count, 0x90);
        return WriteBuffer(address, nops.data(), count);
    }

    inline bool WriteJMP(uintptr_t from, uintptr_t to) {
        BYTE jmp[5] = { 0 };
        jmp[0] = 0xE9;
        *(DWORD*)(jmp + 1) = (DWORD)(to - from - 5);
        return WriteBuffer(from, jmp, 5);
    }

    inline bool WriteCALL(uintptr_t from, uintptr_t to) {
        BYTE call[5] = { 0 };
        call[0] = 0xE8;
        *(DWORD*)(call + 1) = (DWORD)(to - from - 5);
        return WriteBuffer(from, call, 5);
    }

} // namespace Fanta