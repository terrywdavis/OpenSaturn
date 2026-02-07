#pragma once

#include <Windows.h>
#include <cstdint>
#include <optional>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

namespace Handler {

    constexpr size_t BATCH_SIZE = 4096;

    using pNtReadVirtualMemory = NTSTATUS(NTAPI*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
    using pNtWriteVirtualMemory = NTSTATUS(NTAPI*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);

    namespace Internal {
        inline pNtReadVirtualMemory fnNtRead = nullptr;
        inline pNtWriteVirtualMemory fnNtWrite = nullptr;
    }

    inline DWORD HashString(const char* str) {
        DWORD hash = 0;
        while (*str) {
            hash = ((hash << 5) + hash) + *str++;
        }
        return hash;
    }

    inline PVOID GetProcByHash(HMODULE hModule, DWORD hash) {
        if (!hModule) return nullptr;

        auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

        auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
            reinterpret_cast<BYTE*>(hModule) + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return nullptr;

        DWORD exportRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (!exportRva) return nullptr;

        auto exportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(reinterpret_cast<BYTE*>(hModule) + exportRva);
        auto nameRvas = reinterpret_cast<DWORD*>(reinterpret_cast<BYTE*>(hModule) + exportDir->AddressOfNames);
        auto ordinals = reinterpret_cast<WORD*>(reinterpret_cast<BYTE*>(hModule) + exportDir->AddressOfNameOrdinals);
        auto funcRvas = reinterpret_cast<DWORD*>(reinterpret_cast<BYTE*>(hModule) + exportDir->AddressOfFunctions);

        for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
            char* funcName = reinterpret_cast<char*>(reinterpret_cast<BYTE*>(hModule) + nameRvas[i]);
            if (HashString(funcName) == hash) {
                WORD ordinal = ordinals[i];
                DWORD funcRva = funcRvas[ordinal];
                return reinterpret_cast<PVOID>(reinterpret_cast<BYTE*>(hModule) + funcRva);
            }
        }
        return nullptr;
    }

    inline bool InitializeNativeFunctions() {
        if (Internal::fnNtRead) return true;

        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) return false;

        Internal::fnNtRead = reinterpret_cast<pNtReadVirtualMemory>(
            GetProcByHash(ntdll, HashString("NtReadVirtualMemory")));
        Internal::fnNtWrite = reinterpret_cast<pNtWriteVirtualMemory>(
            GetProcByHash(ntdll, HashString("NtWriteVirtualMemory")));

        return (Internal::fnNtRead != nullptr && Internal::fnNtWrite != nullptr);
    }

    inline bool ReadNative(uintptr_t address, void* buffer, size_t size, DWORD pid) {
        if (!buffer && size > 0) return false;
        if (!InitializeNativeFunctions() || !Internal::fnNtRead) return false;

        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProcess || hProcess == INVALID_HANDLE_VALUE) return false;

        size_t offset = 0;
        char* dst = static_cast<char*>(buffer);
        bool success = true;

        while (offset < size) {
            size_t currentChunk = (BATCH_SIZE < (size - offset)) ? BATCH_SIZE : (size - offset);
            SIZE_T bytes = 0;
            NTSTATUS status = Internal::fnNtRead(hProcess,
                reinterpret_cast<PVOID>(address + offset),
                dst + offset,
                currentChunk,
                &bytes);
            if (!NT_SUCCESS(status) || bytes != currentChunk) {
                success = false;
                break;
            }
            offset += currentChunk;
        }

        CloseHandle(hProcess);
        return success;
    }

    inline bool WriteNative(uintptr_t address, const void* buffer, size_t size, DWORD pid) {
        if (!buffer && size > 0) return false;
        if (!InitializeNativeFunctions() || !Internal::fnNtWrite) return false;

        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProcess || hProcess == INVALID_HANDLE_VALUE) return false;

        size_t offset = 0;
        const char* src = static_cast<const char*>(buffer);
        bool success = true;

        while (offset < size) {
            size_t currentChunk = (BATCH_SIZE < (size - offset)) ? BATCH_SIZE : (size - offset);
            SIZE_T bytes = 0;
            NTSTATUS status = Internal::fnNtWrite(hProcess,
                reinterpret_cast<PVOID>(address + offset),
                const_cast<PVOID>(reinterpret_cast<const void*>(src + offset)),
                currentChunk,
                &bytes);
            if (!NT_SUCCESS(status) || bytes != currentChunk) {
                success = false;
                break;
            }
            offset += currentChunk;
        }

        CloseHandle(hProcess);
        return success;
    }

    template <typename Ty>
    inline std::optional<Ty> ReadMemory(uintptr_t address, DWORD pid) {
        Ty value{};
        if (!ReadNative(address, &value, sizeof(Ty), pid))
            return std::nullopt;
        return value;
    }

    template <typename Ty>
    inline bool WriteMemory(uintptr_t address, Ty value, DWORD pid) {
        return WriteNative(address, &value, sizeof(Ty), pid);
    }
}
