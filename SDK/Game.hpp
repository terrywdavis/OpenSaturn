#pragma once

#include <Windows.h>
#include <vector>
#include <TlHelp32.h>
#include <cstdint>
#include <optional>

namespace Game {

    inline std::vector<DWORD> GetProcessIds() {
        std::vector<DWORD> processIds;
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE)
            return processIds;

        PROCESSENTRY32W entry = {};
        entry.dwSize = sizeof(PROCESSENTRY32W);

        if (!Process32FirstW(snapshot, &entry)) {
            CloseHandle(snapshot);
            return processIds;
        }

        do {
            if (_wcsicmp(L"RobloxPlayerBeta.exe", entry.szExeFile) == 0)
                processIds.push_back(entry.th32ProcessID);
        } while (Process32NextW(snapshot, &entry));

        CloseHandle(snapshot);
        return processIds;
    }

    inline std::optional<uintptr_t> GetModuleBase(DWORD pid) {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
        if (snapshot == INVALID_HANDLE_VALUE)
            return std::nullopt;

        MODULEENTRY32W entry = {};
        entry.dwSize = sizeof(MODULEENTRY32W);

        std::optional<uintptr_t> result = std::nullopt;
        if (Module32FirstW(snapshot, &entry)) {
            do {
                if (_wcsicmp(entry.szModule, L"RobloxPlayerBeta.exe") == 0) {
                    result = reinterpret_cast<uintptr_t>(entry.modBaseAddr);
                    break;
                }
            } while (Module32NextW(snapshot, &entry));
        }

        CloseHandle(snapshot);
        return result;
    }

    inline HWND GetWindowFromProcess(DWORD processId) {
        struct EnumData {
            DWORD targetPid;
            HWND hwnd;
        } data = { processId, nullptr };

        EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
            EnumData* pData = reinterpret_cast<EnumData*>(lParam);
            DWORD pid = 0;
            GetWindowThreadProcessId(hwnd, &pid);
            if (pid == pData->targetPid) {
                pData->hwnd = hwnd;
                return FALSE;
            }
            return TRUE;
        }, reinterpret_cast<LPARAM>(&data));

        return data.hwnd;
    }
}
