#include "MainFunctions.hpp"
#include <Windows.h>
#include <string>
#include <vector>
#include <set>
#include <mutex>
#include <atomic>
#include <thread>
#include <deque>
#include <algorithm>

namespace {

    constexpr int RESOURCE_INIT_SCRIPT = 1;
    constexpr int RESOURCE_INIT_SCRIPT_ENC = 101;

    const std::string DECOY_MARKER = "Hello David ily <3";
    const unsigned char XOR_KEY[] = { 0x4A, 0x75, 0x6C, 0x65, 0x73, 0x45, 0x78, 0x65 };

    std::atomic<bool> g_injected{ false };
    std::set<DWORD> g_monitoredPids;
    std::mutex g_pidMutex;

    constexpr size_t MAX_RECENT_ERRORS = 20;
    std::deque<std::string> g_recentErrors;
    std::mutex g_errorsMutex;

    bool ProcessExists(DWORD pid) {
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!h) return false;
        DWORD exitCode = 0;
        GetExitCodeProcess(h, &exitCode);
        CloseHandle(h);
        return exitCode == STILL_ACTIVE;
    }

    std::string XorDecrypt(const std::string& data) {
        std::string result = data;
        const size_t keyLen = sizeof(XOR_KEY);
        for (size_t i = 0; i < result.size(); ++i)
            result[i] ^= XOR_KEY[i % keyLen];
        return result;
    }

    void AddError(const std::string& msg) {
        if (msg.empty()) return;
        std::lock_guard<std::mutex> lock(g_errorsMutex);
        g_recentErrors.push_back(msg);
        if (g_recentErrors.size() > MAX_RECENT_ERRORS)
            g_recentErrors.pop_front();
    }

    std::string GetLuaCode(DWORD pid, int idx) {
        HMODULE hModule = nullptr;
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(&GetLuaCode),
            &hModule);

        HRSRC hRes = FindResourceW(hModule, MAKEINTRESOURCEW(idx), reinterpret_cast<LPCWSTR>(static_cast<ULONG_PTR>(10)));
        if (!hRes) return "";

        HGLOBAL hLoaded = LoadResource(hModule, hRes);
        if (!hLoaded) return "";

        DWORD size = SizeofResource(hModule, hRes);
        void* data = LockResource(hLoaded);
        if (!data) return "";

        std::string code(static_cast<const char*>(data), size);

        if (code.find(DECOY_MARKER) != std::string::npos) {
            HRSRC hEnc = FindResourceW(hModule, MAKEINTRESOURCEW(idx + 100), reinterpret_cast<LPCWSTR>(static_cast<ULONG_PTR>(10)));
            if (hEnc) {
                HGLOBAL hEncLoaded = LoadResource(hModule, hEnc);
                if (hEncLoaded) {
                    DWORD encSize = SizeofResource(hModule, hEnc);
                    void* encData = LockResource(hEncLoaded);
                    if (encData) {
                        std::string encrypted(static_cast<const char*>(encData), encSize);
                        code = XorDecrypt(encrypted);
                    }
                }
            }
        }

        const std::string placeholder = "%-PROCESS-ID-%";
        size_t pos = code.find(placeholder);
        if (pos != std::string::npos)
            code.replace(pos, placeholder.size(), std::to_string(pid));

        return code;
    }

    std::string WideToUtf8(const wchar_t* wide) {
        if (!wide) return "";
        int need = WideCharToMultiByte(CP_UTF8, 0, wide, -1, nullptr, 0, nullptr, nullptr);
        if (need <= 0) return "";
        std::string out(static_cast<size_t>(need), '\0');
        WideCharToMultiByte(CP_UTF8, 0, wide, -1, &out[0], need, nullptr, nullptr);
        if (!out.empty() && out.back() == '\0') out.pop_back();
        return out;
    }

    void MonitorProcess(DWORD pid) {
        auto baseOpt = Game::GetModuleBase(pid);
        if (!baseOpt) {
            AddError("GetModuleBase failed for PID " + std::to_string(pid));
            return;
        }
        uintptr_t base = *baseOpt;

        bool notified = false;

        while (ProcessExists(pid)) {
            Roblox datamodel(0, pid);
            while (ProcessExists(pid)) {
                try {
                    datamodel = FetchDatamodel(base, pid);
                    if (datamodel.GetAddress() != 0 && datamodel.Name() == "Ugc")
                        break;
                } catch (...) {}
                Sleep(250);
            }

            if (!ProcessExists(pid)) {
                std::lock_guard<std::mutex> lock(g_pidMutex);
                g_monitoredPids.erase(pid);
                if (g_monitoredPids.empty()) g_injected = false;
                return;
            }

            if (!notified) {
                std::thread([]() { Beep(500, 500); }).detach();
                notified = true;
            }

            Sleep(2000);

            try {
                Roblox coreGui = datamodel.FindFirstChild("CoreGui");
                if (coreGui.GetAddress() == 0) continue;

                Roblox robloxGui = coreGui.FindFirstChild("RobloxGui");
                if (robloxGui.GetAddress() == 0) {
                    Sleep(1000);
                    continue;
                }

                Roblox existingExecutor = coreGui.FindFirstChild("SaturnAccessPortal");
                if (existingExecutor.GetAddress() != 0) {
                    uintptr_t injectedDataModelAddress = datamodel.GetAddress();
                    int consecutiveErrors = 0;
                    const int errorThreshold = 5;

                    while (ProcessExists(pid)) {
                        try {
                            Roblox currentDm = FetchDatamodel(base, pid);
                            if (currentDm.GetAddress() != 0 && currentDm.GetAddress() != injectedDataModelAddress)
                                break;
                            if (currentDm.GetAddress() == 0 || currentDm.Name() != "Ugc") {
                                if (++consecutiveErrors >= errorThreshold) break;
                            } else {
                                consecutiveErrors = 0;
                            }
                        } catch (...) {
                            if (++consecutiveErrors >= errorThreshold) break;
                        }
                        Sleep(500);
                    }
                    continue;
                }

                std::string initLua = GetLuaCode(pid, RESOURCE_INIT_SCRIPT);
                if (initLua.empty()) {
                    AddError("GetLuaCode failed for PID " + std::to_string(pid));
                    continue;
                }

                size_t initSize = 0;
                auto initCompiled = Encoder::Compile(initLua);
                if (initCompiled.empty()) {
                    AddError("Compile init failed for PID " + std::to_string(pid));
                    continue;
                }
                auto initSigned = Encoder::Sign(initCompiled, initSize);
                if (!initSigned) {
                    AddError("Sign init failed for PID " + std::to_string(pid));
                    continue;
                }

                robloxGui = coreGui.FindFirstChild("RobloxGui");
                if (robloxGui.GetAddress() == 0) continue;

                Roblox modules = robloxGui.FindFirstChild("Modules");
                if (modules.GetAddress() == 0) continue;

                Roblox playerList = modules.FindFirstChild("PlayerList");
                Roblox plmModule = playerList.FindFirstChild("PlayerListManager");

                bool injectionSuccess = false;
                Sleep(1000);

                if (plmModule.GetAddress() != 0) {
                    Roblox corePackages = datamodel.FindFirstChild("CorePackages");
                    if (corePackages.GetAddress() == 0) continue;

                    Roblox packages = corePackages.FindFirstChild("Packages");
                    if (packages.GetAddress() == 0) continue;

                    Roblox index = packages.FindFirstChild("_Index");
                    if (index.GetAddress() == 0) continue;

                    Roblox cm2d1 = index.FindFirstChild("CollisionMatchers2D");
                    if (cm2d1.GetAddress() == 0) continue;

                    Roblox cm2d2 = cm2d1.FindFirstChild("CollisionMatchers2D");
                    if (cm2d2.GetAddress() == 0) continue;

                    Roblox jest = cm2d2.FindFirstChild("Jest");
                    if (jest.GetAddress() == 0) continue;

                    Handler::WriteMemory(base + Offsets::EnableLoadModule, static_cast<BYTE>(1), pid);
                    Handler::WriteMemory(plmModule.GetAddress() + 0x8, jest.GetAddress(), pid);

                    auto revert = jest.SetScriptBytecode(*initSigned, initSize);

                    HWND hwnd = Game::GetWindowFromProcess(pid);
                    HWND oldForeground = GetForegroundWindow();
                    int attempts = 0;
                    while (GetForegroundWindow() != hwnd && attempts < 20) {
                        SetForegroundWindow(hwnd);
                        Sleep(50);
                        ++attempts;
                    }

                    keybd_event(VK_ESCAPE, static_cast<BYTE>(MapVirtualKey(VK_ESCAPE, 0)), KEYEVENTF_SCANCODE, 0);
                    Sleep(10);
                    keybd_event(VK_ESCAPE, static_cast<BYTE>(MapVirtualKey(VK_ESCAPE, 0)), KEYEVENTF_SCANCODE | KEYEVENTF_KEYUP, 0);
                    Sleep(500);
                    keybd_event(VK_ESCAPE, static_cast<BYTE>(MapVirtualKey(VK_ESCAPE, 0)), KEYEVENTF_SCANCODE, 0);
                    Sleep(10);
                    keybd_event(VK_ESCAPE, static_cast<BYTE>(MapVirtualKey(VK_ESCAPE, 0)), KEYEVENTF_SCANCODE | KEYEVENTF_KEYUP, 0);

                    coreGui.WaitForChild("SaturnAccessPortal");
                    SetForegroundWindow(oldForeground);
                    Handler::WriteMemory(plmModule.GetAddress() + 0x8, plmModule.GetAddress(), pid);
                    revert();
                    injectionSuccess = true;
                } else {
                    Roblox initModule = modules.FindFirstChild("AvatarEditorPrompts");
                    if (initModule.GetAddress() != 0) {
                        Handler::WriteMemory(base + Offsets::EnableLoadModule, static_cast<BYTE>(1), pid);
                        auto revert = initModule.SetScriptBytecode(*initSigned, initSize);
                        coreGui.WaitForChild("SaturnAccessPortal");
                        revert();
                        injectionSuccess = true;
                    }
                }

                if (!injectionSuccess)
                    AddError("Injection failed for PID " + std::to_string(pid));
            } catch (const std::exception& e) {
                AddError(std::string("MonitorProcess exception PID ") + std::to_string(pid) + ": " + e.what());
                Sleep(1000);
            } catch (...) {
                AddError("MonitorProcess unknown exception PID " + std::to_string(pid));
                Sleep(1000);
            }
        }

        std::lock_guard<std::mutex> lock(g_pidMutex);
        g_monitoredPids.erase(pid);
        if (g_monitoredPids.empty()) g_injected = false;
    }

    void ManagerThread() {
        for (;;) {
            {
                std::lock_guard<std::mutex> lock(g_pidMutex);
                for (auto it = g_monitoredPids.begin(); it != g_monitoredPids.end(); ) {
                    if (!ProcessExists(*it))
                        it = g_monitoredPids.erase(it);
                    else
                        ++it;
                }
                g_injected = !g_monitoredPids.empty();
            }
            Sleep(100);
        }
    }

    void StartExecutorSystem() {
        static std::atomic<bool> started{ false };
        if (started.exchange(true)) return;
        MainFunctions::StartBridge();
        std::thread(ManagerThread).detach();
    }
}

extern "C" __declspec(dllexport) void Inject() {
    StartExecutorSystem();

    std::vector<DWORD> pids = Game::GetProcessIds();
    std::lock_guard<std::mutex> lock(g_pidMutex);
    for (DWORD pid : pids) {
        if (g_monitoredPids.find(pid) == g_monitoredPids.end()) {
            g_monitoredPids.insert(pid);
            std::thread(MonitorProcess, pid).detach();
        }
    }
    if (!g_monitoredPids.empty())
        g_injected = true;
}

extern "C" __declspec(dllexport) bool IsInjected() {
    return g_injected.load();
}

extern "C" __declspec(dllexport) void Execute(const wchar_t* input) {
    std::string source = WideToUtf8(input);
    if (!source.empty())
        MainFunctions::Execute(std::move(source));
}

extern "C" __declspec(dllexport) void GetLatestErrors(char* buffer, int size) {
    if (!buffer || size <= 0) return;

    std::lock_guard<std::mutex> lock(g_errorsMutex);
    std::string combined;
    for (const auto& s : g_recentErrors) {
        if (!combined.empty()) combined += "\n";
        combined += s;
    }

    if (combined.empty()) {
        buffer[0] = '\0';
        return;
    }

    size_t copyLen = static_cast<size_t>(size - 1);
    if (combined.size() < copyLen) copyLen = combined.size();
    combined.copy(buffer, copyLen);
    buffer[copyLen] = '\0';
}

extern "C" __declspec(dllexport) void GetDebugLog(char* buffer, int size) {
    if (!buffer || size <= 0) return;

    std::string log = MainFunctions::GetDebugLog();
    size_t copyLen = static_cast<size_t>(size - 1);
    if (log.size() < copyLen) copyLen = log.size();
    log.copy(buffer, copyLen);
    buffer[copyLen] = '\0';
}

int main() {
    return 0;
}
