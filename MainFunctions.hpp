#pragma once

#include <winsock2.h>
#include <Windows.h>
#include <winhttp.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <ShlObj_core.h>

#include <functional>
#include <string>
#include <vector>
#include <regex>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <atomic>
#include <memory>
#include <queue>
#include <thread>
#include <cstdint>
#include <iostream>

#include "Dependencies/server/nlohmann/json.hpp"
#include "SDK/Handler.hpp"
#include "SDK/Game.hpp"
#include "SDK/Roblox.hpp"
#include "SDK/Encoder.hpp"
#include "Offsets.hpp"

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ws2_32.lib")

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace MainFunctions {

    inline std::string g_script;
    inline std::atomic<uintptr_t> g_order{ 0 };
    inline std::unordered_map<DWORD, uintptr_t> g_orders;
    inline std::unordered_set<std::string> g_invalidatedInstances;
    inline std::unordered_map<DWORD, std::vector<std::string>> g_teleportQueues;
    inline std::atomic<bool> g_consoleClosable{ false };
    inline std::atomic<bool> g_consoleHandlerSet{ false };
    inline std::queue<std::string> g_outputQueue;
    inline std::mutex g_outputMutex;

    inline std::unordered_map<std::string, uintptr_t> g_fflagOffsets;
    inline std::string g_cachedApiVersion;
    inline bool g_fflagsLoaded = false;
    inline std::mutex g_fflagMutex;
    inline const std::unordered_set<std::string> g_fflagBlacklist = { "EnableLoadModule" };

    constexpr size_t MAX_DEBUG_LOG_SIZE = 32000;
    inline std::string g_debugLog;
    inline std::mutex g_debugMutex;

    inline void LogDebug(const std::string& msg) {
        std::lock_guard<std::mutex> lock(g_debugMutex);
        DWORD t = GetTickCount();
        std::string line = "[" + std::to_string(t) + "] " + msg + "\n";
        g_debugLog += line;
        if (g_debugLog.size() > MAX_DEBUG_LOG_SIZE)
            g_debugLog = g_debugLog.substr(g_debugLog.size() - MAX_DEBUG_LOG_SIZE);
    }

    inline std::string GetDebugLog() {
        std::lock_guard<std::mutex> lock(g_debugMutex);
        return g_debugLog;
    }

    inline std::string GetRobloxVersionFromPid(DWORD pid) {
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (hSnap == INVALID_HANDLE_VALUE) return "";

        MODULEENTRY32W modEntry = {};
        modEntry.dwSize = sizeof(modEntry);
        std::string versionStr;

        if (!Module32FirstW(hSnap, &modEntry)) {
            CloseHandle(hSnap);
            return "";
        }

        do {
            if (_wcsicmp(modEntry.szModule, L"RobloxPlayerBeta.exe") == 0) {
                std::wstring exePath(modEntry.szExePath);
                size_t versionPos = exePath.find(L"version-");
                if (versionPos != std::wstring::npos) {
                    size_t endPos = exePath.find(L'\\', versionPos);
                    if (endPos == std::wstring::npos) endPos = exePath.find(L'/', versionPos);
                    if (endPos == std::wstring::npos) endPos = exePath.length();
                    std::wstring versionWStr = exePath.substr(versionPos, endPos - versionPos);
                    versionStr.assign(versionWStr.begin(), versionWStr.end());
                }
                break;
            }
        } while (Module32NextW(hSnap, &modEntry));

        CloseHandle(hSnap);
        return versionStr;
    }

    inline std::string HttpGet(const std::string& url) {
        std::regex urlRe(R"(^(https?)://([^/]+)(/.*)?$)");
        std::smatch m;
        if (!std::regex_match(url, m, urlRe)) return "";

        bool secure = (m[1].str() == "https");
        std::string host = m[2].str();
        std::string path = m[3].matched ? m[3].str() : "/";

        std::wstring whost(host.begin(), host.end());
        std::wstring wpath(path.begin(), path.end());

        HINTERNET hSession = WinHttpOpen(L"Saturn/1.0",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) return "";

        INTERNET_PORT port = secure ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT;
        HINTERNET hConnect = WinHttpConnect(hSession, whost.c_str(), port, 0);
        if (!hConnect) {
            WinHttpCloseHandle(hSession);
            return "";
        }

        DWORD flags = secure ? WINHTTP_FLAG_SECURE : 0;
        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", wpath.c_str(),
            nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
        if (!hRequest) {
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return "";
        }

        BOOL sent = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
        if (!sent) {
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return "";
        }

        if (!WinHttpReceiveResponse(hRequest, nullptr)) {
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return "";
        }

        std::string body;
        DWORD size = 0;
        do {
            if (!WinHttpQueryDataAvailable(hRequest, &size) || size == 0) break;
            std::vector<char> buf(size);
            DWORD read = 0;
            if (!WinHttpReadData(hRequest, buf.data(), size, &read)) break;
            body.append(buf.data(), read);
        } while (size > 0);

        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return body;
    }

    inline std::string FetchAPIVersion() {
        std::string body = HttpGet("https://offsets.ntgetwritewatch.workers.dev/version");
        while (!body.empty() && (body.back() == '\n' || body.back() == '\r' || body.back() == ' '))
            body.pop_back();
        return body;
    }

    inline void FetchFFlags() {
        std::lock_guard<std::mutex> lock(g_fflagMutex);
        if (g_fflagsLoaded) return;

        std::string body = HttpGet("https://offsets.ntgetwritewatch.workers.dev/FFlags.hpp");
        if (body.empty()) return;

        std::regex pattern(R"(uintptr_t\s+(\w+)\s*=\s*(0x[0-9A-Fa-f]+);)");
        std::smatch match;
        std::string::const_iterator searchStart(body.cbegin());
        while (std::regex_search(searchStart, body.cend(), match, pattern)) {
            std::string name = match[1].str();
            if (g_fflagBlacklist.find(name) == g_fflagBlacklist.end())
                g_fflagOffsets[name] = std::stoull(match[2].str(), nullptr, 16);
            searchStart = match.suffix().first;
        }
        g_cachedApiVersion = FetchAPIVersion();
        g_fflagsLoaded = true;
    }

    inline bool CheckVersionMatch(DWORD pid) {
        if (g_cachedApiVersion.empty())
            g_cachedApiVersion = FetchAPIVersion();
        std::string robloxVersion = GetRobloxVersionFromPid(pid);
        return !robloxVersion.empty() && !g_cachedApiVersion.empty() && robloxVersion == g_cachedApiVersion;
    }

    inline fs::path WorkspaceRoot() {
        static fs::path workspace = []() {
            HMODULE hModule = nullptr;
            GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                reinterpret_cast<LPCWSTR>(&WorkspaceRoot), &hModule);

            wchar_t modulePath[MAX_PATH] = {};
            DWORD len = GetModuleFileNameW(hModule, modulePath, MAX_PATH);
            fs::path mod(modulePath, modulePath + (len ? len : 0));

            fs::path baseDir = fs::current_path();
            if (!mod.empty()) {
                fs::path moduleDir = mod.parent_path();
                if (!moduleDir.empty() && !moduleDir.parent_path().empty())
                    baseDir = moduleDir.parent_path();
                else if (!moduleDir.empty())
                    baseDir = moduleDir;
            }

            fs::path workspaceDir = baseDir / "workspace";
            std::error_code ec;
            fs::create_directories(workspaceDir, ec);
            return workspaceDir;
        }();
        return workspace;
    }

    inline std::vector<std::string> SplitLines(const std::string& str) {
        std::stringstream ss(str);
        std::string line;
        std::vector<std::string> lines;
        while (std::getline(ss, line, '\n'))
            lines.push_back(line);
        return lines;
    }

    inline fs::path ResolvePath(const std::string& rawPath) {
        fs::path rel(rawPath);
        if (rel.is_absolute()) {
            rel = rel.lexically_relative(rel.root_path());
            if (rel.empty()) rel = rel.filename();
        }
        rel = rel.lexically_normal();
        auto base = WorkspaceRoot();
        fs::path combined = (base / rel).lexically_normal();

        std::error_code ec;
        fs::path normalized = fs::weakly_canonical(combined, ec);
        if (ec) normalized = combined;

        auto root = WorkspaceRoot().lexically_normal();
        if (root.empty() || root == "/") return normalized;

        auto normalizedStr = normalized.lexically_normal().wstring();
        auto rootStr = root.wstring();
        bool inRoot = normalizedStr.size() >= rootStr.size() &&
            normalizedStr.compare(0, rootStr.size(), rootStr) == 0 &&
            (normalizedStr.size() == rootStr.size() || normalizedStr[rootStr.size()] == L'\\' || normalizedStr[rootStr.size()] == L'/');
        if (!inRoot) normalized = root / rel.filename();
        return normalized;
    }

    inline bool SendMouseInput(DWORD flags, LONG dx = 0, LONG dy = 0, DWORD mouseData = 0, bool absolute = false) {
        INPUT input = {};
        input.type = INPUT_MOUSE;
        input.mi.dwFlags = flags;
        input.mi.dx = dx;
        input.mi.dy = dy;
        input.mi.mouseData = mouseData;
        if (absolute) input.mi.dwFlags |= MOUSEEVENTF_ABSOLUTE;
        return SendInput(1, &input, sizeof(INPUT)) == 1;
    }

    inline bool SendMouseClick(DWORD downFlag, DWORD upFlag) {
        return SendMouseInput(downFlag) && SendMouseInput(upFlag);
    }

    inline bool SendKeyboardInput(WORD vk, bool down) {
        INPUT input = {};
        input.type = INPUT_KEYBOARD;
        input.ki.wVk = vk;
        input.ki.dwFlags = down ? 0 : KEYEVENTF_KEYUP;
        return SendInput(1, &input, sizeof(INPUT)) == 1;
    }

    inline void DisableConsoleClose() {
        HWND hwnd = GetConsoleWindow();
        if (!hwnd) return;
        HMENU hMenu = GetSystemMenu(hwnd, FALSE);
        if (hMenu) DeleteMenu(hMenu, SC_CLOSE, MF_BYCOMMAND);
    }

    inline void EnableConsoleClose() {
        HWND hwnd = GetConsoleWindow();
        if (!hwnd) return;
        GetSystemMenu(hwnd, TRUE);
        GetSystemMenu(hwnd, FALSE);
    }

    inline BOOL WINAPI ConsoleCtrlHandler(DWORD ctrlType) {
        if (ctrlType == CTRL_CLOSE_EVENT && g_consoleClosable.load())
            FreeConsole();
        return (ctrlType == CTRL_CLOSE_EVENT) ? TRUE : FALSE;
    }

    inline bool EnsureConsole() {
        static std::atomic<bool> initialized{ false };
        if (GetConsoleWindow() && initialized.load()) return true;

        if (!GetConsoleWindow()) {
            if (!AllocConsole()) return false;
        }

        FILE* dummy = nullptr;
        freopen_s(&dummy, "CONOUT$", "w", stdout);
        freopen_s(&dummy, "CONOUT$", "w", stderr);
        freopen_s(&dummy, "CONIN$", "r", stdin);
        SetConsoleOutputCP(CP_UTF8);
        initialized = true;
        g_consoleClosable = false;
        DisableConsoleClose();
        if (!g_consoleHandlerSet.exchange(true))
            SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);
        return true;
    }

    inline WORD DefaultConsoleAttributes() {
        static WORD attrs = []() {
            EnsureConsole();
            CONSOLE_SCREEN_BUFFER_INFO info = {};
            if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &info))
                return info.wAttributes;
            return static_cast<WORD>(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        }();
        return attrs;
    }

    inline void SetConsoleColor(WORD color) {
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
    }

    inline std::wstring ToWide(const std::string& utf8) {
        if (utf8.empty()) return L"";
        int sizeNeeded = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), static_cast<int>(utf8.size()), nullptr, 0);
        if (sizeNeeded <= 0) return L"";
        std::wstring wide(static_cast<size_t>(sizeNeeded), 0);
        MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), static_cast<int>(utf8.size()), wide.data(), sizeNeeded);
        return wide;
    }

    inline std::string ConsoleReadLine() {
        if (!EnsureConsole()) return "";
        std::string line;
        std::getline(std::cin, line);
        return line;
    }

    inline void ConsolePrint(const std::string& msg, WORD color = DefaultConsoleAttributes()) {
        if (!EnsureConsole()) return;
        WORD original = DefaultConsoleAttributes();
        SetConsoleColor(color);
        std::wcout << ToWide(msg);
        if (!msg.empty() && msg.back() != '\n') std::wcout << L"\n";
        SetConsoleColor(original);
    }

    inline void ConsoleClear() {
        if (!EnsureConsole()) return;
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        CONSOLE_SCREEN_BUFFER_INFO csbi = {};
        if (!GetConsoleScreenBufferInfo(hConsole, &csbi)) return;
        DWORD cellCount = csbi.dwSize.X * csbi.dwSize.Y;
        DWORD count = 0;
        FillConsoleOutputCharacter(hConsole, (TCHAR)' ', cellCount, { 0, 0 }, &count);
        FillConsoleOutputAttribute(hConsole, csbi.wAttributes, cellCount, { 0, 0 }, &count);
        SetConsoleCursorPosition(hConsole, { 0, 0 });
    }

    inline Roblox GetPointerInstance(const std::string& name, DWORD processId) {
        auto baseOpt = Game::GetModuleBase(processId);
        if (!baseOpt) return Roblox(0, processId);

        Roblox datamodel = FetchDatamodel(*baseOpt, processId);
        Roblox coreGui = datamodel.FindFirstChild("CoreGui");
        Roblox SaturnAccessPortal = coreGui.FindFirstChild("SaturnAccessPortal");
        Roblox pointers = SaturnAccessPortal.FindFirstChild("Pointer");
        Roblox pointer = pointers.FindFirstChild(name);
        if (pointer.GetAddress() == 0) return Roblox(0, processId);

        auto targetOpt = Handler::ReadMemory<uintptr_t>(pointer.GetAddress() + Offsets::Value, processId);
        if (!targetOpt) return Roblox(0, processId);
        return Roblox(*targetOpt, processId);
    }

    struct PipeConnection {
        HANDLE hPipe = INVALID_HANDLE_VALUE;
        std::vector<std::string> msgQueue;
        std::mutex queueMutex;
        std::atomic<bool> isOpen{ false };
        std::vector<char> readBuffer;

        void pushMessage(std::string msg) {
            std::lock_guard<std::mutex> lock(queueMutex);
            msgQueue.push_back(std::move(msg));
        }

        std::vector<std::string> popAllMessages() {
            std::lock_guard<std::mutex> lock(queueMutex);
            std::vector<std::string> ret = std::move(msgQueue);
            msgQueue.clear();
            return ret;
        }

        bool tryReadMessage() {
            if (hPipe == INVALID_HANDLE_VALUE || !isOpen) return false;
            DWORD size = 0;
            if (!PeekNamedPipe(hPipe, nullptr, 0, nullptr, &size, nullptr) || size < 4)
                return false;
            uint32_t len = 0;
            DWORD read = 0;
            if (!ReadFile(hPipe, &len, 4, &read, nullptr) || read != 4) return false;
            if (len == 0 || len > 1024 * 1024) return false;
            std::string msg(len, '\0');
            if (!ReadFile(hPipe, &msg[0], len, &read, nullptr) || read != len) return false;
            pushMessage(std::move(msg));
            return true;
        }

        void close() {
            if (hPipe != INVALID_HANDLE_VALUE) {
                CloseHandle(hPipe);
                hPipe = INVALID_HANDLE_VALUE;
            }
            isOpen = false;
        }
    };

    inline std::unordered_map<std::string, std::shared_ptr<PipeConnection>> g_pipeConnections;
    inline std::mutex g_pipeMapMutex;

    inline std::string HttpRequest(const std::string& url, const std::string& method,
        const std::string& body, const json& headersJ) {
        std::regex urlRe(R"(^(https?)://([^/]+)(/.*)?$)");
        std::smatch m;
        if (!std::regex_match(url, m, urlRe)) return "[]";

        bool secure = (m[1].str() == "https");
        std::string host = m[2].str();
        std::string path = m[3].matched ? m[3].str() : "/";

        std::wstring whost(host.begin(), host.end());
        std::wstring wpath(path.begin(), path.end());

        HINTERNET hSession = WinHttpOpen(L"Saturn/1.0",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) return "[]";

        INTERNET_PORT port = secure ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT;
        HINTERNET hConnect = WinHttpConnect(hSession, whost.c_str(), port, 0);
        if (!hConnect) {
            WinHttpCloseHandle(hSession);
            return "[]";
        }

        const wchar_t* verb = L"GET";
        if (method == "POST") verb = L"POST";
        else if (method == "PUT") verb = L"PUT";
        else if (method == "DELETE") verb = L"DELETE";
        else if (method == "PATCH") verb = L"PATCH";

        DWORD flags = secure ? WINHTTP_FLAG_SECURE : 0;
        HINTERNET hRequest = WinHttpOpenRequest(hConnect, verb, wpath.c_str(),
            nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
        if (!hRequest) {
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return "[]";
        }

        std::wstring headersStr = L"Content-Type: application/json\r\n";
        for (auto it = headersJ.begin(); it != headersJ.end(); ++it) {
            std::string k = it.key();
            std::string v = it.value().get<std::string>();
            headersStr += std::wstring(k.begin(), k.end()) + L": " + std::wstring(v.begin(), v.end()) + L"\r\n";
        }

        BOOL sent;
        if (body.empty()) {
            sent = WinHttpSendRequest(hRequest, headersStr.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : headersStr.c_str(),
                (DWORD)headersStr.size(), WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
        } else {
            sent = WinHttpSendRequest(hRequest, headersStr.c_str(), (DWORD)headersStr.size(),
                (LPVOID)body.data(), (DWORD)body.size(), (DWORD)body.size(), 0);
        }
        if (!sent) {
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return "[]";
        }

        if (!WinHttpReceiveResponse(hRequest, nullptr)) {
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return "[]";
        }

        std::string responseBody;
        DWORD size = 0;
        do {
            if (!WinHttpQueryDataAvailable(hRequest, &size) || size == 0) break;
            std::vector<char> buf(size);
            DWORD read = 0;
            if (!WinHttpReadData(hRequest, buf.data(), size, &read)) break;
            responseBody.append(buf.data(), read);
        } while (size > 0);

        DWORD statusCode = 0;
        DWORD statusSize = sizeof(statusCode);
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusSize, WINHTTP_NO_HEADER_INDEX);

        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);

        json responseJ;
        responseJ["b"] = responseBody;
        responseJ["c"] = statusCode;
        responseJ["r"] = "";
        responseJ["v"] = "1.1";
        responseJ["h"] = json::object();
        return responseJ.dump();
    }

    using EnvHandler = std::function<std::string(std::string, json, DWORD)>;
    inline std::unordered_map<std::string, EnvHandler> g_env;

    inline void Load() {
        g_env["pipe_connect"] = [](std::string dta, json set, DWORD pid) -> std::string {
            std::string pipename = set.contains("pipename") ? set["pipename"].get<std::string>() : set.contains("url") ? set["url"].get<std::string>() : "";
            if (pipename.empty()) return "";

            if (pipename.find("\\\\.\\pipe\\") != 0 && pipename.find("\\\\?\\pipe\\") != 0)
                pipename = "\\\\.\\pipe\\" + pipename;

            std::wstring wname(pipename.begin(), pipename.end());
            HANDLE h = CreateFileW(wname.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
            if (h == INVALID_HANDLE_VALUE) return "";

            auto conn = std::make_shared<PipeConnection>();
            conn->hPipe = h;
            conn->isOpen = true;
            std::string id = "pipe_" + std::to_string(reinterpret_cast<uintptr_t>(conn.get()));

            {
                std::lock_guard<std::mutex> lock(g_pipeMapMutex);
                g_pipeConnections[id] = conn;
            }
            return id;
        };

        g_env["pipe_send"] = [](std::string dta, json set, DWORD pid) -> std::string {
            std::string id = set.contains("id") ? set["id"].get<std::string>() : "";
            std::string msg = set.contains("msg") ? set["msg"].get<std::string>() : dta;

            std::shared_ptr<PipeConnection> conn;
            {
                std::lock_guard<std::mutex> lock(g_pipeMapMutex);
                auto it = g_pipeConnections.find(id);
                if (it != g_pipeConnections.end()) conn = it->second;
            }

            if (!conn || !conn->isOpen || conn->hPipe == INVALID_HANDLE_VALUE) return "FAILURE";

            uint32_t len = static_cast<uint32_t>(msg.size());
            DWORD written = 0;
            if (!WriteFile(conn->hPipe, &len, 4, &written, nullptr) || written != 4) return "FAILURE";
            if (!WriteFile(conn->hPipe, msg.data(), len, &written, nullptr) || written != len) return "FAILURE";
            return "SUCCESS";
        };

        g_env["pipe_close"] = [](std::string dta, json set, DWORD pid) -> std::string {
            std::string id = set.contains("id") ? set["id"].get<std::string>() : "";

            std::shared_ptr<PipeConnection> conn;
            {
                std::lock_guard<std::mutex> lock(g_pipeMapMutex);
                auto it = g_pipeConnections.find(id);
                if (it != g_pipeConnections.end()) {
                    conn = it->second;
                    g_pipeConnections.erase(it);
                }
            }
            if (conn) {
                conn->close();
                return "SUCCESS";
            }
            return "FAILURE";
        };

        g_env["pipe_poll"] = [](std::string dta, json set, DWORD pid) -> std::string {
            std::string id = set.contains("id") ? set["id"].get<std::string>() : "";

            std::shared_ptr<PipeConnection> conn;
            {
                std::lock_guard<std::mutex> lock(g_pipeMapMutex);
                auto it = g_pipeConnections.find(id);
                if (it != g_pipeConnections.end()) conn = it->second;
            }

            if (conn) {
                while (conn->tryReadMessage()) {}
                auto msgs = conn->popAllMessages();
                json j = json::array();
                for (const auto& m : msgs) j.push_back(m);
                return j.dump();
            }
            return "[]";
        };

        g_env["listen"] = [](std::string dta, json set, DWORD pid) -> std::string {
            std::string res;
            uintptr_t curOrder = g_order.load();
            bool hadPid = (g_orders.count(pid) != 0);
            uintptr_t oldOrderPid = hadPid ? g_orders[pid] : 0;

            if (g_orders.count(pid)) {
                if (g_orders[pid] < curOrder)
                    res = g_script;
                else
                    res = "";
                g_orders[pid] = curOrder;
            } else {
                g_orders[pid] = curOrder;
                res = g_script;
            }
            LogDebug("listen pid=" + std::to_string(pid) + " hadPid=" + (hadPid ? "1" : "0") +
                " oldOrder=" + std::to_string(oldOrderPid) + " curOrder=" + std::to_string(curOrder) +
                " scriptLen=" + std::to_string(g_script.size()) + " returnLen=" + std::to_string(res.size()));
            if (res.size() > 0)
                LogDebug("listen -> SCRIPT SENT TO GAME pid=" + std::to_string(pid) + " len=" + std::to_string(res.size()));
            return res;
        };

        g_env["compile"] = [](std::string dta, json set, DWORD pid) -> std::string {
            if (set.contains("enc") && set["enc"] == "true")
                return Encoder::Compile(dta);
            return Encoder::NormalCompile(dta);
        };

        g_env["setscriptbytecode"] = [](std::string dta, json set, DWORD pid) -> std::string {
            size_t sized = 0;
            auto compressed = Encoder::Sign(dta, sized);
            if (!compressed) return "";

            Roblox theScript = GetPointerInstance(set.contains("cn") ? set["cn"].get<std::string>() : "", pid);
            if (theScript.GetAddress() == 0) return "";
            theScript.SetScriptBytecode(*compressed, sized);
            return "";
        };

        g_env["getscriptbytecode"] = [](std::string dta, json set, DWORD pid) -> std::string {
            Roblox theScript = GetPointerInstance(set.contains("cn") ? set["cn"].get<std::string>() : "", pid);
            if (theScript.GetAddress() == 0) return "";
            return theScript.GetScriptBytecode();
        };

        g_env["request"] = [](std::string dta, json set, DWORD pid) -> std::string {
            std::string url = set.contains("l") ? set["l"].get<std::string>() : "";
            std::string method = set.contains("m") ? set["m"].get<std::string>() : "GET";
            std::string rBody = set.contains("b") ? set["b"].get<std::string>() : "";
            json headersJ = set.contains("h") ? set["h"] : json::object();
            return HttpRequest(url, method, rBody, headersJ);
        };

        g_env["readfile"] = [](std::string dta, json set, DWORD pid) -> std::string {
            auto path = ResolvePath(dta);
            std::error_code ec;
            if (!fs::exists(path, ec) || !fs::is_regular_file(path, ec)) return "__EE_FNF__";
            std::ifstream file(path, std::ios::binary);
            if (!file.is_open()) return "__EE_FNF__";
            std::ostringstream buffer;
            buffer << file.rdbuf();
            return buffer.str();
        };

        g_env["writefile"] = [](std::string dta, json set, DWORD pid) -> std::string {
            std::string pathStr = set.contains("path") ? set["path"].get<std::string>() : "";
            if (pathStr.empty()) return "";
            auto path = ResolvePath(pathStr);
            std::error_code ec;
            if (!path.parent_path().empty()) fs::create_directories(path.parent_path(), ec);
            std::ofstream file(path, std::ios::binary);
            if (!file.is_open()) return "";
            file << dta;
            return "success";
        };

        g_env["makefolder"] = [](std::string dta, json set, DWORD pid) -> std::string {
            auto path = ResolvePath(dta);
            std::error_code ec;
            if (fs::exists(path, ec) && fs::is_directory(path, ec)) return "success";
            fs::create_directories(path, ec);
            return ec ? "" : "success";
        };

        g_env["isfile"] = [](std::string dta, json set, DWORD pid) -> std::string {
            auto path = ResolvePath(dta);
            std::error_code ec;
            return (fs::exists(path, ec) && fs::is_regular_file(path, ec)) ? "true" : "false";
        };

        g_env["isfolder"] = [](std::string dta, json set, DWORD pid) -> std::string {
            auto path = ResolvePath(dta);
            std::error_code ec;
            return (fs::exists(path, ec) && fs::is_directory(path, ec)) ? "true" : "false";
        };

        g_env["listfiles"] = [](std::string dta, json set, DWORD pid) -> std::string {
            auto root = WorkspaceRoot();
            auto path = ResolvePath(dta);
            std::error_code ec;
            json results = json::array();
            if (fs::exists(path, ec) && fs::is_directory(path, ec)) {
                for (const auto& entry : fs::directory_iterator(path, ec)) {
                    if (ec) break;
                    try {
                        results.push_back(fs::relative(entry.path(), root).generic_string());
                    } catch (...) {
                        results.push_back(entry.path().filename().generic_string());
                    }
                }
            }
            return results.dump();
        };

        g_env["delfile"] = [](std::string dta, json set, DWORD pid) -> std::string {
            auto path = ResolvePath(dta);
            std::error_code ec;
            bool removed = (fs::is_regular_file(path, ec) && fs::remove(path, ec)) && !ec;
            return removed ? "success" : "";
        };

        g_env["delfolder"] = [](std::string dta, json set, DWORD pid) -> std::string {
            auto path = ResolvePath(dta);
            std::error_code ec;
            if (!fs::exists(path, ec) || !fs::is_directory(path, ec)) return "";
            fs::remove_all(path, ec);
            return ec ? "" : "success";
        };

        g_env["mouse1click"] = [](std::string, json, DWORD) -> std::string {
            return SendMouseClick(MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP) ? "SUCCESS" : "";
        };
        g_env["mouse2click"] = [](std::string, json, DWORD) -> std::string {
            return SendMouseClick(MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP) ? "SUCCESS" : "";
        };
        g_env["mouse1press"] = [](std::string, json, DWORD) -> std::string {
            return SendMouseInput(MOUSEEVENTF_LEFTDOWN) ? "SUCCESS" : "";
        };
        g_env["mouse1release"] = [](std::string, json, DWORD) -> std::string {
            return SendMouseInput(MOUSEEVENTF_LEFTUP) ? "SUCCESS" : "";
        };
        g_env["mouse2press"] = [](std::string, json, DWORD) -> std::string {
            return SendMouseInput(MOUSEEVENTF_RIGHTDOWN) ? "SUCCESS" : "";
        };
        g_env["mouse2release"] = [](std::string, json, DWORD) -> std::string {
            return SendMouseInput(MOUSEEVENTF_RIGHTUP) ? "SUCCESS" : "";
        };
        g_env["mousemoveabs"] = [](std::string dta, json set, DWORD pid) -> std::string {
            if (!set.contains("x") || !set.contains("y")) return "";
            double x = set["x"].get<double>();
            double y = set["y"].get<double>();
            int screenX = GetSystemMetrics(SM_CXSCREEN) - 1;
            int screenY = GetSystemMetrics(SM_CYSCREEN) - 1;
            LONG dx = static_cast<LONG>(x * 65535.0 / screenX);
            LONG dy = static_cast<LONG>(y * 65535.0 / screenY);
            return SendMouseInput(MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE, dx, dy, 0, true) ? "SUCCESS" : "";
        };
        g_env["mousemoverel"] = [](std::string dta, json set, DWORD pid) -> std::string {
            if (!set.contains("x") || !set.contains("y")) return "";
            LONG dx = static_cast<LONG>(set["x"].get<double>());
            LONG dy = static_cast<LONG>(set["y"].get<double>());
            return SendMouseInput(MOUSEEVENTF_MOVE, dx, dy) ? "SUCCESS" : "";
        };
        g_env["mousescroll"] = [](std::string dta, json set, DWORD pid) -> std::string {
            if (!set.contains("delta")) return "";
            int delta = static_cast<int>(set["delta"].get<double>() * WHEEL_DELTA);
            return SendMouseInput(MOUSEEVENTF_WHEEL, 0, 0, static_cast<DWORD>(delta)) ? "SUCCESS" : "";
        };
        g_env["keypress"] = [](std::string dta, json set, DWORD pid) -> std::string {
            if (!set.contains("key")) return "";
            return SendKeyboardInput(static_cast<WORD>(set["key"].get<int>()), true) ? "SUCCESS" : "";
        };
        g_env["keyrelease"] = [](std::string dta, json set, DWORD pid) -> std::string {
            if (!set.contains("key")) return "";
            return SendKeyboardInput(static_cast<WORD>(set["key"].get<int>()), false) ? "SUCCESS" : "";
        };
        g_env["invalidateinstance"] = [](std::string dta, json set, DWORD pid) -> std::string {
            if (!set.contains("address")) return "";
            g_invalidatedInstances.insert(set["address"].get<std::string>());
            return "SUCCESS";
        };
        g_env["isinstancecached"] = [](std::string dta, json set, DWORD pid) -> std::string {
            if (!set.contains("address")) return "false";
            return g_invalidatedInstances.find(set["address"].get<std::string>()) == g_invalidatedInstances.end() ? "true" : "false";
        };
        g_env["setclipboard"] = [](std::string dta, json set, DWORD pid) -> std::string {
            int wideLen = MultiByteToWideChar(CP_UTF8, 0, dta.c_str(), -1, nullptr, 0);
            if (wideLen <= 0) return "";
            std::wstring wide(static_cast<size_t>(wideLen), 0);
            MultiByteToWideChar(CP_UTF8, 0, dta.c_str(), -1, &wide[0], wideLen);
            if (!OpenClipboard(nullptr)) return "";
            if (!EmptyClipboard()) { CloseClipboard(); return ""; }
            size_t bytes = (wide.size() + 1) * sizeof(wchar_t);
            HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, bytes);
            if (!hMem) { CloseClipboard(); return ""; }
            void* memPtr = GlobalLock(hMem);
            if (!memPtr) { GlobalFree(hMem); CloseClipboard(); return ""; }
            memcpy(memPtr, wide.c_str(), bytes);
            GlobalUnlock(hMem);
            SetClipboardData(CF_UNICODETEXT, hMem);
            CloseClipboard();
            return "SUCCESS";
        };
        g_env["isrbxactive"] = [](std::string dta, json set, DWORD pid) -> std::string {
            HWND target = Game::GetWindowFromProcess(pid);
            return (target && GetForegroundWindow() == target) ? "true" : "false";
        };
        g_env["consolecreate"] = [](std::string, json, DWORD) -> std::string {
            return EnsureConsole() ? "SUCCESS" : "";
        };
        g_env["rconsolecreate"] = g_env["consolecreate"];
        g_env["consoleclear"] = [](std::string, json, DWORD) -> std::string {
            ConsoleClear();
            return "SUCCESS";
			
        };
        g_env["rconsoleclear"] = g_env["consoleclear"];
        g_env["consoleprint"] = [](std::string dta, json, DWORD) -> std::string {
            ConsolePrint(dta, DefaultConsoleAttributes());
            return "SUCCESS";
        };
        g_env["rconsoleprint"] = g_env["consoleprint"];
        g_env["consoleinfo"] = [](std::string dta, json, DWORD) -> std::string {
            ConsolePrint(dta, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            return "SUCCESS";
        };
        g_env["rconsoleinfo"] = g_env["consoleinfo"];
        g_env["consolewarn"] = [](std::string dta, json, DWORD) -> std::string {
            ConsolePrint(dta, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            return "SUCCESS";
        };
        g_env["rconsolewarn"] = g_env["consolewarn"];
        g_env["consoleerr"] = [](std::string dta, json, DWORD) -> std::string {
            ConsolePrint(dta, FOREGROUND_RED | FOREGROUND_INTENSITY);
            return "SUCCESS";
        };
        g_env["rconsoleerr"] = g_env["consoleerr"];
        g_env["rconsoleerror"] = g_env["consoleerr"];
        g_env["consoleinput"] = [](std::string, json, DWORD) -> std::string { return ConsoleReadLine(); };
        g_env["rconsoleinput"] = g_env["consoleinput"];
        g_env["rconsolename"] = [](std::string, json, DWORD) -> std::string {
            char title[256] = {};
            DWORD len = GetConsoleTitleA(title, static_cast<DWORD>(sizeof(title)));
            return len ? std::string(title, len) : "";
        };
        g_env["rconsolesettitle"] = [](std::string dta, json set, DWORD) -> std::string {
            std::string title = set.contains("title") ? set["title"].get<std::string>() : dta;
            if (title.empty()) title = "Saturn Console";
            EnsureConsole();
            SetConsoleTitleA(title.c_str());
            return "SUCCESS";
        };
        g_env["rconsoleclose"] = [](std::string, json, DWORD) -> std::string {
            EnsureConsole();
            g_consoleClosable = true;
            EnableConsoleClose();
            FreeConsole();
            return "SUCCESS";
        };
        g_env["rconsoledestroy"] = g_env["rconsoleclose"];
        g_env["queueteleport"] = [](std::string dta, json set, DWORD pid) -> std::string {
            g_teleportQueues[pid].push_back(dta);
            return "SUCCESS";
        };
        g_env["getteleportqueue"] = [](std::string dta, json set, DWORD pid) -> std::string {
            if (!g_teleportQueues.count(pid) || g_teleportQueues[pid].empty()) return "[]";
            json queue = json::array();
            for (const auto& script : g_teleportQueues[pid]) queue.push_back(script);
            g_teleportQueues[pid].clear();
            return queue.dump();
        };
        g_env["messagebox"] = [](std::string dta, json set, DWORD pid) -> std::string {
            std::string text = set.contains("text") ? set["text"].get<std::string>() : "";
            std::string caption = set.contains("caption") ? set["caption"].get<std::string>() : "";
            int type = set.contains("type") ? set["type"].get<int>() : 0;
            return std::to_string(MessageBoxA(nullptr, text.c_str(), caption.c_str(), type | MB_TOPMOST));
        };
        g_env["getcustomasset"] = [](std::string dta, json set, DWORD pid) -> std::string {
            std::string fileName = set.contains("filePath") ? set["filePath"].get<std::string>() : "";
            if (fileName.empty() || dta.empty()) return "INVALID_PARAMETERS";

            HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (!hProcess) return "ROBLOX_PATH_NOT_FOUND";

            wchar_t exePath[MAX_PATH] = {};
            DWORD size = MAX_PATH;
            BOOL success = QueryFullProcessImageNameW(hProcess, 0, exePath, &size);
            CloseHandle(hProcess);
            if (!success || size == 0) return "ROBLOX_PATH_NOT_FOUND";

            fs::path robloxDir(exePath);
            robloxDir = robloxDir.parent_path();
            fs::path robloxContentPath = robloxDir / "content";

            std::error_code ec;
            if (!fs::exists(robloxContentPath, ec)) {
                fs::create_directories(robloxContentPath, ec);
                if (ec) return "ROBLOX_PATH_NOT_FOUND";
            }

            std::string subFolder;
            fs::path filePath(fileName);
            std::string ext = filePath.extension().string();
            std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

            if (ext == ".mp3" || ext == ".ogg" || ext == ".wav" || ext == ".flac") subFolder = "sounds";
            else if (ext == ".png" || ext == ".jpg" || ext == ".jpeg" || ext == ".bmp" || ext == ".tga" || ext == ".dds") subFolder = "textures";
            else if (ext == ".rbxm" || ext == ".rbxmx") subFolder = "models";
            else if (ext == ".ttf" || ext == ".otf") subFolder = "fonts";

            fs::path targetDir = robloxContentPath;
            if (!subFolder.empty()) {
                targetDir = robloxContentPath / subFolder;
                fs::create_directories(targetDir, ec);
            }

            fs::path targetPath = targetDir / fileName;
            std::ofstream outFile(targetPath, std::ios::binary);
            if (!outFile.is_open()) return "FILE_CREATION_FAILED";
            outFile << dta;
            outFile.close();
            return subFolder.empty() ? fileName : (subFolder + "/" + fileName);
        };
        g_env["output"] = [](std::string dta, json set, DWORD pid) -> std::string {
            std::lock_guard<std::mutex> lock(g_outputMutex);
            std::string type = set.contains("type") ? set["type"].get<std::string>() : "Info";
            g_outputQueue.push("[" + type + "] " + dta);
            return "SUCCESS";
        };
        g_env["setfpscap"] = [](std::string dta, json set, DWORD pid) -> std::string {
            double fps = set.contains("fps") ? set["fps"].get<double>() : 60.0;
            double frameDelay = (fps <= 0 || fps > 10000) ? 0.0 : (1.0 / fps);

            auto baseOpt = Game::GetModuleBase(pid);
            if (!baseOpt) return "FAILED_NO_BASE";
            auto taskSchedulerOpt = Handler::ReadMemory<uintptr_t>(*baseOpt + Offsets::TaskSchedulerPointer, pid);
            if (!taskSchedulerOpt || *taskSchedulerOpt < 0x10000) return "FAILED_NO_SCHEDULER";
            if (!Handler::WriteMemory(*taskSchedulerOpt + Offsets::TaskSchedulerMaxFPS, frameDelay, pid)) return "FAILED";
            return "SUCCESS";
        };
        g_env["closeroblox"] = [](std::string dta, json set, DWORD pid) -> std::string {
            HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
            if (!hProcess) return "FAILED";
            TerminateProcess(hProcess, 0);
            CloseHandle(hProcess);
            return "SUCCESS";
        };
        g_env["getfpscap"] = [](std::string dta, json set, DWORD pid) -> std::string {
            auto baseOpt = Game::GetModuleBase(pid);
            if (!baseOpt) return "60";
            auto taskSchedulerOpt = Handler::ReadMemory<uintptr_t>(*baseOpt + Offsets::TaskSchedulerPointer, pid);
            if (!taskSchedulerOpt) return "60";
            auto frameDelayOpt = Handler::ReadMemory<double>(*taskSchedulerOpt + Offsets::TaskSchedulerMaxFPS, pid);
            if (!frameDelayOpt || *frameDelayOpt <= 0.0001) return "0";
            int fps = static_cast<int>(1.0 / *frameDelayOpt + 0.5);
            return (fps > 10000) ? "0" : std::to_string(fps);
        };
        g_env["setfflag"] = [](std::string dta, json set, DWORD pid) -> std::string {
            std::string name = set.contains("name") ? set["name"].get<std::string>() : "";
            std::string value = set.contains("value") ? set["value"].get<std::string>() : dta;
            if (name.empty()) return "INVALID_NAME";
            if (g_fflagBlacklist.find(name) != g_fflagBlacklist.end()) return "BLACKLISTED";

            FetchFFlags();
            if (!CheckVersionMatch(pid)) return "VERSION_MISMATCH";

            auto it = g_fflagOffsets.find(name);
            if (it == g_fflagOffsets.end()) return "NOT_FOUND";

            auto baseOpt = Game::GetModuleBase(pid);
            if (!baseOpt) return "NO_BASE";

            uintptr_t addr = *baseOpt + it->second;
            bool isBoolFlag = (name.find("Enable") != std::string::npos) || (name.find("Disable") != std::string::npos) ||
                (name.find("Use") == 0) || (name.find("Allow") != std::string::npos) || (name.find("Show") != std::string::npos) || (name.find("Is") == 0);

            if (value == "true" || value == "false" || isBoolFlag) {
                Handler::WriteMemory(addr, (value == "true" || value == "1"), pid);
            } else {
                try {
                    long long llVal = std::stoll(value);
                    if (llVal >= INT_MIN && llVal <= INT_MAX)
                        Handler::WriteMemory(addr, static_cast<int>(llVal), pid);
                    else
                        Handler::WriteMemory(addr, llVal, pid);
                } catch (...) {
                    try {
                        Handler::WriteMemory(addr, std::stod(value), pid);
                    } catch (...) {
                        return "INVALID_VALUE";
                    }
                }
            }
            return "SUCCESS";
        };
        g_env["getfflag"] = [](std::string dta, json set, DWORD pid) -> std::string {
            std::string name = set.contains("name") ? set["name"].get<std::string>() : dta;
            if (name.empty()) return "INVALID_NAME";
            if (g_fflagBlacklist.find(name) != g_fflagBlacklist.end()) return "BLACKLISTED";

            FetchFFlags();
            if (!CheckVersionMatch(pid)) return "VERSION_MISMATCH";

            auto it = g_fflagOffsets.find(name);
            if (it == g_fflagOffsets.end()) return "NOT_FOUND";

            auto baseOpt = Game::GetModuleBase(pid);
            if (!baseOpt) return "NO_BASE";

            uintptr_t addr = *baseOpt + it->second;
            bool isBoolFlag = (name.find("Enable") != std::string::npos) || (name.find("Disable") != std::string::npos) ||
                (name.find("Use") == 0) || (name.find("Allow") != std::string::npos) || (name.find("Show") != std::string::npos) || (name.find("Is") == 0);

            if (isBoolFlag) {
                auto v = Handler::ReadMemory<bool>(addr, pid);
                if (!v) return "FAILED";
                return *v ? "true" : "false";
            }
            auto intVal = Handler::ReadMemory<int>(addr, pid);
            if (!intVal) return "FAILED";
            return std::to_string(*intVal);
        };
        g_env["gethwid"] = [](std::string, json, DWORD) -> std::string {
            HKEY hKey = nullptr;
            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ, &hKey) != ERROR_SUCCESS) return "UNKNOWN";
            char guid[256] = {};
            DWORD size = sizeof(guid);
            if (RegQueryValueExA(hKey, "MachineGuid", nullptr, nullptr, reinterpret_cast<LPBYTE>(guid), &size) != ERROR_SUCCESS) {
                RegCloseKey(hKey);
                return "UNKNOWN";
            }
            RegCloseKey(hKey);
            return std::string(guid);
        };
        g_env["getclipboard"] = [](std::string dta, json set, DWORD pid) -> std::string {
            if (!OpenClipboard(nullptr)) return "";
            HANDLE hData = GetClipboardData(CF_UNICODETEXT);
            if (!hData) { CloseClipboard(); return ""; }
            wchar_t* pszText = static_cast<wchar_t*>(GlobalLock(hData));
            if (!pszText) { CloseClipboard(); return ""; }
            int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, pszText, -1, nullptr, 0, nullptr, nullptr);
            if (sizeNeeded <= 0) { GlobalUnlock(hData); CloseClipboard(); return ""; }
            std::string result(static_cast<size_t>(sizeNeeded - 1), 0);
            WideCharToMultiByte(CP_UTF8, 0, pszText, -1, &result[0], sizeNeeded, nullptr, nullptr);
            GlobalUnlock(hData);
            CloseClipboard();
            return result;
        };
        g_env["iswindowactive"] = [](std::string dta, json set, DWORD pid) -> std::string {
            HWND target = Game::GetWindowFromProcess(pid);
            return (target && GetForegroundWindow() == target) ? "true" : "false";
        };
        g_env["setwindowtitle"] = [](std::string dta, json set, DWORD pid) -> std::string {
            std::string title = set.contains("title") ? set["title"].get<std::string>() : dta;
            HWND hwnd = Game::GetWindowFromProcess(pid);
            if (hwnd && !title.empty()) {
                SetWindowTextA(hwnd, title.c_str());
                return "SUCCESS";
            }
            return "FAILED";
        };
        g_env["getwindowtitle"] = [](std::string dta, json set, DWORD pid) -> std::string {
            HWND hwnd = Game::GetWindowFromProcess(pid);
            if (!hwnd) return "";
            char title[256] = {};
            GetWindowTextA(hwnd, title, sizeof(title));
            return std::string(title);
        };
        g_env["iswindowfullscreen"] = [](std::string dta, json set, DWORD pid) -> std::string {
            HWND hwnd = Game::GetWindowFromProcess(pid);
            if (!hwnd) return "false";
            RECT windowRect = {}, desktopRect = {};
            GetWindowRect(hwnd, &windowRect);
            GetWindowRect(GetDesktopWindow(), &desktopRect);
            bool fullscreen = (windowRect.left == desktopRect.left && windowRect.top == desktopRect.top &&
                windowRect.right == desktopRect.right && windowRect.bottom == desktopRect.bottom);
            return fullscreen ? "true" : "false";
        };
        g_env["getwindowsize"] = [](std::string dta, json set, DWORD pid) -> std::string {
            HWND hwnd = Game::GetWindowFromProcess(pid);
            if (!hwnd) return "0,0";
            RECT rect = {};
            GetClientRect(hwnd, &rect);
            return std::to_string(rect.right - rect.left) + "," + std::to_string(rect.bottom - rect.top);
        };
        g_env["getwindowposition"] = [](std::string dta, json set, DWORD pid) -> std::string {
            HWND hwnd = Game::GetWindowFromProcess(pid);
            if (!hwnd) return "0,0";
            RECT rect = {};
            GetWindowRect(hwnd, &rect);
            return std::to_string(rect.left) + "," + std::to_string(rect.top);
        };
        g_env["setwindowsize"] = [](std::string dta, json set, DWORD pid) -> std::string {
            int width = set.contains("width") ? set["width"].get<int>() : 800;
            int height = set.contains("height") ? set["height"].get<int>() : 600;
            HWND hwnd = Game::GetWindowFromProcess(pid);
            if (hwnd) {
                SetWindowPos(hwnd, nullptr, 0, 0, width, height, SWP_NOMOVE | SWP_NOZORDER);
                return "SUCCESS";
            }
            return "FAILED";
        };
        g_env["setwindowposition"] = [](std::string dta, json set, DWORD pid) -> std::string {
            int x = set.contains("x") ? set["x"].get<int>() : 0;
            int y = set.contains("y") ? set["y"].get<int>() : 0;
            HWND hwnd = Game::GetWindowFromProcess(pid);
            if (hwnd) {
                SetWindowPos(hwnd, nullptr, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
                return "SUCCESS";
            }
            return "FAILED";
        };
        g_env["focuswindow"] = [](std::string dta, json set, DWORD pid) -> std::string {
            HWND hwnd = Game::GetWindowFromProcess(pid);
            if (hwnd) { SetForegroundWindow(hwnd); return "SUCCESS"; }
            return "FAILED";
        };
        g_env["minimizewindow"] = [](std::string dta, json set, DWORD pid) -> std::string {
            HWND hwnd = Game::GetWindowFromProcess(pid);
            if (hwnd) { ShowWindow(hwnd, SW_MINIMIZE); return "SUCCESS"; }
            return "FAILED";
        };
        g_env["maximizewindow"] = [](std::string dta, json set, DWORD pid) -> std::string {
            HWND hwnd = Game::GetWindowFromProcess(pid);
            if (hwnd) { ShowWindow(hwnd, SW_MAXIMIZE); return "SUCCESS"; }
            return "FAILED";
        };
        g_env["restorewindow"] = [](std::string dta, json set, DWORD pid) -> std::string {
            HWND hwnd = Game::GetWindowFromProcess(pid);
            if (hwnd) { ShowWindow(hwnd, SW_RESTORE); return "SUCCESS"; }
            return "FAILED";
        };
        g_env["getscreensize"] = [](std::string dta, json set, DWORD pid) -> std::string {
            return std::to_string(GetSystemMetrics(SM_CXSCREEN)) + "," + std::to_string(GetSystemMetrics(SM_CYSCREEN));
        };
        g_env["getmouseposition"] = [](std::string dta, json set, DWORD pid) -> std::string {
            POINT pt = {};
            if (GetCursorPos(&pt)) return std::to_string(pt.x) + "," + std::to_string(pt.y);
            return "0,0";
        };
        g_env["setmouseposition"] = [](std::string dta, json set, DWORD pid) -> std::string {
            int x = set.contains("x") ? set["x"].get<int>() : 0;
            int y = set.contains("y") ? set["y"].get<int>() : 0;
            return SetCursorPos(x, y) ? "SUCCESS" : "FAILED";
        };
        g_env["mouse3click"] = [](std::string, json, DWORD) -> std::string {
            return SendMouseClick(MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP) ? "SUCCESS" : "";
        };
        g_env["mouse3press"] = [](std::string, json, DWORD) -> std::string {
            return SendMouseInput(MOUSEEVENTF_MIDDLEDOWN) ? "SUCCESS" : "";
        };
        g_env["mouse3release"] = [](std::string, json, DWORD) -> std::string {
            return SendMouseInput(MOUSEEVENTF_MIDDLEUP) ? "SUCCESS" : "";
        };
        g_env["getprocessid"] = [](std::string dta, json set, DWORD pid) -> std::string {
            return std::to_string(pid);
        };
        g_env["getprocessname"] = [](std::string, json, DWORD) -> std::string { return "RobloxPlayerBeta.exe"; };
        g_env["isprocessalive"] = [](std::string dta, json set, DWORD pid) -> std::string {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (!hProcess) return "false";
            DWORD exitCode = 0;
            GetExitCodeProcess(hProcess, &exitCode);
            CloseHandle(hProcess);
            return (exitCode == STILL_ACTIVE) ? "true" : "false";
        };
        g_env["getosinfo"] = [](std::string dta, json set, DWORD pid) -> std::string {
            json info;
            info["platform"] = "Windows";
            info["major"] = 10;
            info["minor"] = 0;
            return info.dump();
        };
        g_env["getmemoryusage"] = [](std::string dta, json set, DWORD pid) -> std::string {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
            if (!hProcess) return "0";
            PROCESS_MEMORY_COUNTERS pmc = {};
            if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
                CloseHandle(hProcess);
                return std::to_string(pmc.WorkingSetSize / (1024 * 1024));
            }
            CloseHandle(hProcess);
            return "0";
        };
        g_env["rconsoletitle"] = g_env["rconsolesettitle"];
        g_env["consoletitle"] = g_env["rconsolesettitle"];
    }

    inline std::string Setup(std::string args) {
        auto lines = SplitLines(args);
        std::string typ = lines.size() > 0 ? lines[0] : "";
        DWORD pid = 0;
        if (lines.size() > 1) {
            try { pid = static_cast<DWORD>(std::stoul(lines[1])); } catch (...) {}
        }
        LogDebug("Setup: type=\"" + typ + "\" pid=" + std::to_string(pid) + " lines=" + std::to_string(lines.size()));

        json set;
        if (lines.size() > 2) {
            int retries = 0;
            const int maxRetries = 3;
            while (retries < maxRetries) {
                try {
                    set = json::parse(lines[2]);
                    break;
                } catch (const json::parse_error&) {
                    if (++retries < maxRetries) Sleep(100);
                    else set = json{};
                }
            }
        } else {
            set = json{};
        }

        std::string dta;
        for (size_t i = 3; i < lines.size(); ++i) {
            dta += lines[i];
            if (i + 1 < lines.size()) dta += "\n";
        }

        auto it = g_env.find(typ);
        if (it == g_env.end() || !it->second) return "";

        try {
            return it->second(dta, set, pid);
        } catch (const std::exception& ex) {
            return std::string("{\"error\":\"") + ex.what() + "\"}";
        } catch (...) {
            return "{\"error\":\"Unknown exception\"}";
        }
    }

    constexpr unsigned short BRIDGE_HTTP_PORT = 8069;
    constexpr size_t MAX_BODY_SIZE = 1024 * 1024;

    inline int ParseContentLength(const std::string& headers) {
        const std::string keyLower = "content-length:";
        for (size_t i = 0; i + keyLower.size() <= headers.size(); ++i) {
            bool match = true;
            for (size_t k = 0; k < keyLower.size(); ++k) {
                unsigned char c = static_cast<unsigned char>(headers[i + k]);
                if (c >= 'A' && c <= 'Z') c += 32;
                if (c != static_cast<unsigned char>(keyLower[k])) { match = false; break; }
            }
            if (!match) continue;
            size_t pos = i + keyLower.size();
            while (pos < headers.size() && (headers[pos] == ' ' || headers[pos] == '\t')) ++pos;
            size_t end = pos;
            while (end < headers.size() && headers[end] >= '0' && headers[end] <= '9') ++end;
            if (end > pos) {
                int len = 0;
                try { len = std::stoi(headers.substr(pos, end - pos)); } catch (...) { return -1; }
                return len >= 0 && len <= static_cast<int>(MAX_BODY_SIZE) ? len : -1;
            }
            return -1;
        }
        return -1;
    }

    inline void StartBridge() {
        Load();

        std::thread([]() {
            WSADATA wsa = {};
            if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return;

            SOCKET listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (listenSocket == INVALID_SOCKET) {
                WSACleanup();
                return;
            }

            int opt = 1;
            setsockopt(listenSocket, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));

            sockaddr_in addr = {};
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            addr.sin_port = htons(BRIDGE_HTTP_PORT);

            if (bind(listenSocket, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
                closesocket(listenSocket);
                WSACleanup();
                return;
            }

            if (listen(listenSocket, SOMAXCONN) == SOCKET_ERROR) {
                closesocket(listenSocket);
                WSACleanup();
                return;
            }
            LogDebug("Bridge HTTP server listening on port " + std::to_string(BRIDGE_HTTP_PORT));

            for (;;) {
                SOCKET client = accept(listenSocket, nullptr, nullptr);
                if (client == INVALID_SOCKET) continue;
                LogDebug("HTTP client connected");

                std::string raw;
                raw.reserve(8192);
                char buf[2048];
                int contentLength = -1;
                size_t headerEnd = 0;

                while (raw.find("\r\n\r\n") == std::string::npos) {
                    int n = recv(client, buf, sizeof(buf), 0);
                    if (n <= 0) break;
                    raw.append(buf, n);
                    if (raw.size() > 65536) break;
                }

                headerEnd = raw.find("\r\n\r\n");
                if (headerEnd != std::string::npos) {
                    contentLength = ParseContentLength(raw);
                    std::string body = raw.substr(headerEnd + 4);
                    if (contentLength > 0) {
                        while (body.size() < static_cast<size_t>(contentLength)) {
                            int n = recv(client, buf, sizeof(buf), 0);
                            if (n <= 0) break;
                            body.append(buf, n);
                        }
                        body.resize(static_cast<size_t>(contentLength));
                    }

                    size_t bodyPreviewLen = (body.size() < 120) ? body.size() : 120u;
                    LogDebug("HTTP body_len=" + std::to_string(body.size()) + " preview=" + body.substr(0, bodyPreviewLen));

                    std::string response = Setup(std::move(body));
                    LogDebug("HTTP response_len=" + std::to_string(response.size()));

                    std::string reply = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\nContent-Length: ";
                    reply += std::to_string(response.size());
                    reply += "\r\n\r\n";
                    reply += response;
                    int sent = send(client, reply.data(), static_cast<int>(reply.size()), 0);
                    LogDebug("HTTP send result=" + std::to_string(sent));
                }

                closesocket(client);
            }
        }).detach();
    }

    inline void Execute(std::string source) {
        g_script = std::move(source);
        uintptr_t newOrder = g_order.fetch_add(1);
        LogDebug("Execute: script_len=" + std::to_string(g_script.size()) + " new_order=" + std::to_string(newOrder + 1));
        Sleep(2000);
    }
}
