#pragma once

#include <Windows.h>
#include <cstdint>
#include <string>
#include <functional>
#include <vector>

#include "Handler.hpp"
#include "../Offsets.hpp"

class Roblox {
public:
    Roblox(uintptr_t addr, DWORD pid)
        : address_(addr)
        , processId_(pid)
    {}

    uintptr_t GetAddress() const {
        return address_;
    }

    std::string Name() const {
        auto nameaddrOpt = Handler::ReadMemory<uintptr_t>(address_ + Offsets::Name, processId_);
        if (!nameaddrOpt) return "";
        uintptr_t nameaddr = *nameaddrOpt;

        auto sizeOpt = Handler::ReadMemory<size_t>(nameaddr + 0x10, processId_);
        if (!sizeOpt) return "";
        size_t size = *sizeOpt;
        if (size >= 16) {
            auto ptrOpt = Handler::ReadMemory<uintptr_t>(nameaddr, processId_);
            if (!ptrOpt) return "";
            nameaddr = *ptrOpt;
        }

        std::string str;
        for (int32_t i = 0;; ++i) {
            auto codeOpt = Handler::ReadMemory<uint8_t>(nameaddr + i, processId_);
            if (!codeOpt) break;
            uint8_t code = *codeOpt;
            if (code == 0) break;
            str.push_back(static_cast<char>(code));
        }
        return str;
    }

    Roblox FindFirstChild(const std::string& name) const {
        auto childrenPtrOpt = Handler::ReadMemory<uintptr_t>(address_ + Offsets::Children, processId_);
        if (!childrenPtrOpt || *childrenPtrOpt == 0)
            return Roblox(0, processId_);

        uintptr_t childrenPtr = *childrenPtrOpt;
        auto childrenStartOpt = Handler::ReadMemory<uintptr_t>(childrenPtr, processId_);
        auto childrenEndOpt = Handler::ReadMemory<uintptr_t>(childrenPtr + Offsets::ChildrenEnd, processId_);
        if (!childrenStartOpt || !childrenEndOpt)
            return Roblox(0, processId_);

        uintptr_t childrenStart = *childrenStartOpt;
        uintptr_t childrenEnd = *childrenEndOpt;

        for (uintptr_t childAddress = childrenStart; childAddress < childrenEnd; childAddress += 0x10) {
            auto childPtrOpt = Handler::ReadMemory<uintptr_t>(childAddress, processId_);
            if (!childPtrOpt || *childPtrOpt == 0) continue;

            uintptr_t childPtr = *childPtrOpt;
            auto nameaddrOpt = Handler::ReadMemory<uintptr_t>(childPtr + Offsets::Name, processId_);
            if (!nameaddrOpt) continue;
            uintptr_t nameaddr = *nameaddrOpt;

            auto sizeOpt = Handler::ReadMemory<size_t>(nameaddr + 0x10, processId_);
            if (!sizeOpt || *sizeOpt != name.length()) continue;
            size_t size = *sizeOpt;
            if (size >= 16) {
                auto ptrOpt = Handler::ReadMemory<uintptr_t>(nameaddr, processId_);
                if (!ptrOpt) continue;
                nameaddr = *ptrOpt;
            }

            std::string str;
            for (int32_t i = 0;; ++i) {
                auto codeOpt = Handler::ReadMemory<uint8_t>(nameaddr + i, processId_);
                if (!codeOpt) break;
                uint8_t code = *codeOpt;
                if (code == 0) break;
                str.push_back(static_cast<char>(code));
                if (str != name.substr(0, str.length())) break;
            }
            if (str == name)
                return Roblox(childPtr, processId_);
        }
        return Roblox(0, processId_);
    }

    Roblox WaitForChild(const std::string& name) const {
        Roblox child = FindFirstChild(name);
        while (child.GetAddress() == 0) {
            Sleep(5);
            child = FindFirstChild(name);
        }
        return child;
    }

    std::string ClassName() const {
        auto classaddrOpt = Handler::ReadMemory<uintptr_t>(address_ + Offsets::ClassDescriptor, processId_);
        if (!classaddrOpt) return "";
        uintptr_t classaddr = *classaddrOpt;

        auto nameaddrOpt = Handler::ReadMemory<uintptr_t>(classaddr + Offsets::ClassDescriptorToClassName, processId_);
        if (!nameaddrOpt) return "";
        uintptr_t nameaddr = *nameaddrOpt;

        auto sizeOpt = Handler::ReadMemory<size_t>(nameaddr + 0x10, processId_);
        if (!sizeOpt) return "";
        size_t size = *sizeOpt;
        if (size >= 16) {
            auto ptrOpt = Handler::ReadMemory<uintptr_t>(nameaddr, processId_);
            if (!ptrOpt) return "";
            nameaddr = *ptrOpt;
        }

        std::string str;
        for (int32_t i = 0;; ++i) {
            auto codeOpt = Handler::ReadMemory<uint8_t>(nameaddr + i, processId_);
            if (!codeOpt) break;
            uint8_t code = *codeOpt;
            if (code == 0) break;
            str.push_back(static_cast<char>(code));
        }
        return str;
    }

    std::function<void()> SetScriptBytecode(const std::vector<char>& bytes, size_t size) {
        uintptr_t offset = (ClassName() == "LocalScript")
            ? Offsets::LocalScriptByteCode
            : Offsets::ModuleScriptByteCode;

        auto embeddedOpt = Handler::ReadMemory<uintptr_t>(address_ + offset, processId_);
        if (!embeddedOpt) return []() {};

        uintptr_t embedded = *embeddedOpt;
        auto originalBytecodePtrOpt = Handler::ReadMemory<uintptr_t>(embedded + 0x10, processId_);
        auto originalSizeOpt = Handler::ReadMemory<uint64_t>(embedded + 0x20, processId_);
        if (!originalBytecodePtrOpt || !originalSizeOpt) return []() {};

        uintptr_t originalBytecodePtr = *originalBytecodePtrOpt;
        uint64_t originalSize = *originalSizeOpt;

        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId_);
        if (!hProcess || hProcess == INVALID_HANDLE_VALUE) return []() {};

        void* newMem = VirtualAllocEx(hProcess, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!newMem) {
            CloseHandle(hProcess);
            return []() {};
        }

        if (!Handler::WriteNative(reinterpret_cast<uintptr_t>(newMem), bytes.data(), bytes.size(), processId_)) {
            VirtualFreeEx(hProcess, newMem, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return []() {};
        }

        Handler::WriteMemory(embedded + 0x10, reinterpret_cast<uintptr_t>(newMem), processId_);
        Handler::WriteMemory(embedded + 0x20, static_cast<uint64_t>(size), processId_);
        CloseHandle(hProcess);

        return [this, embedded, originalBytecodePtr, originalSize, newMem]() {
            Handler::WriteMemory(embedded + 0x10, originalBytecodePtr, processId_);
            Handler::WriteMemory(embedded + 0x20, originalSize, processId_);
            HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId_);
            if (h && h != INVALID_HANDLE_VALUE) {
                VirtualFreeEx(h, newMem, 0, MEM_RELEASE);
                CloseHandle(h);
            }
        };
    }

    std::string GetScriptBytecode() const {
        uintptr_t offset = (ClassName() == "LocalScript")
            ? Offsets::LocalScriptByteCode
            : Offsets::ModuleScriptByteCode;

        auto embeddedOpt = Handler::ReadMemory<uintptr_t>(address_ + offset, processId_);
        if (!embeddedOpt) return "";

        uintptr_t embedded = *embeddedOpt;
        auto bytecodePtrOpt = Handler::ReadMemory<uintptr_t>(embedded + 0x10, processId_);
        auto sizeOpt = Handler::ReadMemory<uint64_t>(embedded + 0x20, processId_);
        if (!bytecodePtrOpt || !sizeOpt) return "";

        uintptr_t bytecodePtr = *bytecodePtrOpt;
        uint64_t size = *sizeOpt;

        std::string bytecode;
        bytecode.resize(static_cast<size_t>(size));
        if (!Handler::ReadNative(bytecodePtr, &bytecode[0], static_cast<size_t>(size), processId_))
            return "";
        return bytecode;
    }

private:
    uintptr_t address_;
    DWORD processId_;
};

inline Roblox FetchDatamodel(uintptr_t baseModule, DWORD processId) {
    auto fakeOpt = Handler::ReadMemory<uintptr_t>(baseModule + Offsets::FakeDataModelPointer, processId);
    if (!fakeOpt) return Roblox(0, processId);
    uintptr_t fake = *fakeOpt;

    auto realOpt = Handler::ReadMemory<uintptr_t>(fake + Offsets::FakeDataModelToDataModel, processId);
    if (!realOpt) return Roblox(0, processId);
    return Roblox(*realOpt, processId);
}
