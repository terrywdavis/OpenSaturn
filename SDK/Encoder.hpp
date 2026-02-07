#pragma once

#include <xxhash.h>
#include <zstd.h>
#include <vector>
#include <string>
#include <cstring>
#include <algorithm>

extern "C" {
#include "../Dependencies/blake3/blake3.h"
}

#include "../Dependencies/Luau/Compiler.h"
#include "../Dependencies/Luau/BytecodeBuilder.h"
#include "../Dependencies/Luau/BytecodeUtils.h"

namespace Encoder {

    class BytecodeEncoderImpl : public Luau::BytecodeEncoder {
    public:
        void encode(uint32_t* data, size_t count) override {
            for (size_t i = 0; i < count;) {
                auto& opcode = *reinterpret_cast<uint8_t*>(data + i);
                i += static_cast<size_t>(Luau::getOpLength(static_cast<LuauOpcode>(opcode)));
                opcode *= 227;
            }
        }
    };

    constexpr uint32_t MAGIC_A = 0x4C464F52;
    constexpr uint32_t MAGIC_B = 0x946AC432;
    constexpr uint8_t KEY_BYTES[4] = { 0x52, 0x4F, 0x46, 0x4C };

    inline uint8_t Rotl8(uint8_t value, int shift) {
        shift &= 7;
        return static_cast<uint8_t>((value << shift) | (value >> (8 - shift)));
    }

    inline std::optional<std::vector<char>> Compress(const std::string& bytecode, size_t& outSize) {
        const size_t dataSize = bytecode.size();
        const size_t maxSize = ZSTD_compressBound(dataSize);
        std::vector<char> buffer(maxSize + 8, 0);

        buffer[0] = 'R';
        buffer[1] = 'S';
        buffer[2] = 'B';
        buffer[3] = '1';
        std::memcpy(&buffer[4], &dataSize, sizeof(dataSize));

        const size_t compressedSize = ZSTD_compress(
            &buffer[8], maxSize,
            bytecode.data(), dataSize,
            ZSTD_maxCLevel());
        if (ZSTD_isError(compressedSize))
            return std::nullopt;

        const size_t size = compressedSize + 8;
        const uint32_t key = XXH32(buffer.data(), size, 42u);
        const uint8_t* keyBytes = reinterpret_cast<const uint8_t*>(&key);

        for (size_t i = 0; i < size; ++i)
            buffer[i] = static_cast<char>(static_cast<uint8_t>(buffer[i]) ^ (keyBytes[i % 4] + static_cast<uint8_t>(i * 41u)));

        outSize = size;
        buffer.resize(size);
        return buffer;
    }

    inline std::string Compile(const std::string& source) {
        static BytecodeEncoderImpl encoder;
        std::string bytecode = Luau::compile(source, {}, {}, &encoder);
        if (bytecode.empty() || bytecode[0] == '\0')
            return "";
        return bytecode;
    }

    inline std::string NormalCompile(const std::string& source) {
        std::string bytecode = Luau::compile(source, {}, {}, nullptr);
        if (bytecode.empty() || bytecode[0] == '\0')
            return "";
        return bytecode;
    }

    inline std::optional<std::vector<char>> Sign(const std::string& bytecode, size_t& outSize) {
        if (bytecode.empty()) {
            outSize = 0;
            return std::vector<char>();
        }

        constexpr uint32_t FOOTER_SIZE = 40u;
        std::vector<uint8_t> blake3Hash(32);
        {
            blake3_hasher hasher;
            blake3_hasher_init(&hasher);
            blake3_hasher_update(&hasher, bytecode.data(), bytecode.size());
            blake3_hasher_finalize(&hasher, blake3Hash.data(), blake3Hash.size());
        }

        std::vector<uint8_t> transformedHash(32);
        for (int i = 0; i < 32; ++i) {
            uint8_t keyByte = KEY_BYTES[i & 3];
            uint8_t hashByte = blake3Hash[i];
            uint8_t combined = static_cast<uint8_t>(keyByte + i);
            uint8_t result;
            switch (i & 3) {
            case 0: {
                int shift = ((combined & 3) + 1);
                result = Rotl8(static_cast<uint8_t>(hashByte ^ ~keyByte), shift);
                break;
            }
            case 1: {
                int shift = ((combined & 3) + 2);
                result = Rotl8(static_cast<uint8_t>(keyByte ^ ~hashByte), shift);
                break;
            }
            case 2: {
                int shift = ((combined & 3) + 3);
                result = Rotl8(static_cast<uint8_t>(hashByte ^ ~keyByte), shift);
                break;
            }
            case 3: {
                int shift = ((combined & 3) + 4);
                result = Rotl8(static_cast<uint8_t>(keyByte ^ ~hashByte), shift);
                break;
            }
            default:
                result = 0;
                break;
            }
            transformedHash[i] = result;
        }

        std::vector<uint8_t> footer(FOOTER_SIZE, 0);
        uint32_t firstHashDword = *reinterpret_cast<uint32_t*>(transformedHash.data());
        uint32_t footerPrefix = firstHashDword ^ MAGIC_B;
        std::memcpy(&footer[0], &footerPrefix, 4);
        uint32_t xored = firstHashDword ^ MAGIC_A;
        std::memcpy(&footer[4], &xored, 4);
        std::memcpy(&footer[8], transformedHash.data(), 32);

        std::string signedBytecode = bytecode;
        signedBytecode.append(reinterpret_cast<const char*>(footer.data()), footer.size());

        auto compressed = Compress(signedBytecode, outSize);
        return compressed;
    }
}
