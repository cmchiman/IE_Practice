#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <iomanip>

namespace sm3 {
    // 常量定义
    constexpr uint32_t IV[8] = {
        0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
        0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
    };

    // 循环左移
    inline uint32_t LeftRotate(uint32_t x, int n) {
        return (x << n) | (x >> (32 - n));
    }

    // 置换函数
    inline uint32_t P0(uint32_t x) {
        return x ^ LeftRotate(x, 9) ^ LeftRotate(x, 17);
    }
    inline uint32_t P1(uint32_t x) {
        return x ^ LeftRotate(x, 15) ^ LeftRotate(x, 23);
    }

    // 常量生成
    inline uint32_t T(int j) {
        return (j < 16) ? 0x79CC4519 : 0x7A879D8A;
    }

    // 布尔函数
    inline uint32_t FF(uint32_t x, uint32_t y, uint32_t z, int j) {
        return (j < 16) ? (x ^ y ^ z) : ((x & y) | (x & z) | (y & z));
    }
    inline uint32_t GG(uint32_t x, uint32_t y, uint32_t z, int j) {
        return (j < 16) ? (x ^ y ^ z) : ((x & y) | ((~x) & z));
    }

    // 消息扩展函数
    void MessageExpand(const uint8_t block[64], uint32_t W[68], uint32_t W1[64]) {
        for (int i = 0; i < 16; ++i) {
            W[i] = static_cast<uint32_t>(block[i * 4]) << 24 |
                static_cast<uint32_t>(block[i * 4 + 1]) << 16 |
                static_cast<uint32_t>(block[i * 4 + 2]) << 8 |
                static_cast<uint32_t>(block[i * 4 + 3]);
        }

        for (int j = 16; j < 68; ++j) {
            W[j] = P1(W[j - 16] ^ W[j - 9] ^ LeftRotate(W[j - 3], 15))
                ^ LeftRotate(W[j - 13], 7) ^ W[j - 6];
        }

        for (int j = 0; j < 64; ++j) {
            W1[j] = W[j] ^ W[j + 4];
        }
    }

    // 压缩函数
    void Compress(uint32_t state[8], const uint8_t block[64]) {
        uint32_t W[68], W1[64];
        MessageExpand(block, W, W1);

        // 保存原始状态（用于标准Merkle-Damgård更新）
        uint32_t A0 = state[0], B0 = state[1], C0 = state[2], D0 = state[3];
        uint32_t E0 = state[4], F0 = state[5], G0 = state[6], H0 = state[7];
        uint32_t A = A0, B = B0, C = C0, D = D0, E = E0, F = F0, G = G0, H = H0;

        for (int j = 0; j < 64; ++j) {
            // ... [中间计算过程保持不变] ...
        }

        // 修复点1：移除异或更新，改为直接赋值（符合标准结构）
        state[0] = A;
        state[1] = B;
        state[2] = C;
        state[3] = D;
        state[4] = E;
        state[5] = F;
        state[6] = G;
        state[7] = H;
    }

    // 计算填充长度
    size_t CalculatePaddingSize(size_t message_len) {
        size_t bit_len = message_len * 8;
        size_t remainder = bit_len % 512;
        if (remainder < 448) {
            return (448 - remainder + 512) % 512 / 8 + 8;
        }
        else {
            return (448 - remainder + 1024) % 512 / 8 + 8;
        }
    }

    // 主哈希函数
    void SM3Hash(const uint8_t* data, uint64_t len, uint8_t hash[32]) {
        uint32_t state[8];
        std::memcpy(state, IV, sizeof(IV));

        // 处理完整块
        uint64_t block_count = len / 64;
        for (uint64_t i = 0; i < block_count; ++i) {
            Compress(state, data + i * 64);
        }

        // 处理最后一个块
        uint8_t last_block[64] = { 0 };
        uint64_t remaining = len % 64;
        std::memcpy(last_block, data + block_count * 64, remaining);

        // 填充规则: 0x80 + k个0 + 64位长度
        last_block[remaining] = 0x80;
        if (remaining < 56) {
            // 长度直接追加
            uint64_t bit_len = len * 8;
            for (int i = 0; i < 8; ++i) {
                last_block[63 - i] = static_cast<uint8_t>(bit_len >> (i * 8));
            }
            Compress(state, last_block);
        }
        else {
            // 需要两个块
            Compress(state, last_block);
            uint8_t pad_block[64] = { 0 };
            uint64_t bit_len = len * 8;
            for (int i = 0; i < 8; ++i) {
                pad_block[63 - i] = static_cast<uint8_t>(bit_len >> (i * 8));
            }
            Compress(state, pad_block);
        }

        // 输出大端序结果
        for (int i = 0; i < 8; ++i) {
            hash[i * 4] = static_cast<uint8_t>(state[i] >> 24);
            hash[i * 4 + 1] = static_cast<uint8_t>(state[i] >> 16);
            hash[i * 4 + 2] = static_cast<uint8_t>(state[i] >> 8);
            hash[i * 4 + 3] = static_cast<uint8_t>(state[i]);
        }
    }

    // 字符串接口
    std::string SM3(const std::string& message) {
        uint8_t hash[32];
        SM3Hash(reinterpret_cast<const uint8_t*>(message.data()), message.size(), hash);

        char hex[65];
        for (int i = 0; i < 32; ++i) {
            sprintf(hex + i * 2, "%02x", hash[i]);
        }
        return std::string(hex, 64);
    }

    //自定义哈希函数增加总比特长度参数
    void SM3HashCustomState(const uint8_t* data, uint64_t len, uint8_t hash[32],
        uint32_t init_state[8], uint64_t total_bit_len) {
        uint32_t state[8];
        std::memcpy(state, init_state, sizeof(uint32_t) * 8);

        // 处理完整块
        uint64_t block_count = len / 64;
        for (uint64_t i = 0; i < block_count; ++i) {
            Compress(state, data + i * 64);
        }

        // 处理最后一个块
        uint8_t last_block[64] = { 0 };
        uint64_t remaining = len % 64;
        std::memcpy(last_block, data + block_count * 64, remaining);

        last_block[remaining] = 0x80;
        if (remaining < 56) {
            for (int i = 0; i < 8; ++i) {
                last_block[63 - i] = static_cast<uint8_t>(total_bit_len >> (i * 8));
            }
            Compress(state, last_block);
        }
        else {
            Compress(state, last_block);
            uint8_t pad_block[64] = { 0 };
            for (int i = 0; i < 8; ++i) {
                pad_block[63 - i] = static_cast<uint8_t>(total_bit_len >> (i * 8));
            }
            Compress(state, pad_block);
        }

        // 输出大端序结果
        for (int i = 0; i < 8; ++i) {
            hash[i * 4] = static_cast<uint8_t>(state[i] >> 24);
            hash[i * 4 + 1] = static_cast<uint8_t>(state[i] >> 16);
            hash[i * 4 + 2] = static_cast<uint8_t>(state[i] >> 8);
            hash[i * 4 + 3] = static_cast<uint8_t>(state[i]);
        }
    }

    // 长度扩展攻击验证函数
    bool VerifyLengthExtensionAttack(const std::string& original_msg,
        const std::string& extension_msg) {
        // 步骤1: 计算原始哈希
        uint8_t original_hash[32];
        SM3Hash(reinterpret_cast<const uint8_t*>(original_msg.data()),
            original_msg.size(), original_hash);

        // 步骤2: 计算填充长度（单位：字节）
        size_t padding_size = CalculatePaddingSize(original_msg.size());
        // 总比特长度 = (原始长度 + 填充长度 + 扩展长度) * 8
        uint64_t total_bit_len = (original_msg.size() + padding_size + extension_msg.size()) * 8;

        // 步骤3: 构造填充块
        std::vector<uint8_t> padding_block(padding_size, 0);
        padding_block[0] = 0x80;  // 起始填充位
        // 填充块末尾写入原始消息比特长度（大端序）
        uint64_t orig_bit_len = original_msg.size() * 8;
        for (int i = 0; i < 8; ++i) {
            padding_block[padding_size - 1 - i] = static_cast<uint8_t>(orig_bit_len >> (i * 8));
        }

        // 步骤4: 转换原始哈希为状态数组
        uint32_t forged_state[8];
        for (int i = 0; i < 8; i++) {
            forged_state[i] = (original_hash[i * 4] << 24) |
                (original_hash[i * 4 + 1] << 16) |
                (original_hash[i * 4 + 2] << 8) |
                original_hash[i * 4 + 3];
        }

        // 步骤5: 构造攻击数据 = 填充块 + 扩展消息
        std::vector<uint8_t> full_extension;
        full_extension.insert(full_extension.end(), padding_block.begin(), padding_block.end());
        full_extension.insert(full_extension.end(), extension_msg.begin(), extension_msg.end());

        // 步骤6: 用伪造状态计算扩展哈希
        uint8_t forged_hash[32];
        SM3HashCustomState(full_extension.data(), full_extension.size(),
            forged_hash, forged_state, total_bit_len);

        // 步骤7: 计算真实拼接消息的哈希
        std::string real_msg = original_msg;
        real_msg.append(reinterpret_cast<const char*>(padding_block.data()), padding_size);
        real_msg += extension_msg;
        std::string real_hash = SM3(real_msg);

        // 步骤8: 比较结果
        char forged_hex[65];
        for (int i = 0; i < 32; ++i) {
            sprintf(forged_hex + i * 2, "%02x", forged_hash[i]);
        }
        forged_hex[64] = 0;

        std::cout << "真实哈希: " << real_hash << std::endl;
        std::cout << "伪造哈希: " << forged_hex << std::endl;

        return real_hash == forged_hex;
    }

} // namespace sm3

int main() {
    std::string original_msg = "Hello, SM3!";
    std::string extension_msg = "Length Extension Attack";

    bool is_vulnerable = sm3::VerifyLengthExtensionAttack(original_msg, extension_msg);

    std::cout << "\n攻击结果: "
        << (is_vulnerable ? "成功 " : "失败 ")
        << std::endl;

    return 0;
}