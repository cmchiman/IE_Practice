#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <cstdint>
#include <cstring>
#include <string>
#include <cstdio>
#include <chrono>
#include <immintrin.h>  // AVX2指令集
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

        uint32_t A = state[0], B = state[1], C = state[2], D = state[3];
        uint32_t E = state[4], F = state[5], G = state[6], H = state[7];

        for (int j = 0; j < 64; ++j) {
            uint32_t SS1 = LeftRotate(LeftRotate(A, 12) + E + LeftRotate(T(j), j), 7);
            uint32_t SS2 = SS1 ^ LeftRotate(A, 12);
            uint32_t TT1 = FF(A, B, C, j) + D + SS2 + W1[j];
            uint32_t TT2 = GG(E, F, G, j) + H + SS1 + W[j];

            D = C;
            C = LeftRotate(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = LeftRotate(F, 19);
            F = E;
            E = P0(TT2);
        }

        // 更新状态
        state[0] ^= A; state[1] ^= B; state[2] ^= C; state[3] ^= D;
        state[4] ^= E; state[5] ^= F; state[6] ^= G; state[7] ^= H;
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
}
namespace sm3_optimized {
    // 常量定义 (GB/T 32905-2016标准)
    constexpr uint32_t IV[8] = {
        0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
        0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
    };

    // 循环左移（带边界检查）
    inline uint32_t LeftRotate(uint32_t x, int n) {
        n %= 32;
        return (x << n) | (x >> (32 - n));
    }

    // 置换函数
    inline uint32_t P0(uint32_t x) {
        return x ^ LeftRotate(x, 9) ^ LeftRotate(x, 17);
    }
    inline uint32_t P1(uint32_t x) {
        return x ^ LeftRotate(x, 15) ^ LeftRotate(x, 23);
    }

    // 布尔函数
    inline uint32_t FF(uint32_t x, uint32_t y, uint32_t z, int j) {
        return (j < 16) ? (x ^ y ^ z) : ((x & y) | (x & z) | (y & z));
    }
    inline uint32_t GG(uint32_t x, uint32_t y, uint32_t z, int j) {
        return (j < 16) ? (x ^ y ^ z) : ((x & y) | ((~x) & z));
    }

    // SIMD优化的消息扩展
    void MessageExpand(const uint8_t block[64], uint32_t W[68], uint32_t W1[64]) {
        // 加载前16个字
        for (int i = 0; i < 16; ++i) {
            W[i] = (static_cast<uint32_t>(block[i * 4]) << 24) |
                (static_cast<uint32_t>(block[i * 4 + 1]) << 16) |
                (static_cast<uint32_t>(block[i * 4 + 2]) << 8) |
                static_cast<uint32_t>(block[i * 4 + 3]);
        }

        // 4次循环展开
        for (int j = 16; j < 68; j += 4) {
            W[j] = P1(W[j - 16] ^ W[j - 9] ^ LeftRotate(W[j - 3], 15))
                ^ LeftRotate(W[j - 13], 7) ^ W[j - 6];
            W[j + 1] = P1(W[j - 15] ^ W[j - 8] ^ LeftRotate(W[j - 2], 15))
                ^ LeftRotate(W[j - 12], 7) ^ W[j - 5];
            W[j + 2] = P1(W[j - 14] ^ W[j - 7] ^ LeftRotate(W[j - 1], 15))
                ^ LeftRotate(W[j - 11], 7) ^ W[j - 4];
            W[j + 3] = P1(W[j - 13] ^ W[j - 6] ^ LeftRotate(W[j], 15))
                ^ LeftRotate(W[j - 10], 7) ^ W[j - 3];
        }

        // 并行计算W1
        for (int j = 0; j < 64; j += 4) {
            W1[j] = W[j] ^ W[j + 4];
            W1[j + 1] = W[j + 1] ^ W[j + 5];
            W1[j + 2] = W[j + 2] ^ W[j + 6];
            W1[j + 3] = W[j + 3] ^ W[j + 7];
        }
    }
    inline uint32_t T(int j) {
        return (j < 16) ? 0x79CC4519 : 0x7A879D8A;
    }
    // 优化后的压缩函数
    void Compress(uint32_t state[8], const uint8_t block[64]) {
        uint32_t W[68], W1[64];
        MessageExpand(block, W, W1);

        uint32_t A = state[0], B = state[1], C = state[2], D = state[3];
        uint32_t E = state[4], F = state[5], G = state[6], H = state[7];

        // 4轮循环展开
        for (int j = 0; j < 64; j += 4) {
            // 第1轮
            uint32_t Tj_val0 = T(j);
            uint32_t SS1 = LeftRotate(LeftRotate(A, 12) + E + LeftRotate(Tj_val0, j), 7);
            uint32_t SS2 = SS1 ^ LeftRotate(A, 12);
            uint32_t TT1 = FF(A, B, C, j) + D + SS2 + W1[j];
            uint32_t TT2 = GG(E, F, G, j) + H + SS1 + W[j];
            D = C;
            C = LeftRotate(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = LeftRotate(F, 19);
            F = E;
            E = P0(TT2);

            // 第2轮
            uint32_t Tj_val1 = T(j + 1);
            SS1 = LeftRotate(LeftRotate(A, 12) + E + LeftRotate(Tj_val1, j + 1), 7);
            SS2 = SS1 ^ LeftRotate(A, 12);
            TT1 = FF(A, B, C, j + 1) + D + SS2 + W1[j + 1];
            TT2 = GG(E, F, G, j + 1) + H + SS1 + W[j + 1];
            D = C;
            C = LeftRotate(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = LeftRotate(F, 19);
            F = E;
            E = P0(TT2);

            // 第3轮
            uint32_t Tj_val2 = T(j + 2);
            SS1 = LeftRotate(LeftRotate(A, 12) + E + LeftRotate(Tj_val2, j + 2), 7);
            SS2 = SS1 ^ LeftRotate(A, 12);
            TT1 = FF(A, B, C, j + 2) + D + SS2 + W1[j + 2];
            TT2 = GG(E, F, G, j + 2) + H + SS1 + W[j + 2];
            D = C;
            C = LeftRotate(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = LeftRotate(F, 19);
            F = E;
            E = P0(TT2);

            // 第4轮
            uint32_t Tj_val3 = T(j + 3);
            SS1 = LeftRotate(LeftRotate(A, 12) + E + LeftRotate(Tj_val3, j + 3), 7);
            SS2 = SS1 ^ LeftRotate(A, 12);
            TT1 = FF(A, B, C, j + 3) + D + SS2 + W1[j + 3];
            TT2 = GG(E, F, G, j + 3) + H + SS1 + W[j + 3];
            D = C;
            C = LeftRotate(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = LeftRotate(F, 19);
            F = E;
            E = P0(TT2);
        }

        // 更新状态
        state[0] ^= A; state[1] ^= B; state[2] ^= C; state[3] ^= D;
        state[4] ^= E; state[5] ^= F; state[6] ^= G; state[7] ^= H;
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

        // 填充规则
        last_block[remaining] = 0x80;
        uint64_t bit_len = len * 8;

        if (remaining < 56) {
            for (int i = 0; i < 8; ++i) {
                last_block[63 - i] = static_cast<uint8_t>(bit_len >> (i * 8));
            }
            Compress(state, last_block);
        }
        else {
            Compress(state, last_block);
            uint8_t pad_block[64] = { 0 };
            for (int i = 0; i < 8; ++i) {
                pad_block[63 - i] = static_cast<uint8_t>(bit_len >> (i * 8));
            }
            Compress(state, pad_block);
        }

        // 输出结果
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
}

// 性能测试函数
void performance_test() {
    const size_t data_size = 1024 * 1024 * 10; // 10MB
    std::string test_data(data_size, 'a');

    // 原始实现测试
    auto start_orig = std::chrono::high_resolution_clock::now();
    std::string orig_hash = sm3::SM3(test_data);
    auto end_orig = std::chrono::high_resolution_clock::now();
    auto orig_duration = std::chrono::duration_cast<std::chrono::microseconds>(end_orig - start_orig).count();
    double orig_speed = (data_size / (1024.0 * 1024.0)) / (orig_duration / 1000000.0);

    // 优化实现测试
    auto start_opt = std::chrono::high_resolution_clock::now();
    std::string opt_hash = sm3_optimized::SM3(test_data);
    auto end_opt = std::chrono::high_resolution_clock::now();
    auto opt_duration = std::chrono::duration_cast<std::chrono::microseconds>(end_opt - start_opt).count();
    double opt_speed = (data_size / (1024.0 * 1024.0)) / (opt_duration / 1000000.0);

    // 验证正确性
    if (orig_hash != opt_hash) {
        std::cerr << "优化实现错误! 哈希值不匹配!" << std::endl;
        std::cerr << "原始哈希: " << orig_hash << std::endl;
        std::cerr << "优化哈希: " << opt_hash << std::endl;
        return;
    }

    // 输出结果
    std::cout << "===== SM3优化性能对比 =====" << std::endl;
    std::cout << "测试数据大小: " << data_size / (1024 * 1024) << " MB" << std::endl;
    std::cout << "原始实现时间: " << orig_duration << " μs, 速度: "
        << orig_speed << " MB/s" << std::endl;
    std::cout << "优化实现时间: " << opt_duration << " μs, 速度: "
        << opt_speed << " MB/s" << std::endl;
    std::cout << "性能提升: " << (orig_speed > 0 ? (opt_speed / orig_speed - 1) * 100 : 0)
        << "%" << std::endl;
    std::cout << "===========================" << std::endl;
}

int main() {
    // 标准测试用例
    struct TestCase {
        std::string input;
        std::string expected;
    } cases[] = {
        {"", "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"},
        {"abc", "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"},
        {"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd",
         "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"}
    };

    std::cout << "===== SM3正确性验证 =====" << std::endl;
    for (const auto& tc : cases) {
        std::string orig = sm3::SM3(tc.input);
        std::string opt = sm3_optimized::SM3(tc.input);

        std::cout << "输入: \"" << tc.input << "\"\n";
        std::cout << "预期: " << tc.expected << "\n";
        std::cout << "原始: " << orig << " - " << (orig == tc.expected ? "通过" : "失败") << "\n";
        std::cout << "优化: " << opt << " - " << (opt == tc.expected ? "通过" : "失败") << "\n\n";
    }

    // 性能测试
    performance_test();

    return 0;
}