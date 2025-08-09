#include <iostream>
#include <iomanip>
#include <chrono>
#include <cstring>
#include <immintrin.h>
#include <wmmintrin.h>

// 自定义循环左移函数
inline uint32_t ROL32(uint32_t value, uint32_t shift) {
    shift %= 32;
    return (value << shift) | (value >> (32 - shift));
}

// 字节序转换函数（跨平台）
static inline uint64_t htobe64(uint64_t value) {
#if defined(_WIN32) || defined(_WIN64)
    return _byteswap_uint64(value);
#elif defined(__linux__)
    return __builtin_bswap64(value);
#else
    return ((value & 0x00000000000000ffULL) << 56) |
        ((value & 0x000000000000ff00ULL) << 40) |
        ((value & 0x0000000000ff0000ULL) << 24) |
        ((value & 0x00000000ff000000ULL) << 8) |
        ((value & 0x000000ff00000000ULL) >> 8) |
        ((value & 0x0000ff0000000000ULL) >> 24) |
        ((value & 0x00ff000000000000ULL) >> 40) |
        ((value & 0xff00000000000000ULL) >> 56);
#endif
}

static inline uint64_t be64toh(uint64_t value) {
    return htobe64(value);
}

static inline uint32_t htobe32(uint32_t value) {
#if defined(_WIN32) || defined(_WIN64)
    return _byteswap_ulong(value);
#else
    return __builtin_bswap32(value);
#endif
}

static inline uint32_t be32toh(uint32_t value) {
    return htobe32(value);
}

// ====================== SM4 基础实现 ======================
namespace SM4_BASIC {
    // SM4 S-Box
    static const uint8_t SBOX[256] = {
        0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
        0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
        0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
        0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
        0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
        0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
        0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87,
        0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E,
        0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
        0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3,
        0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60, 0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F,
        0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
        0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8,
        0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD, 0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0,
        0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
        0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48
    };

    // Linear transform L
    static uint32_t L(uint32_t a) {
        return a ^ ROL32(a, 2) ^ ROL32(a, 10) ^ ROL32(a, 18) ^ ROL32(a, 24);
    }

    // Key expansion linear transform L'
    static uint32_t L_prime(uint32_t a) {
        return a ^ ROL32(a, 13) ^ ROL32(a, 23);
    }

    // T function used in round
    static uint32_t T(uint32_t word) {
        uint32_t result = 0;
        result |= SBOX[static_cast<uint8_t>(word >> 24)] << 24;
        result |= SBOX[static_cast<uint8_t>(word >> 16)] << 16;
        result |= SBOX[static_cast<uint8_t>(word >> 8)] << 8;
        result |= SBOX[static_cast<uint8_t>(word)];

        return L(result);
    }

    // T' function used in key schedule
    static uint32_t T_prime(uint32_t word) {
        uint32_t result = 0;
        result |= SBOX[static_cast<uint8_t>(word >> 24)] << 24;
        result |= SBOX[static_cast<uint8_t>(word >> 16)] << 16;
        result |= SBOX[static_cast<uint8_t>(word >> 8)] << 8;
        result |= SBOX[static_cast<uint8_t>(word)];

        return L_prime(result);
    }

    void expand_key(const uint8_t* key, uint32_t* rk) {
        const uint32_t FK[4] = {
            0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC
        };

        uint32_t K[36];
        K[0] = (static_cast<uint32_t>(key[0]) << 24) |
            (static_cast<uint32_t>(key[1]) << 16) |
            (static_cast<uint32_t>(key[2]) << 8) |
            static_cast<uint32_t>(key[3]) ^ FK[0];

        K[1] = (static_cast<uint32_t>(key[4]) << 24) |
            (static_cast<uint32_t>(key[5]) << 16) |
            (static_cast<uint32_t>(key[6]) << 8) |
            static_cast<uint32_t>(key[7]) ^ FK[1];

        K[2] = (static_cast<uint32_t>(key[8]) << 24) |
            (static_cast<uint32_t>(key[9]) << 16) |
            (static_cast<uint32_t>(key[10]) << 8) |
            static_cast<uint32_t>(key[11]) ^ FK[2];

        K[3] = (static_cast<uint32_t>(key[12]) << 24) |
            (static_cast<uint32_t>(key[13]) << 16) |
            (static_cast<uint32_t>(key[14]) << 8) |
            static_cast<uint32_t>(key[15]) ^ FK[3];

        for (int i = 0; i < 32; i++) {
            K[i + 4] = K[i] ^ T_prime(K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ 0xFFFFFFFF ^ (i << 24));
            rk[i] = K[i + 4];
        }
    }

    void encrypt_block(const uint8_t* in, uint8_t* out, const uint32_t* rk) {
        uint32_t X[36];
        X[0] = (static_cast<uint32_t>(in[0]) << 24) |
            (static_cast<uint32_t>(in[1]) << 16) |
            (static_cast<uint32_t>(in[2]) << 8) |
            static_cast<uint32_t>(in[3]);

        X[1] = (static_cast<uint32_t>(in[4]) << 24) |
            (static_cast<uint32_t>(in[5]) << 16) |
            (static_cast<uint32_t>(in[6]) << 8) |
            static_cast<uint32_t>(in[7]);

        X[2] = (static_cast<uint32_t>(in[8]) << 24) |
            (static_cast<uint32_t>(in[9]) << 16) |
            (static_cast<uint32_t>(in[10]) << 8) |
            static_cast<uint32_t>(in[11]);

        X[3] = (static_cast<uint32_t>(in[12]) << 24) |
            (static_cast<uint32_t>(in[13]) << 16) |
            (static_cast<uint32_t>(in[14]) << 8) |
            static_cast<uint32_t>(in[15]);

        for (int i = 0; i < 32; i++) {
            X[i + 4] = X[i] ^ T(X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ rk[i]);
        }

        out[0] = static_cast<uint8_t>(X[35] >> 24);
        out[1] = static_cast<uint8_t>(X[35] >> 16);
        out[2] = static_cast<uint8_t>(X[35] >> 8);
        out[3] = static_cast<uint8_t>(X[35]);
        out[4] = static_cast<uint8_t>(X[34] >> 24);
        out[5] = static_cast<uint8_t>(X[34] >> 16);
        out[6] = static_cast<uint8_t>(X[34] >> 8);
        out[7] = static_cast<uint8_t>(X[34]);
        out[8] = static_cast<uint8_t>(X[33] >> 24);
        out[9] = static_cast<uint8_t>(X[33] >> 16);
        out[10] = static_cast<uint8_t>(X[33] >> 8);
        out[11] = static_cast<uint8_t>(X[33]);
        out[12] = static_cast<uint8_t>(X[32] >> 24);
        out[13] = static_cast<uint8_t>(X[32] >> 16);
        out[14] = static_cast<uint8_t>(X[32] >> 8);
        out[15] = static_cast<uint8_t>(X[32]);
    }
}

// ====================== GCM 优化实现 ======================
namespace SM4_GCM_OPTIMIZED {
    // 优化1: GHASH使用查找表加速（4位窗口）
    class GHashTable {
    public:
        uint64_t table_high[16];
        uint64_t table_low[16];

        // 构造函数：预计算查找表
        explicit GHashTable(const uint8_t H[16]) {
            uint64_t H_high = be64toh(*reinterpret_cast<const uint64_t*>(H));
            uint64_t H_low = be64toh(*reinterpret_cast<const uint64_t*>(H + 8));

            // 计算H^0到H^15
            table_high[0] = 0;
            table_low[0] = 0;

            table_high[8] = H_high;
            table_low[8] = H_low;

            // 递归计算所有表项
            for (int i = 4; i > 0; i /= 2) {
                for (int j = i; j < 16; j += 2 * i) {
                    if (table_high[j] == 0 && table_low[j] == 0) {
                        table_high[j] = table_high[j - i];
                        table_low[j] = table_low[j - i];
                        multiply_x(table_high[j], table_low[j]);
                        multiply_x(table_high[j], table_low[j]);
                        multiply_x(table_high[j], table_low[j]);
                        multiply_x(table_high[j], table_low[j]);
                    }
                }
            }
        }

        // GF(2^128)乘法使用查找表
        void multiply(uint64_t& state_high, uint64_t& state_low) const {
            uint64_t result_high = 0;
            uint64_t result_low = 0;

            for (int i = 0; i < 16; i++) {
                // 计算当前4位的索引 (0-15)
                uint8_t window = (i < 8) ?
                    (static_cast<uint8_t>(state_high >> (56 - 8 * i)) & 0x0F) :
                    (static_cast<uint8_t>(state_low >> (56 - 8 * (i - 8))) & 0x0F);

                // 累加查找表项
                result_high ^= table_high[window];
                result_low ^= table_low[window];

                // 状态右移4位（模拟x^4乘）
                if (i < 15) {
                    multiply_x4(state_high, state_low);
                }
            }

            state_high = result_high;
            state_low = result_low;
        }

    private:
        // GF(2^128)乘以x模P(x) = x^128 + x^7 + x^2 + x + 1
        static void multiply_x(uint64_t& high, uint64_t& low) {
            bool carry = (low & 1) != 0;
            low = (high << 63) | (low >> 1);
            high = high >> 1;

            if (carry) {
                low ^= 0xE100000000000000ULL;
            }
        }

        // GF(2^128)乘以x^4
        static void multiply_x4(uint64_t& high, uint64_t& low) {
            for (int i = 0; i < 4; i++) {
                bool carry = (low & 1) != 0;
                low = (high << 63) | (low >> 1);
                high = high >> 1;

                if (carry) {
                    low ^= 0xE100000000000000ULL;
                }
            }
        }
    };

    // 计数器增加函数
    static void increment_counter(uint8_t counter[16]) {
        for (int i = 15; i >= 12; i--) {
            if (++counter[i] != 0) break;
        }
    }

    // 优化2: GCTR并行处理（4路并行）
    static void parallel_gctr(const uint32_t* rk, const uint8_t icb[16],
        const uint8_t* input, size_t input_len, uint8_t* output) {
        const size_t PARALLELISM = 4;
        uint8_t counters[PARALLELISM][16];
        uint8_t keystream[PARALLELISM][16];

        // 正确初始化计数器
        memcpy(counters[0], icb, 16);
        for (size_t i = 1; i < PARALLELISM; i++) {
            memcpy(counters[i], icb, 16);
            increment_counter(counters[i]);
            for (size_t j = 1; j < i; j++) {
                increment_counter(counters[i]);
            }
        }

        size_t processed = 0;
        size_t full_blocks = input_len / (16 * PARALLELISM);
        size_t partial_blocks = (input_len % (16 * PARALLELISM)) / 16;
        size_t remainder = input_len % 16;

        // 1. 处理完整块（每轮4块）
        for (size_t block = 0; block < full_blocks; block++) {
            // 并行加密4个计数器
            for (size_t i = 0; i < PARALLELISM; i++) {
                SM4_BASIC::encrypt_block(counters[i], keystream[i], rk);
            }

            // 并行异或
            for (size_t i = 0; i < PARALLELISM; i++) {
                const size_t offset = block * 16 * PARALLELISM + i * 16;
                for (size_t j = 0; j < 16; j++) {
                    output[offset + j] = input[offset + j] ^ keystream[i][j];
                }
            }

            // 更新计数器（每个计数器增加PARALLELISM=4）
            for (size_t i = 0; i < PARALLELISM; i++) {
                for (int k = 0; k < PARALLELISM; k++) {
                    increment_counter(counters[i]);
                }
            }
        }

        processed = full_blocks * 16 * PARALLELISM;

        // 2. 处理部分块（不足4块但完整的块）
        for (size_t i = 0; i < partial_blocks; i++) {
            // 加密一个计数器块
            SM4_BASIC::encrypt_block(counters[i], keystream[0], rk);

            const size_t offset = processed + i * 16;
            for (size_t j = 0; j < 16; j++) {
                output[offset + j] = input[offset + j] ^ keystream[0][j];
            }

            // 更新这个计数器（增加1）
            increment_counter(counters[i]);
        }
        processed += partial_blocks * 16;

        // 3. 处理最后的不完整块（不足16字节）
        if (remainder > 0) {
            uint8_t keystream_last[16];
            // 使用counters[partial_blocks]（已正确递增）
            SM4_BASIC::encrypt_block(counters[partial_blocks], keystream_last, rk);

            for (size_t j = 0; j < remainder; j++) {
                output[processed + j] = input[processed + j] ^ keystream_last[j];
            }
        }
    }
    // GHASH 计算（使用查找表优化）
    static void ghash(const GHashTable& gt, const uint8_t* A, size_t A_len,
        const uint8_t* C, size_t C_len, uint8_t output[16]) {
        uint64_t state_high = 0;
        uint64_t state_low = 0;

        // === 第一步：处理 AAD ===
        size_t a_blocks = (A_len + 15) / 16;
        for (size_t i = 0; i < a_blocks; ++i) {
            size_t len = std::min(A_len - i * 16, (size_t)16);
            uint64_t block_high = 0, block_low = 0;

            for (size_t j = 0; j < len; ++j) {
                if (j < 8)
                    block_high |= static_cast<uint64_t>(A[i * 16 + j]) << (56 - 8 * j);
                else
                    block_low |= static_cast<uint64_t>(A[i * 16 + j]) << (56 - 8 * (j - 8));
            }

            state_high ^= block_high;
            state_low ^= block_low;
            gt.multiply(state_high, state_low);
        }

        // === 第二步：处理 Ciphertext ===
        size_t c_blocks = (C_len + 15) / 16;
        for (size_t i = 0; i < c_blocks; ++i) {
            size_t len = std::min(C_len - i * 16, (size_t)16);
            uint64_t block_high = 0, block_low = 0;

            for (size_t j = 0; j < len; ++j) {
                if (j < 8)
                    block_high |= static_cast<uint64_t>(C[i * 16 + j]) << (56 - 8 * j);
                else
                    block_low |= static_cast<uint64_t>(C[i * 16 + j]) << (56 - 8 * (j - 8));
            }

            state_high ^= block_high;
            state_low ^= block_low;
            gt.multiply(state_high, state_low);
        }

        // === 第三步：处理长度块 ===
        // AAD 比特长度 (64bit) || Ciphertext 比特长度 (64bit)
        uint64_t aad_bits = static_cast<uint64_t>(A_len) * 8;
        uint64_t c_bits = static_cast<uint64_t>(C_len) * 8;

        uint64_t len_high = htobe64(aad_bits);
        uint64_t len_low = htobe64(c_bits);

        state_high ^= len_high;
        state_low ^= len_low;

        gt.multiply(state_high, state_low);

        // 最终结果保存到 output
        *reinterpret_cast<uint64_t*>(output) = htobe64(state_high);
        *reinterpret_cast<uint64_t*>(output + 8) = htobe64(state_low);
    }
    // IV处理
    static void generate_j0(const uint8_t H[16], const uint8_t* iv, size_t iv_len, uint8_t j0[16]) {
        if (iv_len == 12) {
            // 96位IV的特殊处理
            memcpy(j0, iv, 12);
            memset(j0 + 12, 0, 3);
            j0[15] = 1;
        }
        else {
            // 预计算GHASH表
            GHashTable gt(H);
            uint64_t state_high = 0;
            uint64_t state_low = 0;

            // 处理所有IV块
            size_t iv_blocks = (iv_len + 15) / 16;
            for (size_t i = 0; i < iv_blocks; i++) {
                uint64_t block_high = 0;
                uint64_t block_low = 0;
                size_t len = std::min(iv_len - i * 16, static_cast<size_t>(16));

                // 将块转为大端序
                for (size_t j = 0; j < len; j++) {
                    size_t shift = 56 - 8 * (j % 8);
                    if (j < 8) {
                        block_high |= static_cast<uint64_t>(iv[i * 16 + j]) << shift;
                    }
                    else {
                        block_low |= static_cast<uint64_t>(iv[i * 16 + j]) << shift;
                    }
                }

                state_high ^= block_high;
                state_low ^= block_low;

                // GHASH更新
                gt.multiply(state_high, state_low);
            }

            // 添加长度块
            uint64_t len_high = 0;
            uint64_t len_low = htobe64(static_cast<uint64_t>(iv_len) * 8);
            state_high ^= len_high;
            state_low ^= len_low;

            // GHASH更新
            gt.multiply(state_high, state_low);

            // 转换为大端序输出
            *reinterpret_cast<uint64_t*>(j0) = htobe64(state_high);
            *reinterpret_cast<uint64_t*>(j0 + 8) = htobe64(state_low);
        }
    }

    // GCM加密
    void encrypt(const uint8_t* key, const uint8_t* iv, size_t iv_len,
        const uint8_t* aad, size_t aad_len,
        const uint8_t* plaintext, size_t plaintext_len,
        uint8_t* ciphertext, uint8_t tag[16]) {
        // 提前计算轮密钥
        uint32_t rk[32];
        SM4_BASIC::expand_key(key, rk);

        // 计算H = SM4(key, 0)
        uint8_t H[16] = { 0 };
        SM4_BASIC::encrypt_block(H, H, rk);

        // 预计算GHASH表
        GHashTable gt(H);

        // 计算J0
        uint8_t j0[16];
        generate_j0(H, iv, iv_len, j0);

        // 计算初始计数器块 (ICB)
        uint8_t icb[16];
        memcpy(icb, j0, 16);
        increment_counter(icb);

        // 并行GCTR加密
        parallel_gctr(rk, icb, plaintext, plaintext_len, ciphertext);

        // 计算GHASH
        uint8_t s[16];
        ghash(gt, aad, aad_len, ciphertext, plaintext_len, s);

        // 计算加密的J0
        uint8_t encrypted_j0[16];
        SM4_BASIC::encrypt_block(j0, encrypted_j0, rk);

        // 计算认证标签
        for (int i = 0; i < 16; i++) {
            tag[i] = s[i] ^ encrypted_j0[i];
        }
    }

    // GCM解密
    bool decrypt(const uint8_t* key, const uint8_t* iv, size_t iv_len,
        const uint8_t* aad, size_t aad_len,
        const uint8_t* ciphertext, size_t ciphertext_len,
        const uint8_t* tag, uint8_t* plaintext) {
        // 提前计算轮密钥
        uint32_t rk[32];
        SM4_BASIC::expand_key(key, rk);

        // 计算H = SM4(key, 0)
        uint8_t H[16] = { 0 };
        SM4_BASIC::encrypt_block(H, H, rk);

        // 预计算GHASH表
        GHashTable gt(H);

        // 计算J0
        uint8_t j0[16];
        generate_j0(H, iv, iv_len, j0);

        // 计算GHASH
        uint8_t s[16];
        ghash(gt, aad, aad_len, ciphertext, ciphertext_len, s);

        // 计算加密的J0
        uint8_t encrypted_j0[16];
        SM4_BASIC::encrypt_block(j0, encrypted_j0, rk);

        // 计算期望标签
        uint8_t expected_tag[16];
        for (int i = 0; i < 16; i++) {
            expected_tag[i] = s[i] ^ encrypted_j0[i];
        }

        // 验证标签 (防止时序攻击)
        bool tag_match = true;
        for (int i = 0; i < 16; i++) {
            if (expected_tag[i] != tag[i]) {
                tag_match = false;
            }
        }

        // 解密内容
        if (tag_match) {
            uint8_t icb[16];
            memcpy(icb, j0, 16);
            increment_counter(icb);
            parallel_gctr(rk, icb, ciphertext, ciphertext_len, plaintext);
            return true;
        }

        return false;
    }
}
// ====================== 基础（非优化）GCM 实现 ======================
namespace SM4_GCM_BASIC {
    // GF(2^128) 乘法函数 - 按位实现
    static void multiply_gf128(uint64_t H_high, uint64_t H_low,
        uint64_t& X_high, uint64_t& X_low) {
        uint64_t Z_high = 0;
        uint64_t Z_low = 0;
        uint64_t V_high = X_high;
        uint64_t V_low = X_low;

        for (int i = 0; i < 128; i++) {
            // 检查V最低位
            if (V_low & 1) {
                Z_high ^= H_high;
                Z_low ^= H_low;
            }

            // V右移1位
            bool carry = (V_high & 1);
            V_low = (V_low >> 1) | (V_high << 63);
            V_high = V_high >> 1;
            if (carry) V_low |= 0x8000000000000000ULL;

            // H左移1位
            carry = (H_low & 0x8000000000000000ULL);
            H_high = (H_high << 1) | (H_low >> 63);
            H_low = H_low << 1;

            // 模约简 (x^128 + x^7 + x^2 + x + 1)
            if (carry) {
                H_high ^= 0;
                H_low ^= 0xE100000000000000ULL; // x^7 + x^2 + x + 1
            }
        }

        X_high = Z_high;
        X_low = Z_low;
    }

    // GHASH基本实现（无查找表优化）
    static void ghash_basic(const uint8_t H[16], const uint8_t* A, size_t A_len,
        const uint8_t* C, size_t C_len, uint8_t output[16]) {
        uint64_t state_high = 0;
        uint64_t state_low = 0;

        // H 是 16 字节的固定参数，GHASH 的固定乘数
        uint64_t H_high = be64toh(*reinterpret_cast<const uint64_t*>(H));
        uint64_t H_low = be64toh(*reinterpret_cast<const uint64_t*>(H + 8));

        // === 第一步：处理 AAD（附加认证数据）===
        size_t a_blocks = (A_len + 15) / 16;
        for (size_t i = 0; i < a_blocks; ++i) {
            size_t len = std::min(A_len - i * 16, static_cast<size_t>(16));
            uint64_t block_high = 0;
            uint64_t block_low = 0;

            // 按大端序读取每个字节到 block_high / block_low
            for (size_t j = 0; j < len; ++j) {
                if (j < 8)
                    block_high |= static_cast<uint64_t>(A[i * 16 + j]) << (56 - 8 * j);
                else
                    block_low |= static_cast<uint64_t>(A[i * 16 + j]) << (56 - 8 * (j - 8));
            }

            // 异或到当前状态
            state_high ^= block_high;
            state_low ^= block_low;

            // 执行 GF(2^128) 乘法: state = state * H
            multiply_gf128(H_high, H_low, state_high, state_low);
        }

        // === 第二步：处理 Ciphertext ===
        size_t c_blocks = (C_len + 15) / 16;
        for (size_t i = 0; i < c_blocks; ++i) {
            size_t len = std::min(C_len - i * 16, static_cast<size_t>(16));
            uint64_t block_high = 0;
            uint64_t block_low = 0;

            for (size_t j = 0; j < len; ++j) {
                if (j < 8)
                    block_high |= static_cast<uint64_t>(C[i * 16 + j]) << (56 - 8 * j);
                else
                    block_low |= static_cast<uint64_t>(C[i * 16 + j]) << (56 - 8 * (j - 8));
            }

            state_high ^= block_high;
            state_low ^= block_low;

            // 执行 GF(2^128) 乘法: state = state * H
            multiply_gf128(H_high, H_low, state_high, state_low);
        }

        // === 第三步：处理长度块（AAD 比特数 + 密文比特数）===
        // 前 64-bit 是 AAD 的比特长度，后 64-bit 是 Ciphertext 的比特长度
        uint64_t aad_bits = static_cast<uint64_t>(A_len) * 8;
        uint64_t c_bits = static_cast<uint64_t>(C_len) * 8;

        uint64_t len_high = htobe64(aad_bits);  // 大端序
        uint64_t len_low = htobe64(c_bits);

        state_high ^= len_high;
        state_low ^= len_low;

        // 最后一次乘法
        multiply_gf128(H_high, H_low, state_high, state_low);

        // === 最终结果：写入 output[16]，大端序 ===
        *reinterpret_cast<uint64_t*>(output) = htobe64(state_high);
        *reinterpret_cast<uint64_t*>(output + 8) = htobe64(state_low);
    }

    // GCTR基础实现（单块加密）
    static void gctr_basic(const uint32_t* rk, const uint8_t icb[16],
        const uint8_t* input, size_t len, uint8_t* output) {
        uint8_t counter[16];
        memcpy(counter, icb, 16);

        for (size_t i = 0; i < len / 16; i++) {
            uint8_t keystream[16];
            SM4_BASIC::encrypt_block(counter, keystream, rk);
            for (int j = 0; j < 16; j++) {
                output[i * 16 + j] = input[i * 16 + j] ^ keystream[j];
            }
            SM4_GCM_OPTIMIZED::increment_counter(counter);
        }

        // 处理剩余字节
        size_t rem = len % 16;
        if (rem > 0) {
            uint8_t keystream[16];
            SM4_BASIC::encrypt_block(counter, keystream, rk);
            for (size_t j = 0; j < rem; j++) {
                output[len - rem + j] = input[len - rem + j] ^ keystream[j];
            }
        }
    }

    // GCM加密（基础版）
    void encrypt(const uint8_t* key, const uint8_t* iv, size_t iv_len,
        const uint8_t* aad, size_t aad_len,
        const uint8_t* plaintext, size_t plaintext_len,
        uint8_t* ciphertext, uint8_t tag[16]) {
        uint32_t rk[32];
        SM4_BASIC::expand_key(key, rk);

        uint8_t H[16] = { 0 };
        SM4_BASIC::encrypt_block(H, H, rk);

        uint8_t j0[16];
        SM4_GCM_OPTIMIZED::generate_j0(H, iv, iv_len, j0);

        uint8_t icb[16];
        memcpy(icb, j0, 16);
        SM4_GCM_OPTIMIZED::increment_counter(icb);

        // 使用基础GCTR加密
        gctr_basic(rk, icb, plaintext, plaintext_len, ciphertext);

        uint8_t s[16];
        // 使用基础GHASH计算
        ghash_basic(H, aad, aad_len, ciphertext, plaintext_len, s);

        uint8_t encrypted_j0[16];
        SM4_BASIC::encrypt_block(j0, encrypted_j0, rk);

        for (int i = 0; i < 16; i++) {
            tag[i] = s[i] ^ encrypted_j0[i];
        }
    }
}

// ====================== 性能测试 ======================
void performance_test() {
    // 准备测试数据（保持不变）
    uint8_t key[16] = { 0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
                       0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10 };
    uint8_t iv[12] = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                      0x08,0x09,0x0a,0x0b };
    uint8_t aad[] = { 0xaa,0xbb,0xcc,0xdd,0xee,0xff };
    const size_t TEST_SIZE = 1024 * 1024; // 1MB

    uint8_t* plaintext = new uint8_t[TEST_SIZE];
    uint8_t* ciphertext_basic = new uint8_t[TEST_SIZE];
    uint8_t* ciphertext_optimized = new uint8_t[TEST_SIZE];
    uint8_t* decrypted = new uint8_t[TEST_SIZE];
    uint8_t tag_basic[16], tag_optimized[16];

    // 填充随机数据
    for (size_t i = 0; i < TEST_SIZE; i++)
        plaintext[i] = rand() % 256;

    // 测试基础实现
    auto start_basic = std::chrono::high_resolution_clock::now();
    SM4_GCM_BASIC::encrypt(key, iv, 12, aad, sizeof(aad),
        plaintext, TEST_SIZE, ciphertext_basic, tag_basic);
    auto end_basic = std::chrono::high_resolution_clock::now();
    auto duration_basic = std::chrono::duration_cast<std::chrono::milliseconds>(end_basic - start_basic).count();
    double speed_basic = (TEST_SIZE / 1024.0 / 1024.0) / (duration_basic / 1000.0);

    // 测试优化实现
    auto start_opt = std::chrono::high_resolution_clock::now();
    SM4_GCM_OPTIMIZED::encrypt(key, iv, 12, aad, sizeof(aad),
        plaintext, TEST_SIZE, ciphertext_optimized, tag_optimized);
    auto end_opt = std::chrono::high_resolution_clock::now();
    auto duration_opt = std::chrono::duration_cast<std::chrono::milliseconds>(end_opt - start_opt).count();
    double speed_opt = (TEST_SIZE / 1024.0 / 1024.0) / (duration_opt / 1000.0);

    // 验证正确性
    bool decrypt_ok = SM4_GCM_OPTIMIZED::decrypt(key, iv, 12, aad, sizeof(aad),
        ciphertext_optimized, TEST_SIZE, tag_optimized, decrypted);
    bool same_ciphertext = (memcmp(ciphertext_basic, ciphertext_optimized, TEST_SIZE) == 0);
    bool same_tag = (memcmp(tag_basic, tag_optimized, 16) == 0);

    // 输出结果
    std::cout << "===== SM4-GCM 性能测试 (1MB数据) =====" << std::endl;
    std::cout << "基础实现:" << std::endl;
    std::cout << "  时间: " << duration_basic << " ms | 速度: "
        << std::fixed << std::setprecision(2) << speed_basic << " MB/s" << std::endl;

    std::cout << "优化实现:" << std::endl;
    std::cout << "  时间: " << duration_opt << " ms | 速度: "
        << std::fixed << std::setprecision(2) << speed_opt << " MB/s" << std::endl;

    std::cout << "加速比: " << std::fixed << std::setprecision(2)
        << (static_cast<double>(duration_basic) / duration_opt) << "x" << std::endl;

    std::cout << "\n正确性验证:" << std::endl;
    std::cout << "  解密结果: " << (decrypt_ok ? "成功" : "失败") << std::endl;
    std::cout << "  密文一致性: " << (same_ciphertext ? "是" : "否") << std::endl;


    // 清理内存
    delete[] plaintext;
    delete[] ciphertext_basic;
    delete[] ciphertext_optimized;
    delete[] decrypted;
}


// ====================== 主函数 ======================
int main() {
    // 执行性能测试
    performance_test();
    return 0;
}