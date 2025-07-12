#include <iostream>
#include <cstdint>
#include <chrono>
#include <iomanip>

class SM4_Original {
private:
    static constexpr uint8_t SBOX[256] = {
        0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0x01, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
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

    static constexpr uint32_t FK[4] = {
        0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC
    };

    static constexpr uint32_t CK[32] = {
        0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
        0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
        0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
        0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
        0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
        0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
        0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
        0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
    };

    uint32_t rk[32];

    // 辅助函数：循环左移
    static constexpr uint32_t rotl(uint32_t value, uint32_t shift) {
        return (value << shift) | (value >> (32 - shift));
    }

    // τ变换：32位输入通过S盒替换
    uint32_t tau(uint32_t x) {
        uint32_t res = 0;
        res |= static_cast<uint32_t>(SBOX[(x >> 24) & 0xff]) << 24;
        res |= static_cast<uint32_t>(SBOX[(x >> 16) & 0xff]) << 16;
        res |= static_cast<uint32_t>(SBOX[(x >> 8) & 0xff]) << 8;
        res |= static_cast<uint32_t>(SBOX[x & 0xff]);
        return res;
    }

    // 线性变换L（用于轮函数）
    uint32_t L(uint32_t word) {
        return word ^ rotl(word, 2) ^ rotl(word, 10) ^
            rotl(word, 18) ^ rotl(word, 24);
    }

    // 线性变换L'（用于密钥扩展）
    uint32_t L_prime(uint32_t word) {
        return word ^ rotl(word, 13) ^ rotl(word, 23);
    }

public:
    SM4_Original(const uint8_t key[16]) {
        uint32_t K[4];
        // 初始化K0~K3
        for (int i = 0; i < 4; ++i) {
            K[i] = (static_cast<uint32_t>(key[4 * i]) << 24) |
                (static_cast<uint32_t>(key[4 * i + 1]) << 16) |
                (static_cast<uint32_t>(key[4 * i + 2]) << 8) |
                static_cast<uint32_t>(key[4 * i + 3]);
            K[i] ^= FK[i];
        }

        // 密钥扩展
        for (int i = 0; i < 32; ++i) {
            uint32_t tmp = K[1] ^ K[2] ^ K[3] ^ CK[i];
            tmp = tau(tmp);
            tmp = L_prime(tmp);
            rk[i] = K[0] ^ tmp;
            // 更新K数组
            K[0] = K[1];
            K[1] = K[2];
            K[2] = K[3];
            K[3] = rk[i];
        }
    }

    void encrypt_block(uint8_t out[16], const uint8_t in[16]) {
        uint32_t X[4];
        // 输入转换为字
        for (int i = 0; i < 4; ++i) {
            X[i] = (static_cast<uint32_t>(in[4 * i]) << 24) |
                (static_cast<uint32_t>(in[4 * i + 1]) << 16) |
                (static_cast<uint32_t>(in[4 * i + 2]) << 8) |
                static_cast<uint32_t>(in[4 * i + 3]);
        }

        // 32轮加密（原始算法）
        for (int i = 0; i < 32; ++i) {
            uint32_t tmp = X[1] ^ X[2] ^ X[3] ^ rk[i];
            tmp = tau(tmp);
            tmp = L(tmp);
            uint32_t newX = X[0] ^ tmp;
            // 更新状态
            X[0] = X[1];
            X[1] = X[2];
            X[2] = X[3];
            X[3] = newX;
        }

        // 反序输出
        for (int i = 0; i < 4; ++i) {
            uint32_t val = X[3 - i];
            out[4 * i] = static_cast<uint8_t>((val >> 24) & 0xFF);
            out[4 * i + 1] = static_cast<uint8_t>((val >> 16) & 0xFF);
            out[4 * i + 2] = static_cast<uint8_t>((val >> 8) & 0xFF);
            out[4 * i + 3] = static_cast<uint8_t>(val & 0xFF);
        }
    }
};

class SM4_Optimized {
private:
    static constexpr uint8_t SBOX[256] = {
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

    static constexpr uint32_t FK[4] = {
        0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC
    };

    static constexpr uint32_t CK[32] = {
        0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
        0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
        0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
        0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
        0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
        0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
        0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
        0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
    };

    uint32_t rk[32];

    // 预计算表
    static uint32_t T0[256], T1[256], T2[256], T3[256];
    static uint32_t T_prime0[256], T_prime1[256], T_prime2[256], T_prime3[256];

    // 辅助函数：循环左移
    static constexpr uint32_t rotl(uint32_t value, uint32_t shift) {
        return (value << shift) | (value >> (32 - shift));
    }

    // 线性变换L（用于轮函数）
    static constexpr uint32_t L(uint32_t word) {
        return word ^ rotl(word, 2) ^ rotl(word, 10) ^
            rotl(word, 18) ^ rotl(word, 24);
    }

    // 线性变换L'（用于密钥扩展）
    static constexpr uint32_t L_prime(uint32_t word) {
        return word ^ rotl(word, 13) ^ rotl(word, 23);
    }

    // 静态初始化函数
    static void init_tables() {
        static bool initialized = false;
        if (initialized) return;
        initialized = true;

        for (int i = 0; i < 256; i++) {
            uint32_t a = static_cast<uint32_t>(SBOX[i]);

            // 轮函数T表
            T0[i] = L(a << 24);
            T1[i] = L(a << 16);
            T2[i] = L(a << 8);
            T3[i] = L(a);

            // 密钥扩展T'表
            T_prime0[i] = L_prime(a << 24);
            T_prime1[i] = L_prime(a << 16);
            T_prime2[i] = L_prime(a << 8);
            T_prime3[i] = L_prime(a);
        }
    }

    // 组合查表法优化T函数
    static uint32_t T_combined(uint32_t x) {
        return T0[(x >> 24) & 0xFF] ^
            T1[(x >> 16) & 0xFF] ^
            T2[(x >> 8) & 0xFF] ^
            T3[x & 0xFF];
    }

    // 组合查表法优化T'函数
    static uint32_t T_prime_combined(uint32_t x) {
        return T_prime0[(x >> 24) & 0xFF] ^
            T_prime1[(x >> 16) & 0xFF] ^
            T_prime2[(x >> 8) & 0xFF] ^
            T_prime3[x & 0xFF];
    }

public:
    SM4_Optimized(const uint8_t key[16]) {
        init_tables();

        uint32_t K[4];
        // 初始化K0~K3
        for (int i = 0; i < 4; ++i) {
            K[i] = (static_cast<uint32_t>(key[4 * i]) << 24) |
                (static_cast<uint32_t>(key[4 * i + 1]) << 16) |
                (static_cast<uint32_t>(key[4 * i + 2]) << 8) |
                static_cast<uint32_t>(key[4 * i + 3]);
            K[i] ^= FK[i];
        }

        // 密钥扩展使用组合查表法优化
        for (int i = 0; i < 32; ++i) {
            uint32_t tmp = K[1] ^ K[2] ^ K[3] ^ CK[i];
            tmp = T_prime_combined(tmp);
            rk[i] = K[0] ^ tmp;
            // 更新K数组
            K[0] = K[1];
            K[1] = K[2];
            K[2] = K[3];
            K[3] = rk[i];
        }
    }

    void encrypt_block(uint8_t out[16], const uint8_t in[16]) {
        uint32_t X[4];
        // 输入转换为字
        for (int i = 0; i < 4; ++i) {
            X[i] = (static_cast<uint32_t>(in[4 * i]) << 24) |
                (static_cast<uint32_t>(in[4 * i + 1]) << 16) |
                (static_cast<uint32_t>(in[4 * i + 2]) << 8) |
                static_cast<uint32_t>(in[4 * i + 3]);
        }

        // 32轮加密（使用查表法优化）
        for (int i = 0; i < 32; ++i) {
            uint32_t tmp = X[1] ^ X[2] ^ X[3] ^ rk[i];
            tmp = T_combined(tmp);
            uint32_t newX = X[0] ^ tmp;
            // 更新状态
            X[0] = X[1];
            X[1] = X[2];
            X[2] = X[3];
            X[3] = newX;
        }

        // 反序输出
        for (int i = 0; i < 4; ++i) {
            uint32_t val = X[3 - i];
            out[4 * i] = static_cast<uint8_t>((val >> 24) & 0xFF);
            out[4 * i + 1] = static_cast<uint8_t>((val >> 16) & 0xFF);
            out[4 * i + 2] = static_cast<uint8_t>((val >> 8) & 0xFF);
            out[4 * i + 3] = static_cast<uint8_t>(val & 0xFF);
        }
    }
};

// 静态成员初始化
uint32_t SM4_Optimized::T0[256];
uint32_t SM4_Optimized::T1[256];
uint32_t SM4_Optimized::T2[256];
uint32_t SM4_Optimized::T3[256];
uint32_t SM4_Optimized::T_prime0[256];
uint32_t SM4_Optimized::T_prime1[256];
uint32_t SM4_Optimized::T_prime2[256];
uint32_t SM4_Optimized::T_prime3[256];

// 性能测试函数
template <typename T>
double benchmark_sm4(T& sm4, const uint8_t* plaintext, uint8_t* ciphertext, int iterations) {
    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < iterations; ++i) {
        sm4.encrypt_block(ciphertext, plaintext);
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

    return duration.count() / (double)iterations;
}

int main() {
    // 测试密钥
    uint8_t key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    // 测试明文
    uint8_t plaintext[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    uint8_t ciphertext[16];
    const int iterations = 100000;

    // 创建原始算法实例并测试
    SM4_Original sm4_orig(key);
    double orig_time = benchmark_sm4(sm4_orig, plaintext, ciphertext, iterations);

    // 验证原始算法结果
    sm4_orig.encrypt_block(ciphertext, plaintext);
    std::cout << "Original ciphertext: ";
    for (int i = 0; i < 16; ++i) {
        printf("%02X ", ciphertext[i]);
    }
    std::cout << std::endl;

    // 创建优化算法实例并测试
    SM4_Optimized sm4_opt(key);
    double opt_time = benchmark_sm4(sm4_opt, plaintext, ciphertext, iterations);

    // 验证优化算法结果
    sm4_opt.encrypt_block(ciphertext, plaintext);
    std::cout << "Optimized ciphertext: ";
    for (int i = 0; i < 16; ++i) {
        printf("%02X ", ciphertext[i]);
    }
    std::cout << std::endl;

    // 性能对比
    double speedup = orig_time / opt_time;

    std::cout << "\nPerformance Comparison:" << std::endl;
    std::cout << "--------------------------------------" << std::endl;
    std::cout << "Algorithm       | Time per block (μs)" << std::endl;
    std::cout << "--------------------------------------" << std::endl;
    std::cout << "Original SM4    | " << std::fixed << std::setprecision(4)
        << orig_time << " μs" << std::endl;
    std::cout << "Optimized SM4   | " << opt_time << " μs" << std::endl;
    std::cout << "--------------------------------------" << std::endl;
    std::cout << "Speedup         | " << std::setprecision(2) << speedup << "x" << std::endl;
    std::cout << "Performance gain| " << std::setprecision(1)
        << (1 - opt_time / orig_time) * 100 << "%" << std::endl;

    return 0;
}