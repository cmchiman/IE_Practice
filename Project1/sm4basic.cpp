#include <iostream>
#include <vector>
#include <cstring>

class SM4 {
private:
    static const uint8_t SBOX[256];
    static const uint32_t FK[4];
    static const uint32_t CK[32];

    uint32_t rk[32]; // 轮密钥

    // 辅助函数
    uint32_t tau(uint32_t word) {
        uint32_t result = 0;
        result |= SBOX[word >> 24] << 24;
        result |= SBOX[(word >> 16) & 0xFF] << 16;
        result |= SBOX[(word >> 8) & 0xFF] << 8;
        result |= SBOX[word & 0xFF];
        return result;
    }

    uint32_t L(uint32_t word) {
        return word ^ rotl(word, 2) ^ rotl(word, 10) ^
            rotl(word, 18) ^ rotl(word, 24);
    }

    uint32_t L_key(uint32_t word) {
        return word ^ rotl(word, 13) ^ rotl(word, 23);
    }

    uint32_t rotl(uint32_t value, uint32_t shift) {
        return (value << shift) | (value >> (32 - shift));
    }

public:
    SM4(const uint8_t key[16]) {
        // 密钥扩展
        uint32_t K[4];
        for (int i = 0; i < 4; ++i) {
            K[i] = (key[4 * i] << 24) | (key[4 * i + 1] << 16) |
                (key[4 * i + 2] << 8) | key[4 * i + 3];
            K[i] ^= FK[i];
        }

        for (int i = 0; i < 32; ++i) {
            uint32_t tmp = K[1] ^ K[2] ^ K[3] ^ CK[i];
            tmp = tau(tmp);
            tmp = L_key(tmp);
            rk[i] = K[0] ^ tmp;
            K[0] = K[1]; K[1] = K[2]; K[2] = K[3]; K[3] = rk[i];
        }
    }

    void encrypt_block(uint8_t out[16], const uint8_t in[16]) {
        uint32_t X[4];
        for (int i = 0; i < 4; ++i) {
            X[i] = (in[4 * i] << 24) | (in[4 * i + 1] << 16) |
                (in[4 * i + 2] << 8) | in[4 * i + 3];
        }

        // 32轮加密
        for (int i = 0; i < 32; ++i) {
            uint32_t tmp = X[1] ^ X[2] ^ X[3] ^ rk[i];
            tmp = tau(tmp);
            tmp = L(tmp);
            uint32_t newX = X[0] ^ tmp;

            X[0] = X[1];
            X[1] = X[2];
            X[2] = X[3];
            X[3] = newX;
        }

        // 反序输出
        for (int i = 0; i < 4; ++i) {
            out[4 * i] = (X[3 - i] >> 24) & 0xFF;
            out[4 * i + 1] = (X[3 - i] >> 16) & 0xFF;
            out[4 * i + 2] = (X[3 - i] >> 8) & 0xFF;
            out[4 * i + 3] = X[3 - i] & 0xFF;
        }
    }
};

// S盒定义（国家标准GB/T 32907-2016）
const uint8_t SM4::SBOX[256] = {
    0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7,
    // ...（完整S盒数据请参考国家标准文档）
};

// 系统参数
const uint32_t SM4::FK[4] = {
    0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC
};

// 固定参数
const uint32_t SM4::CK[32] = {
    0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
    // ...（完整CK数组请参考标准文档）
};

int main() {
    uint8_t key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    uint8_t plaintext[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    uint8_t ciphertext[16];

    SM4 sm4(key);
    sm4.encrypt_block(ciphertext, plaintext);

    std::cout << "Ciphertext: ";
    for (int i = 0; i < 16; ++i) {
        printf("%02X ", ciphertext[i]);
    }
    std::cout << std::endl;

    return 0;
}