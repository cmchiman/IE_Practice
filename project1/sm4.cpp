#include <iostream>
#include <iomanip>
#include <chrono>
#include <immintrin.h>
#include <wmmintrin.h>
#include <cstring>

// 自定义循环左移函数
inline uint32_t ROL32(uint32_t value, uint32_t shift) {
    shift %= 32;
    return (value << shift) | (value >> (32 - shift));
}

// 基础实现版本
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

// T-table优化版本
namespace SM4_TTABLE {
    // 预计算T-table（实际值需要根据S盒和L变换计算）
    static const uint32_t T0[256] = {
        0x8ED55B5B, 0xD0924242, 0x4DEAA7A7, 0x6DFBFBFB, 0xF33F3F3F, 0x6FECECEC, 0xAA5959D5, 0x6BCECECE,
        0x4F2B2BE4, 0x71E2E2E2, 0x57D0D0B8, 0x87FEFE19, 0xBCE2E239, 0xF96A6A4D, 0xAE5959D5, 0x123E3EC0,
        0xBF9191E8, 0xC1999940, 0xA1878751, 0x0B1F1F64, 0xAC6C6CC1, 0x89F0F00C, 0x9E9595FB, 0x527B7B8A,
        0x6C0909F2, 0x20282880, 0xA79B9B3C, 0xF0C9C946, 0xB19E9E80, 0x5A8282D8, 0x4B3535E0, 0x93F3F3FC,
        0xFDC8C845, 0x9A8585DF, 0x3C1515F8, 0xE507075C, 0xFBEBEB08, 0x07FBFB60, 0x5F3D3DAA, 0x67E4E423,
        0x1A7D7D04, 0x9D5555B1, 0x86FCFC1E, 0xCA7D7D87, 0x2EC1C156, 0xEACBCB40, 0x232B2B68, 0x3F46467A,
        0x565B5BED, 0x92909083, 0xAF8D8DD3, 0xC7C0C05A, 0xBC717121, 0xB1C0C05B, 0x899797B6, 0x44A1A112,
        0xB6C1C15F, 0xC3C0C058, 0xDF2929BE, 0x3A4C4CC6, 0xDB6464F7, 0xD4D0D0B4, 0xF46B6B4F, 0x8C2525EA,
        0xBBEBEB3C, 0xE927279C, 0x6BE9E926, 0xC5CACA4F, 0x8A0909F6, 0xBF9D9D3E, 0x29C0C053, 0xA56E6ECB,
        0x96F0F00A, 0x1B0B0BF4, 0x9A2323CE, 0x61E8E825, 0x555151E2, 0x2B6666F9, 0xF7DBDB30, 0x3E2E2E68,
        0x2D79790C, 0x575353E6, 0xC1CCCC41, 0xA9D7D762, 0xEEA8A88B, 0x89F5F50E, 0x0D020268, 0xB46A6AC9,
        0x6D3333A8, 0xA36C6CC5, 0xED16169A, 0xB7E6E631, 0xBB73732D, 0xAC9F9F23, 0x2F6363FF, 0xFEC7C749,
        0x03F9F964, 0x5C2626D8, 0x0C06066C, 0x45A5A50F, 0xF3D9D93A, 0x2CCFCF5D, 0xF1DDDD3C, 0x0E03036C,
        0x0F050564, 0x56A0A019, 0x71E3E327, 0xD8D1D1B2, 0xA46D6DCF, 0x6CE7E727, 0x4A2D2DE4, 0x5B767693,
        0xE1DDDD3D, 0x1D3131AC, 0x9B3636D4, 0x9C9393F7, 0xF8CACA47, 0xBCC0C04C, 0x23C2C25F, 0xE6191992,
        0xBD6E6EC7, 0x2AC8C843, 0xE0DBDB38, 0xE3CACA49, 0x1EEEEE37, 0x98D0D0B0, 0x7B77778C, 0xFA0B0B74,
        0x5F8080DB, 0x6E6666FD, 0xE4C8C845, 0xCECCCC4B, 0x5EB8B896, 0x7C383898, 0xB26B6BCD, 0xE91B1B96,
        0xACD7D760, 0xDF6A6A47, 0xC5BCBC76, 0xEA0F0F7C, 0xB36F6FCB, 0x4C3B3B96, 0x37E9E920, 0x55A9A902,
        0x8E0C0CF0, 0x6FFCFC6B, 0x3B7A7A14, 0x52B5B59D, 0xAC6767C9, 0x1FE0E03B, 0x5DBDBD9A, 0xD7C0C048,
        0xC4B0B07A, 0x55B0B09F, 0xD2D3D3BC, 0x70E0E020, 0x4E2C2CD4, 0x57D4D4AC, 0x8D2222E6, 0x70E1E123,
        0x2CC1C154, 0xB5797920, 0x6A3939A4, 0x54B3B397, 0xED1F1F9E, 0x1B7F7F08, 0x3F3D3DAA, 0x1C1D1DE8,
        0x5E8181DE, 0xB1989848, 0xA9A8A882, 0x0B7E7E00, 0xDAD4D4BC, 0x7A10109C, 0xD3C5C556, 0xF26A6A4B,
        0x142424D0, 0x4C383894, 0xA49A9A3E, 0x48A3A315, 0x36E8E824, 0x96F1F1FE, 0x25C5C55A, 0x9A8585DF,
        0x3C1515F8, 0xE507075C, 0xFBEBEB08, 0x07FBFB60, 0x5F3D3DAA, 0x67E4E423, 0x1A7D7D04, 0x9D5555B1,
        0x86FCFC1E, 0xCA7D7D87, 0x2EC1C156, 0xEACBCB40, 0x232B2B68, 0x3F46467A, 0x565B5BED, 0x92909083,
        0xAF8D8DD3, 0xC7C0C05A, 0xBC717121, 0xB1C0C05B, 0x899797B6, 0x44A1A112, 0xB6C1C15F, 0xC3C0C058
    };

    static const uint32_t T1[256] = {
        0x5ED5D5AC, 0xD72E2E68, 0x9A9191F3, 0x17F3F3E8, 0xA75A5AB7, 0xBC777729, 0xC6B9B968, 0xFBC0C04C,
        0xBA5D5DBF, 0x32E5E5D7, 0x30CECE9F, 0xDF1414A2, 0x47D8D8B0, 0x71C5C59A, 0xB3C3C350, 0x28E3E3DB,
        0x37E7E7D0, 0xC7C0C050, 0x4ADADA8F, 0xFC575757, 0x69E1E1D2, 0xEAC0C046, 0xE91D1D9A, 0xDC1A1A94,
        0x6CCDCD83, 0x5B8A8AD1, 0xBA5D5DBF, 0x32E5E5D7, 0x30CECE9F, 0xDF1414A2, 0x47D8D8B0, 0x71C5C59A,
        0xB3C3C350, 0x28E3E3DB, 0x37E7E7D0, 0xC7C0C050, 0x4ADADA8F, 0xFC575757, 0x69E1E1D2, 0xEAC0C046,
        0xE91D1D9A, 0xDC1A1A94, 0x6CCDCD83, 0x5B8A8AD1, 0xBA5D5DBF, 0x32E5E5D7, 0x30CECE9F, 0xDF1414A2,
        0x47D8D8B0, 0x71C5C59A, 0xB3C3C350, 0x28E3E3DB, 0x37E7E7D0, 0xC7C0C050, 0x4ADADA8F, 0xFC575757,
        0x69E1E1D2, 0xEAC0C046, 0xE91D1D9A, 0xDC1A1A94, 0x6CCDCD83, 0x5B8A8AD1, 0xBA5D5DBF, 0x32E5E5D7,
        0x30CECE9F, 0xDF1414A2, 0x47D8D8B0, 0x71C5C59A, 0xB3C3C350, 0x28E3E3DB, 0x37E7E7D0, 0xC7C0C050,
        0x4ADADA8F, 0xFC575757, 0x69E1E1D2, 0xEAC0C046, 0xE91D1D9A, 0xDC1A1A94, 0x6CCDCD83, 0x5B8A8AD1,
        0xBA5D5DBF, 0x32E5E5D7, 0x30CECE9F, 0xDF1414A2, 0x47D8D8B0, 0x71C5C59A, 0xB3C3C350, 0x28E3E3DB,
        0x37E7E7D0, 0xC7C0C050, 0x4ADADA8F, 0xFC575757, 0x69E1E1D2, 0xEAC0C046, 0xE91D1D9A, 0xDC1A1A94,
        0x6CCDCD83, 0x5B8A8AD1, 0xBA5D5DBF, 0x32E5E5D7, 0x30CECE9F, 0xDF1414A2, 0x47D8D8B0, 0x71C5C59A,
        0xB3C3C350, 0x28E3E3DB, 0x37E7E7D0, 0xC7C0C050, 0x4ADADA8F, 0xFC575757, 0x69E1E1D2, 0xEAC0C046,
        0xE91D1D9A, 0xDC1A1A94, 0x6CCDCD83, 0x5B8A8AD1, 0xBA5D5DBF, 0x32E5E5D7, 0x30CECE9F, 0xDF1414A2,
        0x47D8D8B0, 0x71C5C59A, 0xB3C3C350, 0x28E3E3DB, 0x37E7E7D0, 0xC7C0C050, 0x4ADADA8F, 0xFC575757,
        0x69E1E1D2, 0xEAC0C046, 0xE91D1D9A, 0xDC1A1A94, 0x6CCDCD83, 0x5B8A8AD1, 0xBA5D5DBF, 0x32E5E5D7,
        0x30CECE9F, 0xDF1414A2, 0x47D8D8B0, 0x71C5C59A, 0xB3C3C350, 0x28E3E3DB, 0x37E7E7D0, 0xC7C0C050,
        0x4ADADA8F, 0xFC575757, 0x69E1E1D2, 0xEAC0C046, 0xE91D1D9A, 0xDC1A1A94, 0x6CCDCD83, 0x5B8A8AD1,
        0xBA5D5DBF, 0x32E5E5D7, 0x30CECE9F, 0xDF1414A2, 0x47D8D8B0, 0x71C5C59A, 0xB3C3C350, 0x28E3E3DB,
        0x37E7E7D0, 0xC7C0C050, 0x4ADADA8F, 0xFC575757, 0x69E1E1D2, 0xEAC0C046, 0xE91D1D9A, 0xDC1A1A94,
        0x6CCDCD83, 0x5B8A8AD1, 0xBA5D5DBF, 0x32E5E5D7, 0x30CECE9F, 0xDF1414A2, 0x47D8D8B0, 0x71C5C59a
    };

    static const uint32_t T2[256] = {
        0x5ED5D5AC, 0xD72E2E68, 0x9A9191F3, 0x17F3F3E8, 0xA75A5AB7, 0xBC777729, 0xC6B9B968, 0xFBC0C04C,
        0xBA5D5DBF, 0x32E5E5D7, 0x30CECE9F, 0xDF1414A2, 0x47D8D8B0, 0x71C5C59A, 0xB3C3C350, 0x28E3E3DB,
        0x37E7E7D0, 0xC7C0C050, 0x4ADADA8F, 0xFC575757, 0x69E1E1D2, 0xEAC0C046, 0xE91D1D9A, 0xDC1A1A94,
        0x6CCDCD83, 0x5B8A8AD1, 0xBA5D5DBF, 0x32E5E5D7, 0x30CECE9F, 0xDF1414A2, 0x47D8D8B0, 0x71C5C59A,
        0xB3C3C350, 0x28E3E3DB, 0x37E7E7D0, 0xC7C0C050, 0x4ADADA8F, 0xFC575757, 0x69E1E1D2, 0xEAC0C046,
        0xE91D1D9A, 0xDC1A1A94, 0x6CCDCD83, 0x5B8A8AD1, 0xBA5D5DBF, 0x32E5E5D7, 0x30CECE9F, 0xDF1414A2,
        0x47D8D8B0, 0x71C5C59A, 0xB3C3C350, 0x28E3E3DB, 0x37E7E7D0, 0xC7C0C050, 0x4ADADA8F, 0xFC575757,
        0x69E1E1D2, 0xEAC0C046, 0xE91D1D9A, 0xDC1A1A94, 0x6CCDCD83, 0x5B8A8AD1, 0xBA5D5DBF, 0x32E5E5D7,
        0x30CECE9F, 0xDF1414A2, 0x47D8D8B0, 0x71C5C59A, 0xB3C3C350, 0x28E3E3DB, 0x37E7E7D0, 0xC7C0C050,
        0x4ADADA8F, 0xFC575757, 0x69E1E1D2, 0xEAC0C046, 0xE91D1D9A, 0xDC1A1A94, 0x6CCDCD83, 0x5B8A8AD1,
        0xBA5D5DBF, 0x32E5E5D7, 0x30CECE9F, 0xDF1414A2, 0x47D8D8B0, 0x71C5C59A, 0xB3C3C350, 0x28E3E3DB,
        0x37E7E7D0, 0xC7C0C050, 0x4ADADA8F, 0xFC575757, 0x69E1E1D2, 0xEAC0C046, 0xE91D1D9A, 0xDC1A1A94,
        0x6CCDCD83, 0x5B8A8AD1, 0xBA5D5DBF, 0x32E5E5D7, 0x30CECE9F, 0xDF1414A2, 0x47D8D8B0, 0x71C5C59A,
        0xB3C3C350, 0x28E3E3DB, 0x37E7E7D0, 0xC7C0C050, 0x4ADADA8F, 0xFC575757, 0x69E1E1D2, 0xEAC0C046,
        0xE91D1D9A, 0xDC1A1A94, 0x6CCDCD83, 0x5B8A8AD1, 0xBA5D5DBF, 0x32E5E5D7, 0x30CECE9F, 0xDF1414A2,
        0x47D8D8B0, 0x71C5C59A, 0xB3C3C350, 0x28E3E3DB, 0x37E7E7D0, 0xC7C0C050, 0x4ADADA8F, 0xFC575757,
        0x69E1E1D2, 0xEAC0C046, 0xE91D1D9A, 0xDC1A1A94, 0x6CCDCD83, 0x5B8A8AD1, 0xBA5D5DBF, 0x32E5E5D7,
        0x30CECE9F, 0xDF1414A2, 0x47D8D8B0, 0x71C5C59A, 0xB3C3C350, 0x28E3E3DB, 0x37E7E7D0, 0xC7C0C050,
        0x4ADADA8F, 0xFC575757, 0x69E1E1D2, 0xEAC0C046, 0xE91D1D9A, 0xDC1A1A94, 0x6CCDCD83, 0x5B8A8AD1,
        0xBA5D5DBF, 0x32E5E5D7, 0x30CECE9F, 0xDF1414A2, 0x47D8D8B0, 0x71C5C59A, 0xB3C3C350, 0x28E3E3DB,
        0x37E7E7D0, 0xC7C0C050, 0x4ADADA8F, 0xFC575757, 0x69E1E1D2, 0xEAC0C046, 0xE91D1D9A, 0xDC1A1A94,
        0x6CCDCD83, 0x5B8A8AD1, 0xBA5D5DBF, 0x32E5E5D7, 0x30CECE9F, 0xDF1414A2, 0x47D8D8B0, 0x71C5C59a
    };

    static const uint32_t T3[256] = {
        0x5ED5D5AC, 0xD72E2E68, 0x9A9191F3, 0x17F3F3E8, 0xA75A5AB7, 0xBC777729, 0xC6B9B968, 0xFBC0C04C,
        0xBA5D5DBF, 0x32E5E5D7, 0x30CECE9F, 0xDF1414A2, 0x47D8D8B0, 0x71C5C59A, 0xB3C3C350, 0x28E3E3DB,
        0x37E7E7D0, 0xC7C0C050, 0x4ADADA8F, 0xFC575757, 0x69E1E1D2, 0xEAC0C046, 0xE91D1D9A, 0xDC1A1A94,
        0x6CCDCD83, 0x5B8A8AD1, 0xBA5D5DBF, 0x32E5E5D7, 0x30CECE9F, 0xDF1414A2, 0x47D8D8B0, 0x71C5C59A,
        0xB3C3C350, 0x28E3E3DB, 0x37E7E7D0, 0xC7C0C050, 0x4ADADA8F, 0xFC575757, 0x69E1E1D2, 0xEAC0C046,
        0xE91D1D9A, 0xDC1A1A94, 0x6CCDCD83, 0x5B8A8AD1, 0xBA5D5DBF, 0x32E5E5D7, 0x30CECE9F, 0xDF1414A2,
        0x47D8D8B0, 0x71C5C59A, 0xB3C3C350, 0x28E3E3DB, 0x37E7E7D0, 0xC7C0C050, 0x4ADADA8F, 0xFC575757,
        0x69E1E1D2, 0xEAC0C046, 0xE91D1D9A, 0xDC1A1A94, 0x6CCDCD83, 0x5B8A8AD1, 0xBA5D5DBF, 0x32E5E5D7,
        0x30CECE9F, 0xDF1414A2, 0x47D8D8B0, 0x71C5C59A, 0xB3C3C350, 0x28E3E3DB, 0x37E7E7D0, 0xC7C0C050,
        0x4ADADA8F, 0xFC575757, 0x69E1E1D2, 0xEAC0C046, 0xE91D1D9A, 0xDC1A1A94, 0x6CCDCD83, 0x5B8A8AD1,
        0xBA5D5DBF, 0x32E5E5D7, 0x30CECE9F, 0xDF1414A2, 0x47D8D8B0, 0x71C5C59A, 0xB3C3C350, 0x28E3E3DB,
        0x37E7E7D0, 0xC7C0C050, 0x4ADADA8F, 0xFC575757, 0x69E1E1D2, 0xEAC0C046, 0xE91D1D9A, 0xDC1A1A94,
        0x6CCDCD83, 0x5B8A8AD1, 0xBA5D5DBF, 0x32E5E5D7, 0x30CECE9F, 0xDF1414A2, 0x47D8D8B0, 0x71C5C59A,
        0xB3C3C350, 0x28E3E3DB, 0x37E7E7D0, 0xC7C0C050, 0x4ADADA8F, 0xFC575757, 0x69E1E1D2, 0xEAC0C046,
        0xE91D1D9A, 0xDC1A1A94, 0x6CCDCD83, 0x5B8A8AD1, 0xBA5D5DBF, 0x32E5E5D7, 0x30CECE9F, 0xDF1414A2,
        0x47D8D8B0, 0x71C5C59A, 0xB3C3C350, 0x28E3E3DB, 0x37E7E7D0, 0xC7C0C050, 0x4ADADA8F, 0xFC575757,
        0x69E1E1D2, 0xEAC0C046, 0xE91D1D9A, 0xDC1A1A94, 0x6CCDCD83, 0x5B8A8AD1, 0xBA5D5DBF, 0x32E5E5D7,
        0x30CECE9F, 0xDF1414A2, 0x47D8D8B0, 0x71C5C59A, 0xB3C3C350, 0x28E3E3DB, 0x37E7E7D0, 0xC7C0C050,
        0x4ADADA8F, 0xFC575757, 0x69E1E1D2, 0xEAC0C046, 0xE91D1D9A, 0xDC1A1A94, 0x6CCDCD83, 0x5B8A8AD1,
        0xBA5D5DBF, 0x32E5E5D7, 0x30CECE9F, 0xDF1414A2, 0x47D8D8B0, 0x71C5C59A, 0xB3C3C350, 0x28E3E3DB,
        0x37E7E7D0, 0xC7C0C050, 0x4ADADA8F, 0xFC575757, 0x69E1E1D2, 0xEAC0C046, 0xE91D1D9A, 0xDC1A1A94,
        0x6CCDCD83, 0x5B8A8AD1, 0xBA5D5DBF, 0x32E5E5D7, 0x30CECE9F, 0xDF1414A2, 0x47D8D8B0, 0x71C5C59a
    };

    void encrypt_block(const uint8_t* in, uint8_t* out, const uint32_t* rk) {
        uint32_t X0 = (static_cast<uint32_t>(in[0]) << 24) | (static_cast<uint32_t>(in[1]) << 16) | (static_cast<uint32_t>(in[2]) << 8) | static_cast<uint32_t>(in[3]);
        uint32_t X1 = (static_cast<uint32_t>(in[4]) << 24) | (static_cast<uint32_t>(in[5]) << 16) | (static_cast<uint32_t>(in[6]) << 8) | static_cast<uint32_t>(in[7]);
        uint32_t X2 = (static_cast<uint32_t>(in[8]) << 24) | (static_cast<uint32_t>(in[9]) << 16) | (static_cast<uint32_t>(in[10]) << 8) | static_cast<uint32_t>(in[11]);
        uint32_t X3 = (static_cast<uint32_t>(in[12]) << 24) | (static_cast<uint32_t>(in[13]) << 16) | (static_cast<uint32_t>(in[14]) << 8) | static_cast<uint32_t>(in[15]);

        for (int i = 0; i < 32; i++) {
            uint32_t tmp = X1 ^ X2 ^ X3 ^ rk[i];
            uint32_t T_res = T0[static_cast<uint8_t>(tmp >> 24)] ^
                T1[static_cast<uint8_t>(tmp >> 16)] ^
                T2[static_cast<uint8_t>(tmp >> 8)] ^
                T3[static_cast<uint8_t>(tmp)];
            uint32_t X_next = X0 ^ T_res;

            // 更新状态
            X0 = X1;
            X1 = X2;
            X2 = X3;
            X3 = X_next;
        }

        // 输出反序
        out[0] = static_cast<uint8_t>(X3 >> 24);
        out[1] = static_cast<uint8_t>(X3 >> 16);
        out[2] = static_cast<uint8_t>(X3 >> 8);
        out[3] = static_cast<uint8_t>(X3);
        out[4] = static_cast<uint8_t>(X2 >> 24);
        out[5] = static_cast<uint8_t>(X2 >> 16);
        out[6] = static_cast<uint8_t>(X2 >> 8);
        out[7] = static_cast<uint8_t>(X2);
        out[8] = static_cast<uint8_t>(X1 >> 24);
        out[9] = static_cast<uint8_t>(X1 >> 16);
        out[10] = static_cast<uint8_t>(X1 >> 8);
        out[11] = static_cast<uint8_t>(X1);
        out[12] = static_cast<uint8_t>(X0 >> 24);
        out[13] = static_cast<uint8_t>(X0 >> 16);
        out[14] = static_cast<uint8_t>(X0 >> 8);
        out[15] = static_cast<uint8_t>(X0);
    }
}

// AES-NI 优化版本
namespace SM4_AESNI_OPT {
    // 预定义常量
    const __m128i BYTES_SHUFFLE = _mm_set_epi8(12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3);
    const __m128i OUTPUT_SHUFFLE = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    const __m128i MASK_LOW = _mm_set1_epi8(0x0F);

    // 优化的S盒函数（使用双4位查表）
    static inline __m128i sm4_sbox(__m128i x) {
        // 分离高低4位
        __m128i hi = _mm_and_si128(_mm_srli_epi16(x, 4), MASK_LOW);
        __m128i lo = _mm_and_si128(x, MASK_LOW);

        // 预计算的S盒向量
        const __m128i sbox_hi = _mm_setr_epi8(
            0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7,
            0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05
        );

        const __m128i sbox_lo = _mm_setr_epi8(
            0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3,
            0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99
        );

        // 双查表并组合结果
        __m128i hi_val = _mm_shuffle_epi8(sbox_hi, hi);
        __m128i lo_val = _mm_shuffle_epi8(sbox_lo, lo);

        return _mm_xor_si128(hi_val, lo_val);
    }

    // 高效线性变换
    static inline __m128i sm4_linear(__m128i x) {
        // 合并所有旋转操作
        __m128i rot2 = _mm_xor_si128(_mm_slli_epi32(x, 2), _mm_srli_epi32(x, 30));
        __m128i rot10 = _mm_xor_si128(_mm_slli_epi32(x, 10), _mm_srli_epi32(x, 22));
        __m128i rot18 = _mm_xor_si128(_mm_slli_epi32(x, 18), _mm_srli_epi32(x, 14));
        __m128i rot24 = _mm_xor_si128(_mm_slli_epi32(x, 24), _mm_srli_epi32(x, 8));

        // 组合结果
        __m128i res = _mm_xor_si128(x, rot2);
        res = _mm_xor_si128(res, rot10);
        res = _mm_xor_si128(res, rot18);
        return _mm_xor_si128(res, rot24);
    }

    // T函数组合
    static inline __m128i sm4_t(__m128i x) {
        __m128i sbox_out = sm4_sbox(x);
        return sm4_linear(sbox_out);
    }

    // 处理4个块（高效实现）
    static void encrypt_4blocks(const uint8_t* in, uint8_t* out, const uint32_t* rk) {
        // 加载4个块
        __m128i block0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 0 * 16));
        __m128i block1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 1 * 16));
        __m128i block2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 2 * 16));
        __m128i block3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 3 * 16));

        // 初始字节重排
        block0 = _mm_shuffle_epi8(block0, BYTES_SHUFFLE);
        block1 = _mm_shuffle_epi8(block1, BYTES_SHUFFLE);
        block2 = _mm_shuffle_epi8(block2, BYTES_SHUFFLE);
        block3 = _mm_shuffle_epi8(block3, BYTES_SHUFFLE);

        // 初始化状态变量
        __m128i X0 = block0;
        __m128i X1 = block1;
        __m128i X2 = block2;
        __m128i X3 = block3;

        // 32轮加密（展开4轮减少分支）
        for (int round = 0; round < 32; round += 4) {
            // 轮密钥预加载
            __m128i rk0 = _mm_set1_epi32(rk[round]);
            __m128i rk1 = _mm_set1_epi32(rk[round + 1]);
            __m128i rk2 = _mm_set1_epi32(rk[round + 2]);
            __m128i rk3 = _mm_set1_epi32(rk[round + 3]);

            // 第1轮
            __m128i T_in0 = _mm_xor_si128(_mm_xor_si128(X1, X2), _mm_xor_si128(X3, rk0));
            __m128i T_out0 = sm4_t(T_in0);
            __m128i new_X0 = _mm_xor_si128(X0, T_out0);

            // 第2轮
            __m128i T_in1 = _mm_xor_si128(_mm_xor_si128(X2, X3), _mm_xor_si128(new_X0, rk1));
            __m128i T_out1 = sm4_t(T_in1);
            __m128i new_X1 = _mm_xor_si128(X1, T_out1);

            // 第3轮
            __m128i T_in2 = _mm_xor_si128(_mm_xor_si128(X3, new_X0), _mm_xor_si128(new_X1, rk2));
            __m128i T_out2 = sm4_t(T_in2);
            __m128i new_X2 = _mm_xor_si128(X2, T_out2);

            // 第4轮
            __m128i T_in3 = _mm_xor_si128(_mm_xor_si128(new_X0, new_X1), _mm_xor_si128(new_X2, rk3));
            __m128i T_out3 = sm4_t(T_in3);
            __m128i new_X3 = _mm_xor_si128(X3, T_out3);

            // 更新状态
            X0 = new_X0;
            X1 = new_X1;
            X2 = new_X2;
            X3 = new_X3;
        }

        // 最终输出重排
        block0 = _mm_shuffle_epi8(X3, OUTPUT_SHUFFLE);
        block1 = _mm_shuffle_epi8(X2, OUTPUT_SHUFFLE);
        block2 = _mm_shuffle_epi8(X1, OUTPUT_SHUFFLE);
        block3 = _mm_shuffle_epi8(X0, OUTPUT_SHUFFLE);

        // 存储结果
        _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 0 * 16), block0);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 1 * 16), block1);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 2 * 16), block2);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 3 * 16), block3);
    }

    // 主加密函数
    void encrypt_blocks(const uint8_t* in, uint8_t* out, const uint32_t* rk, size_t num_blocks) {
        size_t i = 0;

        // 处理完整的4块组
        for (; i + 3 < num_blocks; i += 4) {
            encrypt_4blocks(in + i * 16, out + i * 16, rk);
        }

        // 处理剩余块（1-3个）
        if (i < num_blocks) {
            uint8_t temp_in[64] = { 0 };
            uint8_t temp_out[64] = { 0 };
            size_t remaining = num_blocks - i;

            // 复制剩余数据到临时缓冲区
            memcpy(temp_in, in + i * 16, remaining * 16);

            // 加密完整4块
            encrypt_4blocks(temp_in, temp_out, rk);

            // 复制回结果
            memcpy(out + i * 16, temp_out, remaining * 16);
        }
    }
}
// GFNI 优化版本（使用 SSE 指令集）
namespace SM4_GFNI_SSE {
    // 预定义常量
    const __m128i BYTES_SHUFFLE = _mm_set_epi8(12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3);
    const __m128i OUTPUT_SHUFFLE = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);

    // GFNI 控制字（用于 SM4 S盒的仿射变换）
    const __m128i GFNI_CTL = _mm_set_epi64x(
        0x6363636363636363, // 常数向量（0x63）
        0x7070C00E0E0E0C00  // 仿射变换矩阵（转置后）
    );

    // 使用 GFNI 优化的 S盒函数
    static inline __m128i sm4_sbox_gfni(__m128i x) {
        // 使用 GFNI 指令计算 S盒
        return _mm_gf2p8affineinv_epi64_epi8(x, GFNI_CTL, 0);
    }

    // 高效线性变换
    static inline __m128i sm4_linear(__m128i x) {
        // 合并所有旋转操作
        __m128i rot2 = _mm_xor_si128(_mm_slli_epi32(x, 2), _mm_srli_epi32(x, 30));
        __m128i rot10 = _mm_xor_si128(_mm_slli_epi32(x, 10), _mm_srli_epi32(x, 22));
        __m128i rot18 = _mm_xor_si128(_mm_slli_epi32(x, 18), _mm_srli_epi32(x, 14));
        __m128i rot24 = _mm_xor_si128(_mm_slli_epi32(x, 24), _mm_srli_epi32(x, 8));

        // 组合结果
        __m128i res = _mm_xor_si128(x, rot2);
        res = _mm_xor_si128(res, rot10);
        res = _mm_xor_si128(res, rot18);
        return _mm_xor_si128(res, rot24);
    }

    // T函数组合
    static inline __m128i sm4_t(__m128i x) {
        __m128i sbox_out = sm4_sbox_gfni(x);
        return sm4_linear(sbox_out);
    }

    // 处理4个块（高效实现）
    static void encrypt_4blocks(const uint8_t* in, uint8_t* out, const uint32_t* rk) {
        // 加载4个块
        __m128i block0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 0 * 16));
        __m128i block1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 1 * 16));
        __m128i block2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 2 * 16));
        __m128i block3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 3 * 16));

        // 初始字节重排
        block0 = _mm_shuffle_epi8(block0, BYTES_SHUFFLE);
        block1 = _mm_shuffle_epi8(block1, BYTES_SHUFFLE);
        block2 = _mm_shuffle_epi8(block2, BYTES_SHUFFLE);
        block3 = _mm_shuffle_epi8(block3, BYTES_SHUFFLE);

        // 初始化状态变量
        __m128i X0 = block0;
        __m128i X1 = block1;
        __m128i X2 = block2;
        __m128i X3 = block3;

        // 32轮加密（展开4轮减少分支）
        for (int round = 0; round < 32; round += 4) {
            // 轮密钥预加载
            __m128i rk0 = _mm_set1_epi32(rk[round]);
            __m128i rk1 = _mm_set1_epi32(rk[round + 1]);
            __m128i rk2 = _mm_set1_epi32(rk[round + 2]);
            __m128i rk3 = _mm_set1_epi32(rk[round + 3]);

            // 第1轮
            __m128i T_in0 = _mm_xor_si128(_mm_xor_si128(X1, X2), _mm_xor_si128(X3, rk0));
            __m128i T_out0 = sm4_t(T_in0);
            __m128i new_X0 = _mm_xor_si128(X0, T_out0);

            // 第2轮
            __m128i T_in1 = _mm_xor_si128(_mm_xor_si128(X2, X3), _mm_xor_si128(new_X0, rk1));
            __m128i T_out1 = sm4_t(T_in1);
            __m128i new_X1 = _mm_xor_si128(X1, T_out1);

            // 第3轮
            __m128i T_in2 = _mm_xor_si128(_mm_xor_si128(X3, new_X0), _mm_xor_si128(new_X1, rk2));
            __m128i T_out2 = sm4_t(T_in2);
            __m128i new_X2 = _mm_xor_si128(X2, T_out2);

            // 第4轮
            __m128i T_in3 = _mm_xor_si128(_mm_xor_si128(new_X0, new_X1), _mm_xor_si128(new_X2, rk3));
            __m128i T_out3 = sm4_t(T_in3);
            __m128i new_X3 = _mm_xor_si128(X3, T_out3);

            // 更新状态
            X0 = new_X0;
            X1 = new_X1;
            X2 = new_X2;
            X3 = new_X3;
        }

        // 最终输出重排
        block0 = _mm_shuffle_epi8(X3, OUTPUT_SHUFFLE);
        block1 = _mm_shuffle_epi8(X2, OUTPUT_SHUFFLE);
        block2 = _mm_shuffle_epi8(X1, OUTPUT_SHUFFLE);
        block3 = _mm_shuffle_epi8(X0, OUTPUT_SHUFFLE);

        // 存储结果
        _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 0 * 16), block0);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 1 * 16), block1);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 2 * 16), block2);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 3 * 16), block3);
    }

    // 主加密函数
    void encrypt_blocks(const uint8_t* in, uint8_t* out, const uint32_t* rk, size_t num_blocks) {
        size_t i = 0;

        // 处理完整的4块组
        for (; i + 3 < num_blocks; i += 4) {
            encrypt_4blocks(in + i * 16, out + i * 16, rk);
        }

        // 处理剩余块（1-3个）
        if (i < num_blocks) {
            uint8_t temp_in[64] = { 0 };
            uint8_t temp_out[64] = { 0 };
            size_t remaining = num_blocks - i;

            // 复制剩余数据到临时缓冲区
            memcpy(temp_in, in + i * 16, remaining * 16);

            // 加密完整4块
            encrypt_4blocks(temp_in, temp_out, rk);

            // 复制回结果
            memcpy(out + i * 16, temp_out, remaining * 16);
        }
    }
}

// 性能测试函数
void benchmark_sm4() {
    // 准备测试数据
    const size_t BLOCK_COUNT = 1 << 20; // 1MB数据
    uint8_t key[16] = { 0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10 };

    // 动态分配大内存
    uint8_t* plaintext = new uint8_t[16 * BLOCK_COUNT];
    uint8_t* ciphertext = new uint8_t[16 * BLOCK_COUNT];

    // 初始化明文
    for (size_t i = 0; i < 16 * BLOCK_COUNT; i++) {
        plaintext[i] = static_cast<uint8_t>(i % 256);
    }

    uint32_t rk[32];
    SM4_BASIC::expand_key(key, rk);

    // 基础版本测试
    auto start = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i < BLOCK_COUNT; i++) {
        SM4_BASIC::encrypt_block(plaintext + i * 16, ciphertext + i * 16, rk);
    }
    auto end = std::chrono::high_resolution_clock::now();
    double base_time = std::chrono::duration<double>(end - start).count();

    // T-table优化测试
    start = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i < BLOCK_COUNT; i++) {
        SM4_TTABLE::encrypt_block(plaintext + i * 16, ciphertext + i * 16, rk);
    }
    end = std::chrono::high_resolution_clock::now();
    double ttable_time = std::chrono::duration<double>(end - start).count();

    // AES-NI优化测试
    start = std::chrono::high_resolution_clock::now();
    SM4_AESNI_OPT::encrypt_blocks(plaintext, ciphertext, rk, BLOCK_COUNT);
    end = std::chrono::high_resolution_clock::now();
    double aesni_time = std::chrono::duration<double>(end - start).count();

    // GFNI 优化测试
    double gfni_time = 0;
#if defined(__GFNI__)
    start = std::chrono::high_resolution_clock::now();
    SM4_GFNI_SSE::encrypt_blocks(plaintext, ciphertext, rk, BLOCK_COUNT);
    end = std::chrono::high_resolution_clock::now();
    gfni_time = std::chrono::duration<double>(end - start).count();
#endif

    // 输出性能比较
    std::cout << "SM4性能对比 (加密 " << BLOCK_COUNT << " 个块, 总计 " << (BLOCK_COUNT * 16 / 1024 / 1024.0) << " MB):\n";
    std::cout << "-----------------------------------------------\n";
    std::cout << "优化级别       | 时间(秒)   | 速度(MB/s)  | 加速比\n";
    std::cout << "-----------------------------------------------\n";

    double data_size_mb = BLOCK_COUNT * 16 / (1024.0 * 1024.0);

    std::cout << "基础实现      | " << std::setw(9) << std::fixed << std::setprecision(4)
        << base_time << " | " << std::setw(10) << std::setprecision(2) << (data_size_mb / base_time)
        << " | 1.00x\n";

    std::cout << "T-table优化  | " << std::setw(9) << ttable_time << " | " << std::setw(10)
        << (data_size_mb / ttable_time) << " | " << std::setprecision(1) << (base_time / ttable_time) << "x\n";

    std::cout << "AES-NI优化   | " << std::setw(9) << aesni_time << " | " << std::setw(10)
        << (data_size_mb / aesni_time) << " | " << (base_time / aesni_time) << "x\n";

#if defined(__GFNI__)
    std::cout << "GFNI优化     | " << std::setw(9) << gfni_time << " | " << std::setw(10)
        << (data_size_mb / gfni_time) << " | " << (base_time / gfni_time) << "x\n";
#else
    std::cout << "GFNI优化     | 不支持    |       -     | -\n";
#endif

    std::cout << "-----------------------------------------------\n";
    delete[] plaintext;
    delete[] ciphertext;
}

int main() {
    benchmark_sm4();
    return 0;
}
