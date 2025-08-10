#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <vector>
#include <algorithm>
#include <string>
#include <cstring>
#include <queue>
#include <chrono>
#include <memory>
#include <immintrin.h>

namespace sm3 {
    // SM3哈希算法实现
    constexpr uint32_t IV[8] = {
        0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
        0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
    };

    inline uint32_t LeftRotate(uint32_t x, int n) {
        return (x << n) | (x >> (32 - n));
    }

    inline uint32_t P0(uint32_t x) {
        return x ^ LeftRotate(x, 9) ^ LeftRotate(x, 17);
    }

    inline uint32_t P1(uint32_t x) {
        return x ^ LeftRotate(x, 15) ^ LeftRotate(x, 23);
    }

    inline uint32_t T(int j) {
        return (j < 16) ? 0x79CC4519 : 0x7A879D8A;
    }

    inline uint32_t FF(uint32_t x, uint32_t y, uint32_t z, int j) {
        return (j < 16) ? (x ^ y ^ z) : ((x & y) | (x & z) | (y & z));
    }

    inline uint32_t GG(uint32_t x, uint32_t y, uint32_t z, int j) {
        return (j < 16) ? (x ^ y ^ z) : ((x & y) | ((~x) & z));
    }

    void MessageExpand(const uint8_t block[64], uint32_t W[68], uint32_t W1[64]) {
        for (int i = 0; i < 16; ++i) {
            W[i] = static_cast<uint32_t>(block[i * 4]) << 24 |
                static_cast<uint32_t>(block[i * 4 + 1]) << 16 |
                static_cast<uint32_t>(block[i * 4 + 2]) << 8 |
                static_cast<uint32_t>(block[i * 4 + 3]);
        }

        for (int j = 16; j < 68; ++j) {
            W[j] = P1(W[j - 16] ^ W[j - 9] ^ LeftRotate(W[j - 3], 15)) ^
                LeftRotate(W[j - 13], 7) ^ W[j - 6];
        }

        for (int j = 0; j < 64; ++j) {
            W1[j] = W[j] ^ W[j + 4];
        }
    }

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

        state[0] ^= A; state[1] ^= B; state[2] ^= C; state[3] ^= D;
        state[4] ^= E; state[5] ^= F; state[6] ^= G; state[7] ^= H;
    }

    void SM3Hash(const uint8_t* data, uint64_t len, uint8_t hash[32]) {
        uint32_t state[8];
        std::memcpy(state, IV, sizeof(IV));

        uint64_t block_count = len / 64;
        for (uint64_t i = 0; i < block_count; ++i) {
            Compress(state, data + i * 64);
        }

        uint8_t last_block[64] = { 0 };
        uint64_t remaining = len % 64;
        std::memcpy(last_block, data + block_count * 64, remaining);

        last_block[remaining] = 0x80;
        if (remaining < 56) {
            uint64_t bit_len = len * 8;
            for (int i = 0; i < 8; ++i) {
                last_block[63 - i] = static_cast<uint8_t>(bit_len >> (i * 8));
            }
            Compress(state, last_block);
        }
        else {
            Compress(state, last_block);
            uint8_t pad_block[64] = { 0 };
            uint64_t bit_len = len * 8;
            for (int i = 0; i < 8; ++i) {
                pad_block[63 - i] = static_cast<uint8_t>(bit_len >> (i * 8));
            }
            Compress(state, pad_block);
        }

        for (int i = 0; i < 8; ++i) {
            hash[i * 4] = static_cast<uint8_t>(state[i] >> 24);
            hash[i * 4 + 1] = static_cast<uint8_t>(state[i] >> 16);
            hash[i * 4 + 2] = static_cast<uint8_t>(state[i] >> 8);
            hash[i * 4 + 3] = static_cast<uint8_t>(state[i]);
        }
    }

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

class MerkleTree {
private:
    struct Node {
        std::string hash;
        std::unique_ptr<Node> left;
        std::unique_ptr<Node> right;
        Node* parent;
        bool is_leaf;
        std::string data;

        Node(const std::string& h,
            std::unique_ptr<Node> l = nullptr,
            std::unique_ptr<Node> r = nullptr,
            Node* p = nullptr,
            bool leaf = false,
            const std::string& d = "")
            : hash(h),
            left(std::move(l)),
            right(std::move(r)),
            parent(p),
            is_leaf(leaf),
            data(d) {}
    };

    std::unique_ptr<Node> root;
    std::vector<Node*> leaves;
    std::vector<std::string> leaf_data;

    // 高效构建Merkle树
    void buildTree() {
        if (leaves.empty()) {
            root = nullptr;
            return;
        }

        std::vector<Node*> current_level;
        for (auto& leaf : leaves) {
            current_level.push_back(leaf);
        }

        while (current_level.size() > 1) {
            std::vector<Node*> next_level;
            for (size_t i = 0; i < current_level.size(); i += 2) {
                Node* left_node = current_level[i];
                Node* right_node = nullptr;

                if (i + 1 < current_level.size()) {
                    right_node = current_level[i + 1];
                }
                else {
                    // 创建独立副本节点防止双重删除
                    right_node = new Node(left_node->hash,
                        nullptr,
                        nullptr,
                        nullptr,
                        left_node->is_leaf,
                        left_node->data);
                }

                std::string left_bytes = hexToBytes(left_node->hash);
                std::string right_bytes = hexToBytes(right_node->hash);
                std::string concat = "\x01" + left_bytes + right_bytes;
                std::string new_hash = sm3::SM3(concat);

                // 创建父节点并转移子节点所有权
                auto parent = std::make_unique<Node>(
                    new_hash,
                    std::unique_ptr<Node>(left_node),
                    std::unique_ptr<Node>(right_node)
                    );

                // 设置父指针
                if (parent->left) parent->left->parent = parent.get();
                if (parent->right) parent->right->parent = parent.get();

                Node* parent_raw = parent.get();
                next_level.push_back(parent_raw);

                // 临时释放所有权，由下一轮管理
                parent.release();
            }

            // 转移所有权到当前层
            current_level.clear();
            for (auto& node : next_level) {
                current_level.push_back(node);
            }
        }

        // 设置根节点所有权
        root = std::unique_ptr<Node>(current_level[0]);
    }

    // 十六进制转字节
    static std::string hexToBytes(const std::string& hex) {
        if (hex.empty()) return "";
        std::string bytes;
        bytes.reserve(hex.length() / 2);
        for (size_t i = 0; i < hex.length(); i += 2) {
            std::string byteString = hex.substr(i, 2);
            char byte = static_cast<char>(std::stoi(byteString, nullptr, 16));
            bytes.push_back(byte);
        }
        return bytes;
    }

public:
    MerkleTree(const std::vector<std::string>& data) {
        leaf_data = data;
        std::sort(leaf_data.begin(), leaf_data.end());

        // 创建叶子节点
        std::vector<std::unique_ptr<Node>> leaf_owners;
        for (const auto& d : leaf_data) {
            std::string leaf_hash = sm3::SM3("\x00" + d);
            auto leaf = std::make_unique<Node>(
                leaf_hash, nullptr, nullptr, nullptr, true, d
                );
            leaves.push_back(leaf.get());
            leaf_owners.push_back(std::move(leaf));
        }
        buildTree();

        // 转移所有权
        for (auto& leaf : leaf_owners) {
            leaf.release();
        }
    }

    ~MerkleTree() = default;

    std::string getRootHash() const {
        return root ? root->hash : "";
    }

    const std::vector<std::string>& getLeafData() const {
        return leaf_data;
    }

    // 存在性证明结构
    struct ProofStep {
        std::string hash;
        bool is_left; // 是否为左节点
    };

    // 存在性证明
    std::vector<ProofStep> getExistenceProof(const std::string& data) {
        std::vector<ProofStep> proof;
        auto it = std::lower_bound(leaf_data.begin(), leaf_data.end(), data);
        if (it == leaf_data.end() || *it != data) return proof;

        Node* leaf = leaves[it - leaf_data.begin()];
        Node* current = leaf;
        while (current != root.get()) {
            Node* parent = current->parent;
            if (!parent) break;

            if (parent->left.get() == current) {
                if (parent->right) {
                    proof.push_back({ parent->right->hash, false });
                }
            }
            else {
                if (parent->left) {
                    proof.push_back({ parent->left->hash, true });
                }
            }
            current = parent;
        }
        return proof;
    }

    // 不存在性证明结构
    struct NonExistenceProof {
        std::vector<std::string> all_leaves;
        std::vector<ProofStep> proof_predecessor;
        std::vector<ProofStep> proof_successor;
    };

    // 不存在性证明
    NonExistenceProof getNonExistenceProof(const std::string& data) {
        NonExistenceProof proof;
        proof.all_leaves = leaf_data;

        auto it = std::lower_bound(leaf_data.begin(), leaf_data.end(), data);
        if (it != leaf_data.begin()) {
            std::string predecessor = *(it - 1);
            proof.proof_predecessor = getExistenceProof(predecessor);
        }
        if (it != leaf_data.end()) {
            std::string successor = *it;
            proof.proof_successor = getExistenceProof(successor);
        }
        return proof;
    }

    // 验证存在性证明
    static bool verifyExistenceProof(
        const std::string& root_hash,
        const std::string& data,
        const std::vector<ProofStep>& proof
    ) {
        std::string current = sm3::SM3("\x00" + data);
        for (const auto& step : proof) {
            std::string left_bytes = step.is_left ? hexToBytes(step.hash) : hexToBytes(current);
            std::string right_bytes = step.is_left ? hexToBytes(current) : hexToBytes(step.hash);
            std::string concat = "\x01" + left_bytes + right_bytes;
            current = sm3::SM3(concat);
        }
        return current == root_hash;
    }

    // 验证不存在性证明
    static bool verifyNonExistenceProof(
        const std::string& root_hash,
        const std::string& data,
        const NonExistenceProof& proof
    ) {
        // 验证数据不在叶子节点中
        if (std::binary_search(proof.all_leaves.begin(), proof.all_leaves.end(), data)) {
            return false;
        }

        // 重新构建Merkle树并验证根哈希
        MerkleTree temp_tree(proof.all_leaves);
        if (temp_tree.getRootHash() != root_hash) {
            return false;
        }

        // 验证前驱和后继的存在性及顺序
        auto it = std::lower_bound(proof.all_leaves.begin(), proof.all_leaves.end(), data);
        if (it != proof.all_leaves.begin()) {
            std::string predecessor = *(it - 1);
            if (!verifyExistenceProof(root_hash, predecessor, proof.proof_predecessor)) {
                return false;
            }
            if (predecessor >= data) return false;
        }
        if (it != proof.all_leaves.end()) {
            std::string successor = *it;
            if (!verifyExistenceProof(root_hash, successor, proof.proof_successor)) {
                return false;
            }
            if (successor <= data) return false;
        }
        return true;
    }
};

// 生成随机字符串
std::string random_string(size_t length) {
    auto randchar = []() -> char {
        const char charset[] =
            "0123456789"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz";
        const size_t max_index = (sizeof(charset) - 1);
        return charset[rand() % max_index];
    };
    std::string str(length, 0);
    std::generate_n(str.begin(), length, randchar);
    return str;
}

int main() {
    using namespace std::chrono;
    const int LEAF_COUNT = 100000;

    // 1. 生成10万随机字符串
    std::vector<std::string> data;
    srand(time(nullptr));
    for (int i = 0; i < LEAF_COUNT; ++i) {
        data.push_back(random_string(20));
    }

    // 2. 构建Merkle树并计时
    auto start_build = high_resolution_clock::now();
    MerkleTree tree(data);
    auto end_build = high_resolution_clock::now();
    auto build_time = duration_cast<milliseconds>(end_build - start_build).count();
    std::cout << "构建" << LEAF_COUNT << "个叶子节点的Merkle树耗时: "
        << build_time << " ms\n";
    std::cout << "Merkle Root: " << tree.getRootHash().substr(0, 12)
        << "..." << tree.getRootHash().substr(52, 12) << "\n\n";

    // 3. 存在性证明测试
    std::string target = data[data.size() / 2]; // 选择中间节点测试
    auto start_exist = high_resolution_clock::now();
    auto existence_proof = tree.getExistenceProof(target);
    auto end_exist = high_resolution_clock::now();
    auto exist_time = duration_cast<microseconds>(end_exist - start_exist).count();

    bool is_verified = MerkleTree::verifyExistenceProof(
        tree.getRootHash(), target, existence_proof
    );
    std::cout << "存在性证明验证: " << (is_verified ? "成功" : "失败")
        << " | 耗时: " << exist_time << " μs\n";
    std::cout << "证明路径长度: " << existence_proof.size() << " 个节点\n\n";

    // 4. 不存在性证明测试
    std::string non_target = "ThisDataCertainlyDoesNotExistInTheTree";
    auto start_non_exist = high_resolution_clock::now();
    auto non_existence_proof = tree.getNonExistenceProof(non_target);
    auto end_non_exist = high_resolution_clock::now();
    auto non_exist_time = duration_cast<milliseconds>(end_non_exist - start_non_exist).count();

    bool is_non_verified = MerkleTree::verifyNonExistenceProof(
        tree.getRootHash(), non_target, non_existence_proof
    );
    std::cout << "不存在性证明验证: " << (is_non_verified ? "成功" : "失败")
        << " | 耗时: " << non_exist_time << " ms\n";
    std::cout << "证明包含叶子数: " << non_existence_proof.all_leaves.size() << "\n";

    return 0;
}