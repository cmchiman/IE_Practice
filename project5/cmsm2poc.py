import random
import hashlib
from math import ceil
from typing import Union
import time


# =====================================================================
# 常量定义与工具函数
# =====================================================================

def print_header(title):
    """打印美观的标题"""
    print("\n" + "=" * 80)
    print(f"| {title.center(76)} |")
    print("=" * 80)


def print_section(title):
    """打印小节标题"""
    print("\n" + "-" * 80)
    print(f"| {title}")
    print("-" * 80)


def format_hex(value, length=16):
    """格式化十六进制值"""
    hex_str = hex(value)[2:]
    if len(hex_str) > length * 2:
        return f"{hex_str[:length]}...{hex_str[-length:]}"
    return hex_str


# =====================================================================
# SM2椭圆曲线参数（国家标准）
# =====================================================================
print_header("SM2椭圆曲线加密算法实现")

P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0

# =====================================================================
# 椭圆曲线点类
# =====================================================================
print_section("椭圆曲线点实现")


class Point:
    """椭圆曲线点类，支持序列化和反序列化"""

    def __init__(self, x=None, y=None):
        self.x = x
        self.y = y

    def __str__(self):
        if self.x is None or self.y is None:
            return "Point(Infinity)"
        return f"Point({format_hex(self.x)}, {format_hex(self.y)})"

    def __repr__(self):
        return self.__str__()

    def __eq__(self, other):
        if not isinstance(other, Point):
            return False
        if self.is_infinity() and other.is_infinity():
            return True
        return self.x == other.x and self.y == other.y

    def is_infinity(self):
        return self.x is None or self.y is None

    def to_bytes(self):
        """将点序列化为字节格式 (04 || x || y)"""
        if self.is_infinity():
            return b'\x00' * 65
        return b'\x04' + self.x.to_bytes(32, 'big') + self.y.to_bytes(32, 'big')

    @classmethod
    def from_bytes(cls, data):
        """从字节反序列化点"""
        if len(data) != 65:
            raise ValueError("Invalid point data length")
        if data[0] == 4:  # 未压缩格式
            x = int.from_bytes(data[1:33], 'big')
            y = int.from_bytes(data[33:65], 'big')
            return cls(x, y)
        raise ValueError("Unsupported point format")


# 无穷远点
INFINITY = Point(None, None)
BASE_POINT = Point(Gx, Gy)

print(f"基点G: {BASE_POINT}")

# =====================================================================
# 椭圆曲线数学运算
# =====================================================================
print_section("椭圆曲线数学运算")


def mod_inv(a: int, modulus: int = P) -> int:
    """模逆运算（扩展欧几里得算法）"""
    if a == 0:
        return 0
    lm, hm = 1, 0
    low, high = a % modulus, modulus
    while low > 1:
        ratio = high // low
        nm = hm - lm * ratio
        new = high - low * ratio
        hm, lm = lm, nm
        high, low = low, new
    return lm % modulus


def point_add(p: Point, q: Point) -> Point:
    """椭圆曲线点加运算"""
    # 处理无穷远点
    if p.is_infinity():
        return q
    if q.is_infinity():
        return p

    # P + (-P) = 无穷远点
    if p.x == q.x and p.y != q.y:
        return INFINITY

    # 计算斜率λ
    if p.x == q.x:
        # 点相同 (倍点)
        lam = (3 * p.x * p.x + A) * mod_inv(2 * p.y, P) % P
    else:
        # 点不同
        lam = (q.y - p.y) * mod_inv(q.x - p.x, P) % P

    # 计算新点坐标
    x3 = (lam * lam - p.x - q.x) % P
    y3 = (lam * (p.x - x3) - p.y) % P

    return Point(x3, y3)


def point_double(p: Point) -> Point:
    """椭圆曲线倍点运算"""
    if p.is_infinity() or p.y == 0:
        return INFINITY

    lam = (3 * p.x * p.x + A) * mod_inv(2 * p.y) % P
    x3 = (lam * lam - 2 * p.x) % P
    y3 = (lam * (p.x - x3) - p.y) % P

    return Point(x3, y3)


def point_multiply(k: int, p: Point) -> Point:
    """椭圆曲线点乘（二进制展开法）"""
    # 处理特殊值
    if k % N == 0 or p.is_infinity():
        return INFINITY

    k = k % N
    if k == 0:
        return INFINITY

    result = INFINITY
    current = p

    # 使用二进制展开法
    while k:
        if k & 1:
            result = point_add(result, current)
        current = point_double(current)
        k >>= 1

    return result


# =====================================================================
# 密码学基础函数
# =====================================================================
print_section("密码学基础函数")


def sm3_hash(data: Union[bytes, str, int]) -> bytes:
    """SM3哈希函数实现（使用SHA-256作为替代）"""
    if isinstance(data, int):
        # 将整数转换为字节串，考虑零值情况
        if data == 0:
            data = b'\x00'
        else:
            data = data.to_bytes((data.bit_length() + 7) // 8, 'big')
    elif isinstance(data, str):
        data = data.encode('utf-8')
    elif not isinstance(data, bytes):
        raise TypeError(f"不支持的参数类型: {type(data)}")

    return hashlib.sha256(data).digest()


def kdf(z: bytes, klen: int) -> bytes:
    """密钥派生函数（KDF）实现"""
    ct = 0x00000001
    h = b''

    for i in range(ceil(klen / 32)):
        # 组合数据: z || ct
        data = z + ct.to_bytes(4, 'big')
        h += hashlib.sha256(data).digest()
        ct += 1

    return h[:klen]


def calculate_za(user_id: Union[bytes, str, int], pub_key: Point) -> bytes:
    """计算SM2的ZA值，支持多种数据类型"""
    # 转换user_id为字节类型
    if isinstance(user_id, int):
        # 将整数转换为字节串，考虑零值情况
        if user_id == 0:
            user_id_bytes = b'\x00'
        else:
            user_id_bytes = user_id.to_bytes((user_id.bit_length() + 7) // 8, 'big')
    elif isinstance(user_id, str):
        user_id_bytes = user_id.encode('utf-8')
    elif isinstance(user_id, bytes):
        user_id_bytes = user_id
    else:
        raise TypeError(f"不支持的user_id类型: {type(user_id)}")

    # 计算ENTLA（用户ID长度的比特数）
    entla = len(user_id_bytes) * 8
    entla_bytes = entla.to_bytes(2, 'big')

    # 准备数据: ENTLA || ID_A || a || b || x_G || y_G || x_A || y_A
    data = entla_bytes
    data += user_id_bytes
    data += A.to_bytes(32, 'big')
    data += B.to_bytes(32, 'big')
    data += Gx.to_bytes(32, 'big')
    data += Gy.to_bytes(32, 'big')
    data += pub_key.x.to_bytes(32, 'big')
    data += pub_key.y.to_bytes(32, 'big')

    # 计算哈希值
    return sm3_hash(data)


# =====================================================================
# SM2核心算法实现
# =====================================================================
print_section("SM2核心算法实现")


def sm2_keygen() -> tuple[int, Point]:
    """生成SM2密钥对"""
    print("> 生成SM2密钥对...")
    start_time = time.time()

    private_key = random.SystemRandom().randint(1, N - 1)
    public_key = point_multiply(private_key, BASE_POINT)

    end_time = time.time()
    print(f"  私钥: {format_hex(private_key)}")
    print(f"  公钥: {public_key}")
    print(f"  生成时间: {(end_time - start_time) * 1000:.2f} ms")

    return private_key, public_key


def sm2_sign(private_key: int, msg: Union[bytes, str],
             user_id: Union[bytes, str, int] = b'user_id',
             k: int = None) -> tuple[tuple[int, int], int]:
    """SM2签名算法，支持多种数据类型输入"""
    start_time = time.time()
    print(f"\n> 签名消息: {msg[:20] if isinstance(msg, str) else msg[:20].decode('utf-8', 'ignore')}...")

    # 计算公钥
    public_key = point_multiply(private_key, BASE_POINT)

    # 计算ZA
    za = calculate_za(user_id, public_key)

    # 准备消息
    if isinstance(msg, str):
        msg_bytes = msg.encode('utf-8')
    else:
        msg_bytes = msg

    # 计算消息摘要
    m_hat = za + msg_bytes
    e_bytes = sm3_hash(m_hat)
    e = int.from_bytes(e_bytes, 'big') % N

    # 签名过程
    attempt = 0
    while attempt < 10:  # 防止无限循环
        attempt += 1

        # 生成或使用指定的k值
        if k is None:
            k_val = random.SystemRandom().randint(1, N - 1)
        else:
            k_val = k
            k = None  # 仅使用一次指定的k值

        # 计算kG
        kG = point_multiply(k_val, BASE_POINT)
        if kG.is_infinity():
            continue

        # 计算r = (e + x1) mod n
        r = (e + kG.x) % N
        if r == 0 or r + k_val == N:
            continue

        # 计算s = (1+dA)^-1 * (k - r*dA) mod n
        s = mod_inv(1 + private_key, N) * (k_val - r * private_key) % N
        if s == 0:
            continue

        end_time = time.time()
        print(f"  签名(r): {format_hex(r)}")
        print(f"  签名(s): {format_hex(s)}")
        print(f"  使用的k值: {format_hex(k_val)}")
        print(f"  签名时间: {(end_time - start_time) * 1000:.2f} ms")
        return (r, s), k_val

    raise RuntimeError("签名生成失败: 超过最大尝试次数")


def sm2_verify(public_key: Point, msg: Union[bytes, str],
               signature: tuple[int, int],
               user_id: Union[bytes, str, int] = b'user_id') -> bool:
    """SM2签名验证"""
    start_time = time.time()
    r, s = signature
    print(f"\n> 验证签名: r={format_hex(r)}, s={format_hex(s)}")

    # 验证签名值范围
    if not (1 <= r <= N - 1) or not (1 <= s <= N - 1):
        print("  验证失败: 签名值超出范围")
        return False

    # 计算ZA
    za = calculate_za(user_id, public_key)

    # 准备消息
    if isinstance(msg, str):
        msg_bytes = msg.encode('utf-8')
    else:
        msg_bytes = msg

    # 计算消息摘要
    m_hat = za + msg_bytes
    e_bytes = sm3_hash(m_hat)
    e = int.from_bytes(e_bytes, 'big') % N

    # 计算t = (r + s) mod n
    t = (r + s) % N
    if t == 0:
        print("  验证失败: t值为0")
        return False

    # 计算sG + tP
    sG = point_multiply(s, BASE_POINT)
    tP = point_multiply(t, public_key)
    x1y1 = point_add(sG, tP)

    if x1y1.is_infinity():
        print("  验证失败: 计算结果为无穷远点")
        return False

    # 计算R = (e + x1) mod n
    R = (e + x1y1.x) % N

    end_time = time.time()
    if R == r:
        print(f"  验证成功: R={format_hex(R)} 匹配 r={format_hex(r)}")
        print(f"  验证时间: {(end_time - start_time) * 1000:.2f} ms")
        return True
    else:
        print(f"  验证失败: R={format_hex(R)} 不匹配 r={format_hex(r)}")
        return False


# =====================================================================
# 安全漏洞PoC验证
# =====================================================================
print_section("安全漏洞PoC验证")


def leak_k_attack(signature: tuple[int, int], k: int) -> int:
    """利用泄露的k恢复私钥"""
    print("\n> k值泄露攻击")
    r, s = signature
    print(f"  签名(r): {format_hex(r)}")
    print(f"  签名(s): {format_hex(s)}")
    print(f"  泄露的k值: {format_hex(k)}")

    # 公式: d = (k - s) * (r + s)^-1 mod n
    denominator = (r + s) % N
    if denominator == 0:
        print("  攻击失败: 分母为0")
        return 0

    d = (k - s) * mod_inv(denominator, N) % N
    print(f"  恢复的私钥: {format_hex(d)}")
    return d


def reuse_k_attack(signature1: tuple[int, int], signature2: tuple[int, int]) -> int:
    """利用同一用户对两个消息使用相同k值进行攻击"""
    print("\n> 同一用户k值重用攻击")
    r1, s1 = signature1
    r2, s2 = signature2
    print(f"  签名1(r): {format_hex(r1)}, s={format_hex(s1)}")
    print(f"  签名2(r): {format_hex(r2)}, s={format_hex(s2)}")

    # 公式: d = (s2 - s1) * (s1 - s2 + r1 - r2)^-1 mod n
    numerator = (s2 - s1) % N
    denominator = (s1 - s2 + r1 - r2) % N

    if denominator == 0:
        print("  攻击失败: 分母为0")
        return 0

    d = numerator * mod_inv(denominator, N) % N
    print(f"  恢复的私钥: {format_hex(d)}")
    return d


def cross_user_reuse_k_attack(signatureA: tuple[int, int], signatureB: tuple[int, int],
                              public_keyA: Point, public_keyB: Point) -> int:
    """利用不同用户使用相同k值进行攻击"""
    print("\n> 不同用户k值重用攻击")
    rA, sA = signatureA
    rB, sB = signatureB
    print(f"  用户A签名(r): {format_hex(rA)}, s={format_hex(sA)}")
    print(f"  用户B签名(r): {format_hex(rB)}, s={format_hex(sB)}")

    # 计算点kG
    sG_A = point_multiply(sA, BASE_POINT)
    tA = (rA + sA) % N
    tP_A = point_multiply(tA, public_keyA)
    kG_A = point_add(sG_A, tP_A)

    sG_B = point_multiply(sB, BASE_POINT)
    tB = (rB + sB) % N
    tP_B = point_multiply(tB, public_keyB)
    kG_B = point_add(sG_B, tP_B)

    # 验证相同的k值
    if kG_A != kG_B:
        print("  攻击失败: kG点不匹配")
        return 0

    print(f"  恢复的kG.x: {format_hex(kG_A.x)}")
    return kG_A.x


def sm2_ecdsa_sign(private_key: int, msg: Union[bytes, str], k: int = None) -> tuple[tuple[int, int], int]:
    """ECDSA签名算法（用于对比攻击）"""
    print(f"\n> ECDSA签名: {msg[:20] if isinstance(msg, str) else msg[:20].decode('utf-8', 'ignore')}...")

    # 准备消息
    if isinstance(msg, str):
        msg_bytes = msg.encode('utf-8')
    else:
        msg_bytes = msg

    # 计算消息摘要
    e_bytes = hashlib.sha256(msg_bytes).digest()
    e = int.from_bytes(e_bytes, 'big') % N

    # 生成或使用指定的k值
    if k is None:
        k_val = random.SystemRandom().randint(1, N - 1)
    else:
        k_val = k

    # 计算kG
    kG = point_multiply(k_val, BASE_POINT)
    if kG.is_infinity():
        raise ValueError("kG为无穷远点")

    # 计算r = x1 mod n
    r = kG.x % N
    if r == 0:
        raise ValueError("r值为0")

    # 计算s = k^-1 * (e + d*r) mod n
    s = mod_inv(k_val, N) * (e + private_key * r) % N
    if s == 0:
        raise ValueError("s值为0")

    print(f"  签名(r): {format_hex(r)}")
    print(f"  签名(s): {format_hex(s)}")
    return (r, s), k_val


def sm2_ecdsa_reuse_k_attack(sm2_sig: tuple[int, int], ecdsa_sig: tuple[int, int], e: int) -> int:
    """利用SM2和ECDSA间重用k值进行攻击"""
    print("\n> SM2-ECDSA k值重用攻击")
    r_sm2, s_sm2 = sm2_sig
    r_ecdsa, s_ecdsa = ecdsa_sig
    print(f"  SM2签名(r): {format_hex(r_sm2)}, s={format_hex(s_sm2)}")
    print(f"  ECDSA签名(r): {format_hex(r_ecdsa)}, s={format_hex(s_ecdsa)}")
    print(f"  消息摘要(e): {format_hex(e)}")

    # 公式: d = (s_ecdsa * s_sm2 - e) * (r_ecdsa - s_ecdsa * s_sm2 - s_ecdsa * r_sm2)^-1 mod n
    numerator = (s_ecdsa * s_sm2 - e) % N
    denominator = (r_ecdsa - s_ecdsa * s_sm2 - s_ecdsa * r_sm2) % N

    if denominator == 0:
        print("  攻击失败: 分母为0")
        return 0

    d = numerator * mod_inv(denominator, N) % N
    print(f"  恢复的私钥: {format_hex(d)}")
    return d


# =====================================================================
# 主测试函数
# =====================================================================
print_header("测试演示")


def run_sm2_tests():
    """运行所有SM2测试用例"""
    # 1. 基础功能测试
    print_section("SM2基础功能测试")
    private_key, public_key = sm2_keygen()

    # 测试不同消息类型
    test_messages = [
        b"Binary message",
        "String message",
        123456  # 整数消息
    ]

    for msg in test_messages:
        # 测试不同user_id类型
        for user_id in [b"user_id", "string_id", 123]:
            try:
                print(f"\n测试消息: {msg} (类型: {type(msg).__name__})")
                print(f"用户ID: {user_id} (类型: {type(user_id).__name__})")

                signature, k = sm2_sign(private_key, msg, user_id)
                valid = sm2_verify(public_key, msg, signature, user_id)

                if valid:
                    print("✅ 签名验证成功")
                else:
                    print("❌ 签名验证失败")
            except Exception as e:
                print(f"⚠️ 测试失败: {str(e)}")

    # 2. 安全漏洞PoC测试
    print_section("安全漏洞PoC验证")

    # 2.1 k值泄露攻击
    print("\n[测试2.1] k值泄露攻击")
    msg = b"Test message for k-leak attack"
    signature, k = sm2_sign(private_key, msg)
    recovered_private_key = leak_k_attack(signature, k)

    if private_key == recovered_private_key:
        print("✅ 私钥恢复成功")
    else:
        print("❌ 私钥恢复失败")
        print(f"原始私钥: {format_hex(private_key)}")
        print(f"恢复私钥: {format_hex(recovered_private_key)}")

    # 2.2 同一用户k值重用攻击
    print("\n[测试2.2] 同一用户k值重用攻击")
    k_fixed = random.SystemRandom().randint(1, N - 1)
    msg1 = b"First message with reused k"
    signature1, _ = sm2_sign(private_key, msg1, k=k_fixed)
    msg2 = b"Second message with reused k"
    signature2, _ = sm2_sign(private_key, msg2, k=k_fixed)
    recovered_private_key = reuse_k_attack(signature1, signature2)

    if private_key == recovered_private_key:
        print("✅ 私钥恢复成功")
    else:
        print("❌ 私钥恢复失败")
        print(f"原始私钥: {format_hex(private_key)}")
        print(f"恢复私钥: {format_hex(recovered_private_key)}")

    # 2.3 不同用户k值重用攻击
    print("\n[测试2.3] 不同用户k值重用攻击")
    private_keyA, public_keyA = sm2_keygen()
    private_keyB, public_keyB = sm2_keygen()
    k_shared = random.SystemRandom().randint(1, N - 1)
    msgA = b"User A's message"
    signatureA, _ = sm2_sign(private_keyA, msgA, k=k_shared)
    msgB = b"User B's message"
    signatureB, _ = sm2_sign(private_keyB, msgB, k=k_shared)
    recovered_kx = cross_user_reuse_k_attack(signatureA, signatureB, public_keyA, public_keyB)
    actual_kG = point_multiply(k_shared, BASE_POINT)

    if recovered_kx == actual_kG.x:
        print("✅ kG.x恢复成功")
    else:
        print("❌ kG.x恢复失败")
        print(f"实际kG.x: {format_hex(actual_kG.x)}")
        print(f"恢复kG.x: {format_hex(recovered_kx)}")

    # 2.4 SM2与ECDSA间k值重用攻击
    print("\n[测试2.4] SM2与ECDSA间k值重用攻击")
    k_shared = random.SystemRandom().randint(1, N - 1)
    msg_sm2 = b"Message for SM2 signature"
    sm2_sig, _ = sm2_sign(private_key, msg_sm2, k=k_shared)
    msg_ecdsa = b"Message for ECDSA signature"
    e = int.from_bytes(hashlib.sha256(msg_ecdsa).digest(), 'big') % N
    ecdsa_sig, _ = sm2_ecdsa_sign(private_key, msg_ecdsa, k_shared)
    recovered_private_key = sm2_ecdsa_reuse_k_attack(sm2_sig, ecdsa_sig, e)

    if private_key == recovered_private_key:
        print("✅ 私钥恢复成功")
    else:
        print("❌ 私钥恢复失败")
        print(f"原始私钥: {format_hex(private_key)}")
        print(f"恢复私钥: {format_hex(recovered_private_key)}")

    print_header("所有测试完成")


if __name__ == "__main__":
    run_sm2_tests()