import random
import time
import hashlib
from gmpy2 import mpz, powmod, invert
import numpy as np
import matplotlib.pyplot as plt
from concurrent.futures import ThreadPoolExecutor
 
# SM2椭圆曲线参数
P = mpz(0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF)
A = mpz(0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC)
B = mpz(0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93)
N = mpz(0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123)
Gx = mpz(0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7)
Gy = mpz(0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0)


class Point:
    __slots__ = ("x", "y", "z")

    def __init__(self, x=None, y=None, z=None):
        self.x = x
        self.y = y
        self.z = z or mpz(1)  # Jacobian坐标默认值

    def __str__(self):
        return f"Point({self.x}, {self.y}, {self.z})"

    def __eq__(self, other):
        if not other:
            return False
        if self.z == 1 and other.z == 1:
            return self.x == other.x and self.y == other.y
        # 转换为仿射坐标比较
        if self.is_infinity() and other.is_infinity():
            return True
        if self.is_infinity() or other.is_infinity():
            return False
        lhs = (self.x * other.z ** 2) % P
        rhs = (other.x * self.z ** 2) % P
        if lhs != rhs:
            return False
        lhs = (self.y * other.z ** 3) % P
        rhs = (other.y * self.z ** 3) % P
        return lhs == rhs

    def is_infinity(self):
        return self.x is None or self.y is None

    @classmethod
    def infinity(cls):
        return cls(None, None, None)

    @classmethod
    def base_point(cls):
        return cls(Gx, Gy, 1)


# ====================================================
# 基础实现 - 仿射坐标系
# ====================================================

def affine_add(p, q):
    """仿射坐标系点加运算"""
    if p.is_infinity(): return q
    if q.is_infinity(): return p
    if p.x == q.x:
        if p.y != q.y:  # P + (-P) = O
            return Point.infinity()
        return affine_double(p)

    # 斜率计算
    s = (q.y - p.y) * invert(q.x - p.x, P) % P
    x = (s ** 2 - p.x - q.x) % P
    y = (s * (p.x - x) - p.y) % P
    return Point(x, y)


def affine_double(p):
    """仿射坐标系倍点运算"""
    if p.is_infinity() or p.y == 0:
        return Point.infinity()

    # 斜率计算
    s = (3 * p.x ** 2 + A) * invert(2 * p.y, P) % P
    x = (s ** 2 - 2 * p.x) % P
    y = (s * (p.x - x) - p.y) % P
    return Point(x, y)


def affine_multiply(k, p):
    """仿射坐标系点乘 - 二进制展开法"""
    result = Point.infinity()
    current = Point(p.x, p.y, 1)
    while k:
        if k & 1:
            result = affine_add(result, current)
        current = affine_double(current)
        k >>= 1
    return result


# ====================================================
# Jacobian坐标系优化实现
# ====================================================

def jacobian_add(p, q):
    """Jacobian坐标系点加运算"""
    if p.is_infinity(): return q
    if q.is_infinity(): return p

    z1z1 = powmod(p.z, 2, P)
    z2z2 = powmod(q.z, 2, P)
    u1 = (p.x * z2z2) % P
    u2 = (q.x * z1z1) % P
    s1 = (p.y * q.z * z2z2) % P
    s2 = (q.y * p.z * z1z1) % P

    if u1 == u2:
        return jacobian_double(p) if s1 == s2 else Point.infinity()

    h = (u2 - u1) % P
    r = (s2 - s1) % P
    h2 = powmod(h, 2, P)
    h3 = (h * h2) % P
    t = (u1 * h2) % P

    x3 = (r ** 2 - h3 - 2 * t) % P
    y3 = (r * (t - x3) - s1 * h3) % P
    z3 = (h * p.z * q.z) % P

    return Point(x3, y3, z3)


def jacobian_double(p):
    """Jacobian坐标系倍点运算"""
    if p.is_infinity() or p.y == 0:
        return Point.infinity()

    ysq = powmod(p.y, 2, P)
    s = (4 * p.x * ysq) % P
    m = (3 * p.x ** 2 + A * powmod(p.z, 4, P)) % P

    x3 = (m ** 2 - 2 * s) % P
    y3 = (m * (s - x3) - 8 * powmod(ysq, 2, P)) % P
    z3 = (2 * p.y * p.z) % P

    return Point(x3, y3, z3)


def jacobian_multiply(k, p):
    """Jacobian坐标系点乘 - NAF方法"""
    k %= N
    if k == 0 or p.is_infinity():
        return Point.infinity()

    # 转换为NAF形式
    naf = []
    while k:
        k, r = divmod(k, 2)
        if r == 0:
            naf.append(0)
        else:
            t = r - 2 * (k & 1)
            naf.append(t)
            k -= k & 1

    result = Point.infinity()
    current = Point(p.x, p.y, p.z)
    for digit in reversed(naf):
        result = jacobian_double(result)
        if digit == 1:
            result = jacobian_add(result, current)
        elif digit == -1:
            # 负点加 (x, -y)
            neg_current = Point(current.x, -current.y % P, current.z)
            result = jacobian_add(result, neg_current)
    return result


def from_jacobian(p):
    """将Jacobian坐标转换为仿射坐标"""
    if p.is_infinity():
        return Point.infinity()
    zinv = invert(p.z, P)
    zinv2 = powmod(zinv, 2, P)
    zinv3 = (zinv2 * zinv) % P
    x = (p.x * zinv2) % P
    y = (p.y * zinv3) % P
    return Point(x, y, 1)


# ====================================================
# wNAF优化实现 (窗口非相邻形式)
# ====================================================

def compute_wnaf(k, w=5):
    """计算wNAF表示"""
    half_window = 1 << (w - 1)
    mask = (1 << w) - 1

    naf = []
    t = k
    while t:
        if t & 1:
            # 获取最低w位
            mod = t & mask
            if mod > half_window:
                mod -= (1 << w)
            naf.append(mod)
            t -= mod
        else:
            naf.append(0)
        t >>= 1
    return naf


def precompute_points(p, w):
    """预计算点用于wNAF"""
    base = p
    points = [base]

    for i in range(1, (1 << (w - 2))):
        points.append(jacobian_add(points[i - 1], base))

    return points


def wnaf_multiply(k, p, w=5):
    """wNAF点乘算法"""
    naf = compute_wnaf(k, w)
    precomputed = precompute_points(p, w)

    result = Point.infinity()
    for i in range(len(naf) - 1, -1, -1):
        digit = naf[i]
        result = jacobian_double(result)

        if digit > 0:
            result = jacobian_add(result, precomputed[(digit - 1) // 2])
        elif digit < 0:
            idx = (-digit - 1) // 2
            neg_p = Point(precomputed[idx].x, -precomputed[idx].y % P, precomputed[idx].z)
            result = jacobian_add(result, neg_p)

    return result


# ====================================================
# 混合坐标系优化实现
# ====================================================

def mixed_add(p_affine, p_jacobian):
    """混合坐标系点加 (仿射+Jacobian)"""
    if p_affine.is_infinity(): return p_jacobian
    if p_jacobian.is_infinity(): return Point(p_affine.x, p_affine.y, 1)

    z1z1 = powmod(p_jacobian.z, 2, P)
    u2 = (p_affine.x * z1z1) % P
    s2 = (p_affine.y * p_jacobian.z * z1z1) % P

    if p_jacobian.x == u2:
        if p_jacobian.y != s2:
            return Point.infinity()
        return jacobian_double(p_jacobian)

    h = (u2 - p_jacobian.x) % P
    r = (s2 - p_jacobian.y) % P
    h2 = powmod(h, 2, P)
    h3 = (h * h2) % P
    t = (p_jacobian.x * h2) % P

    x3 = (r ** 2 - h3 - 2 * t) % P
    y3 = (r * (t - x3) - p_jacobian.y * h3) % P
    z3 = (h * p_jacobian.z) % P

    return Point(x3, y3, z3)


def hybrid_multiply(k, p):
    """混合坐标系点乘 (wNAF+混合加法)"""
    w = 5
    naf = compute_wnaf(k, w)

    # 预计算点 (仿射坐标系)
    base_affine = Point(p.x, p.y, 1)
    precomputed_affine = [base_affine]
    current = base_affine
    for i in range(1, (1 << (w - 2))):
        current = affine_add(current, base_affine)
        precomputed_affine.append(current)

    result = Point.infinity()
    for digit in reversed(naf):
        result = jacobian_double(result)

        if digit != 0:
            idx = (abs(digit) - 1) // 2
            point_to_add = precomputed_affine[idx]
            if digit < 0:
                point_to_add = Point(point_to_add.x, -point_to_add.y % P, 1)
            result = mixed_add(point_to_add, result)

    return from_jacobian(result)


# ====================================================
# 并行优化实现
# ====================================================

def parallel_multiply(k, p, num_threads=4):
    """并行点乘 (多线程拆分任务)"""
    # 将标量拆分为多个部分
    bits = k.bit_length()
    chunks = []
    for i in range(num_threads):
        start_bit = bits * i // num_threads
        end_bit = bits * (i + 1) // num_threads
        mask = (1 << (end_bit - start_bit)) - 1
        chunk = (k >> start_bit) & mask
        chunks.append(chunk)

    # 预先计算 2^(start_bit) * P
    base_points = []
    current = Point(p.x, p.y, p.z)
    for i in range(num_threads):
        shift = bits * i // num_threads
        base_points.append(jacobian_multiply(1 << shift, current))

    # 并行计算每个部分
    results = []
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = []
        for i in range(num_threads):
            futures.append(executor.submit(jacobian_multiply, chunks[i], base_points[i]))
        for future in futures:
            results.append(future.result())

    # 合并结果
    result = Point.infinity()
    for res in results:
        result = jacobian_add(result, res)

    return from_jacobian(result)


# ====================================================
# SM2签名算法实现
# ====================================================

def hash_message(msg):
    """SM3哈希函数简化版本"""
    if not isinstance(msg, bytes):
        msg = str(msg).encode()
    return int(hashlib.sha256(msg).hexdigest(), 16) % N


def sm2_sign(msg, priv_key, method="base"):
    """SM2签名算法"""
    e = hash_message(msg)
    k = random.randint(1, N - 1)

    # 获取基点
    base_point = Point.base_point()

    # 根据指定方法进行点乘
    methods = {
        "base": affine_multiply,
        "jacobian": lambda k, p: from_jacobian(jacobian_multiply(k, p)),
        "wnaf": lambda k, p: from_jacobian(wnaf_multiply(k, p)),
        "hybrid": hybrid_multiply,
        "parallel": lambda k, p: parallel_multiply(k, p)
    }

    start = time.perf_counter_ns()
    p = methods[method](k, base_point)
    elapsed_time = time.perf_counter_ns() - start

    if p.is_infinity():
        return sm2_sign(msg, priv_key, method)  # 重新尝试

    r = (e + p.x) % N
    s = (invert(1 + priv_key, N) * (k - r * priv_key)) % N

    return (r, s), elapsed_time / 1e6  # 返回毫秒时间


def benchmark(msg_size=32, iterations=100):
    """性能测试函数"""
    # 生成测试数据
    msg = b'\xab' * msg_size
    priv_key = random.randint(1, N - 1)

    # 测试不同点乘算法的性能
    methods = ["base", "jacobian", "wnaf", "hybrid", "parallel"]
    times = {m: [] for m in methods}

    print(f"开始性能测试, 消息大小={msg_size}字节, 迭代次数={iterations}...")

    for i in range(iterations):
        for method in methods:
            _, elapsed = sm2_sign(msg, priv_key, method)
            times[method].append(elapsed)

    # 计算平均时间
    avg_times = {m: np.mean(times[m]) for m in methods}

    print("\n测试结果 (单次签名平均时间 ms):")
    for method in methods:
        print(f"{method.upper():<10}: {avg_times[method]:.6f} ms")

    # 计算相对于基础版本的加速比
    base_time = avg_times["base"]
    for method in methods[1:]:
        speedup = base_time / avg_times[method]
        print(f"{method.upper():<10} 相对于基础版本加速: {speedup:.2f}x")

    # 绘制结果
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.bar(methods, [avg_times[m] for m in methods])
    ax.set_xlabel("点乘算法")
    ax.set_ylabel("时间 (ms)")
    ax.set_title(f"SM2点乘算法性能比较 (平均{msg_size}字节消息)")
    plt.tight_layout()
    plt.savefig('sm2_performance.png')
    plt.show()

    return avg_times

# 添加字体配置
plt.rcParams['font.sans-serif'] = ['SimHei']  # 用来正常显示中文标签
plt.rcParams['axes.unicode_minus'] = False  # 用来正常显示负号

if __name__ == "__main__":
    # 验证点加和倍点运算
    base = Point.base_point()
    double_base = affine_double(base)
    two_base = affine_multiply(2, base)
    assert double_base == two_base, "点运算验证失败"

    # 性能测试
    sizes = [ 64, 1024, 4096]
    results = {method: [] for method in ["base", "jacobian", "hybrid"]}

    for size in sizes:
        print(f"Testing message size: {size} bytes")
        times = benchmark(size, 20)  # 每种方法测试20次以减少时间
        for method in results:
            results[method].append(times[method])

    # 生成一个可视化图 - 不同消息大小的性能对比
    plt.figure(figsize=(10, 6))
    for method in results:
        plt.plot(sizes, results[method], 'o-', linewidth=2, markersize=8, label=f"{method.upper()} method")

    plt.xlabel("消息大小 (字节)", fontsize=12)
    plt.ylabel("签名时间 (毫秒)", fontsize=12)
    plt.title("SM2签名性能与消息大小关系", fontsize=14)
    plt.xscale('log')
    plt.xticks(sizes, [str(s) for s in sizes])
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.legend(fontsize=10)
    plt.tight_layout()

    # 保存为英文文件名
    plt.savefig('sm2_performance_analysis.png', dpi=300)
    print("\n可视化图表已保存为 'sm2_performance_analysis.png'")