import ecdsa
import random
import hashlib
from ecdsa.ecdsa import Public_key
from ecdsa import curves, ellipticcurve
import phe  # Paillier同态加密库
 
# 选择NIST P-256曲线
CURVE = curves.NIST256p
G = CURVE.generator  # 生成元
ORDER = CURVE.order  # 曲线阶
BASELEN = CURVE.baselen  # 基础长度（字节）


class Party:
    def __init__(self, items):
        """
        初始化参与方
        P1: items = [id1, id2, ...] (标识符列表)
        P2: items = [(id1, value1), (id2, value2), ...] (标识符-值对)
        """
        self.items = items


def ddh_intersection_sum(p1, p2):
    """
    实现Figure 2中的Private Intersection-Sum协议
    返回交集关联值的和
    """
    # ===== 1. 参数设置 =====
    n = ORDER  # 曲线阶

    # ===== 2. Setup阶段 =====
    # P2生成Paillier密钥对
    public_key, private_key = phe.generate_paillier_keypair(n_length=1024)

    # 双方生成椭圆曲线私钥
    k1 = random.randint(1, n - 1)  # P1私钥
    k2 = random.randint(1, n - 1)  # P2私钥

    # ===== 3. Round 1 (P1 → P2) =====
    p1_to_p2 = []  # P1发送给P2的数据

    for identifier in p1.items:
        # 将标识符哈希到曲线上的点
        H_point = _hash_to_point(identifier)

        # 计算点乘: H(identifier)^k1
        k1H_point = _scalar_multiply(H_point, k1)

        # 将点转换为字节形式进行传输
        p1_to_p2.append(point_to_bytes(k1H_point))

    # ===== 4. Round 2 (P2 → P1) =====
    # 4.1 计算Z = {H(v_i)^k1k₂}
    z_set = []  # 交集测试集

    for point_bytes in p1_to_p2:
        # 将字节反序列化为点
        point = bytes_to_point(point_bytes)

        # 计算点乘: (H(v_i)^k1)^k₂
        k1k2_point = _scalar_multiply(point, k2)
        z_set.append(point_to_bytes(k1k2_point))

    # 4.2 计算P2的集合: (H(w_j)^k₂, Enc(t_j))
    p2_to_p1_set = []  # P2发送给P1的数据

    for identifier, value in p2.items:
        # 计算H(w_j)^k₂
        H_point = _hash_to_point(identifier)
        k2H_point = _scalar_multiply(H_point, k2)

        # 加密关联值
        enc_value = public_key.encrypt(value)

        # 存储点和加密值
        p2_to_p1_set.append((point_to_bytes(k2H_point), enc_value))

    # 打乱顺序发送
    random.shuffle(z_set)
    random.shuffle(p2_to_p1_set)

    # ===== 5. Round 3 (P1) =====
    # 5.1 计算交集
    intersection_sum = public_key.encrypt(0)  # 初始化为加密的0

    # 优化：创建z_set的哈希索引
    z_index = set(z_set)

    for k2H_point_bytes, enc_value in p2_to_p1_set:
        # 计算H(w_j)^k1k₂
        k2H_point = bytes_to_point(k2H_point_bytes)
        k1k2_point = point_to_bytes(_scalar_multiply(k2H_point, k1))

        # 检查是否在Z集合中
        if k1k2_point in z_index:
            # 同态加法
            intersection_sum += enc_value

    # ===== 6. Output (P2) =====
    return private_key.decrypt(intersection_sum)


# ===== 椭圆曲线辅助函数 =====
def _hash_to_point(identifier):
    """将标识符哈希到椭圆曲线点"""
    # 使用SHA256哈希标识符
    h = hashlib.sha256(identifier.encode('utf-8')).digest()

    # 将哈希结果转换为整数
    secret_int = int.from_bytes(h, 'big') % ORDER

    # 使用这个整数作为私钥生成点
    return _scalar_multiply(G, secret_int)


def _scalar_multiply(point, scalar):
    """标量乘法：计算 scalar * point"""
    # 使用椭圆曲线库的乘法
    return scalar * point


def point_to_bytes(point):
    """将椭圆曲线点转换为字节字符串（未压缩格式）"""
    # 未压缩格式：04 + x + y
    x = int(point.x())
    y = int(point.y())

    # 确保坐标值有正确的长度
    x_bytes = x.to_bytes(BASELEN, 'big')
    y_bytes = y.to_bytes(BASELEN, 'big')

    return b'\x04' + x_bytes + y_bytes


def bytes_to_point(point_bytes):
    """将字节字符串转换为椭圆曲线点"""
    # 检查格式：第一个字节应为0x04（未压缩点）
    if point_bytes[0] != 0x04:
        raise ValueError("仅支持未压缩点格式")

    # 提取坐标
    x_bytes = point_bytes[1:1 + BASELEN]
    y_bytes = point_bytes[1 + BASELEN:1 + 2 * BASELEN]

    x = int.from_bytes(x_bytes, 'big')
    y = int.from_bytes(y_bytes, 'big')

    # 创建点对象
    return ellipticcurve.Point(CURVE.curve, x, y, ORDER)


# ===== 测试用例 =====
if __name__ == "__main__":
    # 创建测试数据
    p1 = Party(["user1", "user2", "user3", "user5"])
    p2 = Party([("user1", 50), ("user2", 30), ("user4", 40), ("user3", 20)])

    print("开始执行协议...")
    result = ddh_intersection_sum(p1, p2)
    print(f"交集关联值和: {result}")  # 应输出 100 (user1+user2+user3)

    # 点序列化/反序列化测试
    print("\n点序列化测试...")
    test_point = _hash_to_point("test")
    print(f"原始点: x={test_point.x()}, y={test_point.y()}")

    test_bytes = point_to_bytes(test_point)
    print(f"序列化字节长度: {len(test_bytes)}")

    restored_point = bytes_to_point(test_bytes)
    print(f"恢复点: x={restored_point.x()}, y={restored_point.y()}")
    print(f"序列化/反序列化: {'成功' if test_point == restored_point else '失败'}")

    # 标量乘法测试
    print("\n标量乘法测试...")
    k = 12345
    k_point = _scalar_multiply(G, k)
    k2 = random.randint(1, ORDER - 1)
    kk2_point = _scalar_multiply(k_point, k2)
    k2k_point = _scalar_multiply(_scalar_multiply(G, k2), k)
    print(f"乘法律: {'成立' if kk2_point == k2k_point else '不成立'}")

    # 边界测试
    print("\n边界测试...")
    p1_empty = Party([])
    p2_empty = Party([])
    result_empty = ddh_intersection_sum(p1_empty, p2_empty)
    print(f"空集合测试: {result_empty} (应为0)")

    p1_single = Party(["user1"])
    p2_single = Party([("user1", 100)])
    result_single = ddh_intersection_sum(p1_single, p2_single)
    print(f"单元素集合测试: {result_single} (应为100)")

    p1_no_match = Party(["user6"])
    p2_no_match = Party([("user7", 200)])
    result_no_match = ddh_intersection_sum(p1_no_match, p2_no_match)
    print(f"无交集测试: {result_no_match} (应为0)")