import hashlib
import random
from ecdsa import SigningKey, SECP256k1, VerifyingKey
from ecdsa.util import sigencode_der, sigdecode_der

 
class SatoshiSignatureSystem:
    """中本聪数字签名系统模拟"""

    def __init__(self):
        self.curve = SECP256k1
        self.private_key = None
        self.public_key = None

    def generate_keys(self):
        """生成比特币密钥对"""
        self.private_key = SigningKey.generate(curve=self.curve)
        self.public_key = self.private_key.get_verifying_key()
        print("中本聪密钥生成:")
        print(f"私钥: {self.private_key.to_string().hex()[:32]}...")
        print(f"公钥: {self.public_key.to_string().hex()[:32]}...")
        return self.private_key, self.public_key

    def sign_transaction(self, message, k=None):
        """签署交易（模拟中本聪）"""
        if not k:
            k = random.randint(1, self.curve.order - 1)

        signature = self.private_key.sign(
            message.encode(),
            k=k,
            hashfunc=hashlib.sha256,
            sigencode=sigencode_der
        )

        return signature, k

    def verify_transaction(self, message, signature):
        """验证交易签名"""
        try:
            self.public_key.verify(
                signature,
                message.encode(),
                hashfunc=hashlib.sha256,
                sigdecode=sigdecode_der
            )
            return True
        except:
            return False


class SignatureForgeSystem:
    """签名伪造系统（利用k重用漏洞）"""

    def __init__(self):
        self.curve = SECP256k1

    def extract_private_key(self, sig1, sig2, msg1, msg2):
        """从两个签名中提取私钥"""
        # 解码签名
        r1, s1 = sigdecode_der(sig1, self.curve.order)
        r2, s2 = sigdecode_der(sig2, self.curve.order)

        # 验证是否使用相同k
        if r1 != r2:
            raise ValueError("签名未使用相同的随机数k")

        # 计算消息哈希
        order = self.curve.order
        h1 = int.from_bytes(hashlib.sha256(msg1.encode()).digest(), 'big') % order
        h2 = int.from_bytes(hashlib.sha256(msg2.encode()).digest(), 'big') % order

        # 计算随机数k
        s_diff_inv = pow(s1 - s2, -1, order)
        k_calculated = (h1 - h2) * s_diff_inv % order

        # 计算私钥d
        r_inv = pow(r1, -1, order)
        d_private = (s1 * k_calculated - h1) * r_inv % order

        return d_private, k_calculated

    def forge_signature(self, private_key, message):
        """伪造中本聪风格签名"""
        forged_key = SigningKey.from_secret_exponent(
            private_key,
            curve=self.curve,
            hashfunc=hashlib.sha256
        )

        return forged_key.sign(
            message.encode(),
            hashfunc=hashlib.sha256,
            sigencode=sigencode_der
        )


# 教学演示
def demonstrate_signature_forgery():
    # 1. 创建中本聪钱包
    print("\n[1/4] 创建中本聪钱包")
    satoshi_system = SatoshiSignatureSystem()
    private_key, public_key = satoshi_system.generate_keys()

    # 2. 中本聪签署两笔交易（模拟k重用漏洞）
    print("\n[2/4] 中本聪签署交易（存在k重用漏洞）")
    msg1 = "Send 10 BTC to Alice"
    msg2 = "Send 5 BTC to Bob"

    # 故意重用相同的k值（实际中不会发生）
    k = random.randint(1, SECP256k1.order - 1)
    sig1, _ = satoshi_system.sign_transaction(msg1, k)
    sig2, _ = satoshi_system.sign_transaction(msg2, k)

    print(f"交易1: '{msg1}'")
    print(f"交易2: '{msg2}'")
    print(f"使用相同k值: {hex(k)[:10]}...")

    # 3. 攻击者获取签名并提取私钥
    print("\n[3/4] 攻击者提取私钥")
    forge_system = SignatureForgeSystem()
    extracted_private_key, extracted_k = forge_system.extract_private_key(sig1, sig2, msg1, msg2)

    print(f"提取私钥: {hex(extracted_private_key)[:10]}...")
    print(f"实际私钥: {private_key.to_string().hex()[:10]}...")
    print(f"提取k值: {hex(extracted_k)[:10]}...")
    print(f"实际k值: {hex(k)[:10]}...")

    # 4. 伪造中本聪签名
    print("\n[4/4] 伪造中本聪签名")
    forged_message = "Send 1000 BTC to Attacker"
    forged_sig = forge_system.forge_signature(extracted_private_key, forged_message)

    # 验证伪造签名
    is_valid = satoshi_system.verify_transaction(forged_message, forged_sig)

    print(f"伪造消息: '{forged_message}'")
    print(f"伪造签名是否有效: {'✅' if is_valid else '❌'}")

if __name__ == "__main__":
    demonstrate_signature_forgery()