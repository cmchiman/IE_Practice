from blind_watermark import WaterMark
import cv2
import numpy as np

# ========== 嵌入水印 ==========
bwm1 = WaterMark(password_img=1, password_wm=1)
bwm1.read_img('test_image.jpg')
wm = 'SECRET'
bwm1.read_wm(wm, mode='str')
bwm1.embed('embedded.png')
len_wm = len(bwm1.wm_bit)
print(f'水印比特长度：{len_wm}')


# ========== 攻击模拟函数（含几何攻击）==========
def apply_attacks(img_path):
    """应用各种攻击并返回处理后的图像"""
    img = cv2.imread(img_path)
    attacks = {}
    h, w = img.shape[:2]

    # 1. 水平翻转（几何攻击）
    attacks['水平翻转'] = cv2.flip(img, 1)

    # 2. 垂直翻转（几何攻击）
    attacks['垂直翻转'] = cv2.flip(img, 0)

    # 3. 平移攻击（30像素偏移）
    M = np.float32([[1, 0, 30], [0, 1, 30]])
    attacks['平移'] = cv2.warpAffine(img, M, (w, h))

    # 4. 随机截取（裁剪50%区域）
    attacks['截取'] = img[int(h / 4):int(3 * h / 4), int(w / 4):int(3 * w / 4)]

    # 5. 对比度调整
    attacks['高对比度'] = cv2.convertScaleAbs(img, alpha=1.5, beta=0)

    # 6. 亮度调整
    attacks['高亮度'] = cv2.convertScaleAbs(img, alpha=1.0, beta=50)

    # 7. 椒盐噪声（5%噪声密度）
    noise = np.copy(img)
    prob = 0.05
    rnd = np.random.rand(*noise.shape[:2])
    noise[rnd < prob / 2] = 0
    noise[rnd > 1 - prob / 2] = 255
    attacks['椒盐噪声'] = noise

    # 8. JPEG压缩（质量因子=30）
    cv2.imwrite('temp_compressed.jpg', img, [int(cv2.IMWRITE_JPEG_QUALITY), 30])
    attacks['JPEG压缩'] = cv2.imread('temp_compressed.jpg')

    return attacks, (h, w)  # 返回原始尺寸


# ========== 几何攻击校正模块 ==========
def correct_geometric_attacks(img, attack_name, original_size):
    """校正几何攻击：翻转、平移、裁剪"""
    h_orig, w_orig = original_size

    # 1. 翻转校正
    if attack_name == '水平翻转':
        return cv2.flip(img, 1)  # 水平翻转还原
    elif attack_name == '垂直翻转':
        return cv2.flip(img, 0)  # 垂直翻转还原

    # 2. 裁剪校正（填充黑边恢复原始尺寸）
    elif attack_name == '截取':
        h, w = img.shape[:2]
        padded = np.zeros((h_orig, w_orig, 3), dtype=np.uint8)
        y_offset = (h_orig - h) // 2
        x_offset = (w_orig - w) // 2
        padded[y_offset:y_offset + h, x_offset:x_offset + w] = img
        return padded

    # 3. 平移校正（反向平移）
    elif attack_name == '平移':
        M_inv = np.float32([[1, 0, -30], [0, 1, -30]])
        return cv2.warpAffine(img, M_inv, (w_orig, h_orig))

    return img  # 非几何攻击直接返回


# ========== 应用攻击并提取水印 ==========
attacked_images, orig_size = apply_attacks('embedded.png')
results = []

for attack_name, img in attacked_images.items():
    # 几何攻击校正
    corrected_img = correct_geometric_attacks(img, attack_name, orig_size)
    attack_path = f'attacked_{attack_name}.png'
    cv2.imwrite(attack_path, corrected_img)

    # 尝试提取水印
    bwm2 = WaterMark(password_img=1, password_wm=1)
    try:
        wm_extract = bwm2.extract(attack_path, wm_shape=len_wm, mode='str')
    except Exception as e:
        wm_extract = f"提取失败: {str(e)}"

    # 记录结果
    results.append({
        '攻击类型': attack_name,
        '提取结果': wm_extract,
        '图像路径': attack_path
    })
    print(f"{attack_name}攻击后提取结果: {wm_extract}")

# ========== 输出最终报告 ==========
print("\n=== 鲁棒性测试最终报告 ===")
for res in results:
    status = "成功" if res['提取结果'] == wm else "失败"
    print(f"{res['攻击类型']}: 提取{status} -> {res['提取结果']}")

# ========== 完整提取代码（无攻击）==========
bwm_final = WaterMark(password_img=1, password_wm=1)
wm_extract_final = bwm_final.extract('embedded.png', wm_shape=len_wm, mode='str')
print(f"\n最终提取的水印信息: {wm_extract_final}")