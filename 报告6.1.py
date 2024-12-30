import sys
import time
import math
import random
from PyQt5.QtWidgets import (
    QApplication, QWidget, QPushButton, QVBoxLayout, QHBoxLayout,
    QLabel, QTextEdit, QLineEdit, QFileDialog, QMessageBox, QSpinBox,
    QTabWidget, QGroupBox, QProgressBar, QGridLayout, QScrollArea, QComboBox
)
from PyQt5.QtGui import QFont, QIcon, QColor, QTextCursor
from PyQt5.QtCore import Qt, QThread, pyqtSignal

# 语言资源字典
LANGUAGE = {
    'en': {
        'title': "RSA Encryption & Decryption Tool",
        'key_generation': "Key Generation",
        'encrypt': "Encryption",
        'decrypt': "Decryption",
        'bit_size': "Bit Size for Primes:",
        'generate_keys': "Generate Keys",
        'public_key_e': "Public Key e:",
        'public_key_n': "Public Key n:",
        'private_key_d': "Private Key d:",
        'copy': "Copy",
        'key_steps': "Key Generation Steps",
        'plaintext': "Plaintext Message:",
        'load_from_file': "Load from File",
        'encrypt_btn': "Encrypt",
        'encryption_time': "Encryption Time:",
        'ciphertext': "Ciphertext:",
        'save_ciphertext': "Save Ciphertext to File",
        'encryption_steps': "Encryption Steps",
        'cipher_input': "Ciphertext (space-separated integers):",
        'decrypt_btn': "Decrypt",
        'decryption_time': "Decryption Time:",
        'plaintext_output': "Plaintext:",
        'save_plaintext': "Save Plaintext to File",
        'decryption_steps': "Decryption Steps",
        'language': "Language:",
        'copy_success': "{} copied to clipboard.",
        'copy_error': "Keys have not been generated yet.",
        'input_error': "Please enter a {}.",
        'key_error': "Please generate keys first.",
        'file_error': "Failed to {} file:\n{}",
        'save_success': "{} saved successfully.",
        'save_error': "No {} to save.",
        'save_fail': "Failed to save {}:\n{}",
        'generate_fail': "Key generation failed!\n{}",
        'encrypt_fail': "Encryption failed!\n{}",
        'decrypt_fail': "Decryption failed!\n{}",
        'copied_e': "Public Key e",
        'copied_n': "Public Key n",
        'copied_d': "Private Key d",
        'view_steps': "View Detailed Steps",
        'made_by': "Made by: Ziheng Wang"
    },
    'zh': {
        'title': "RSA 加密与解密工具",
        'key_generation': "密钥生成",
        'encrypt': "加密",
        'decrypt': "解密",
        'bit_size': "素数位数：",
        'generate_keys': "生成密钥",
        'public_key_e': "公钥 e:",
        'public_key_n': "公钥 n:",
        'private_key_d': "私钥 d:",
        'copy': "复制",
        'key_steps': "密钥生成步骤",
        'plaintext': "明文消息：",
        'load_from_file': "从文件加载",
        'encrypt_btn': "加密",
        'encryption_time': "加密时间：",
        'ciphertext': "密文：",
        'save_ciphertext': "保存密文到文件",
        'encryption_steps': "加密步骤",
        'cipher_input': "密文（以空格分隔的整数）：",
        'decrypt_btn': "解密",
        'decryption_time': "解密时间：",
        'plaintext_output': "明文：",
        'save_plaintext': "保存明文到文件",
        'decryption_steps': "解密步骤",
        'language': "语言：",
        'copy_success': "{} 已复制到剪贴板。",
        'copy_error': "密钥尚未生成。",
        'input_error': "请输入{}。",
        'key_error': "请先生成密钥。",
        'file_error': "无法{}文件：\n{}",
        'save_success': "{} 已成功保存。",
        'save_error': "没有{}可保存。",
        'save_fail': "无法保存{}：\n{}",
        'generate_fail': "密钥生成失败！\n{}",
        'encrypt_fail': "加密失败！\n{}",
        'decrypt_fail': "解密失败！\n{}",
        'copied_e': "公钥 e",
        'copied_n': "公钥 n",
        'copied_d': "私钥 d",
        'view_steps': "查看详细步骤",
        'made_by': "制作：Ziheng Wang"
    }
}

class RSAKeyGenerator:
    def __init__(self, bit_size=512, lang='en'):
        self.bit_size = bit_size
        self.p = None
        self.q = None
        self.n = None
        self.phi = None
        self.e = 65537  # Common choice for e
        self.d = None
        self.steps = []
        self.lang = lang

    def is_prime(self, n, k=5):
        """Miller-Rabin primality test."""
        if self.lang == 'en':
            self.steps.append(f"Checking if {n} is prime using Miller-Rabin test with {k} iterations.")
        else:
            self.steps.append(f"检查 {n} 是否为素数，使用 Miller-Rabin 测试，迭代次数={k}")
        if n <= 1:
            return False
        if n <= 3:
            return True
        if n % 2 == 0:
            return False

        # Write n-1 as 2^r * d
        r, d = 0, n - 1
        while d % 2 == 0:
            d //= 2
            r += 1
        if self.lang == 'en':
            self.steps.append(f"n-1 = 2^{r} * {d}")
        else:
            self.steps.append(f"n-1 = 2^{r} * {d}")

        for _ in range(k):
            a = random.randint(2, n - 2)
            x = pow(a, d, n)
            if self.lang == 'en':
                self.steps.append(f"Random a={a}, x={x}")
            else:
                self.steps.append(f"随机选择 a={a}, 计算 x = {a}^{d} mod {n} = {x}")
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if self.lang == 'en':
                    self.steps.append(f"x squared mod n = {x}")
                else:
                    self.steps.append(f"x = x^2 mod n = {x}")
                if x == n - 1:
                    break
            else:
                if self.lang == 'en':
                    self.steps.append(f"{n} is composite.")
                else:
                    self.steps.append(f"{n} 是合数。")
                return False
        if self.lang == 'en':
            self.steps.append(f"{n} is probably prime.")
        else:
            self.steps.append(f"{n} 可能是素数。")
        return True

    def generate_prime(self):
        while True:
            # Generate random odd integer of bit_size
            prime_candidate = random.getrandbits(self.bit_size)
            prime_candidate |= (1 << self.bit_size - 1) | 1  # Ensure high bit and odd
            if self.lang == 'en':
                self.steps.append(f"Generated prime candidate: {prime_candidate}")
            else:
                self.steps.append(f"生成素数候选：{prime_candidate}")
            if self.is_prime(prime_candidate):
                if self.lang == 'en':
                    self.steps.append(f"Prime number found: {prime_candidate}")
                else:
                    self.steps.append(f"找到素数：{prime_candidate}")
                return prime_candidate

    def gcd(self, a, b):
        while b != 0:
            a, b = b, a % b
        return a

    def modinv(self, a, m):
        if self.lang == 'en':
            self.steps.append(f"Calculating modular inverse of {a} mod {m}")
        else:
            self.steps.append(f"计算 {a} 在模 {m} 下的逆元")
        g, x, y = self.egcd(a, m)
        if g != 1:
            raise Exception('Modular inverse does not exist')
        else:
            return x % m

    def egcd(self, a, b):
        if a == 0:
            if self.lang == 'en':
                self.steps.append(f"EGCD step: a={a}, b={b}, return ({b}, 0, 1)")
            else:
                self.steps.append(f"EGCD 步骤：a={a}, b={b}, 返回 ({b}, 0, 1)")
            return (b, 0, 1)
        else:
            g, y, x = self.egcd(b % a, a)
            if self.lang == 'en':
                self.steps.append(f"EGCD step: a={a}, b={b}, g={g}, x={x}, y={y}")
            else:
                self.steps.append(f"EGCD 步骤：a={a}, b={b}, g={g}, x={x}, y={y}")
            return (g, x - (b // a) * y, y)

    def generate_keys(self):
        if self.lang == 'en':
            self.steps.append("Starting key generation...")
        else:
            self.steps.append("开始生成密钥...")
        self.p = self.generate_prime()
        self.q = self.generate_prime()
        if self.lang == 'en':
            self.steps.append(f"Generated primes p={self.p}, q={self.q}")
        else:
            self.steps.append(f"生成的素数 p={self.p}, q={self.q}")
        self.n = self.p * self.q
        self.phi = (self.p - 1) * (self.q - 1)
        if self.lang == 'en':
            self.steps.append(f"Calculated n=p*q={self.n} and phi=(p-1)*(q-1)={self.phi}")
        else:
            self.steps.append(f"计算 n = p*q = {self.n} 和 phi = (p-1)*(q-1) = {self.phi}")
        if self.gcd(self.e, self.phi) != 1:
            raise Exception("e and phi(n) are not coprime.")
        self.d = self.modinv(self.e, self.phi)
        if self.lang == 'en':
            self.steps.append(f"Calculated d as the modular inverse of e: d={self.d}")
            self.steps.append("Key generation completed.")
        else:
            self.steps.append(f"计算 d，作为 e 的模逆元：d={self.d}")
            self.steps.append("密钥生成完成。")
        return (self.e, self.n, self.d)

class RSAEncryptor:
    def __init__(self, e, n, lang='en'):
        self.e = e
        self.n = n
        self.steps = []
        self.lang = lang

    def encode_message(self, message):
        if self.lang == 'en':
            self.steps.append(f"Encoding message: {message}")
        else:
            self.steps.append(f"编码消息：{message}")
        return [ord(char) for char in message]

    def encrypt(self, plaintext):
        if self.lang == 'en':
            self.steps.append(f"Starting encryption with e={self.e}, n={self.n}")
        else:
            self.steps.append(f"开始加密，使用 e={self.e}, n={self.n}")
        plaintext_nums = self.encode_message(plaintext)
        ciphertext = []
        for num in plaintext_nums:
            cipher_num, cipher_steps = self.modular_exponentiation(num, self.e, self.n)
            self.steps.extend(cipher_steps)
            ciphertext.append(cipher_num)
        if self.lang == 'en':
            self.steps.append(f"Encryption completed. Ciphertext: {ciphertext}")
        else:
            self.steps.append(f"加密完成。密文：{ciphertext}")
        return ciphertext

    def modular_exponentiation(self, base, exponent, modulus):
        if self.lang == 'en':
            self.steps.append(f"Modular Exponentiation: {base}^{exponent} mod {modulus}")
        else:
            self.steps.append(f"模幂运算：{base}^{exponent} mod {modulus}")
        result = 1
        steps = []
        base = base % modulus
        steps.append(f"Initial result={result}, base={base}")
        while exponent > 0:
            if exponent % 2 == 1:
                result = (result * base) % modulus
                steps.append(f"Exponent odd, result=({result} * {base}) mod {modulus} = {result}")
            exponent = exponent >> 1
            steps.append(f"Exponent shifted right: exponent={exponent}")
            base = (base * base) % modulus
            steps.append(f"Base squared modulo n: {base}")
        steps.append(f"Final encrypted number: {result}")
        return result, steps

class RSADecryptor:
    def __init__(self, d, n, lang='en'):
        self.d = d
        self.n = n
        self.steps = []
        self.lang = lang

    def decrypt(self, ciphertext):
        if self.lang == 'en':
            self.steps.append(f"Starting decryption with d={self.d}, n={self.n}")
        else:
            self.steps.append(f"开始解密，使用 d={self.d}, n={self.n}")
        decrypted_nums = []
        for num in ciphertext:
            plain_num, decrypt_steps = self.modular_exponentiation(num, self.d, self.n)
            self.steps.extend(decrypt_steps)
            decrypted_nums.append(plain_num)
        plaintext = ''.join([chr(num) for num in decrypted_nums])
        if self.lang == 'en':
            self.steps.append(f"Decryption completed. Plaintext: {plaintext}")
        else:
            self.steps.append(f"解密完成。明文：{plaintext}")
        return plaintext

    def modular_exponentiation(self, base, exponent, modulus):
        if self.lang == 'en':
            self.steps.append(f"Modular Exponentiation: {base}^{exponent} mod {modulus}")
        else:
            self.steps.append(f"模幂运算：{base}^{exponent} mod {modulus}")
        result = 1
        steps = []
        base = base % modulus
        steps.append(f"Initial result={result}, base={base}")
        while exponent > 0:
            if exponent % 2 == 1:
                result = (result * base) % modulus
                steps.append(f"Exponent odd, result=({result} * {base}) mod {modulus} = {result}")
            exponent = exponent >> 1
            steps.append(f"Exponent shifted right: exponent={exponent}")
            base = (base * base) % modulus
            steps.append(f"Base squared modulo n: {base}")
        steps.append(f"Final decrypted number: {result}")
        return result, steps

class KeyGenerationThread(QThread):
    finished_signal = pyqtSignal(tuple, list)

    def __init__(self, bit_size, lang):
        super().__init__()
        self.bit_size = bit_size
        self.lang = lang

    def run(self):
        generator = RSAKeyGenerator(self.bit_size, self.lang)
        try:
            keys = generator.generate_keys()
            steps = generator.steps
            self.finished_signal.emit(keys, steps)
        except Exception as e:
            self.finished_signal.emit(None, [str(e)])

class EncryptionThread(QThread):
    finished_signal = pyqtSignal(list, list, float)

    def __init__(self, plaintext, e, n, lang):
        super().__init__()
        self.plaintext = plaintext
        self.e = e
        self.n = n
        self.lang = lang

    def run(self):
        encryptor = RSAEncryptor(self.e, self.n, self.lang)
        try:
            start_time = time.time()
            ciphertext = encryptor.encrypt(self.plaintext)
            end_time = time.time()
            steps = encryptor.steps
            elapsed_time = end_time - start_time
            self.finished_signal.emit(ciphertext, steps, elapsed_time)
        except Exception as e:
            self.finished_signal.emit(None, [str(e)], 0.0)

class DecryptionThread(QThread):
    finished_signal = pyqtSignal(str, list, float)

    def __init__(self, ciphertext, d, n, lang):
        super().__init__()
        self.ciphertext = ciphertext
        self.d = d
        self.n = n
        self.lang = lang

    def run(self):
        decryptor = RSADecryptor(self.d, self.n, self.lang)
        try:
            start_time = time.time()
            plaintext = decryptor.decrypt(self.ciphertext)
            end_time = time.time()
            steps = decryptor.steps
            elapsed_time = end_time - start_time
            self.finished_signal.emit(plaintext, steps, elapsed_time)
        except Exception as e:
            self.finished_signal.emit("", [str(e)], 0.0)

class StepsWindow(QWidget):
    def __init__(self, title, steps, lang='en'):
        super().__init__()
        self.lang = lang
        self.setWindowTitle(title)
        self.setGeometry(200, 200, 700, 500)
        layout = QVBoxLayout()
        self.steps_text = QTextEdit()
        self.steps_text.setReadOnly(True)
        self.steps_text.setStyleSheet("background-color: #ffffff;")
        # 格式化步骤文本，关键词加粗和颜色
        formatted_steps = self.format_steps(steps)
        self.steps_text.setHtml(formatted_steps)
        layout.addWidget(self.steps_text)
        self.setLayout(layout)

    def format_steps(self, steps):
        # 定义需要高亮显示的关键词
        keywords = ['prime', 'phi', 'modular inverse', 'exponent', 'base', 'result', 'ciphertext', 'plaintext']
        if self.lang == 'zh':
            keywords = ['素数', 'phi', '模逆元', '指数', '基数', '结果', '密文', '明文']
        # 使用HTML格式化步骤文本
        formatted = ""
        for step in steps:
            for keyword in keywords:
                if keyword in step:
                    # 使用不同颜色和加粗
                    step = step.replace(keyword, f"<b><span style='color:blue;'>{keyword}</span></b>")
            formatted += step + "<br>"
        return formatted

class RSAApp(QWidget):
    def __init__(self):
        super().__init__()
        self.lang = 'en'  # 默认语言为英文
        self.setWindowTitle(LANGUAGE[self.lang]['title'])
        self.setGeometry(100, 100, 1400, 1000)
        self.setWindowIcon(QIcon())  # 可以设置一个图标
        self.font = QFont("Arial", 10)
        self.setStyleSheet("background-color: #f0f0f0;")
        self.steps_windows = []  # 用于存储打开的步骤窗口引用，防止被垃圾回收
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        # 顶部布局：制作标签、标题和语言切换
        top_layout = QHBoxLayout()

        # 制作标签
        made_by_label = QLabel(LANGUAGE[self.lang]['made_by'])
        made_by_label.setFont(QFont("Arial", 12))
        made_by_label.setStyleSheet("color: #555555;")
        top_layout.addWidget(made_by_label, alignment=Qt.AlignLeft)

        # 标签标题
        title = QLabel(LANGUAGE[self.lang]['title'])
        title.setFont(QFont("Arial", 20, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("color: #333333;")
        top_layout.addWidget(title, stretch=1)

        # 语言切换
        lang_label = QLabel(LANGUAGE[self.lang]['language'] + ":")
        lang_label.setFont(QFont("Arial", 12))
        self.lang_combo = QComboBox()
        self.lang_combo.addItem("English")
        self.lang_combo.addItem("中文")
        self.lang_combo.currentIndexChanged.connect(self.switch_language)
        top_layout.addWidget(lang_label)
        top_layout.addWidget(self.lang_combo)

        layout.addLayout(top_layout)

        # 分割线
        line = QLabel()
        line.setFixedHeight(2)
        line.setStyleSheet("background-color: #444444;")
        layout.addWidget(line)

        # 标签页
        self.tabs = QTabWidget()
        self.tabs.setFont(self.font)
        self.tabs.setStyleSheet("""
            QTabWidget::pane { border: 1px solid #cccccc; }
            QTabBar::tab { 
                background: #dddddd; 
                padding: 10px;
                margin: 2px;
                border-radius: 4px;
            }
            QTabBar::tab:selected { 
                background: #ffffff; 
                font-weight: bold;
            }
        """)
        self.key_tab = QWidget()
        self.encrypt_tab = QWidget()
        self.decrypt_tab = QWidget()

        self.tabs.addTab(self.key_tab, LANGUAGE[self.lang]['key_generation'])
        self.tabs.addTab(self.encrypt_tab, LANGUAGE[self.lang]['encrypt'])
        self.tabs.addTab(self.decrypt_tab, LANGUAGE[self.lang]['decrypt'])

        self.init_key_tab()
        self.init_encrypt_tab()
        self.init_decrypt_tab()

        layout.addWidget(self.tabs)
        self.setLayout(layout)

    def init_key_tab(self):
        layout = QHBoxLayout()

        # 左侧：密钥生成设置
        settings_group = QGroupBox(LANGUAGE[self.lang]['key_generation'])
        settings_layout = QVBoxLayout()

        # 位数输入
        bit_layout = QHBoxLayout()
        bit_label = QLabel(LANGUAGE[self.lang]['bit_size'])
        self.bit_input = QSpinBox()
        self.bit_input.setRange(16, 4096)
        self.bit_input.setValue(512)
        bit_layout.addWidget(bit_label)
        bit_layout.addWidget(self.bit_input)
        settings_layout.addLayout(bit_layout)

        # 生成按钮
        self.gen_key_btn = QPushButton(LANGUAGE[self.lang]['generate_keys'])
        self.gen_key_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50; 
                color: white;
                padding: 10px;
                border: none;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)
        self.gen_key_btn.clicked.connect(self.generate_keys)
        settings_layout.addWidget(self.gen_key_btn)

        # 进度条
        self.key_progress = QProgressBar()
        self.key_progress.setValue(0)
        self.key_progress.setVisible(False)
        settings_layout.addWidget(self.key_progress)

        settings_group.setLayout(settings_layout)
        layout.addWidget(settings_group)

        # 右侧：密钥显示
        display_group = QGroupBox(LANGUAGE[self.lang]['key_generation'])
        display_layout = QGridLayout()

        # 公钥 e
        e_label = QLabel(LANGUAGE[self.lang]['public_key_e'])
        self.e_display = QLineEdit()
        self.e_display.setReadOnly(True)
        self.e_display.setStyleSheet("""
            background-color: #ffffff;
            border: 1px solid #cccccc;
            border-radius: 4px;
            padding: 5px;
        """)
        self.copy_e_btn = QPushButton(LANGUAGE[self.lang]['copy'])
        self.copy_e_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3; 
                color: white;
                padding: 5px;
                border: none;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #0b7dda;
            }
        """)
        self.copy_e_btn.clicked.connect(lambda: self.copy_text("e"))
        display_layout.addWidget(e_label, 0, 0)
        display_layout.addWidget(self.e_display, 0, 1)
        display_layout.addWidget(self.copy_e_btn, 0, 2)

        # 公钥 n
        n_label = QLabel(LANGUAGE[self.lang]['public_key_n'])
        self.n_display = QLineEdit()
        self.n_display.setReadOnly(True)
        self.n_display.setStyleSheet("""
            background-color: #ffffff;
            border: 1px solid #cccccc;
            border-radius: 4px;
            padding: 5px;
        """)
        self.copy_n_btn = QPushButton(LANGUAGE[self.lang]['copy'])
        self.copy_n_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3; 
                color: white;
                padding: 5px;
                border: none;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #0b7dda;
            }
        """)
        self.copy_n_btn.clicked.connect(lambda: self.copy_text("n"))
        display_layout.addWidget(n_label, 1, 0)
        display_layout.addWidget(self.n_display, 1, 1)
        display_layout.addWidget(self.copy_n_btn, 1, 2)

        # 私钥 d
        d_label = QLabel(LANGUAGE[self.lang]['private_key_d'])
        self.d_display = QLineEdit()
        self.d_display.setReadOnly(True)
        self.d_display.setStyleSheet("""
            background-color: #ffffff;
            border: 1px solid #cccccc;
            border-radius: 4px;
            padding: 5px;
        """)
        self.copy_d_btn = QPushButton(LANGUAGE[self.lang]['copy'])
        self.copy_d_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3; 
                color: white;
                padding: 5px;
                border: none;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #0b7dda;
            }
        """)
        self.copy_d_btn.clicked.connect(lambda: self.copy_text("d"))
        display_layout.addWidget(d_label, 2, 0)
        display_layout.addWidget(self.d_display, 2, 1)
        display_layout.addWidget(self.copy_d_btn, 2, 2)

        display_group.setLayout(display_layout)
        layout.addWidget(display_group)

        # 下方：步骤显示与查看详细按钮
        steps_group = QGroupBox(LANGUAGE[self.lang]['key_steps'])
        steps_layout = QVBoxLayout()
        self.key_steps = QTextEdit()
        self.key_steps.setReadOnly(True)
        self.key_steps.setStyleSheet("""
            background-color: #ffffff;
            border: 1px solid #cccccc;
            border-radius: 4px;
            padding: 5px;
        """)
        steps_layout.addWidget(self.key_steps)

        # 查看详细步骤按钮
        self.view_key_steps_btn = QPushButton(LANGUAGE[self.lang]['view_steps'])
        self.view_key_steps_btn.setStyleSheet("""
            QPushButton {
                background-color: #FF9800; 
                color: white;
                padding: 10px;
                border: none;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #e68a00;
            }
        """)
        self.view_key_steps_btn.clicked.connect(lambda: self.show_steps_window(
            LANGUAGE[self.lang]['key_steps'], self.key_steps.toPlainText()))
        steps_layout.addWidget(self.view_key_steps_btn)

        steps_group.setLayout(steps_layout)
        main_layout = QVBoxLayout()
        main_layout.addLayout(layout)
        main_layout.addWidget(steps_group)
        self.key_tab.setLayout(main_layout)

    def init_encrypt_tab(self):
        layout = QHBoxLayout()

        # 左侧：加密设置
        encrypt_group = QGroupBox(LANGUAGE[self.lang]['encrypt'])
        encrypt_layout = QVBoxLayout()

        # 明文输入
        self.encrypt_input = QTextEdit()
        self.encrypt_input.setPlaceholderText(LANGUAGE[self.lang]['plaintext'])
        self.encrypt_input.setStyleSheet("""
            background-color: #ffffff;
            border: 1px solid #cccccc;
            border-radius: 4px;
            padding: 5px;
        """)
        encrypt_layout.addWidget(QLabel(LANGUAGE[self.lang]['plaintext']))
        encrypt_layout.addWidget(self.encrypt_input)

        # 文件操作
        file_layout = QHBoxLayout()
        self.load_encrypt_btn = QPushButton(LANGUAGE[self.lang]['load_from_file'])
        self.load_encrypt_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3; 
                color: white;
                padding: 10px;
                border: none;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #0b7dda;
            }
        """)
        self.load_encrypt_btn.clicked.connect(self.load_encrypt_file)
        file_layout.addWidget(self.load_encrypt_btn)
        encrypt_layout.addLayout(file_layout)

        # 加密按钮
        self.encrypt_btn = QPushButton(LANGUAGE[self.lang]['encrypt_btn'])
        self.encrypt_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50; 
                color: white;
                padding: 10px;
                border: none;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)
        self.encrypt_btn.clicked.connect(self.encrypt_message)
        encrypt_layout.addWidget(self.encrypt_btn)

        # 进度条
        self.encrypt_progress = QProgressBar()
        self.encrypt_progress.setValue(0)
        self.encrypt_progress.setVisible(False)
        encrypt_layout.addWidget(self.encrypt_progress)

        encrypt_group.setLayout(encrypt_layout)
        layout.addWidget(encrypt_group)

        # 右侧：加密结果
        result_group = QGroupBox(LANGUAGE[self.lang]['encrypt'])
        result_layout = QVBoxLayout()

        # 加密时间
        self.encrypt_time_label = QLabel(f"{LANGUAGE[self.lang]['encryption_time']}0.00 seconds")
        result_layout.addWidget(self.encrypt_time_label)

        # 密文显示
        self.ciphertext_display = QTextEdit()
        self.ciphertext_display.setReadOnly(True)
        self.ciphertext_display.setStyleSheet("""
            background-color: #ffffff;
            border: 1px solid #cccccc;
            border-radius: 4px;
            padding: 5px;
        """)
        self.ciphertext_display.setPlaceholderText(LANGUAGE[self.lang]['ciphertext'])
        result_layout.addWidget(QLabel(LANGUAGE[self.lang]['ciphertext']))
        result_layout.addWidget(self.ciphertext_display)

        # 保存密文按钮
        self.save_cipher_btn = QPushButton(LANGUAGE[self.lang]['save_ciphertext'])
        self.save_cipher_btn.setStyleSheet("""
            QPushButton {
                background-color: #FF9800; 
                color: white;
                padding: 10px;
                border: none;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #e68a00;
            }
        """)
        self.save_cipher_btn.clicked.connect(self.save_ciphertext)
        result_layout.addWidget(self.save_cipher_btn)

        # 步骤显示与查看详细按钮
        steps_group = QGroupBox(LANGUAGE[self.lang]['encryption_steps'])
        steps_layout = QVBoxLayout()
        self.encrypt_steps = QTextEdit()
        self.encrypt_steps.setReadOnly(True)
        self.encrypt_steps.setStyleSheet("""
            background-color: #ffffff;
            border: 1px solid #cccccc;
            border-radius: 4px;
            padding: 5px;
        """)
        steps_layout.addWidget(self.encrypt_steps)

        # 查看详细步骤按钮
        self.view_encrypt_steps_btn = QPushButton(LANGUAGE[self.lang]['view_steps'])
        self.view_encrypt_steps_btn.setStyleSheet("""
            QPushButton {
                background-color: #FF9800; 
                color: white;
                padding: 10px;
                border: none;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #e68a00;
            }
        """)
        self.view_encrypt_steps_btn.clicked.connect(lambda: self.show_steps_window(
            LANGUAGE[self.lang]['encryption_steps'], self.encrypt_steps.toPlainText()))
        steps_layout.addWidget(self.view_encrypt_steps_btn)

        steps_group.setLayout(steps_layout)
        result_layout.addWidget(steps_group)

        result_group.setLayout(result_layout)
        layout.addWidget(result_group)

        # 下方：进度与布局
        main_layout = QVBoxLayout()
        main_layout.addLayout(layout)
        self.encrypt_tab.setLayout(main_layout)

    def init_decrypt_tab(self):
        layout = QHBoxLayout()

        # 左侧：解密设置
        decrypt_group = QGroupBox(LANGUAGE[self.lang]['decrypt'])
        decrypt_layout = QVBoxLayout()

        # 密文输入
        self.decrypt_input = QTextEdit()
        self.decrypt_input.setPlaceholderText(LANGUAGE[self.lang]['cipher_input'])
        self.decrypt_input.setStyleSheet("""
            background-color: #ffffff;
            border: 1px solid #cccccc;
            border-radius: 4px;
            padding: 5px;
        """)
        decrypt_layout.addWidget(QLabel(LANGUAGE[self.lang]['cipher_input']))
        decrypt_layout.addWidget(self.decrypt_input)

        # 文件操作
        file_layout = QHBoxLayout()
        self.load_decrypt_btn = QPushButton(LANGUAGE[self.lang]['load_from_file'])
        self.load_decrypt_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3; 
                color: white;
                padding: 10px;
                border: none;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #0b7dda;
            }
        """)
        self.load_decrypt_btn.clicked.connect(self.load_decrypt_file)
        file_layout.addWidget(self.load_decrypt_btn)
        decrypt_layout.addLayout(file_layout)

        # 解密按钮
        self.decrypt_btn = QPushButton(LANGUAGE[self.lang]['decrypt_btn'])
        self.decrypt_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50; 
                color: white;
                padding: 10px;
                border: none;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)
        self.decrypt_btn.clicked.connect(self.decrypt_message)
        decrypt_layout.addWidget(self.decrypt_btn)

        # 进度条
        self.decrypt_progress = QProgressBar()
        self.decrypt_progress.setValue(0)
        self.decrypt_progress.setVisible(False)
        decrypt_layout.addWidget(self.decrypt_progress)

        decrypt_group.setLayout(decrypt_layout)
        layout.addWidget(decrypt_group)

        # 右侧：解密结果
        result_group = QGroupBox(LANGUAGE[self.lang]['decrypt'])
        result_layout = QVBoxLayout()

        # 解密时间
        self.decrypt_time_label = QLabel(f"{LANGUAGE[self.lang]['decryption_time']}0.00 seconds")
        result_layout.addWidget(self.decrypt_time_label)

        # 明文显示
        self.plaintext_display = QTextEdit()
        self.plaintext_display.setReadOnly(True)
        self.plaintext_display.setStyleSheet("""
            background-color: #ffffff;
            border: 1px solid #cccccc;
            border-radius: 4px;
            padding: 5px;
        """)
        self.plaintext_display.setPlaceholderText(LANGUAGE[self.lang]['plaintext_output'])
        result_layout.addWidget(QLabel(LANGUAGE[self.lang]['plaintext_output']))
        result_layout.addWidget(self.plaintext_display)

        # 保存明文按钮
        self.save_plain_btn = QPushButton(LANGUAGE[self.lang]['save_plaintext'])
        self.save_plain_btn.setStyleSheet("""
            QPushButton {
                background-color: #FF9800; 
                color: white;
                padding: 10px;
                border: none;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #e68a00;
            }
        """)
        self.save_plain_btn.clicked.connect(self.save_plaintext)
        result_layout.addWidget(self.save_plain_btn)

        # 步骤显示与查看详细按钮
        steps_group = QGroupBox(LANGUAGE[self.lang]['decryption_steps'])
        steps_layout = QVBoxLayout()
        self.decrypt_steps = QTextEdit()
        self.decrypt_steps.setReadOnly(True)
        self.decrypt_steps.setStyleSheet("""
            background-color: #ffffff;
            border: 1px solid #cccccc;
            border-radius: 4px;
            padding: 5px;
        """)
        steps_layout.addWidget(self.decrypt_steps)

        # 查看详细步骤按钮
        self.view_decrypt_steps_btn = QPushButton(LANGUAGE[self.lang]['view_steps'])
        self.view_decrypt_steps_btn.setStyleSheet("""
            QPushButton {
                background-color: #FF9800; 
                color: white;
                padding: 10px;
                border: none;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #e68a00;
            }
        """)
        self.view_decrypt_steps_btn.clicked.connect(lambda: self.show_steps_window(
            LANGUAGE[self.lang]['decryption_steps'], self.decrypt_steps.toPlainText()))
        steps_layout.addWidget(self.view_decrypt_steps_btn)

        steps_group.setLayout(steps_layout)
        result_layout.addWidget(steps_group)

        result_group.setLayout(result_layout)
        layout.addWidget(result_group)

        # 下方：进度与布局
        main_layout = QVBoxLayout()
        main_layout.addLayout(layout)
        self.decrypt_tab.setLayout(main_layout)

    def switch_language(self):
        index = self.lang_combo.currentIndex()
        if index == 0:
            self.lang = 'en'
        else:
            self.lang = 'zh'

        # 更新所有文本
        self.update_texts()

    def update_texts(self):
        # 更新窗口标题
        self.setWindowTitle(LANGUAGE[self.lang]['title'])

        # 更新顶部标题和制作标签
        top_layout = self.layout().itemAt(0).layout()
        made_by_label = top_layout.itemAt(0).widget()
        made_by_label.setText(LANGUAGE[self.lang]['made_by'])

        title = top_layout.itemAt(1).widget()
        title.setText(LANGUAGE[self.lang]['title'])

        # 更新语言标签
        lang_label = top_layout.itemAt(2).widget()
        lang_label.setText(LANGUAGE[self.lang]['language'] + ":")

        # 更新标签页标题
        self.tabs.setTabText(0, LANGUAGE[self.lang]['key_generation'])
        self.tabs.setTabText(1, LANGUAGE[self.lang]['encrypt'])
        self.tabs.setTabText(2, LANGUAGE[self.lang]['decrypt'])

        # 更新Key Generation Tab
        key_group = self.key_tab.findChild(QGroupBox, LANGUAGE['en']['key_generation'] if self.lang == 'en' else LANGUAGE['zh']['key_generation'])
        if key_group:
            key_group.setTitle(LANGUAGE[self.lang]['key_generation'])
            bit_label = key_group.findChild(QLabel, LANGUAGE['en']['bit_size'] if self.lang == 'en' else LANGUAGE['zh']['bit_size'])
            if bit_label:
                bit_label.setText(LANGUAGE[self.lang]['bit_size'])
            self.gen_key_btn.setText(LANGUAGE[self.lang]['generate_keys'])
            self.view_key_steps_btn.setText(LANGUAGE[self.lang]['view_steps'])

        # 更新Encrypt Tab
        encrypt_group = self.encrypt_tab.findChild(QGroupBox, LANGUAGE['en']['encrypt'] if self.lang == 'en' else LANGUAGE['zh']['encrypt'])
        if encrypt_group:
            encrypt_group.setTitle(LANGUAGE[self.lang]['encrypt'])
            plaintext_label = encrypt_group.findChild(QLabel, LANGUAGE['en']['plaintext'] if self.lang == 'en' else LANGUAGE['zh']['plaintext'])
            if plaintext_label:
                plaintext_label.setText(LANGUAGE[self.lang]['plaintext'])
            self.load_encrypt_btn.setText(LANGUAGE[self.lang]['load_from_file'])
            self.encrypt_btn.setText(LANGUAGE[self.lang]['encrypt_btn'])
            self.encrypt_time_label.setText(f"{LANGUAGE[self.lang]['encryption_time']}0.00 seconds")
            ciphertext_label = encrypt_group.findChild(QLabel, LANGUAGE['en']['ciphertext'] if self.lang == 'en' else LANGUAGE['zh']['ciphertext'])
            if ciphertext_label:
                ciphertext_label.setText(LANGUAGE[self.lang]['ciphertext'])
            self.save_cipher_btn.setText(LANGUAGE[self.lang]['save_ciphertext'])
            self.view_encrypt_steps_btn.setText(LANGUAGE[self.lang]['view_steps'])

        # 更新Decrypt Tab
        decrypt_group = self.decrypt_tab.findChild(QGroupBox, LANGUAGE['en']['decrypt'] if self.lang == 'en' else LANGUAGE['zh']['decrypt'])
        if decrypt_group:
            decrypt_group.setTitle(LANGUAGE[self.lang]['decrypt'])
            cipher_input_label = decrypt_group.findChild(QLabel, LANGUAGE['en']['cipher_input'] if self.lang == 'en' else LANGUAGE['zh']['cipher_input'])
            if cipher_input_label:
                cipher_input_label.setText(LANGUAGE[self.lang]['cipher_input'])
            self.load_decrypt_btn.setText(LANGUAGE[self.lang]['load_from_file'])
            self.decrypt_btn.setText(LANGUAGE[self.lang]['decrypt_btn'])
            self.decrypt_time_label.setText(f"{LANGUAGE[self.lang]['decryption_time']}0.00 seconds")
            plaintext_output_label = decrypt_group.findChild(QLabel, LANGUAGE['en']['plaintext_output'] if self.lang == 'en' else LANGUAGE['zh']['plaintext_output'])
            if plaintext_output_label:
                plaintext_output_label.setText(LANGUAGE[self.lang]['plaintext_output'])
            self.save_plain_btn.setText(LANGUAGE[self.lang]['save_plaintext'])
            self.view_decrypt_steps_btn.setText(LANGUAGE[self.lang]['view_steps'])

        # 更新制作标签
        made_by_label = self.layout().itemAt(0).layout().itemAt(0).widget()
        made_by_label.setText(LANGUAGE[self.lang]['made_by'])

    def generate_keys(self):
        bit_size = self.bit_input.value()
        self.e_display.clear()
        self.n_display.clear()
        self.d_display.clear()
        self.key_steps.clear()
        self.key_progress.setValue(0)
        self.key_progress.setVisible(True)
        self.gen_key_btn.setEnabled(False)

        # 开启线程进行密钥生成
        self.key_thread = KeyGenerationThread(bit_size, self.lang)
        self.key_thread.finished_signal.connect(self.on_key_generated)
        self.key_thread.start()

    def on_key_generated(self, keys, steps):
        self.key_progress.setVisible(False)
        self.gen_key_btn.setEnabled(True)
        if keys:
            e, n, d = keys
            self.e_display.setText(str(e))
            self.n_display.setText(str(n))
            self.d_display.setText(str(d))
            self.public_key = (e, n)
            self.private_key = (d, n)
            # 格式化步骤文本
            formatted_steps = "<br>".join(steps)
            self.key_steps.setHtml(formatted_steps.replace("\n", "<br>"))
        else:
            error_msg = '\n'.join(steps)
            QMessageBox.critical(self, "Error", LANGUAGE[self.lang]['generate_fail'].format(error_msg))

    def copy_text(self, key_type):
        try:
            if key_type == "e":
                e = self.e_display.text()
                QApplication.clipboard().setText(e)
                message = LANGUAGE[self.lang]['copy_success'].format(LANGUAGE[self.lang]['copied_e'])
            elif key_type == "n":
                n = self.n_display.text()
                QApplication.clipboard().setText(n)
                message = LANGUAGE[self.lang]['copy_success'].format(LANGUAGE[self.lang]['copied_n'])
            elif key_type == "d":
                d = self.d_display.text()
                QApplication.clipboard().setText(d)
                message = LANGUAGE[self.lang]['copy_success'].format(LANGUAGE[self.lang]['copied_d'])
            QMessageBox.information(self, "Success", message)
        except AttributeError:
            QMessageBox.warning(self, "Warning", LANGUAGE[self.lang]['copy_error'])

    def encrypt_message(self):
        plaintext = self.encrypt_input.toPlainText()
        if not plaintext:
            QMessageBox.warning(self, "Input Error", LANGUAGE[self.lang]['input_error'].format(LANGUAGE[self.lang]['plaintext']))
            return
        if not hasattr(self, 'public_key'):
            QMessageBox.warning(self, "Key Error", LANGUAGE[self.lang]['key_error'])
            return
        e, n = self.public_key
        self.ciphertext_display.clear()
        self.encrypt_steps.clear()
        self.encrypt_time_label.setText(f"{LANGUAGE[self.lang]['encryption_time']}0.00 seconds")
        self.encrypt_progress.setValue(0)
        self.encrypt_progress.setVisible(True)
        self.encrypt_btn.setEnabled(False)

        # 开启线程进行加密
        self.encrypt_thread = EncryptionThread(plaintext, e, n, self.lang)
        self.encrypt_thread.finished_signal.connect(self.on_encrypted)
        self.encrypt_thread.start()

    def on_encrypted(self, ciphertext, steps, elapsed_time):
        self.encrypt_progress.setVisible(False)
        self.encrypt_btn.setEnabled(True)
        if ciphertext:
            self.ciphertext_display.setPlainText(' '.join(map(str, ciphertext)))
            self.encrypt_time_label.setText(f"{LANGUAGE[self.lang]['encryption_time']}{elapsed_time:.2f} seconds")
            # 格式化步骤文本
            formatted_steps = "<br>".join(steps)
            self.encrypt_steps.setHtml(formatted_steps.replace("\n", "<br>"))
        else:
            error_msg = '\n'.join(steps)
            QMessageBox.critical(self, "Error", LANGUAGE[self.lang]['encrypt_fail'].format(error_msg))

    def decrypt_message(self):
        ciphertext_str = self.decrypt_input.toPlainText()
        if not ciphertext_str:
            QMessageBox.warning(self, "Input Error", LANGUAGE[self.lang]['input_error'].format(LANGUAGE[self.lang]['cipher_input']))
            return
        if not hasattr(self, 'private_key'):
            QMessageBox.warning(self, "Key Error", LANGUAGE[self.lang]['key_error'])
            return
        try:
            ciphertext = list(map(int, ciphertext_str.strip().split()))
        except ValueError:
            QMessageBox.warning(self, "Input Error", "Ciphertext should be space-separated integers.")
            return
        d, n = self.private_key
        self.plaintext_display.clear()
        self.decrypt_steps.clear()
        self.decrypt_time_label.setText(f"{LANGUAGE[self.lang]['decryption_time']}0.00 seconds")
        self.decrypt_progress.setValue(0)
        self.decrypt_progress.setVisible(True)
        self.decrypt_btn.setEnabled(False)

        # 开启线程进行解密
        self.decrypt_thread = DecryptionThread(ciphertext, d, n, self.lang)
        self.decrypt_thread.finished_signal.connect(self.on_decrypted)
        self.decrypt_thread.start()

    def on_decrypted(self, plaintext, steps, elapsed_time):
        self.decrypt_progress.setVisible(False)
        self.decrypt_btn.setEnabled(True)
        if plaintext:
            self.plaintext_display.setPlainText(plaintext)
            self.decrypt_time_label.setText(f"{LANGUAGE[self.lang]['decryption_time']}{elapsed_time:.2f} seconds")
            # 格式化步骤文本
            formatted_steps = "<br>".join(steps)
            self.decrypt_steps.setHtml(formatted_steps.replace("\n", "<br>"))
        else:
            error_msg = '\n'.join(steps)
            QMessageBox.critical(self, "Error", LANGUAGE[self.lang]['decrypt_fail'].format(error_msg))

    def load_encrypt_file(self):
        options = QFileDialog.Options()
        filename, _ = QFileDialog.getOpenFileName(self, "Open Plaintext File", "", "Text Files (*.txt);;All Files (*)", options=options)
        if filename:
            try:
                with open(filename, 'r', encoding='utf-8') as file:
                    data = file.read()
                    self.encrypt_input.setPlainText(data)
            except Exception as ex:
                QMessageBox.critical(self, "Error", LANGUAGE[self.lang]['file_error'].format("load", str(ex)))

    def save_ciphertext(self):
        ciphertext = self.ciphertext_display.toPlainText()
        if not ciphertext:
            QMessageBox.warning(self, "Save Error", LANGUAGE[self.lang]['save_error'].format(LANGUAGE[self.lang]['ciphertext']))
            return
        options = QFileDialog.Options()
        filename, _ = QFileDialog.getSaveFileName(self, "Save Ciphertext", "", "Text Files (*.txt);;All Files (*)", options=options)
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as file:
                    file.write(ciphertext)
                QMessageBox.information(self, "Success", LANGUAGE[self.lang]['save_success'].format(LANGUAGE[self.lang]['ciphertext']))
            except Exception as ex:
                QMessageBox.critical(self, "Error", LANGUAGE[self.lang]['save_fail'].format(LANGUAGE[self.lang]['ciphertext'], str(ex)))

    def load_decrypt_file(self):
        options = QFileDialog.Options()
        filename, _ = QFileDialog.getOpenFileName(self, "Open Ciphertext File", "", "Text Files (*.txt);;All Files (*)", options=options)
        if filename:
            try:
                with open(filename, 'r', encoding='utf-8') as file:
                    data = file.read()
                    self.decrypt_input.setPlainText(data)
            except Exception as ex:
                QMessageBox.critical(self, "Error", LANGUAGE[self.lang]['file_error'].format("load", str(ex)))

    def save_plaintext(self):
        plaintext = self.plaintext_display.toPlainText()
        if not plaintext:
            QMessageBox.warning(self, "Save Error", LANGUAGE[self.lang]['save_error'].format(LANGUAGE[self.lang]['plaintext_output']))
            return
        options = QFileDialog.Options()
        filename, _ = QFileDialog.getSaveFileName(self, "Save Plaintext", "", "Text Files (*.txt);;All Files (*)", options=options)
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as file:
                    file.write(plaintext)
                QMessageBox.information(self, "Success", LANGUAGE[self.lang]['save_success'].format(LANGUAGE[self.lang]['plaintext_output']))
            except Exception as ex:
                QMessageBox.critical(self, "Error", LANGUAGE[self.lang]['save_fail'].format(LANGUAGE[self.lang]['plaintext_output'], str(ex)))

    def show_steps_window(self, title, steps_text):
        steps = steps_text.split('<br>')
        window = StepsWindow(title, steps, self.lang)
        window.show()
        self.steps_windows.append(window)  # 保持引用，防止被垃圾回收

def main():
    app = QApplication(sys.argv)
    rsa_app = RSAApp()
    rsa_app.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()

