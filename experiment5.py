import base64
import os
import threading
import time
from tkinter import *
from tkinter import ttk, filedialog, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import mimetypes

# 国际化支持
LANGUAGES = {
    'English': {
        'title': "AES Encryption/Decryption Tool",
        'encrypt_tab': "Encrypt",
        'decrypt_tab': "Decrypt",
        'key_label': "Enter Key:",
        'generate_key': "Generate Random Key",
        'copy_key': "Copy Key",
        'key_size': "Key Size:",
        'modes': "Mode:",
        'encrypt_button': "Start Encryption",
        'decrypt_button': "Start Decryption",
        'select_file_encrypt': "Select File to Encrypt",
        'select_file_decrypt': "Select File to Decrypt",
        'language': "Language",
        'theme': "Theme",
        'copy_success': "Content copied to clipboard!",
        'save_success': "Content saved to {}",
        'save_failure': "Error saving file: {}",
        'copy_warning': "No content to copy!",
        'save_warning': "No content to save!",
        'missing_key': "Key cannot be empty!",
        'missing_data': "Data cannot be empty!",
        'invalid_iv': "Invalid IV! It must be a valid Base64-encoded 12 or 16-byte value.",
        'encryption_complete': "Encryption Complete!",
        'decryption_complete': "Decryption Complete!",
        'error': "Error",
        'information': "Information",
        'warning': "Warning",
        'select_iv': "Enter IV (Base64):",
        'iv_required': "IV is required for this mode!",
        'visualization': "Visualization",
        'input_data': "Input Data",
        'output': "Output",
        'save_output': "Save Output",
        'aes_flow': "AES Encryption Process",
        'aes_decryption_flow': "AES Decryption Process",
        'test_example': "Load Test Example",
        'advanced_settings': "Advanced Settings",
        'custom_iv': "Use Custom IV",
        'test_menu_label': "Test",
        'hacker_theme': "Hacker",
    },
    '中文': {
        'title': "AES加密解密工具",
        'encrypt_tab': "加密",
        'decrypt_tab': "解密",
        'key_label': "输入密钥：",
        'generate_key': "生成随机密钥",
        'copy_key': "复制密钥",
        'key_size': "密钥大小：",
        'modes': "模式：",
        'encrypt_button': "开始加密",
        'decrypt_button': "开始解密",
        'select_file_encrypt': "选择要加密的文件",
        'select_file_decrypt': "选择要解密的文件",
        'language': "语言",
        'theme': "风格",
        'copy_success': "内容已复制到剪贴板！",
        'save_success': "内容已保存到 {}",
        'save_failure': "保存文件时出错：{}",
        'copy_warning': "没有内容可复制！",
        'save_warning': "没有内容可保存！",
        'missing_key': "密钥不能为空！",
        'missing_data': "数据不能为空！",
        'invalid_iv': "无效的IV！它必须是有效的Base64编码的12或16字节值。",
        'encryption_complete': "加密完成！",
        'decryption_complete': "解密完成！",
        'error': "错误",
        'information': "信息",
        'warning': "警告",
        'select_iv': "请输入IV（Base64）：",
        'iv_required': "此模式需要IV！",
        'visualization': "可视化",
        'input_data': "输入数据",
        'output': "输出",
        'save_output': "保存输出",
        'aes_flow': "AES加密流程",
        'aes_decryption_flow': "AES解密流程",
        'test_example': "加载测试例",
        'advanced_settings': "高级设置",
        'custom_iv': "使用自定义IV",
        'test_menu_label': "测试",
        'hacker_theme': "黑客",
    }
}

class AES_Crypto:
    def __init__(self, key_size=128, mode='CTR'):
        self.key_size = key_size
        self.mode = mode
        self.key = None
        self.iv = None

    def generate_random_key(self):
        if self.key_size == 128:
            self.key = os.urandom(16)
        elif self.key_size == 192:
            self.key = os.urandom(24)
        elif self.key_size == 256:
            self.key = os.urandom(32)
        else:
            raise ValueError("Unsupported key size")
        return base64.b64encode(self.key).decode('utf-8')

    def set_key(self, key):
        if isinstance(key, str):
            self.key = base64.b64decode(key)
        else:
            self.key = key

    def encrypt(self, data, callback=None):
        if isinstance(data, str):
            data = data.encode('utf-8')

        # Choose encryption mode
        if self.mode == 'CTR':
            self.iv = os.urandom(16)
            cipher_mode = modes.CTR(self.iv)
        elif self.mode == 'CBC':
            self.iv = os.urandom(16)
            cipher_mode = modes.CBC(self.iv)
        elif self.mode == 'ECB':
            self.iv = None
            cipher_mode = modes.ECB()
        elif self.mode == 'GCM':
            self.iv = os.urandom(12)
            cipher_mode = modes.GCM(self.iv)
        else:
            raise ValueError("Unsupported encryption mode")

        cipher = Cipher(algorithms.AES(self.key), cipher_mode, backend=default_backend())
        encryptor = cipher.encryptor()

        # Padding for modes that require it
        if self.mode in ['CBC', 'ECB']:
            padder = padding.PKCS7(128).padder()
            data = padder.update(data) + padder.finalize()
            if callback:
                callback("Padding complete.")

        # Encryption
        encrypted = encryptor.update(data) + encryptor.finalize()
        if callback:
            callback("Encryption complete.")

        # For GCM mode, append the tag
        if self.mode == 'GCM':
            encrypted += encryptor.tag

        encrypted_b64 = base64.b64encode(encrypted).decode('utf-8')
        iv_b64 = base64.b64encode(self.iv).decode('utf-8') if self.iv else None
        return encrypted_b64, iv_b64

    def decrypt(self, encrypted_data, iv=None, callback=None):
        encrypted_data = base64.b64decode(encrypted_data)

        # Choose decryption mode
        if self.mode == 'CTR':
            if not iv:
                raise ValueError("IV is required for CTR mode")
            self.iv = base64.b64decode(iv)
            cipher_mode = modes.CTR(self.iv)
        elif self.mode == 'CBC':
            if not iv:
                raise ValueError("IV is required for CBC mode")
            self.iv = base64.b64decode(iv)
            cipher_mode = modes.CBC(self.iv)
        elif self.mode == 'ECB':
            self.iv = None
            cipher_mode = modes.ECB()
        elif self.mode == 'GCM':
            if not iv:
                raise ValueError("IV is required for GCM mode")
            self.iv = base64.b64decode(iv)
            # In GCM, the last 16 bytes are the tag
            if len(encrypted_data) < 16:
                raise ValueError("Encrypted data is too short for GCM mode.")
            tag = encrypted_data[-16:]
            encrypted_data = encrypted_data[:-16]
            cipher_mode = modes.GCM(self.iv, tag)
        else:
            raise ValueError("Unsupported decryption mode")

        cipher = Cipher(algorithms.AES(self.key), cipher_mode, backend=default_backend())
        decryptor = cipher.decryptor()

        # Decryption
        decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()
        if callback:
            callback("Decryption complete.")

        # Unpadding for modes that require it
        if self.mode in ['CBC', 'ECB']:
            unpadder = padding.PKCS7(128).unpadder()
            decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
            if callback:
                callback("Unpadding complete.")
        else:
            decrypted = decrypted_padded

        return decrypted  # Return bytes directly

class AES_GUI:
    def __init__(self, root):
        self.root = root
        self.current_language = 'English'
        self.translations = LANGUAGES[self.current_language]
        self.current_theme = 'Default'  # Track current theme
        self.root.title(self.translations['title'])
        self.root.geometry("1400x1000")
        self.crypto = AES_Crypto()

        # Initialize style
        self.style = ttk.Style()
        self.style.theme_use('default')  # Set default theme

        # Initialize menu
        self.create_menu()

        # Create Notebook (Tabs)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(expand=1, fill='both')

        # Encryption Tab
        self.encrypt_frame = Frame(self.notebook)
        self.notebook.add(self.encrypt_frame, text=self.translations['encrypt_tab'])

        # Decryption Tab
        self.decrypt_frame = Frame(self.notebook)
        self.notebook.add(self.decrypt_frame, text=self.translations['decrypt_tab'])

        # Create Tabs
        self.create_encrypt_tab()
        self.create_decrypt_tab()

    def create_menu(self):
        self.menubar = Menu(self.root)

        # Language Menu
        self.language_menu = Menu(self.menubar, tearoff=0)
        for lang in LANGUAGES.keys():
            self.language_menu.add_command(label=lang, command=lambda l=lang: self.change_language(l))
        self.menubar.add_cascade(label=self.translations['language'], menu=self.language_menu)

        # Theme Menu
        self.theme_menu = Menu(self.menubar, tearoff=0)
        themes = self.style.theme_names()
        # Select more distinct themes
        distinct_themes = ['clam', 'alt', 'default', 'classic']
        for theme in distinct_themes:
            if theme in themes:
                self.theme_menu.add_command(label=theme, command=lambda t=theme: self.change_theme(t))
        # Add custom 'Hacker' theme
        self.theme_menu.add_separator()
        self.theme_menu.add_command(label=self.translations['hacker_theme'], command=lambda: self.change_theme('Hacker'))
        self.menubar.add_cascade(label=self.translations['theme'], menu=self.theme_menu)

        # Test Menu
        self.test_menu = Menu(self.menubar, tearoff=0)
        self.test_menu.add_command(label=self.translations['test_example'], command=self.load_test_example)
        self.menubar.add_cascade(label=self.translations['test_menu_label'], menu=self.test_menu)

        self.root.config(menu=self.menubar)

    def change_language(self, selected_language):
        self.current_language = selected_language
        self.translations = LANGUAGES[self.current_language]
        self.update_language()

    def update_language(self):
        self.root.title(self.translations['title'])
        # Update menu labels
        try:
            self.menubar.entryconfig(0, label=self.translations['language'])
            self.menubar.entryconfig(1, label=self.translations['theme'])
            self.menubar.entryconfig(2, label=self.translations['test_menu_label'])
        except Exception as e:
            messagebox.showerror(self.translations['error'], f"Menu update error: {str(e)}")

        # Update Test Menu entry label
        self.test_menu.entryconfig(0, label=self.translations['test_example'])

        # Update tabs
        self.notebook.tab(0, text=self.translations['encrypt_tab'])
        self.notebook.tab(1, text=self.translations['decrypt_tab'])

        # Update Encrypt Tab
        self.update_encrypt_tab_language()

        # Update Decrypt Tab
        self.update_decrypt_tab_language()

    def change_theme(self, selected_theme):
        try:
            if selected_theme == 'Hacker':
                self.apply_hacker_theme()
                self.current_theme = 'Hacker'
            else:
                self.style.theme_use(selected_theme)
                self.current_theme = selected_theme
                # Reset any custom styles if not in Hacker theme
                if selected_theme != 'Hacker':
                    self.reset_styles()
            # Update Canvas background based on theme
            self.update_canvas_backgrounds()
        except Exception as e:
            messagebox.showerror(self.translations['error'], f"Failed to apply theme: {selected_theme}\n{str(e)}")

    def apply_hacker_theme(self):
        # Define custom styles for Hacker theme
        self.style.theme_use('clam')  # Start with a base theme
        self.style.configure('.', background='black', foreground='lime', fieldbackground='black')
        self.style.configure('TButton', background='black', foreground='lime')
        self.style.configure('TLabel', background='black', foreground='lime')
        self.style.configure('TEntry', background='black', foreground='lime', fieldbackground='black')
        self.style.configure('TText', background='black', foreground='lime')
        self.style.configure('TFrame', background='black')
        self.style.configure('TLabelframe', background='black', foreground='lime')
        self.style.configure('TLabelframe.Label', background='black', foreground='lime')
        self.style.configure('TCheckbutton', background='black', foreground='lime')
        self.style.configure('TMenubutton', background='black', foreground='lime')
        # Update specific widget styles if needed
        self.style.map('TButton',
                       background=[('active', 'dark green')],
                       foreground=[('active', 'white')])
        self.style.map('TCheckbutton',
                       background=[('active', 'black')],
                       foreground=[('active', 'lime')])
        self.style.map('TMenubutton',
                       background=[('active', 'dark green')],
                       foreground=[('active', 'white')])
        # Set canvas background to black
        if hasattr(self, 'canvas_encrypt'):
            self.canvas_encrypt.config(bg='black')
        if hasattr(self, 'canvas_decrypt'):
            self.canvas_decrypt.config(bg='black')

    def reset_styles(self):
        # Reset styles to default
        self.style.theme_use('default')
        self.style.configure('.', background='SystemButtonFace', foreground='black', fieldbackground='white')
        self.style.configure('TButton', background='SystemButtonFace', foreground='black')
        self.style.configure('TLabel', background='SystemButtonFace', foreground='black')
        self.style.configure('TEntry', background='white', foreground='black', fieldbackground='white')
        self.style.configure('TText', background='white', foreground='black')
        self.style.configure('TFrame', background='SystemButtonFace')
        self.style.configure('TLabelframe', background='SystemButtonFace', foreground='black')
        self.style.configure('TLabelframe.Label', background='SystemButtonFace', foreground='black')
        self.style.configure('TCheckbutton', background='SystemButtonFace', foreground='black')
        self.style.configure('TMenubutton', background='SystemButtonFace', foreground='black')
        # Reset canvas background to white
        if hasattr(self, 'canvas_encrypt'):
            self.canvas_encrypt.config(bg='white')
        if hasattr(self, 'canvas_decrypt'):
            self.canvas_decrypt.config(bg='white')

    def update_canvas_backgrounds(self):
        if self.current_theme == 'Hacker':
            if hasattr(self, 'canvas_encrypt'):
                self.canvas_encrypt.config(bg='black')
            if hasattr(self, 'canvas_decrypt'):
                self.canvas_decrypt.config(bg='black')
        else:
            if hasattr(self, 'canvas_encrypt'):
                self.canvas_encrypt.config(bg='white')
            if hasattr(self, 'canvas_decrypt'):
                self.canvas_decrypt.config(bg='white')

    def create_encrypt_tab(self):
        frame = self.encrypt_frame

        # Key Settings
        key_frame = LabelFrame(frame, text=self.translations['key_label'], padx=10, pady=10)
        key_frame.pack(fill='x', padx=10, pady=5)

        self.encrypt_key_label = Label(key_frame, text=self.translations['key_label'])
        self.encrypt_key_label.grid(row=0, column=0, padx=5, pady=5, sticky='e')

        self.encrypt_key_size_var = IntVar(value=128)
        key_sizes = [128, 192, 256]
        self.encrypt_key_size_label = Label(key_frame, text=self.translations['key_size'])
        self.encrypt_key_size_label.grid(row=0, column=1, padx=5, pady=5, sticky='e')
        self.encrypt_key_size_menu = OptionMenu(key_frame, self.encrypt_key_size_var, *key_sizes)
        self.encrypt_key_size_menu.grid(row=0, column=2, padx=5, pady=5, sticky='w')

        self.generate_key_btn = Button(key_frame, text=self.translations['generate_key'], command=self.generate_key_encrypt)
        self.generate_key_btn.grid(row=0, column=3, padx=5, pady=5)

        self.encrypt_key_entry = Entry(key_frame, width=50)
        self.encrypt_key_entry.grid(row=1, column=0, columnspan=3, padx=5, pady=5)
        self.copy_key_btn_encrypt = Button(key_frame, text=self.translations['copy_key'], command=lambda: self.copy_to_clipboard(self.encrypt_key_entry.get()))
        self.copy_key_btn_encrypt.grid(row=1, column=3, padx=5, pady=5)

        # Encryption Settings
        settings_frame = LabelFrame(frame, text=self.translations['modes'], padx=10, pady=10)
        settings_frame.pack(fill='x', padx=10, pady=5)

        self.encrypt_mode_label = Label(settings_frame, text=self.translations['modes'])
        self.encrypt_mode_label.grid(row=0, column=0, padx=5, pady=5, sticky='e')

        self.encrypt_mode_var = StringVar(value='CTR')
        modes = ['CTR', 'CBC', 'ECB', 'GCM']
        self.encrypt_mode_menu = OptionMenu(settings_frame, self.encrypt_mode_var, *modes)
        self.encrypt_mode_menu.grid(row=0, column=1, padx=5, pady=5, sticky='w')

        # Advanced Settings (Custom IV)
        advanced_settings_frame = LabelFrame(settings_frame, text=self.translations['advanced_settings'], padx=10, pady=10)
        advanced_settings_frame.grid(row=1, column=0, columnspan=4, padx=5, pady=5, sticky='w')

        self.custom_iv_var = BooleanVar(value=False)
        self.custom_iv_checkbox = Checkbutton(advanced_settings_frame, text=self.translations['custom_iv'], variable=self.custom_iv_var, command=self.toggle_custom_iv)
        self.custom_iv_checkbox.pack(side='left', padx=5, pady=5)

        self.custom_iv_entry = Entry(advanced_settings_frame, width=50)
        self.custom_iv_entry.pack(side='left', padx=5, pady=5)
        self.custom_iv_entry.config(state='disabled')

        # Input Data
        data_frame = LabelFrame(frame, text=self.translations['input_data'], padx=10, pady=10)
        data_frame.pack(fill='both', expand=True, padx=10, pady=5)

        self.data_entry_encrypt = Text(data_frame, height=10, wrap=WORD)
        self.data_entry_encrypt.pack(fill='both', expand=True, padx=5, pady=5)

        # File Selection
        file_frame = Frame(data_frame)
        file_frame.pack(fill='x', padx=5, pady=5)

        self.select_encrypt_file_btn = Button(file_frame, text=self.translations['select_file_encrypt'], command=self.encrypt_file)
        self.select_encrypt_file_btn.pack(side='left', padx=5, pady=5)

        # Progress Bar
        self.progress_encrypt = ttk.Progressbar(frame, length=1300, mode='determinate', maximum=100)
        self.progress_encrypt.pack(pady=10)

        # Output
        output_frame = LabelFrame(frame, text=self.translations['output'], padx=10, pady=10)
        output_frame.pack(fill='both', expand=True, padx=10, pady=5)

        self.output_text_encrypt = Text(output_frame, height=10, wrap=WORD)
        self.output_text_encrypt.pack(fill='both', expand=True, padx=5, pady=5)

        self.save_encrypt_btn = Button(frame, text=self.translations['save_output'], command=lambda: self.save_output(self.output_text_encrypt))
        self.save_encrypt_btn.pack(pady=5)

        # Encrypt Button
        self.start_encrypt_btn = Button(frame, text=self.translations['encrypt_button'], command=self.start_encryption, width=20)
        self.start_encrypt_btn.pack(pady=10)

        # Visualization Canvas
        visualization_frame = LabelFrame(frame, text=self.translations['visualization'], padx=10, pady=10)
        visualization_frame.pack(fill='both', expand=True, padx=10, pady=5)

        # Canvas背景颜色根据当前主题设置
        canvas_bg = 'black' if self.current_theme == 'Hacker' else 'white'
        self.canvas_encrypt = Canvas(visualization_frame, width=1300, height=400, bg=canvas_bg)
        self.canvas_encrypt.pack(pady=10)

        self.encrypt_steps = [
            "Input Data",
            "Padding",
            "Key Expansion",
            "Initial Round",
            "Rounds\n(SubBytes, ShiftRows,\nMixColumns, AddRoundKey)",
            "Final Round\n(SubBytes, ShiftRows,\nAddRoundKey)",
            "Encrypted Data"
        ]

        self.encrypt_positions = [(50, 150), (250, 150), (450, 150), (650, 150), (850, 150), (1050, 150), (650, 300)]

        self.encrypt_rect_ids = []
        self.draw_flowchart(self.canvas_encrypt, self.encrypt_steps, self.encrypt_positions, "encryption")

    def create_decrypt_tab(self):
        frame = self.decrypt_frame

        # Key Settings
        key_frame = LabelFrame(frame, text=self.translations['key_label'], padx=10, pady=10)
        key_frame.pack(fill='x', padx=10, pady=5)

        self.decrypt_key_label = Label(key_frame, text=self.translations['key_label'])
        self.decrypt_key_label.grid(row=0, column=0, padx=5, pady=5, sticky='e')

        self.decrypt_key_size_var = IntVar(value=128)
        key_sizes = [128, 192, 256]
        self.decrypt_key_size_label = Label(key_frame, text=self.translations['key_size'])
        self.decrypt_key_size_label.grid(row=0, column=1, padx=5, pady=5, sticky='e')
        self.decrypt_key_size_menu = OptionMenu(key_frame, self.decrypt_key_size_var, *key_sizes)
        self.decrypt_key_size_menu.grid(row=0, column=2, padx=5, pady=5, sticky='w')

        self.decrypt_key_entry = Entry(key_frame, width=50)
        self.decrypt_key_entry.grid(row=1, column=0, columnspan=3, padx=5, pady=5)
        self.copy_key_btn_decrypt = Button(key_frame, text=self.translations['copy_key'], command=lambda: self.copy_to_clipboard(self.decrypt_key_entry.get()))
        self.copy_key_btn_decrypt.grid(row=1, column=3, padx=5, pady=5)

        # Decryption Settings
        settings_frame = LabelFrame(frame, text=self.translations['modes'], padx=10, pady=10)
        settings_frame.pack(fill='x', padx=10, pady=5)

        self.decrypt_mode_label = Label(settings_frame, text=self.translations['modes'])
        self.decrypt_mode_label.grid(row=0, column=0, padx=5, pady=5, sticky='e')

        self.decrypt_mode_var = StringVar(value='CTR')
        modes = ['CTR', 'CBC', 'ECB', 'GCM']
        self.decrypt_mode_menu = OptionMenu(settings_frame, self.decrypt_mode_var, *modes)
        self.decrypt_mode_menu.grid(row=0, column=1, padx=5, pady=5, sticky='w')

        # Advanced Settings (Custom IV)
        advanced_settings_frame = LabelFrame(settings_frame, text=self.translations['advanced_settings'], padx=10, pady=10)
        advanced_settings_frame.grid(row=1, column=0, columnspan=4, padx=5, pady=5, sticky='w')

        self.custom_iv_var_decrypt = BooleanVar(value=False)
        self.custom_iv_checkbox_decrypt = Checkbutton(advanced_settings_frame, text=self.translations['custom_iv'], variable=self.custom_iv_var_decrypt, command=self.toggle_custom_iv_decrypt)
        self.custom_iv_checkbox_decrypt.pack(side='left', padx=5, pady=5)

        self.custom_iv_entry_decrypt = Entry(advanced_settings_frame, width=50)
        self.custom_iv_entry_decrypt.pack(side='left', padx=5, pady=5)
        self.custom_iv_entry_decrypt.config(state='disabled')

        # Input Data
        data_frame = LabelFrame(frame, text=self.translations['input_data'], padx=10, pady=10)
        data_frame.pack(fill='both', expand=True, padx=10, pady=5)

        self.data_entry_decrypt = Text(data_frame, height=10, wrap=WORD)
        self.data_entry_decrypt.pack(fill='both', expand=True, padx=5, pady=5)

        # File Selection
        file_frame = Frame(data_frame)
        file_frame.pack(fill='x', padx=5, pady=5)

        self.select_decrypt_file_btn = Button(file_frame, text=self.translations['select_file_decrypt'], command=self.decrypt_file)
        self.select_decrypt_file_btn.pack(side='left', padx=5, pady=5)

        # Progress Bar
        self.progress_decrypt = ttk.Progressbar(frame, length=1300, mode='determinate', maximum=100)
        self.progress_decrypt.pack(pady=10)

        # Output
        output_frame = LabelFrame(frame, text=self.translations['output'], padx=10, pady=10)
        output_frame.pack(fill='both', expand=True, padx=10, pady=5)

        self.output_text_decrypt = Text(output_frame, height=10, wrap=WORD)
        self.output_text_decrypt.pack(fill='both', expand=True, padx=5, pady=5)

        self.save_decrypt_btn = Button(frame, text=self.translations['save_output'], command=lambda: self.save_output(self.output_text_decrypt))
        self.save_decrypt_btn.pack(pady=5)

        # Decrypt Button
        self.start_decrypt_btn = Button(frame, text=self.translations['decrypt_button'], command=self.start_decryption, width=20)
        self.start_decrypt_btn.pack(pady=10)

        # Visualization Canvas
        visualization_frame = LabelFrame(frame, text=self.translations['visualization'], padx=10, pady=10)
        visualization_frame.pack(fill='both', expand=True, padx=10, pady=5)

        # Canvas背景颜色根据当前主题设置
        canvas_bg = 'black' if self.current_theme == 'Hacker' else 'white'
        self.canvas_decrypt = Canvas(visualization_frame, width=1300, height=400, bg=canvas_bg)
        self.canvas_decrypt.pack(pady=10)

        self.decrypt_steps = [
            "Encrypted Data",
            "Initial Round",
            "Rounds\n(InvSubBytes, InvShiftRows,\nInvMixColumns, AddRoundKey)",
            "Final Round\n(InvSubBytes, InvShiftRows,\nAddRoundKey)",
            "Unpadding",
            "Decrypted Data"
        ]

        self.decrypt_positions = [(50, 150), (250, 150), (450, 150), (650, 150), (850, 150), (650, 300)]

        self.decrypt_rect_ids = []
        self.draw_flowchart(self.canvas_decrypt, self.decrypt_steps, self.decrypt_positions, "decryption")

    def toggle_custom_iv(self):
        if self.custom_iv_var.get():
            self.custom_iv_entry.config(state='normal')
        else:
            self.custom_iv_entry.config(state='disabled')
            self.custom_iv_entry.delete(0, END)

    def toggle_custom_iv_decrypt(self):
        if self.custom_iv_var_decrypt.get():
            self.custom_iv_entry_decrypt.config(state='normal')
        else:
            self.custom_iv_entry_decrypt.config(state='disabled')
            self.custom_iv_entry_decrypt.delete(0, END)

    def draw_flowchart(self, canvas, steps, positions, mode_type):
        canvas.delete("all")
        rect_ids = []
        for i, (step, pos) in enumerate(zip(steps, positions)):
            x, y = pos
            if mode_type == "encryption":
                fill_color = '#87CEFA'  # Light Blue
                text_color = 'black'
            else:
                fill_color = '#FFA07A'  # Light Salmon
                text_color = 'black'
            rect = canvas.create_rectangle(x, y, x+200, y+60, fill=fill_color, outline='black')
            text = canvas.create_text(x+100, y+30, text=step, width=190, justify='center', fill=text_color)
            rect_ids.append(rect)
            rect_ids.append(text)

        # Draw arrows
        for i in range(len(positions)-1):
            x1, y1 = positions[i]
            x2, y2 = positions[i+1]
            canvas.create_line(x1+200, y1+30, x2, y2+30, arrow=LAST, width=2)

        # Start and End points
        if mode_type == "encryption":
            start_text = self.translations['aes_flow']
            end_text = self.translations['encryption_complete']
        else:
            start_text = self.translations['aes_decryption_flow']
            end_text = self.translations['decryption_complete']

        canvas.create_text(100, 50, text=start_text, font=('Arial', 14, 'bold'), fill='lime' if self.current_theme == 'Hacker' else 'black')
        canvas.create_text(1200, 50, text=end_text, font=('Arial', 14, 'bold'), fill='lime' if self.current_theme == 'Hacker' else 'black')

        if mode_type == "encryption":
            self.encrypt_rect_ids = rect_ids
        else:
            self.decrypt_rect_ids = rect_ids

    def update_language_elements(self, elements):
        for element, key in elements:
            element.config(text=self.translations.get(key, key))

    def update_encrypt_tab_language(self):
        frame = self.encrypt_frame

        # Update key frame
        key_frame = frame.winfo_children()[0]
        key_frame.config(text=self.translations['key_label'])

        self.encrypt_key_label.config(text=self.translations['key_label'])
        self.encrypt_key_size_label.config(text=self.translations['key_size'])
        self.generate_key_btn.config(text=self.translations['generate_key'])
        self.copy_key_btn_encrypt.config(text=self.translations['copy_key'])

        self.encrypt_mode_label.config(text=self.translations['modes'])
        self.encrypt_mode_menu['menu'].delete(0, 'end')
        for mode in ['CTR', 'CBC', 'ECB', 'GCM']:
            self.encrypt_mode_menu['menu'].add_command(label=mode, command=lambda value=mode: self.encrypt_mode_var.set(value))

        self.custom_iv_checkbox.config(text=self.translations['custom_iv'])

        self.select_encrypt_file_btn.config(text=self.translations['select_file_encrypt'])
        self.save_encrypt_btn.config(text=self.translations['save_output'])
        self.start_encrypt_btn.config(text=self.translations['encrypt_button'])

        # Update output frame
        output_frame = frame.winfo_children()[3]
        output_frame.config(text=self.translations['output'])

        # Update visualization
        visualization_frame = frame.winfo_children()[4]
        visualization_frame.config(text=self.translations['visualization'])
        self.canvas_encrypt.delete("all")
        self.draw_flowchart(self.canvas_encrypt, self.encrypt_steps, self.encrypt_positions, "encryption")

    def update_decrypt_tab_language(self):
        frame = self.decrypt_frame

        # Update key frame
        key_frame = frame.winfo_children()[0]
        key_frame.config(text=self.translations['key_label'])

        self.decrypt_key_label.config(text=self.translations['key_label'])
        self.decrypt_key_size_label.config(text=self.translations['key_size'])
        self.copy_key_btn_decrypt.config(text=self.translations['copy_key'])

        self.decrypt_mode_label.config(text=self.translations['modes'])
        self.decrypt_mode_menu['menu'].delete(0, 'end')
        for mode in ['CTR', 'CBC', 'ECB', 'GCM']:
            self.decrypt_mode_menu['menu'].add_command(label=mode, command=lambda value=mode: self.decrypt_mode_var.set(value))

        self.custom_iv_checkbox_decrypt.config(text=self.translations['custom_iv'])

        self.select_decrypt_file_btn.config(text=self.translations['select_file_decrypt'])
        self.save_decrypt_btn.config(text=self.translations['save_output'])
        self.start_decrypt_btn.config(text=self.translations['decrypt_button'])

        # Update output frame
        output_frame = frame.winfo_children()[3]
        output_frame.config(text=self.translations['output'])

        # Update visualization
        visualization_frame = frame.winfo_children()[4]
        visualization_frame.config(text=self.translations['visualization'])
        self.canvas_decrypt.delete("all")
        self.draw_flowchart(self.canvas_decrypt, self.decrypt_steps, self.decrypt_positions, "decryption")

    def generate_key_encrypt(self):
        key_size = self.encrypt_key_size_var.get()
        self.crypto.key_size = key_size
        key = self.crypto.generate_random_key()
        self.encrypt_key_entry.delete(0, END)
        self.encrypt_key_entry.insert(0, key)

    def copy_to_clipboard(self, text):
        if not text.strip():
            messagebox.showwarning(self.translations['warning'], self.translations['copy_warning'])
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        messagebox.showinfo(self.translations['information'], self.translations['copy_success'])

    def save_output(self, text_widget):
        data = text_widget.get("1.0", END).strip()
        if not data:
            messagebox.showwarning(self.translations['warning'], self.translations['save_warning'])
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                                 filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(data)
                messagebox.showinfo(self.translations['information'], self.translations['save_success'].format(file_path))
            except Exception as e:
                messagebox.showerror(self.translations['error'], self.translations['save_failure'].format(str(e)))

    def start_encryption(self):
        # Disable buttons during encryption
        self.start_encrypt_btn.config(state='disabled')
        self.select_encrypt_file_btn.config(state='disabled')
        self.save_encrypt_btn.config(state='disabled')

        threading.Thread(target=self.encrypt).start()

    def encrypt(self):
        self.progress_encrypt['value'] = 0
        self.output_text_encrypt.delete("1.0", END)
        data = self.data_entry_encrypt.get("1.0", END).strip().encode('utf-8')  # Treat input as bytes
        key = self.encrypt_key_entry.get().strip()
        mode = self.encrypt_mode_var.get()
        key_size = self.encrypt_key_size_var.get()
        use_custom_iv = self.custom_iv_var.get()
        custom_iv = self.custom_iv_entry.get().strip() if use_custom_iv else None

        if not key:
            self.output_text_encrypt.insert(END, self.translations['missing_key'] + "\n")
            self.enable_encrypt_buttons()
            return

        # Start timeout timer
        timeout = 30  # seconds
        start_time = time.time()

        try:
            self.progress_encrypt['value'] += 5
            self.root.update_idletasks()

            self.crypto = AES_Crypto(key_size=key_size, mode=mode)
            if self.is_base64(key):
                self.crypto.set_key(key)
            else:
                # 自动将密钥编码为Base64
                encoded_key = base64.b64encode(key.encode('utf-8')).decode('utf-8')
                self.crypto.set_key(encoded_key)

            if use_custom_iv:
                if not self.is_base64(custom_iv):
                    self.output_text_encrypt.insert(END, self.translations['invalid_iv'] + "\n")
                    self.enable_encrypt_buttons()
                    return
                decoded_iv = base64.b64decode(custom_iv)
                if mode == 'GCM' and len(decoded_iv) != 12:
                    self.output_text_encrypt.insert(END, self.translations['invalid_iv'] + "\n")
                    self.enable_encrypt_buttons()
                    return
                elif mode in ['CBC', 'CTR'] and len(decoded_iv) != 16:
                    self.output_text_encrypt.insert(END, self.translations['invalid_iv'] + "\n")
                    self.enable_encrypt_buttons()
                    return
                self.crypto.iv = decoded_iv

            self.progress_encrypt['value'] += 5
            self.root.update_idletasks()
            self.update_visualization("encryption", 0)

            if data:
                encrypted_data, iv = self.crypto.encrypt(data, callback=lambda msg: self.update_encrypt_output(msg))
                self.output_text_encrypt.insert(END, f"Encrypted Data:\n{encrypted_data}\n\n")
                if iv:
                    self.output_text_encrypt.insert(END, f"IV (Base64):\n{iv}\n\n")
                self.progress_encrypt['value'] += 80
                self.output_text_encrypt.insert(END, self.translations['encryption_complete'] + "\n")
            else:
                self.output_text_encrypt.insert(END, self.translations['missing_data'] + "\n")
                self.update_visualization("encryption", len(self.encrypt_steps))

            self.progress_encrypt['value'] = 100
            self.update_visualization("encryption", len(self.encrypt_steps))

            # Check for timeout
            elapsed_time = time.time() - start_time
            if elapsed_time > timeout:
                messagebox.showwarning(self.translations['warning'], f"Encryption exceeded {timeout} seconds and was stopped.")
        except Exception as e:
            messagebox.showerror(self.translations['error'], f"{self.translations['error']}: {str(e)}")
            self.progress_encrypt['value'] = 0
        finally:
            self.enable_encrypt_buttons()

    def update_encrypt_output(self, msg):
        self.output_text_encrypt.insert(END, f"{msg}\n")
        # 根据消息映射步骤
        step_map = {
            "Padding complete.": 1,
            "Encryption complete.": 2,
        }
        step_index = step_map.get(msg, -1)
        if step_index != -1:
            self.update_visualization("encryption", step_index)
            self.progress_encrypt['value'] += 20
            self.root.update_idletasks()
            time.sleep(0.5)  # 模拟延迟以展示可视化

    def enable_encrypt_buttons(self):
        self.start_encrypt_btn.config(state='normal')
        self.select_encrypt_file_btn.config(state='normal')
        self.save_encrypt_btn.config(state='normal')

    def start_decryption(self):
        # Disable buttons during decryption
        self.start_decrypt_btn.config(state='disabled')
        self.select_decrypt_file_btn.config(state='disabled')
        self.save_decrypt_btn.config(state='disabled')

        threading.Thread(target=self.decrypt).start()

    def decrypt(self):
        self.progress_decrypt['value'] = 0
        self.output_text_decrypt.delete("1.0", END)
        data = self.data_entry_decrypt.get("1.0", END).strip()
        key = self.decrypt_key_entry.get().strip()
        mode = self.decrypt_mode_var.get()
        key_size = self.decrypt_key_size_var.get()
        use_custom_iv = self.custom_iv_var_decrypt.get()
        custom_iv = self.custom_iv_entry_decrypt.get().strip() if use_custom_iv else None

        if not key:
            self.output_text_decrypt.insert(END, self.translations['missing_key'] + "\n")
            self.enable_decrypt_buttons()
            return

        # Start timeout timer
        timeout = 30  # seconds
        start_time = time.time()

        try:
            self.progress_decrypt['value'] += 5
            self.root.update_idletasks()

            self.crypto = AES_Crypto(key_size=key_size, mode=mode)
            if self.is_base64(key):
                self.crypto.set_key(key)
            else:
                # 自动将密钥编码为Base64
                encoded_key = base64.b64encode(key.encode('utf-8')).decode('utf-8')
                self.crypto.set_key(encoded_key)

            if use_custom_iv:
                if not self.is_base64(custom_iv):
                    self.output_text_decrypt.insert(END, self.translations['invalid_iv'] + "\n")
                    self.enable_decrypt_buttons()
                    return
                decoded_iv = base64.b64decode(custom_iv)
                if mode == 'GCM' and len(decoded_iv) != 12:
                    self.output_text_decrypt.insert(END, self.translations['invalid_iv'] + "\n")
                    self.enable_decrypt_buttons()
                    return
                elif mode in ['CBC', 'CTR'] and len(decoded_iv) != 16:
                    self.output_text_decrypt.insert(END, self.translations['invalid_iv'] + "\n")
                    self.enable_decrypt_buttons()
                    return
                self.crypto.iv = decoded_iv

            self.progress_decrypt['value'] += 5
            self.root.update_idletasks()
            self.update_visualization("decryption", 0)

            if data:
                decrypted_data = self.crypto.decrypt(data, iv=custom_iv if use_custom_iv else None, callback=lambda msg: self.update_decrypt_output(msg))
                if isinstance(decrypted_data, bytes):
                    # 如果是二进制数据
                    self.output_text_decrypt.insert(END, f"Decrypted Data (binary):\n{decrypted_data}\n\n")
                else:
                    self.output_text_decrypt.insert(END, f"Decrypted Data:\n{decrypted_data}\n\n")
                self.progress_decrypt['value'] += 80
                self.output_text_decrypt.insert(END, self.translations['decryption_complete'] + "\n")
            else:
                self.output_text_decrypt.insert(END, self.translations['missing_data'] + "\n")
                self.update_visualization("decryption", len(self.decrypt_steps))

            self.progress_decrypt['value'] = 100
            self.update_visualization("decryption", len(self.decrypt_steps))

            # Check for timeout
            elapsed_time = time.time() - start_time
            if elapsed_time > timeout:
                messagebox.showwarning(self.translations['warning'], f"Decryption exceeded {timeout} seconds and was stopped.")
        except Exception as e:
            messagebox.showerror(self.translations['error'], f"{self.translations['error']}: {str(e)}")
            self.progress_decrypt['value'] = 0
        finally:
            self.enable_decrypt_buttons()

    def update_decrypt_output(self, msg):
        self.output_text_decrypt.insert(END, f"{msg}\n")
        # 根据消息映射步骤
        step_map = {
            "Decryption complete.": 1,
            "Unpadding complete.": 2,
        }
        step_index = step_map.get(msg, -1)
        if step_index != -1:
            self.update_visualization("decryption", step_index)
            self.progress_decrypt['value'] += 20
            self.root.update_idletasks()
            time.sleep(0.5)  # 模拟延迟以展示可视化

    def enable_decrypt_buttons(self):
        self.start_decrypt_btn.config(state='normal')
        self.select_decrypt_file_btn.config(state='normal')
        self.save_decrypt_btn.config(state='normal')

    def is_base64(self, s):
        try:
            # 添加必要的填充
            missing_padding = len(s) % 4
            if missing_padding:
                s += '=' * (4 - missing_padding)
            return base64.b64encode(base64.b64decode(s)).decode('utf-8') == s
        except Exception:
            return False

    def encrypt_file(self):
        file_path = filedialog.askopenfilename(title=self.translations['select_file_encrypt'])
        if not file_path:
            return

        key = self.encrypt_key_entry.get().strip()
        mode = self.encrypt_mode_var.get()
        key_size = self.encrypt_key_size_var.get()
        use_custom_iv = self.custom_iv_var.get()
        custom_iv = self.custom_iv_entry.get().strip() if use_custom_iv else None

        if not key:
            messagebox.showwarning(self.translations['warning'], self.translations['missing_key'])
            return

        threading.Thread(target=self.encrypt_file_thread, args=(file_path, key, mode, key_size, use_custom_iv, custom_iv)).start()

    def encrypt_file_thread(self, file_path, key, mode, key_size, use_custom_iv, custom_iv):
        try:
            self.progress_encrypt['value'] = 0
            self.output_text_encrypt.delete("1.0", END)

            self.crypto = AES_Crypto(key_size=key_size, mode=mode)
            if self.is_base64(key):
                self.crypto.set_key(key)
            else:
                # 自动将密钥编码为Base64
                encoded_key = base64.b64encode(key.encode('utf-8')).decode('utf-8')
                self.crypto.set_key(encoded_key)

            if use_custom_iv:
                if not self.is_base64(custom_iv):
                    self.output_text_encrypt.insert(END, self.translations['invalid_iv'] + "\n")
                    return
                decoded_iv = base64.b64decode(custom_iv)
                if mode == 'GCM' and len(decoded_iv) != 12:
                    self.output_text_encrypt.insert(END, self.translations['invalid_iv'] + "\n")
                    return
                elif mode in ['CBC', 'CTR'] and len(decoded_iv) != 16:
                    self.output_text_encrypt.insert(END, self.translations['invalid_iv'] + "\n")
                    return
                self.crypto.iv = decoded_iv

            # 检测文件类型
            mime_type, _ = mimetypes.guess_type(file_path)
            if mime_type:
                if mime_type.startswith('image/'):
                    is_binary = True
                elif mime_type.startswith('text/'):
                    is_binary = False
                else:
                    # 支持其他常见类型或根据需要调整
                    is_binary = True
            else:
                # 如果无法猜测，基于文件内容判断
                try:
                    with open(file_path, 'rb') as f:
                        chunk = f.read(1024)
                        if b'\0' in chunk:
                            is_binary = True
                        else:
                            is_binary = False
                except Exception as e:
                    is_binary = False

            if is_binary:
                self.output_text_encrypt.insert(END, "Detected binary file. Proceeding with binary encryption.\n")
            else:
                self.output_text_encrypt.insert(END, "Detected text file. Proceeding with text encryption.\n")

            self.progress_encrypt['value'] += 10
            self.root.update_idletasks()

            with open(file_path, 'rb') as f:
                data = f.read()
            self.update_visualization_file("encryption", 0)

            encrypted_data, iv = self.crypto.encrypt(data, callback=lambda msg: self.update_encrypt_output_file(msg))
            self.output_text_encrypt.insert(END, f"Encrypted Data:\n{encrypted_data}\n\n")
            if iv:
                self.output_text_encrypt.insert(END, f"IV (Base64):\n{iv}\n\n")

            self.progress_encrypt['value'] += 70
            self.root.update_idletasks()

            save_path = filedialog.asksaveasfilename(defaultextension=".enc",
                                                     filetypes=[("Encrypted Files", "*.enc"), ("All Files", "*.*")])
            if save_path:
                with open(save_path, 'w') as f:
                    f.write(encrypted_data)
                if iv:
                    with open(save_path + ".iv", 'w') as f_iv:
                        f_iv.write(iv)
                self.progress_encrypt['value'] += 10
                self.output_text_encrypt.insert(END, f"{self.translations['save_success'].format(save_path)}\n")
                if iv:
                    self.output_text_encrypt.insert(END, f"IV saved to: {save_path}.iv\n")
            else:
                self.output_text_encrypt.insert(END, f"{self.translations['save_warning']}\n")

            self.progress_encrypt['value'] = 100
            self.update_visualization_file("encryption", len(self.encrypt_steps))
            self.output_text_encrypt.insert(END, self.translations['encryption_complete'] + "\n")
        except Exception as e:
            messagebox.showerror(self.translations['error'], f"{self.translations['error']}: {str(e)}")
            self.progress_encrypt['value'] = 0

    def update_encrypt_output_file(self, msg):
        self.output_text_encrypt.insert(END, f"{msg}\n")
        # 这里可以根据需要映射消息到步骤
        # 简化处理，不逐步更新可视化
        time.sleep(0.5)

    def decrypt_file(self):
        file_path = filedialog.askopenfilename(title=self.translations['select_file_decrypt'],
                                               filetypes=[("Encrypted Files", "*.enc"), ("All Files", "*.*")])
        if not file_path:
            return

        key = self.decrypt_key_entry.get().strip()
        mode = self.decrypt_mode_var.get()
        key_size = self.decrypt_key_size_var.get()
        use_custom_iv = self.custom_iv_var_decrypt.get()
        custom_iv = self.custom_iv_entry_decrypt.get().strip() if use_custom_iv else None

        if not key:
            messagebox.showwarning(self.translations['warning'], self.translations['missing_key'])
            return

        threading.Thread(target=self.decrypt_file_thread, args=(file_path, key, mode, key_size, use_custom_iv, custom_iv)).start()

    def decrypt_file_thread(self, file_path, key, mode, key_size, use_custom_iv, custom_iv):
        try:
            self.progress_decrypt['value'] = 0
            self.output_text_decrypt.delete("1.0", END)

            self.crypto = AES_Crypto(key_size=key_size, mode=mode)
            if self.is_base64(key):
                self.crypto.set_key(key)
            else:
                # 自动将密钥编码为Base64
                encoded_key = base64.b64encode(key.encode('utf-8')).decode('utf-8')
                self.crypto.set_key(encoded_key)

            if use_custom_iv:
                if not self.is_base64(custom_iv):
                    self.output_text_decrypt.insert(END, self.translations['invalid_iv'] + "\n")
                    return
                decoded_iv = base64.b64decode(custom_iv)
                if mode == 'GCM' and len(decoded_iv) != 12:
                    self.output_text_decrypt.insert(END, self.translations['invalid_iv'] + "\n")
                    return
                elif mode in ['CBC', 'CTR'] and len(decoded_iv) != 16:
                    self.output_text_decrypt.insert(END, self.translations['invalid_iv'] + "\n")
                    return
                self.crypto.iv = decoded_iv

            # 检测文件类型
            mime_type, _ = mimetypes.guess_type(file_path)
            if mime_type:
                if mime_type.startswith('image/'):
                    is_binary = True
                elif mime_type.startswith('text/'):
                    is_binary = False
                else:
                    # 支持其他常见类型或根据需要调整
                    is_binary = True
            else:
                # 如果无法猜测，基于文件内容判断
                try:
                    with open(file_path, 'rb') as f:
                        chunk = f.read(1024)
                        if b'\0' in chunk:
                            is_binary = True
                        else:
                            is_binary = False
                except Exception as e:
                    is_binary = False

            if is_binary:
                self.output_text_decrypt.insert(END, "Detected binary file. Proceeding with binary decryption.\n")
            else:
                self.output_text_decrypt.insert(END, "Detected text file. Proceeding with text decryption.\n")

            self.progress_decrypt['value'] += 10
            self.root.update_idletasks()

            with open(file_path, 'r') as f:
                encrypted_data = f.read()
            self.update_visualization_file("decryption", 0)

            decrypted_data = self.crypto.decrypt(encrypted_data, iv=custom_iv if use_custom_iv else None, callback=lambda msg: self.update_decrypt_output(msg))
            if isinstance(decrypted_data, bytes):
                # 如果是二进制数据
                self.output_text_decrypt.insert(END, f"Decrypted Data (binary):\n{decrypted_data}\n\n")
            else:
                self.output_text_decrypt.insert(END, f"Decrypted Data:\n{decrypted_data}\n\n")
            self.progress_decrypt['value'] += 80
            self.output_text_decrypt.insert(END, self.translations['decryption_complete'] + "\n")

            save_path = filedialog.asksaveasfilename(defaultextension=".dec",
                                                     filetypes=[("Decrypted Files", "*.dec"), ("All Files", "*.*")])
            if save_path:
                if isinstance(decrypted_data, bytes):
                    with open(save_path, 'wb') as f:
                        f.write(decrypted_data)
                else:
                    with open(save_path, 'w', encoding='utf-8') as f:
                        f.write(decrypted_data)
                self.progress_decrypt['value'] += 10
                self.output_text_decrypt.insert(END, f"{self.translations['save_success'].format(save_path)}\n")
            else:
                self.output_text_decrypt.insert(END, f"{self.translations['save_warning']}\n")

            self.progress_decrypt['value'] = 100
            self.update_visualization_file("decryption", len(self.decrypt_steps))
        except Exception as e:
            messagebox.showerror(self.translations['error'], f"{self.translations['error']}: {str(e)}")
            self.progress_decrypt['value'] = 0

    def update_decrypt_output(self, msg):
        self.output_text_decrypt.insert(END, f"{msg}\n")
        # 根据消息映射步骤
        step_map = {
            "Decryption complete.": 1,
            "Unpadding complete.": 2,
        }
        step_index = step_map.get(msg, -1)
        if step_index != -1:
            self.update_visualization("decryption", step_index)
            self.progress_decrypt['value'] += 20
            self.root.update_idletasks()
            time.sleep(0.5)  # 模拟延迟以展示可视化

    def draw_flowchart(self, canvas, steps, positions, mode_type):
        canvas.delete("all")
        rect_ids = []
        for i, (step, pos) in enumerate(zip(steps, positions)):
            x, y = pos
            if mode_type == "encryption":
                fill_color = '#87CEFA'  # Light Blue
                text_color = 'black'
            else:
                fill_color = '#FFA07A'  # Light Salmon
                text_color = 'black'
            rect = canvas.create_rectangle(x, y, x+200, y+60, fill=fill_color, outline='black')
            text = canvas.create_text(x+100, y+30, text=step, width=190, justify='center', fill=text_color)
            rect_ids.append(rect)
            rect_ids.append(text)

        # Draw arrows
        for i in range(len(positions)-1):
            x1, y1 = positions[i]
            x2, y2 = positions[i+1]
            canvas.create_line(x1+200, y1+30, x2, y2+30, arrow=LAST, width=2)

        # Start and End points
        if mode_type == "encryption":
            start_text = self.translations['aes_flow']
            end_text = self.translations['encryption_complete']
        else:
            start_text = self.translations['aes_decryption_flow']
            end_text = self.translations['decryption_complete']

        canvas.create_text(100, 50, text=start_text, font=('Arial', 14, 'bold'), fill='lime' if self.current_theme == 'Hacker' else 'black')
        canvas.create_text(1200, 50, text=end_text, font=('Arial', 14, 'bold'), fill='lime' if self.current_theme == 'Hacker' else 'black')

        if mode_type == "encryption":
            self.encrypt_rect_ids = rect_ids
        else:
            self.decrypt_rect_ids = rect_ids

    def update_visualization(self, mode_type, step_index):
        if mode_type == "encryption":
            canvas = self.canvas_encrypt
            rect_ids = self.encrypt_rect_ids
        else:
            canvas = self.canvas_decrypt
            rect_ids = self.decrypt_rect_ids

        # 重置所有矩形为原始颜色
        for i in range(0, len(rect_ids), 2):
            if mode_type == "encryption":
                fill_color = '#87CEFA'  # Light Blue
            else:
                fill_color = '#FFA07A'  # Light Salmon
            canvas.itemconfig(rect_ids[i], fill=fill_color)

        # 高亮当前步骤
        if step_index < len(rect_ids)//2:
            rect_id = rect_ids[step_index*2]
            canvas.itemconfig(rect_id, fill='yellow')

    def update_visualization_file(self, mode_type, step_index):
        # 简化处理，不逐步更新可视化
        pass

    def load_test_example(self):
        if self.notebook.index("current") == 0:
            # Encrypt Tab
            sample_key = "ThisIsA16ByteKey"  # 128-bit key
            sample_data = "Hello, this is a test message with 中文字符!"
            self.encrypt_key_entry.delete(0, END)
            self.encrypt_key_entry.insert(0, base64.b64encode(sample_key.encode('utf-8')).decode('utf-8'))
            self.encrypt_key_size_var.set(128)
            self.encrypt_mode_var.set('CBC')
            self.custom_iv_var.set(True)
            self.custom_iv_entry.config(state='normal')
            # 使用CBC模式生成IV
            crypto_temp = AES_Crypto(key_size=128, mode='CBC')
            crypto_temp.set_key(base64.b64encode(sample_key.encode('utf-8')).decode('utf-8'))
            encrypted_data, iv = crypto_temp.encrypt(sample_data)
            self.custom_iv_entry.delete(0, END)
            self.custom_iv_entry.insert(0, iv)
            self.custom_iv_entry.config(state='normal')
            self.data_entry_encrypt.delete("1.0", END)
            self.data_entry_encrypt.insert("1.0", sample_data)
        else:
            # Decrypt Tab
            sample_key = "ThisIsA16ByteKey"  # 128-bit key
            sample_plaintext = "This is a sample encrypted message."
            crypto_temp = AES_Crypto(key_size=128, mode='CBC')
            crypto_temp.set_key(base64.b64encode(sample_key.encode('utf-8')).decode('utf-8'))
            encrypted_data, iv = crypto_temp.encrypt(sample_plaintext)
            # Pre-fill decrypt tab
            self.decrypt_key_entry.delete(0, END)
            self.decrypt_key_entry.insert(0, base64.b64encode(sample_key.encode('utf-8')).decode('utf-8'))
            self.decrypt_key_size_var.set(128)
            self.decrypt_mode_var.set('CBC')
            self.custom_iv_var_decrypt.set(True)
            self.custom_iv_entry_decrypt.config(state='normal')
            self.custom_iv_entry_decrypt.delete(0, END)
            self.custom_iv_entry_decrypt.insert(0, iv)
            self.data_entry_decrypt.delete("1.0", END)
            self.data_entry_decrypt.insert("1.0", encrypted_data)

    def encrypt_file(self):
        file_path = filedialog.askopenfilename(title=self.translations['select_file_encrypt'])
        if not file_path:
            return

        key = self.encrypt_key_entry.get().strip()
        mode = self.encrypt_mode_var.get()
        key_size = self.encrypt_key_size_var.get()
        use_custom_iv = self.custom_iv_var.get()
        custom_iv = self.custom_iv_entry.get().strip() if use_custom_iv else None

        if not key:
            messagebox.showwarning(self.translations['warning'], self.translations['missing_key'])
            return

        threading.Thread(target=self.encrypt_file_thread, args=(file_path, key, mode, key_size, use_custom_iv, custom_iv)).start()

    def encrypt_file_thread(self, file_path, key, mode, key_size, use_custom_iv, custom_iv):
        try:
            self.progress_encrypt['value'] = 0
            self.output_text_encrypt.delete("1.0", END)

            self.crypto = AES_Crypto(key_size=key_size, mode=mode)
            if self.is_base64(key):
                self.crypto.set_key(key)
            else:
                # 自动将密钥编码为Base64
                encoded_key = base64.b64encode(key.encode('utf-8')).decode('utf-8')
                self.crypto.set_key(encoded_key)

            if use_custom_iv:
                if not self.is_base64(custom_iv):
                    self.output_text_encrypt.insert(END, self.translations['invalid_iv'] + "\n")
                    return
                decoded_iv = base64.b64decode(custom_iv)
                if mode == 'GCM' and len(decoded_iv) != 12:
                    self.output_text_encrypt.insert(END, self.translations['invalid_iv'] + "\n")
                    return
                elif mode in ['CBC', 'CTR'] and len(decoded_iv) != 16:
                    self.output_text_encrypt.insert(END, self.translations['invalid_iv'] + "\n")
                    return
                self.crypto.iv = decoded_iv

            # 检测文件类型
            mime_type, _ = mimetypes.guess_type(file_path)
            if mime_type:
                if mime_type.startswith('image/'):
                    is_binary = True
                elif mime_type.startswith('text/'):
                    is_binary = False
                else:
                    # 支持其他常见类型或根据需要调整
                    is_binary = True
            else:
                # 如果无法猜测，基于文件内容判断
                try:
                    with open(file_path, 'rb') as f:
                        chunk = f.read(1024)
                        if b'\0' in chunk:
                            is_binary = True
                        else:
                            is_binary = False
                except Exception as e:
                    is_binary = False

            if is_binary:
                self.output_text_encrypt.insert(END, "Detected binary file. Proceeding with binary encryption.\n")
            else:
                self.output_text_encrypt.insert(END, "Detected text file. Proceeding with text encryption.\n")

            self.progress_encrypt['value'] += 10
            self.root.update_idletasks()

            with open(file_path, 'rb') as f:
                data = f.read()
            self.update_visualization_file("encryption", 0)

            encrypted_data, iv = self.crypto.encrypt(data, callback=lambda msg: self.update_encrypt_output_file(msg))
            self.output_text_encrypt.insert(END, f"Encrypted Data:\n{encrypted_data}\n\n")
            if iv:
                self.output_text_encrypt.insert(END, f"IV (Base64):\n{iv}\n\n")

            self.progress_encrypt['value'] += 70
            self.root.update_idletasks()

            save_path = filedialog.asksaveasfilename(defaultextension=".enc",
                                                     filetypes=[("Encrypted Files", "*.enc"), ("All Files", "*.*")])
            if save_path:
                with open(save_path, 'w') as f:
                    f.write(encrypted_data)
                if iv:
                    with open(save_path + ".iv", 'w') as f_iv:
                        f_iv.write(iv)
                self.progress_encrypt['value'] += 10
                self.output_text_encrypt.insert(END, f"{self.translations['save_success'].format(save_path)}\n")
                if iv:
                    self.output_text_encrypt.insert(END, f"IV saved to: {save_path}.iv\n")
            else:
                self.output_text_encrypt.insert(END, f"{self.translations['save_warning']}\n")

            self.progress_encrypt['value'] = 100
            self.update_visualization_file("encryption", len(self.encrypt_steps))
            self.output_text_encrypt.insert(END, self.translations['encryption_complete'] + "\n")
        except Exception as e:
            messagebox.showerror(self.translations['error'], f"{self.translations['error']}: {str(e)}")
            self.progress_encrypt['value'] = 0

    def update_encrypt_output_file(self, msg):
        self.output_text_encrypt.insert(END, f"{msg}\n")
        # 这里可以根据需要映射消息到步骤
        # 简化处理，不逐步更新可视化
        time.sleep(0.5)

    def decrypt_file(self):
        file_path = filedialog.askopenfilename(title=self.translations['select_file_decrypt'],
                                               filetypes=[("Encrypted Files", "*.enc"), ("All Files", "*.*")])
        if not file_path:
            return

        key = self.decrypt_key_entry.get().strip()
        mode = self.decrypt_mode_var.get()
        key_size = self.decrypt_key_size_var.get()
        use_custom_iv = self.custom_iv_var_decrypt.get()
        custom_iv = self.custom_iv_entry_decrypt.get().strip() if use_custom_iv else None

        if not key:
            messagebox.showwarning(self.translations['warning'], self.translations['missing_key'])
            return

        threading.Thread(target=self.decrypt_file_thread, args=(file_path, key, mode, key_size, use_custom_iv, custom_iv)).start()

    def decrypt_file_thread(self, file_path, key, mode, key_size, use_custom_iv, custom_iv):
        try:
            self.progress_decrypt['value'] = 0
            self.output_text_decrypt.delete("1.0", END)

            self.crypto = AES_Crypto(key_size=key_size, mode=mode)
            if self.is_base64(key):
                self.crypto.set_key(key)
            else:
                # 自动将密钥编码为Base64
                encoded_key = base64.b64encode(key.encode('utf-8')).decode('utf-8')
                self.crypto.set_key(encoded_key)

            if use_custom_iv:
                if not self.is_base64(custom_iv):
                    self.output_text_decrypt.insert(END, self.translations['invalid_iv'] + "\n")
                    return
                decoded_iv = base64.b64decode(custom_iv)
                if mode == 'GCM' and len(decoded_iv) != 12:
                    self.output_text_decrypt.insert(END, self.translations['invalid_iv'] + "\n")
                    return
                elif mode in ['CBC', 'CTR'] and len(decoded_iv) != 16:
                    self.output_text_decrypt.insert(END, self.translations['invalid_iv'] + "\n")
                    return
                self.crypto.iv = decoded_iv

            # 检测文件类型
            mime_type, _ = mimetypes.guess_type(file_path)
            if mime_type:
                if mime_type.startswith('image/'):
                    is_binary = True
                elif mime_type.startswith('text/'):
                    is_binary = False
                else:
                    # 支持其他常见类型或根据需要调整
                    is_binary = True
            else:
                # 如果无法猜测，基于文件内容判断
                try:
                    with open(file_path, 'rb') as f:
                        chunk = f.read(1024)
                        if b'\0' in chunk:
                            is_binary = True
                        else:
                            is_binary = False
                except Exception as e:
                    is_binary = False

            if is_binary:
                self.output_text_decrypt.insert(END, "Detected binary file. Proceeding with binary decryption.\n")
            else:
                self.output_text_decrypt.insert(END, "Detected text file. Proceeding with text decryption.\n")

            self.progress_decrypt['value'] += 10
            self.root.update_idletasks()

            with open(file_path, 'r') as f:
                encrypted_data = f.read()
            self.update_visualization_file("decryption", 0)

            decrypted_data = self.crypto.decrypt(encrypted_data, iv=custom_iv if use_custom_iv else None, callback=lambda msg: self.update_decrypt_output(msg))
            if isinstance(decrypted_data, bytes):
                # 如果是二进制数据
                self.output_text_decrypt.insert(END, f"Decrypted Data (binary):\n{decrypted_data}\n\n")
            else:
                self.output_text_decrypt.insert(END, f"Decrypted Data:\n{decrypted_data}\n\n")
            self.progress_decrypt['value'] += 80
            self.output_text_decrypt.insert(END, self.translations['decryption_complete'] + "\n")

            save_path = filedialog.asksaveasfilename(defaultextension=".dec",
                                                     filetypes=[("Decrypted Files", "*.dec"), ("All Files", "*.*")])
            if save_path:
                if isinstance(decrypted_data, bytes):
                    with open(save_path, 'wb') as f:
                        f.write(decrypted_data)
                else:
                    with open(save_path, 'w', encoding='utf-8') as f:
                        f.write(decrypted_data)
                self.progress_decrypt['value'] += 10
                self.output_text_decrypt.insert(END, f"{self.translations['save_success'].format(save_path)}\n")
            else:
                self.output_text_decrypt.insert(END, f"{self.translations['save_warning']}\n")

            self.progress_decrypt['value'] = 100
            self.update_visualization_file("decryption", len(self.decrypt_steps))
        except Exception as e:
            messagebox.showerror(self.translations['error'], f"{self.translations['error']}: {str(e)}")
            self.progress_decrypt['value'] = 0

    def update_decrypt_output(self, msg):
        self.output_text_decrypt.insert(END, f"{msg}\n")
        # 根据消息映射步骤
        step_map = {
            "Decryption complete.": 1,
            "Unpadding complete.": 2,
        }
        step_index = step_map.get(msg, -1)
        if step_index != -1:
            self.update_visualization("decryption", step_index)
            self.progress_decrypt['value'] += 20
            self.root.update_idletasks()
            time.sleep(0.5)  # 模拟延迟以展示可视化

    def save_output(self, text_widget):
        data = text_widget.get("1.0", END).strip()
        if not data:
            messagebox.showwarning(self.translations['warning'], self.translations['save_warning'])
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                                 filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(data)
                messagebox.showinfo(self.translations['information'], self.translations['save_success'].format(file_path))
            except Exception as e:
                messagebox.showerror(self.translations['error'], self.translations['save_failure'].format(str(e)))

    def update_visualization_file(self, mode_type, step_index):
        # 简化处理，不逐步更新可视化
        pass

def main():
    root = Tk()  # 使用标准的 Tk 实例
    app = AES_GUI(root)
    root.mainloop()

if __name__ == '__main__':
    main()
