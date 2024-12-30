import hashlib
import os
import random
import time
from typing import Callable, List
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox, simpledialog
import threading
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# Ensure that matplotlib uses a backend compatible with Tkinter
plt.switch_backend('TkAgg')

# ----------------------------- Feistel Cipher Implementation -----------------------------

class FeistelCipher:
    def __init__(self, rounds: int, master_key: bytes, F_function: Callable[[int, int], int]):
        """
        Initialize the Feistel cipher.
        """
        self.rounds = rounds
        self.master_key = master_key
        self.F = F_function
        self.round_keys = self.key_schedule(master_key, rounds)

    def key_schedule(self, master_key: bytes, rounds: int) -> List[int]:
        """
        Generate a list of round keys using SHA-256 derived from the master key.
        """
        round_keys = []
        hash_digest = hashlib.sha256(master_key).digest()
        for i in range(rounds):
            # Use a different salt for each round
            data = hash_digest + i.to_bytes(4, byteorder='big')
            round_key = int.from_bytes(hashlib.sha256(data).digest()[:4], byteorder='big')
            round_keys.append(round_key)
        return round_keys

    def pad(self, data: bytes) -> bytes:
        """
        Apply PKCS#7 padding to ensure the data length is a multiple of 8 bytes.
        """
        pad_len = 8 - (len(data) % 8)
        return data + bytes([pad_len] * pad_len)

    def unpad(self, data: bytes) -> bytes:
        """
        Remove PKCS#7 padding.
        """
        pad_len = data[-1]
        return data[:-pad_len]

    def encrypt_block(self, block: int) -> int:
        """
        Encrypt a single 64-bit block.
        """
        L = (block >> 32) & 0xFFFFFFFF
        R = block & 0xFFFFFFFF

        for i in range(self.rounds):
            K = self.round_keys[i]
            F_out = self.F(R, K)
            L, R = R, L ^ F_out

        # Combine left and right parts
        return (L << 32) | R

    def decrypt_block(self, block: int) -> int:
        """
        Decrypt a single 64-bit block.
        """
        L = (block >> 32) & 0xFFFFFFFF
        R = block & 0xFFFFFFFF

        for i in reversed(range(self.rounds)):
            K = self.round_keys[i]
            F_out = self.F(L, K)
            L, R = R ^ F_out, L

        # Combine left and right parts
        return (L << 32) | R

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt data of arbitrary length.
        """
        plaintext = self.pad(plaintext)
        ciphertext = b''
        for i in range(0, len(plaintext), 8):
            block = plaintext[i:i + 8]
            block_int = int.from_bytes(block, byteorder='big')
            cipher_block_int = self.encrypt_block(block_int)
            cipher_block = cipher_block_int.to_bytes(8, byteorder='big')
            ciphertext += cipher_block
        return ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decrypt data of arbitrary length.
        """
        plaintext = b''
        for i in range(0, len(ciphertext), 8):
            block = ciphertext[i:i + 8]
            block_int = int.from_bytes(block, byteorder='big')
            plain_block_int = self.decrypt_block(block_int)
            plain_block = plain_block_int.to_bytes(8, byteorder='big')
            plaintext += plain_block
        plaintext = self.unpad(plaintext)
        return plaintext

# ----------------------------- Round Functions -----------------------------

def linear_F(data: int, key: int) -> int:
    """
    Linear round function: simple XOR operation.
    """
    return (data ^ key) & 0xFFFFFFFF

def nonlinear_F(data: int, key: int) -> int:
    """
    Non-linear round function: includes shifting and mixing operations.
    """
    combined = (data + key) & 0xFFFFFFFF
    combined = ((combined << 5) | (combined >> 27)) & 0xFFFFFFFF  # Rotate left 5 bits
    combined = combined ^ ((combined >> 12) & 0xFFFFF)
    return combined

def hash_based_F(data: int, key: int) -> int:
    """
    Hash-based round function: uses SHA-256 hash function.
    """
    combined = (data ^ key).to_bytes(4, byteorder='big')
    hash_digest = hashlib.sha256(combined).digest()
    return int.from_bytes(hash_digest[:4], byteorder='big')

# ----------------------------- Helper Functions -----------------------------

def bit_difference(a: int, b: int) -> int:
    """
    Calculate the number of differing bits between two integers.
    """
    return bin(a ^ b).count('1')

def flip_random_bit(data: bytes) -> bytes:
    """
    Flip a random bit in the data.
    """
    byte_arr = bytearray(data)
    byte_idx = random.randint(0, len(byte_arr) - 1)
    bit_idx = random.randint(0, 7)
    byte_arr[byte_idx] ^= 1 << bit_idx
    return bytes(byte_arr)

def get_random_plaintext(length: int = 8) -> bytes:
    """
    Generate random plaintext.
    """
    return os.urandom(length)

# ----------------------------- GUI Application -----------------------------

class FeistelCipherGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Feistel Cipher Encryption and Analysis")
        self.current_style = 'Classic Dark'  # Default style
        self.set_style(self.current_style)
        self.create_widgets()

    def set_style(self, style_name):
        # Set theme based on the style_name
        style = ttk.Style()
        style.theme_use('clam')

        if style_name == 'Hacker':
            self.root.configure(bg='#1e1e1e')
            style.configure('.', background='#1e1e1e', foreground='#00ff00', fieldbackground='#252526', font=('Fira Code', 10))
            style.configure('TButton', background='#252526', foreground='#00ff00', font=('Fira Code', 10))
            style.configure('TLabel', background='#1e1e1e', foreground='#00ff00', font=('Fira Code', 10))
            style.configure('TEntry', background='#252526', foreground='#00ff00', fieldbackground='#252526', font=('Fira Code', 10))
            style.configure('TCombobox', fieldbackground='#252526', background='#252526', foreground='#00ff00', font=('Fira Code', 10))
            style.configure('TMenubutton', background='#252526', foreground='#00ff00', font=('Fira Code', 10))
            style.configure('TNotebook', background='#1e1e1e', foreground='#00ff00', font=('Fira Code', 10))
            style.configure('TNotebook.Tab', background='#252526', foreground='#00ff00', font=('Fira Code', 10))
            style.map('TButton', background=[('active', '#333333')])
            self.text_bg = '#252526'
            self.text_fg = '#00ff00'
            self.plot_bg = '#1e1e1e'
            self.plot_facecolor = '#252526'
            self.plot_grid_color = '#333333'
            self.plot_label_color = '#00ff00'
        elif style_name == 'Classic Dark':
            self.root.configure(bg='#2b2b2b')
            style.configure('.', background='#2b2b2b', foreground='#dcdcdc', fieldbackground='#3c3f41', font=('Segoe UI', 10))
            style.configure('TButton', background='#3c3f41', foreground='#dcdcdc', font=('Segoe UI', 10), borderwidth=1)
            style.configure('TLabel', background='#2b2b2b', foreground='#dcdcdc', font=('Segoe UI', 10))
            style.configure('TEntry', background='#3c3f41', foreground='#dcdcdc', fieldbackground='#3c3f41', font=('Segoe UI', 10))
            style.configure('TCombobox', fieldbackground='#3c3f41', background='#3c3f41', foreground='#dcdcdc', font=('Segoe UI', 10))
            style.configure('TMenubutton', background='#3c3f41', foreground='#dcdcdc', font=('Segoe UI', 10))
            style.configure('TNotebook', background='#2b2b2b', foreground='#dcdcdc', font=('Segoe UI', 10))
            style.configure('TNotebook.Tab', background='#3c3f41', foreground='#dcdcdc', font=('Segoe UI', 10))
            style.map('TButton', background=[('active', '#5c5f61')])
            self.text_bg = '#3c3f41'
            self.text_fg = '#dcdcdc'
            self.plot_bg = '#2b2b2b'
            self.plot_facecolor = '#3c3f41'
            self.plot_grid_color = '#555555'
            self.plot_label_color = '#dcdcdc'
        elif style_name == 'Minimal':
            self.root.configure(bg='#f0f0f0')
            style.configure('.', background='#f0f0f0', foreground='#000000', fieldbackground='#ffffff', font=('Segoe UI', 10))
            style.configure('TButton', background='#e0e0e0', foreground='#000000', font=('Segoe UI', 10))
            style.configure('TLabel', background='#f0f0f0', foreground='#000000', font=('Segoe UI', 10))
            style.configure('TEntry', background='#ffffff', foreground='#000000', fieldbackground='#ffffff', font=('Segoe UI', 10))
            style.configure('TCombobox', fieldbackground='#ffffff', background='#ffffff', foreground='#000000', font=('Segoe UI', 10))
            style.configure('TMenubutton', background='#e0e0e0', foreground='#000000', font=('Segoe UI', 10))
            style.configure('TNotebook', background='#f0f0f0', foreground='#000000', font=('Segoe UI', 10))
            style.configure('TNotebook.Tab', background='#e0e0e0', foreground='#000000', font=('Segoe UI', 10))
            style.map('TButton', background=[('active', '#d0d0d0')])
            self.text_bg = '#ffffff'
            self.text_fg = '#000000'
            self.plot_bg = '#f0f0f0'
            self.plot_facecolor = '#ffffff'
            self.plot_grid_color = '#cccccc'
            self.plot_label_color = '#000000'

    def create_widgets(self):
        # Menu Bar
        self.create_menu()

        # Main Notebook
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(expand=1, fill='both')

        # Encryption/Decryption Tab
        self.enc_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.enc_tab, text='Encrypt/Decrypt')

        # Analysis Tab
        self.analysis_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.analysis_tab, text='Analysis')

        # Create content for tabs
        self.create_encrypt_decrypt_tab()
        self.create_analysis_tab()

    def create_menu(self):
        menubar = tk.Menu(self.root)

        # About Menu
        about_menu = tk.Menu(menubar, tearoff=0)
        about_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=about_menu)

        # Style Menu
        style_menu = tk.Menu(menubar, tearoff=0)
        style_menu.add_command(label="Hacker Style", command=lambda: self.change_style('Hacker'))
        style_menu.add_command(label="Classic Dark Style", command=lambda: self.change_style('Classic Dark'))
        style_menu.add_command(label="Minimal Style", command=lambda: self.change_style('Minimal'))
        menubar.add_cascade(label="Style", menu=style_menu)

        self.root.config(menu=menubar)

    def show_about(self):
        message = "Feistel Cipher Encryption and Analysis Tool\nVersion 1.0\nDeveloped by OpenAI's ChatGPT"
        messagebox.showinfo("About", message)

    def change_style(self, style_name):
        self.current_style = style_name
        self.set_style(style_name)
        # Reconfigure text widgets with new styles
        self.update_text_widget_styles()

    def update_text_widget_styles(self):
        # Update text widgets in encryption/decryption tab
        self.plaintext_text.configure(bg=self.text_bg, fg=self.text_fg, insertbackground=self.text_fg)
        self.ciphertext_text.configure(bg=self.text_bg, fg=self.text_fg, insertbackground=self.text_fg)
        self.decrypted_text.configure(bg=self.text_bg, fg=self.text_fg, insertbackground=self.text_fg)
        # Update text widget in analysis tab
        self.analysis_text.configure(bg=self.text_bg, fg=self.text_fg, insertbackground=self.text_fg)

    def create_encrypt_decrypt_tab(self):
        # Parameters Frame
        self.create_parameters_frame(self.enc_tab)

        # Encryption/Decryption Frame
        self.create_encryption_frame(self.enc_tab)

    def create_parameters_frame(self, parent):
        params_frame = ttk.LabelFrame(parent, text="Encryption Parameters")
        params_frame.pack(padx=10, pady=10, fill='x')

        # Number of Rounds
        ttk.Label(params_frame, text="Number of Rounds:").grid(row=0, column=0, padx=5, pady=5, sticky='e')
        self.rounds_var = tk.IntVar(value=16)
        self.rounds_entry = ttk.Entry(params_frame, textvariable=self.rounds_var, width=10)
        self.rounds_entry.grid(row=0, column=1, padx=5, pady=5, sticky='w')

        # Key Length
        ttk.Label(params_frame, text="Key Length (bits):").grid(row=0, column=2, padx=5, pady=5, sticky='e')
        self.key_length_var = tk.IntVar(value=128)
        self.key_length_combo = ttk.Combobox(params_frame, textvariable=self.key_length_var, state='readonly', width=10)
        self.key_length_combo['values'] = (64, 128, 256)
        self.key_length_combo.grid(row=0, column=3, padx=5, pady=5, sticky='w')

        # Round Function
        ttk.Label(params_frame, text="Round Function:").grid(row=0, column=4, padx=5, pady=5, sticky='e')
        self.round_function_var = tk.StringVar(value='Hash-based')
        self.round_function_combo = ttk.Combobox(params_frame, textvariable=self.round_function_var, state='readonly', width=12)
        self.round_function_combo['values'] = ('Linear', 'Nonlinear', 'Hash-based')
        self.round_function_combo.grid(row=0, column=5, padx=5, pady=5, sticky='w')

        # Generate Key Button
        self.generate_key_button = ttk.Button(params_frame, text="Generate Key", command=self.generate_key)
        self.generate_key_button.grid(row=0, column=6, padx=5, pady=5, sticky='w')

        # Save Key Button
        self.save_key_button = ttk.Button(params_frame, text="Save Key", command=self.save_key)
        self.save_key_button.grid(row=0, column=7, padx=5, pady=5, sticky='w')

        # Load Key Button
        self.load_key_button = ttk.Button(params_frame, text="Load Key", command=self.load_key)
        self.load_key_button.grid(row=0, column=8, padx=5, pady=5, sticky='w')

        # Key Display
        ttk.Label(params_frame, text="Master Key:").grid(row=1, column=0, padx=5, pady=5, sticky='e')
        self.master_key_var = tk.StringVar()
        self.master_key_entry = ttk.Entry(params_frame, textvariable=self.master_key_var, width=80)
        self.master_key_entry.grid(row=1, column=1, columnspan=8, padx=5, pady=5, sticky='w')

    def create_encryption_frame(self, parent):
        io_frame = ttk.Frame(parent)
        io_frame.pack(padx=10, pady=10, fill='both', expand=True)

        # Centering the text boxes
        io_frame.columnconfigure(0, weight=1)
        io_frame.columnconfigure(1, weight=1)

        # Plaintext Input
        ttk.Label(io_frame, text="Plaintext:").grid(row=0, column=0, columnspan=2, padx=5, pady=5, sticky='n')
        self.plaintext_text = scrolledtext.ScrolledText(io_frame, wrap=tk.WORD, width=60, height=10, font=('Consolas', 10))
        self.plaintext_text.grid(row=1, column=0, columnspan=2, padx=5, pady=5, sticky='n')
        self.plaintext_text.configure(bg=self.text_bg, fg=self.text_fg, insertbackground=self.text_fg)

        # Encrypt Button
        self.encrypt_button = ttk.Button(io_frame, text="Encrypt", command=self.encrypt_text)
        self.encrypt_button.grid(row=2, column=0, columnspan=2, padx=5, pady=5)

        # Ciphertext Output
        ttk.Label(io_frame, text="Ciphertext (Hex):").grid(row=3, column=0, columnspan=2, padx=5, pady=5, sticky='n')
        self.ciphertext_text = scrolledtext.ScrolledText(io_frame, wrap=tk.WORD, width=60, height=10, font=('Consolas', 10))
        self.ciphertext_text.grid(row=4, column=0, columnspan=2, padx=5, pady=5, sticky='n')
        self.ciphertext_text.configure(bg=self.text_bg, fg=self.text_fg, insertbackground=self.text_fg)

        # Save Ciphertext Button
        self.save_ciphertext_button = ttk.Button(io_frame, text="Save Ciphertext", command=self.save_ciphertext)
        self.save_ciphertext_button.grid(row=5, column=0, padx=5, pady=5, sticky='e')

        # Decrypt Button
        self.decrypt_button = ttk.Button(io_frame, text="Decrypt", command=self.decrypt_text)
        self.decrypt_button.grid(row=5, column=1, padx=5, pady=5, sticky='w')

        # Decrypted Text Output
        ttk.Label(io_frame, text="Decrypted Text:").grid(row=6, column=0, columnspan=2, padx=5, pady=5, sticky='n')
        self.decrypted_text = scrolledtext.ScrolledText(io_frame, wrap=tk.WORD, width=60, height=10, font=('Consolas', 10))
        self.decrypted_text.grid(row=7, column=0, columnspan=2, padx=5, pady=5, sticky='n')
        self.decrypted_text.configure(bg=self.text_bg, fg=self.text_fg, insertbackground=self.text_fg)

        # Save Decrypted Text Button
        self.save_decrypted_button = ttk.Button(io_frame, text="Save Decrypted Text", command=self.save_decrypted_text)
        self.save_decrypted_button.grid(row=8, column=0, columnspan=2, padx=5, pady=5)

    def create_analysis_tab(self):
        analysis_frame = ttk.Frame(self.analysis_tab)
        analysis_frame.pack(padx=10, pady=10, fill='both', expand=True)

        # Frame for Analysis Options
        options_frame = ttk.LabelFrame(analysis_frame, text="Analysis Options")
        options_frame.pack(padx=10, pady=10, fill='x')

        # Number of Tests for Avalanche Effect
        ttk.Label(options_frame, text="Number of Tests:").grid(row=0, column=0, padx=5, pady=5, sticky='e')
        self.num_tests_var = tk.IntVar(value=1000)
        self.num_tests_entry = ttk.Entry(options_frame, textvariable=self.num_tests_var, width=10)
        self.num_tests_entry.grid(row=0, column=1, padx=5, pady=5, sticky='w')

        # Data Sizes for Performance Test
        ttk.Label(options_frame, text="Performance Test Sizes (bytes):").grid(row=0, column=2, padx=5, pady=5, sticky='e')
        self.data_sizes_var = tk.StringVar(value='64,128,256,512,1024')
        self.data_sizes_entry = ttk.Entry(options_frame, textvariable=self.data_sizes_var, width=20)
        self.data_sizes_entry.grid(row=0, column=3, padx=5, pady=5, sticky='w')

        # Analysis Buttons
        buttons_frame = ttk.Frame(analysis_frame)
        buttons_frame.pack(padx=10, pady=10, fill='x')

        self.avalanche_button = ttk.Button(buttons_frame, text="Avalanche Effect Test", command=self.perform_avalanche_test)
        self.avalanche_button.pack(padx=5, pady=5, fill='x')

        self.difference_button = ttk.Button(buttons_frame, text="Difference Propagation Visualization", command=self.perform_difference_propagation)
        self.difference_button.pack(padx=5, pady=5, fill='x')

        self.performance_button = ttk.Button(buttons_frame, text="Performance Test", command=self.perform_performance_test)
        self.performance_button.pack(padx=5, pady=5, fill='x')

        self.differential_button = ttk.Button(buttons_frame, text="Differential Cryptanalysis Test", command=self.perform_differential_cryptanalysis)
        self.differential_button.pack(padx=5, pady=5, fill='x')

        # Progress Bar
        self.progress = ttk.Progressbar(analysis_frame, orient=tk.HORIZONTAL, length=300, mode='determinate')
        self.progress.pack(padx=10, pady=10)

        # Canvas for Plots
        self.plot_canvas = None

        # Text Box for Analysis Results
        ttk.Label(analysis_frame, text="Analysis Results:").pack(padx=5, pady=5, anchor='nw')
        self.analysis_text = scrolledtext.ScrolledText(analysis_frame, wrap=tk.WORD, width=80, height=10, font=('Consolas', 10))
        self.analysis_text.pack(padx=5, pady=5, fill='both', expand=True)
        self.analysis_text.configure(bg=self.text_bg, fg=self.text_fg, insertbackground=self.text_fg)

    # ----------------------------- Key Management -----------------------------

    def generate_key(self):
        key_length_bits = self.key_length_var.get()
        key_length_bytes = key_length_bits // 8
        master_key = os.urandom(key_length_bytes)
        self.master_key_var.set(master_key.hex())

    def save_key(self):
        master_key_hex = self.master_key_var.get()
        if not master_key_hex:
            messagebox.showwarning("No Key", "No master key to save.")
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".key", filetypes=[("Key Files", "*.key"), ("All Files", "*.*")])
        if file_path:
            with open(file_path, 'w') as f:
                f.write(master_key_hex)
            messagebox.showinfo("Success", "Master key saved successfully.")

    def load_key(self):
        file_path = filedialog.askopenfilename(filetypes=[("Key Files", "*.key"), ("All Files", "*.*")])
        if file_path:
            with open(file_path, 'r') as f:
                master_key_hex = f.read().strip()
            self.master_key_var.set(master_key_hex)
            messagebox.showinfo("Success", "Master key loaded successfully.")

    # ----------------------------- Encryption and Decryption -----------------------------

    def get_cipher_instance(self):
        rounds = self.rounds_var.get()
        key_length_bits = self.key_length_var.get()
        round_function_name = self.round_function_var.get()

        if rounds <= 0:
            messagebox.showerror("Invalid Number of Rounds", "Number of rounds must be a positive integer.")
            return None
        if key_length_bits not in (64, 128, 256):
            messagebox.showerror("Invalid Key Length", "Key length must be 64, 128, or 256 bits.")
            return None
        if round_function_name not in ('Linear', 'Nonlinear', 'Hash-based'):
            messagebox.showerror("Invalid Round Function", "Please select a valid round function.")
            return None

        # Get master key
        master_key_hex = self.master_key_var.get()
        if not master_key_hex:
            messagebox.showerror("Master Key Missing", "Please generate or input a master key.")
            return None
        try:
            master_key = bytes.fromhex(master_key_hex)
        except ValueError:
            messagebox.showerror("Invalid Master Key", "Master key must be a valid hexadecimal string.")
            return None

        # Select round function
        F_functions = {
            'Linear': linear_F,
            'Nonlinear': nonlinear_F,
            'Hash-based': hash_based_F
        }
        F_function = F_functions[round_function_name]

        # Initialize cipher
        cipher = FeistelCipher(rounds=rounds, master_key=master_key, F_function=F_function)
        return cipher

    def encrypt_text(self):
        plaintext = self.plaintext_text.get('1.0', tk.END).strip()
        if not plaintext:
            messagebox.showwarning("Plaintext Missing", "Please enter plaintext to encrypt.")
            return
        cipher = self.get_cipher_instance()
        if cipher is None:
            return
        plaintext_bytes = plaintext.encode('utf-8')
        ciphertext_bytes = cipher.encrypt(plaintext_bytes)
        self.ciphertext_text.delete('1.0', tk.END)
        self.ciphertext_text.insert(tk.END, ciphertext_bytes.hex())

    def decrypt_text(self):
        ciphertext_hex = self.ciphertext_text.get('1.0', tk.END).strip()
        if not ciphertext_hex:
            messagebox.showwarning("Ciphertext Missing", "Please enter ciphertext to decrypt.")
            return
        cipher = self.get_cipher_instance()
        if cipher is None:
            return
        try:
            ciphertext_bytes = bytes.fromhex(ciphertext_hex)
        except ValueError:
            messagebox.showerror("Invalid Ciphertext", "Ciphertext must be a valid hexadecimal string.")
            return
        try:
            plaintext_bytes = cipher.decrypt(ciphertext_bytes)
            plaintext = plaintext_bytes.decode('utf-8')
        except Exception as e:
            messagebox.showerror("Decryption Error", f"An error occurred during decryption:\n{e}")
            return
        self.decrypted_text.delete('1.0', tk.END)
        self.decrypted_text.insert(tk.END, plaintext)

    # ----------------------------- Save Functions -----------------------------

    def save_ciphertext(self):
        ciphertext_hex = self.ciphertext_text.get('1.0', tk.END).strip()
        if not ciphertext_hex:
            messagebox.showwarning("No Ciphertext", "No ciphertext to save.")
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if file_path:
            with open(file_path, 'w') as f:
                f.write(ciphertext_hex)
            messagebox.showinfo("Success", "Ciphertext saved successfully.")

    def save_decrypted_text(self):
        decrypted_text = self.decrypted_text.get('1.0', tk.END).strip()
        if not decrypted_text:
            messagebox.showwarning("No Decrypted Text", "No decrypted text to save.")
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if file_path:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(decrypted_text)
            messagebox.showinfo("Success", "Decrypted text saved successfully.")

    # ----------------------------- Analysis Functions -----------------------------

    def perform_avalanche_test(self):
        cipher = self.get_cipher_instance()
        if cipher is None:
            return

        try:
            num_tests = int(self.num_tests_var.get())
            if num_tests <= 0:
                raise ValueError
        except ValueError:
            messagebox.showerror("Invalid Input", "Number of tests must be a positive integer.")
            return

        threading.Thread(target=self.run_avalanche_test, args=(cipher, num_tests)).start()

    def run_avalanche_test(self, cipher, num_tests):
        self.progress['maximum'] = num_tests
        differences = []

        for i in range(num_tests):
            plaintext = get_random_plaintext(8)
            modified_plaintext = flip_random_bit(plaintext)
            ciphertext1 = cipher.encrypt(plaintext)
            ciphertext2 = cipher.encrypt(modified_plaintext)
            ct1_int = int.from_bytes(ciphertext1, byteorder='big')
            ct2_int = int.from_bytes(ciphertext2, byteorder='big')
            diff = bit_difference(ct1_int, ct2_int)
            differences.append(diff)
            self.progress['value'] = i + 1

        avg_diff = sum(differences) / len(differences)
        result_text = f"Avalanche Effect Test Completed.\nAverage Bit Differences: {avg_diff:.2f} / 64"
        self.analysis_text.insert(tk.END, result_text + '\n')
        self.show_plot(plot_avalanche, differences, title='Avalanche Effect Histogram')

    def perform_difference_propagation(self):
        cipher = self.get_cipher_instance()
        if cipher is None:
            return
        plaintext_block = b'ABCDEFGH'  # 8 bytes
        modified_plaintext_block = flip_random_bit(plaintext_block)
        diffs = difference_propagation(cipher, plaintext_block, modified_plaintext_block)
        result_text = "Difference Propagation Visualization Completed."
        self.analysis_text.insert(tk.END, result_text + '\n')
        self.show_plot(plot_difference_propagation, diffs, rounds=cipher.rounds, title='Difference Propagation Over Rounds')

    def perform_performance_test(self):
        cipher = self.get_cipher_instance()
        if cipher is None:
            return

        try:
            data_sizes = [int(size.strip()) for size in self.data_sizes_var.get().split(',')]
            if not data_sizes or any(size <= 0 for size in data_sizes):
                raise ValueError
        except ValueError:
            messagebox.showerror("Invalid Input", "Data sizes must be positive integers separated by commas.")
            return

        threading.Thread(target=self.run_performance_test, args=(cipher, data_sizes)).start()

    def run_performance_test(self, cipher, data_sizes):
        self.progress['maximum'] = len(data_sizes)
        encrypt_times = []
        decrypt_times = []

        for idx, size in enumerate(data_sizes):
            plaintext = os.urandom(size)

            # Test encryption time
            start_time = time.time()
            ciphertext = cipher.encrypt(plaintext)
            end_time = time.time()
            encrypt_times.append(end_time - start_time)

            # Test decryption time
            start_time = time.time()
            decrypted = cipher.decrypt(ciphertext)
            end_time = time.time()
            decrypt_times.append(end_time - start_time)

            # Verify correctness
            assert decrypted == plaintext, f"Decryption failed! Data size: {size} bytes"

            self.progress['value'] = idx + 1

        result_text = "Performance Test Completed."
        self.analysis_text.insert(tk.END, result_text + '\n')
        self.show_plot(plot_performance, data_sizes, encrypt_times, decrypt_times, title='Encryption and Decryption Performance')

    def perform_differential_cryptanalysis(self):
        cipher = self.get_cipher_instance()
        if cipher is None:
            return

        threading.Thread(target=self.run_differential_cryptanalysis, args=(cipher,)).start()

    def run_differential_cryptanalysis(self, cipher):
        self.progress['maximum'] = 10
        known_plaintexts = [get_random_plaintext(8) for _ in range(10)]
        known_ciphertexts = []
        for idx, pt in enumerate(known_plaintexts):
            ct = cipher.encrypt(pt)
            known_ciphertexts.append(ct)
            self.progress['value'] = idx + 1

        # Simple differential cryptanalysis (illustrative)
        diffs = {}
        for i in range(len(known_plaintexts)):
            for j in range(i + 1, len(known_plaintexts)):
                pt1 = known_plaintexts[i]
                pt2 = known_plaintexts[j]
                ct1 = known_ciphertexts[i]
                ct2 = known_ciphertexts[j]
                pt_diff = int.from_bytes(pt1, 'big') ^ int.from_bytes(pt2, 'big')
                ct_diff = int.from_bytes(ct1, 'big') ^ int.from_bytes(ct2, 'big')
                diffs[pt_diff] = diffs.get(pt_diff, 0) + 1

        # Prepare result text
        result_text = "Differential Cryptanalysis Test Completed.\nMost common plaintext differences and their counts:\n"
        sorted_diffs = sorted(diffs.items(), key=lambda item: item[1], reverse=True)
        for diff, count in sorted_diffs[:5]:
            result_text += f"Difference: {diff:016x}, Count: {count}\n"

        result_text += "\nNote: This is a simplified example."
        self.analysis_text.insert(tk.END, result_text + '\n')

    def show_plot(self, plot_function, *args, **kwargs):
        # Clear previous plot
        if self.plot_canvas:
            self.plot_canvas.get_tk_widget().destroy()

        # Create a figure and plot
        fig = plt.Figure(figsize=(8, 6))
        ax = fig.add_subplot(111)

        # Customize plot based on style
        fig.patch.set_facecolor(self.plot_bg)
        ax.set_facecolor(self.plot_facecolor)
        ax.tick_params(colors=self.plot_label_color)
        ax.xaxis.label.set_color(self.plot_label_color)
        ax.yaxis.label.set_color(self.plot_label_color)
        ax.title.set_color(self.plot_label_color)
        grid_color = self.plot_grid_color

        # Pass the axis to the plot function
        kwargs['ax'] = ax
        plot_function(*args, **kwargs)

        # Set grid color
        ax.grid(True, linestyle='--', alpha=0.7, color=grid_color)

        # Embed the plot in the Tkinter window
        self.plot_canvas = FigureCanvasTkAgg(fig, master=self.analysis_tab)
        self.plot_canvas.draw()
        self.plot_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

# ----------------------------- Visualization Functions -----------------------------

def plot_avalanche(differences: List[int], title: str = 'Avalanche Effect Histogram', ax=None):
    """
    Plot a histogram of the avalanche effect.
    """
    ax.hist(differences, bins=range(0, 65), edgecolor='black', alpha=0.7, density=True)
    ax.set_title(title, fontsize=16)
    ax.set_xlabel('Number of Bit Differences', fontsize=14)
    ax.set_ylabel('Frequency', fontsize=14)
    ax.set_xticks(range(0, 65, 4))

def plot_difference_propagation(diffs: List[int], rounds: int, title: str = 'Difference Propagation Over Rounds', ax=None):
    """
    Plot the propagation of bit differences over rounds.
    """
    ax.plot(range(1, rounds + 1), diffs, marker='o', linestyle='-')
    ax.set_title(title, fontsize=16)
    ax.set_xlabel('Round', fontsize=14)
    ax.set_ylabel('Number of Bit Differences', fontsize=14)
    ax.set_xticks(range(1, rounds + 1))
    ax.set_ylim(0, max(diffs) + 5)

def plot_performance(data_sizes: List[int], encrypt_times: List[float], decrypt_times: List[float], title: str = 'Encryption and Decryption Performance', ax=None):
    """
    Plot encryption and decryption times against data sizes.
    """
    ax.plot(data_sizes, encrypt_times, label='Encryption Time', marker='o', linestyle='-')
    ax.plot(data_sizes, decrypt_times, label='Decryption Time', marker='x', linestyle='--')
    ax.set_title(title, fontsize=16)
    ax.set_xlabel('Data Size (bytes)', fontsize=14)
    ax.set_ylabel('Time (seconds)', fontsize=14)
    ax.legend(fontsize=12)
    ax.set_xscale('log')
    ax.set_yscale('log')
    ax.set_xticks(data_sizes)
    ax.get_xaxis().set_major_formatter(plt.ScalarFormatter())
    ax.tick_params(axis='x', which='major', labelrotation=45)

def difference_propagation(cipher: FeistelCipher, plaintext: bytes, modified_plaintext: bytes) -> List[int]:
    """
    Visualize the propagation of differences during encryption.
    """
    block1 = int.from_bytes(plaintext, byteorder='big')
    block2 = int.from_bytes(modified_plaintext, byteorder='big')

    L1 = (block1 >> 32) & 0xFFFFFFFF
    R1 = block1 & 0xFFFFFFFF
    L2 = (block2 >> 32) & 0xFFFFFFFF
    R2 = block2 & 0xFFFFFFFF

    diffs = []

    for i in range(cipher.rounds):
        K = cipher.round_keys[i]
        F_out1 = cipher.F(R1, K)
        F_out2 = cipher.F(R2, K)

        new_L1, new_R1 = R1, L1 ^ F_out1
        new_L2, new_R2 = R2, L2 ^ F_out2

        diff = bit_difference(new_L1 ^ new_L2, new_R1 ^ new_R2)
        diffs.append(diff)

        L1, R1 = new_L1, new_R1
        L2, R2 = new_L2, new_R2

    return diffs

# ----------------------------- Main Function -----------------------------

def main():
    root = tk.Tk()
    app = FeistelCipherGUI(root)
    root.mainloop()

# ----------------------------- Run the Main Function -----------------------------

if __name__ == '__main__':
    main()
