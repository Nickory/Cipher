import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import string
import math
from collections import defaultdict
import matplotlib
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt

# Suppress libpng warnings
import warnings
warnings.filterwarnings("ignore", category=UserWarning, module='matplotlib')

# Use TkAgg backend
matplotlib.use('TkAgg')


# === Playfair Cipher Implementation ===

class PlayfairCipher:
    def __init__(self, key: str):
        self.key = key.upper().replace('J', 'I')  # Replace J with I
        self.matrix = self.generate_matrix()

    def generate_matrix(self):
        """Generate a 5x5 Playfair matrix"""
        letters = string.ascii_uppercase.replace('J', '')  # 25 letters
        seen = set()
        matrix = []

        # Use key to generate matrix
        for char in self.key + letters:
            if char not in seen and char in letters:
                seen.add(char)
                matrix.append(char)

        # Fill remaining letters
        while len(matrix) < 25:
            for char in letters:
                if char not in seen:
                    seen.add(char)
                    matrix.append(char)
                if len(matrix) == 25:
                    break

        return [matrix[i:i + 5] for i in range(0, 25, 5)]

    def display_matrix(self):
        """Display the matrix as a string"""
        return '\n'.join([' '.join(row) for row in self.matrix])

    def locate(self, char):
        """Locate a character in the matrix"""
        for row in range(5):
            for col in range(5):
                if self.matrix[row][col] == char:
                    return row, col
        raise ValueError(f"Character {char} not found in matrix.")

    def preprocess_plaintext(self, plaintext):
        """
        Preprocess plaintext:
        - Convert to uppercase
        - Replace 'J' with 'I'
        - Insert 'X' between duplicate letters
        - Preserve non-letter characters without inserting 'X's before them
        """
        plaintext = plaintext.upper().replace('J', 'I')
        processed = []
        i = 0
        while i < len(plaintext):
            char = plaintext[i]
            if not char.isalpha():
                # Non-letter characters are preserved
                processed.append(char)
                i += 1
                continue

            # Current character is a letter
            if i + 1 < len(plaintext):
                next_char = plaintext[i + 1]
                if not next_char.isalpha():
                    # Next character is non-letter; no 'X' inserted
                    processed.append(char)
                    i += 1
                elif char == next_char:
                    # Duplicate letters; insert 'X' between them
                    processed.append(char)
                    processed.append('X')
                    i += 1
                else:
                    # Pair of distinct letters
                    processed.append(char)
                    processed.append(next_char)
                    i += 2
            else:
                # Last character is a letter; pad with 'X'
                processed.append(char)
                processed.append('X')
                i += 1
        return processed

    def postprocess_decrypted_text(self, decrypted_text):
        """
        Post-process decrypted text to remove inserted 'X's:
        - Remove 'X' between duplicate letters
        - Remove trailing 'X' if it was used as padding
        - Preserve original 'X's in the text
        """
        cleaned_text = []
        i = 0
        while i < len(decrypted_text):
            char = decrypted_text[i]
            if (i + 2 < len(decrypted_text) and
                    decrypted_text[i + 1] == 'X' and
                    decrypted_text[i] == decrypted_text[i + 2]):
                # Skip the 'X' between duplicate letters
                cleaned_text.append(char)
                i += 2
            else:
                cleaned_text.append(char)
                i += 1
        # Remove trailing 'X' if it was added as padding
        if cleaned_text and cleaned_text[-1] == 'X':
            cleaned_text.pop()
        return ''.join(cleaned_text)

    def encrypt(self, plaintext):
        """Encrypt plaintext, preserving symbols"""
        processed = self.preprocess_plaintext(plaintext)
        ciphertext = []
        i = 0
        while i < len(processed):
            char1 = processed[i]
            char2 = processed[i + 1] if i + 1 < len(processed) else 'X'

            if not char1.isalpha():
                # Non-letter characters are preserved
                ciphertext.append(char1)
                i += 1
                continue

            if not char2.isalpha():
                # If the second character is non-letter, preserve it without encryption
                ciphertext.append(char1)
                ciphertext.append(char2)
                i += 2
                continue

            row1, col1 = self.locate(char1)
            row2, col2 = self.locate(char2)

            if row1 == row2:
                # Same row: shift right
                ciphertext.append(self.matrix[row1][(col1 + 1) % 5])
                ciphertext.append(self.matrix[row2][(col2 + 1) % 5])
            elif col1 == col2:
                # Same column: shift down
                ciphertext.append(self.matrix[(row1 + 1) % 5][col1])
                ciphertext.append(self.matrix[(row2 + 1) % 5][col2])
            else:
                # Rectangle: swap columns
                ciphertext.append(self.matrix[row1][col2])
                ciphertext.append(self.matrix[row2][col1])

            i += 2
        return ''.join(ciphertext)

    def decrypt(self, ciphertext):
        """Decrypt ciphertext, preserving symbols"""
        plaintext = []
        i = 0
        while i < len(ciphertext):
            char1 = ciphertext[i]
            char2 = ciphertext[i + 1] if i + 1 < len(ciphertext) else 'X'

            if not char1.isalpha():
                # Non-letter characters are preserved
                plaintext.append(char1)
                i += 1
                continue

            if not char2.isalpha():
                # If the second character is non-letter, preserve it without decryption
                plaintext.append(char1)
                plaintext.append(char2)
                i += 2
                continue

            row1, col1 = self.locate(char1)
            row2, col2 = self.locate(char2)

            if row1 == row2:
                # Same row: shift left
                plaintext.append(self.matrix[row1][(col1 - 1) % 5])
                plaintext.append(self.matrix[row2][(col2 - 1) % 5])
            elif col1 == col2:
                # Same column: shift up
                plaintext.append(self.matrix[(row1 - 1) % 5][col1])
                plaintext.append(self.matrix[(row2 - 1) % 5][col2])
            else:
                # Rectangle: swap columns
                plaintext.append(self.matrix[row1][col2])
                plaintext.append(self.matrix[row2][col1])

            i += 2

        decrypted_text = ''.join(plaintext)

        # Post-process to remove inserted 'X's
        cleaned_text = self.postprocess_decrypted_text(decrypted_text)
        return cleaned_text


# === GUI Implementation ===

class PlayfairCipherGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Playfair Cipher GUI")
        self.root.geometry("1600x1000")
        self.root.resizable(False, False)

        self.key = tk.StringVar()
        self.plaintext = tk.StringVar()
        self.ciphertext = tk.StringVar()
        self.generated_matrix = []
        self.cipher = None

        self.setup_ui()

    def setup_ui(self):
        """Set up the UI layout"""
        self.set_dark_theme()
        self.create_menu()
        self.create_tabs()

    def set_dark_theme(self):
        """Set dark theme"""
        self.root.configure(bg='#1e1e1e')
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('.', background='#1e1e1e', foreground='#ffffff', fieldbackground='#2d2d2d')
        style.configure('TButton', background='#2d2d2d', foreground='#ffffff')
        style.configure('TLabel', background='#1e1e1e', foreground='#ffffff')
        style.configure('TEntry', background='#2d2d2d', foreground='#ffffff', fieldbackground='#2d2d2d')
        style.configure('TNotebook', background='#1e1e1e', foreground='#ffffff')
        style.configure('TNotebook.Tab', background='#2d2d2d', foreground='#ffffff')
        style.map('TButton', background=[('active', '#3e3e3e')])
        style.configure('Horizontal.TProgressbar', troughcolor='#2d2d2d', background='#00ff00',
                        lightcolor='#00ff00', darkcolor='#00ff00', bordercolor='#2d2d2d')

    def create_menu(self):
        """Create menu bar"""
        self.menu_bar = tk.Menu(self.root, bg='#1e1e1e', fg='#ffffff', tearoff=0)
        self.root.config(menu=self.menu_bar)

        # File menu
        self.file_menu = tk.Menu(self.menu_bar, tearoff=0, bg='#1e1e1e', fg='#ffffff')
        self.menu_bar.add_cascade(label="File", menu=self.file_menu)
        self.file_menu.add_command(label="Exit", command=self.root.quit)

        # Help menu
        self.help_menu = tk.Menu(self.menu_bar, tearoff=0, bg='#1e1e1e', fg='#ffffff')
        self.menu_bar.add_cascade(label="Help", menu=self.help_menu)
        self.help_menu.add_command(label="About", command=self.show_about)

    def create_tabs(self):
        """Create multiple tabs"""
        self.tab_control = ttk.Notebook(self.root)

        self.tab_encrypt = ttk.Frame(self.tab_control)
        self.tab_decrypt = ttk.Frame(self.tab_control)
        self.tab_analysis = ttk.Frame(self.tab_control)

        self.tab_control.add(self.tab_encrypt, text='Encrypt')
        self.tab_control.add(self.tab_decrypt, text='Decrypt')
        self.tab_control.add(self.tab_analysis, text='Analysis')
        self.tab_control.pack(expand=1, fill='both')

        self.create_encrypt_tab()
        self.create_decrypt_tab()
        self.create_analysis_tab()

    def create_encrypt_tab(self):
        """Create Encrypt tab"""
        # Key input
        frame_key = ttk.LabelFrame(self.tab_encrypt, text='Key Input', padding=10)
        frame_key.pack(fill='x', padx=20, pady=10)

        ttk.Label(frame_key, text='Enter Key:').grid(row=0, column=0, sticky='w')
        self.entry_key = ttk.Entry(frame_key, textvariable=self.key, width=60)
        self.entry_key.grid(row=0, column=1, padx=10)
        ttk.Button(frame_key, text='Generate Matrix', command=self.generate_matrix).grid(row=0, column=2, padx=10)

        # Matrix display
        self.text_matrix = scrolledtext.ScrolledText(frame_key, width=70, height=5, state='disabled',
                                                    bg='#2d2d2d', fg='#00ff00', font=("Courier", 12))
        self.text_matrix.grid(row=1, column=0, columnspan=3, pady=10)

        # Plaintext input
        frame_plaintext = ttk.LabelFrame(self.tab_encrypt, text='Plaintext Encryption', padding=10)
        frame_plaintext.pack(fill='both', padx=20, pady=10)

        ttk.Label(frame_plaintext, text='Enter Plaintext:').pack(anchor='w')
        self.txt_plaintext = scrolledtext.ScrolledText(frame_plaintext, width=120, height=15, bg='#2d2d2d',
                                                       fg='#00ff00', font=("Courier", 12))
        self.txt_plaintext.pack(padx=10, pady=10)

        # Encrypt button
        ttk.Button(frame_plaintext, text='Encrypt', command=self.encrypt_text).pack(pady=5)

        # Ciphertext display
        ttk.Label(frame_plaintext, text='Ciphertext:').pack(anchor='w')
        self.txt_ciphertext_encrypted = scrolledtext.ScrolledText(frame_plaintext, width=120, height=15, bg='#2d2d2d',
                                                                 fg='#00ff00', state='disabled', font=("Courier", 12))
        self.txt_ciphertext_encrypted.pack(padx=10, pady=10)

    def create_decrypt_tab(self):
        """Create Decrypt tab"""
        frame_decrypt = ttk.LabelFrame(self.tab_decrypt, text='Ciphertext Decryption', padding=10)
        frame_decrypt.pack(fill='both', padx=20, pady=10)

        # Ciphertext input
        ttk.Label(frame_decrypt, text='Enter Ciphertext:').pack(anchor='w')
        self.txt_ciphertext_decrypt = scrolledtext.ScrolledText(frame_decrypt, width=120, height=15, bg='#2d2d2d',
                                                                 fg='#00ff00', font=("Courier", 12))
        self.txt_ciphertext_decrypt.pack(padx=10, pady=10)

        # Key input
        frame_key_decrypt = ttk.Frame(frame_decrypt)
        frame_key_decrypt.pack(fill='x', padx=10, pady=5)

        ttk.Label(frame_key_decrypt, text='Enter Key:').pack(side='left')
        self.entry_key_decrypt = ttk.Entry(frame_key_decrypt, width=60)
        self.entry_key_decrypt.pack(side='left', padx=10)

        # Decrypt button
        ttk.Button(frame_key_decrypt, text='Decrypt', command=self.decrypt_text).pack(side='left', padx=10)

        # Plaintext display
        ttk.Label(frame_decrypt, text='Decrypted Plaintext:').pack(anchor='w')
        self.txt_plaintext_decrypted = scrolledtext.ScrolledText(frame_decrypt, width=120, height=15, bg='#2d2d2d',
                                                                 fg='#00ff00', state='disabled', font=("Courier", 12))
        self.txt_plaintext_decrypted.pack(padx=10, pady=10)

    def create_analysis_tab(self):
        """Create Analysis tab"""
        frame_analysis = ttk.Frame(self.tab_analysis)
        frame_analysis.pack(fill='both', padx=20, pady=10)

        # Left side: Analysis Controls
        frame_controls = ttk.Frame(frame_analysis)
        frame_controls.pack(side='left', fill='y', padx=(0, 10))

        # Avalanche Effect Analysis
        frame_avalanche = ttk.LabelFrame(frame_controls, text='Avalanche Effect Analysis', padding=10)
        frame_avalanche.pack(fill='x', pady=10)

        ttk.Button(frame_avalanche, text='Analyze Plaintext Avalanche Effect',
                   command=self.avalanche_effect_plaintext).pack(fill='x', pady=5)
        ttk.Button(frame_avalanche, text='Analyze Key Avalanche Effect',
                   command=self.avalanche_effect_key).pack(fill='x', pady=5)

        # Ciphertext Frequency Analysis
        frame_frequency = ttk.LabelFrame(frame_controls, text='Ciphertext Frequency Analysis', padding=10)
        frame_frequency.pack(fill='x', pady=10)

        ttk.Button(frame_frequency, text='Analyze Ciphertext Frequency',
                   command=self.frequency_analysis).pack(fill='x', pady=5)

        # Keyspace Analysis
        frame_keyspace = ttk.LabelFrame(frame_controls, text='Keyspace Analysis', padding=10)
        frame_keyspace.pack(fill='x', pady=10)

        ttk.Button(frame_keyspace, text='Analyze Keyspace',
                   command=self.keyspace_analysis).pack(fill='x', pady=5)

        # Custom Avalanche Analysis
        frame_custom_avalanche = ttk.LabelFrame(frame_controls, text='Custom Avalanche Analysis', padding=10)
        frame_custom_avalanche.pack(fill='x', pady=10)

        ttk.Label(frame_custom_avalanche, text='Enter Modified Plaintext:').pack(anchor='w')
        self.entry_custom_plaintext = ttk.Entry(frame_custom_avalanche, width=50)
        self.entry_custom_plaintext.pack(padx=5, pady=5)
        ttk.Button(frame_custom_avalanche, text='Analyze Custom Avalanche',
                   command=self.custom_avalanche_effect).pack(pady=5)

        # Right side: Visualization and Results
        frame_visualization = ttk.Frame(frame_analysis)
        frame_visualization.pack(side='left', fill='both', expand=True)

        # Matplotlib Figure
        self.figure_analysis = plt.Figure(figsize=(12, 6), dpi=100, facecolor='#1e1e1e')  # Increased width
        self.ax_analysis = self.figure_analysis.add_subplot(111)
        self.ax_analysis.set_facecolor('#1e1e1e')
        self.ax_analysis.tick_params(axis='x', colors='#ffffff')
        self.ax_analysis.tick_params(axis='y', colors='#ffffff')

        self.canvas_analysis = FigureCanvasTkAgg(self.figure_analysis, master=frame_visualization)
        # 增加底部垂直间隔（pady=(0, 20)），让图表与文本框之间有更多空间
        self.canvas_analysis.get_tk_widget().pack(fill='both', expand=True, pady=(0, 20))

        # Textual Analysis Results
        frame_textual = ttk.LabelFrame(frame_visualization, text='Analysis Results', padding=10)
        # 增加顶部垂直间隔（pady=(20, 10)），确保与图表之间有足够空间
        frame_textual.pack(fill='x', pady=(20, 10))

        self.text_analysis_results = scrolledtext.ScrolledText(frame_textual, width=100, height=15, bg='#2d2d2d',
                                                              fg='#00ff00', state='disabled', font=("Courier", 12))
        self.text_analysis_results.pack(padx=10, pady=10)

    def generate_matrix(self):
        """Generate Playfair matrix and display"""
        key = self.key.get().strip()
        if not key:
            messagebox.showwarning("Warning", "Please enter a key!")
            return
        try:
            self.cipher = PlayfairCipher(key)
            self.generated_matrix = self.cipher.matrix
            self.text_matrix.config(state='normal')
            self.text_matrix.delete('1.0', tk.END)
            self.text_matrix.insert(tk.END, self.cipher.display_matrix())
            self.text_matrix.config(state='disabled')
            messagebox.showinfo("Success", "Matrix generated successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate matrix: {e}")

    def encrypt_text(self):
        """Encrypt plaintext and display ciphertext"""
        plaintext = self.txt_plaintext.get('1.0', tk.END).strip()
        if not plaintext:
            messagebox.showwarning("Warning", "Please enter plaintext!")
            return
        if not self.cipher:
            messagebox.showwarning("Warning", "Please generate the matrix first!")
            return
        try:
            ciphertext = self.cipher.encrypt(plaintext)
            self.txt_ciphertext_encrypted.config(state='normal')
            self.txt_ciphertext_encrypted.delete('1.0', tk.END)
            self.txt_ciphertext_encrypted.insert(tk.END, ciphertext)
            self.txt_ciphertext_encrypted.config(state='disabled')
            messagebox.showinfo("Success", "Encryption completed!")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {e}")

    def decrypt_text(self):
        """Decrypt ciphertext and display plaintext"""
        ciphertext = self.txt_ciphertext_decrypt.get('1.0', tk.END).strip()
        key = self.entry_key_decrypt.get().strip()
        if not ciphertext or not key:
            messagebox.showwarning("Warning", "Please enter ciphertext and key!")
            return
        try:
            cipher = PlayfairCipher(key)
            plaintext = cipher.decrypt(ciphertext)
            self.txt_plaintext_decrypted.config(state='normal')
            self.txt_plaintext_decrypted.delete('1.0', tk.END)
            self.txt_plaintext_decrypted.insert(tk.END, plaintext)
            self.txt_plaintext_decrypted.config(state='disabled')
            messagebox.showinfo("Success", "Decryption completed!")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {e}")

    def avalanche_effect_plaintext(self):
        """Analyze plaintext avalanche effect with predefined modifications"""
        if not self.cipher:
            messagebox.showwarning("Warning", "Please generate the matrix first!")
            return

        # Define original and multiple modified plaintexts
        original_plaintext = (
            "This is a simple test message for encryption. "
            "It includes various characters, such as letters, numbers (12345), "
            "punctuation marks (!@#$%), and spaces. The goal is to evaluate the "
            "encryption algorithm's ability to handle diverse input and produce a secure ciphertext. "
            "Let's see how well the system performs under different scenarios!"
        )

        # Define multiple modifications
        modifications = [
            {"type": "Add Character", "description": "Add 'S' at the end", "modified": original_plaintext + "S"},
            {"type": "Modify Character", "description": "Change 'encryption' to 'encyrption'",
             "modified": original_plaintext.replace("encryption", "encyrption")},
            {"type": "Delete Character", "description": "Delete 'algorithm's'", "modified": original_plaintext.replace("algorithm's", "algorithm")},
            {"type": "Swap Characters", "description": "Swap 'c' and 'e' in 'secure'",
             "modified": original_plaintext.replace("secure", "seucer")},
            {"type": "Replace Character", "description": "Replace 'different' with 'd1fferent'",
             "modified": original_plaintext.replace("different", "d1fferent")},
        ]

        results = []

        ciphertext_original = self.cipher.encrypt(original_plaintext)

        for mod in modifications:
            modified_plaintext = mod["modified"]
            ciphertext_modified = self.cipher.encrypt(modified_plaintext)
            distance = self.hamming_distance(ciphertext_original, ciphertext_modified)
            total = max(len(ciphertext_original), len(ciphertext_modified))
            avalanche_percentage = (distance / total) * 100
            results.append({
                "type": mod["type"],
                "description": mod["description"],
                "original_plaintext": original_plaintext,
                "modified_plaintext": modified_plaintext,
                "ciphertext_original": ciphertext_original,
                "ciphertext_modified": ciphertext_modified,
                "hamming_distance": distance,
                "avalanche_percentage": avalanche_percentage
            })

        # Visualization
        self.ax_analysis.cla()
        # Limit the description length to prevent overly long labels
        labels = [f"{res['type']}\n{res['description'][:15]}..." if len(res['description']) > 15 else f"{res['type']}\n{res['description']}" for res in results]
        data = [res['hamming_distance'] for res in results]
        self.ax_analysis.bar(labels, data, color='orange')
        self.ax_analysis.set_title('Plaintext Avalanche Effect Analysis', color='#ffffff')
        self.ax_analysis.set_ylabel('Number of Different Characters', color='#ffffff')
        self.ax_analysis.tick_params(axis='y', colors='#ffffff')
        self.ax_analysis.set_facecolor('#1e1e1e')
        self.ax_analysis.patch.set_facecolor('#1e1e1e')
        self.ax_analysis.spines['bottom'].set_color('white')
        self.ax_analysis.spines['left'].set_color('white')
        self.ax_analysis.spines['right'].set_color('white')
        self.ax_analysis.spines['top'].set_color('white')

        # Rotate and align x-axis labels
        for label in self.ax_analysis.get_xticklabels():
            label.set_rotation(45)
            label.set_horizontalalignment('right')
            label.set_fontsize(8)  # Reduce font size

        # Adjust layout to prevent clipping
        self.figure_analysis.tight_layout()

        # Add text labels for each bar
        for idx, res in enumerate(results):
            self.ax_analysis.text(idx, res['hamming_distance'] + 1, f"{res['hamming_distance']}\n{res['avalanche_percentage']:.2f}%",
                                  color='white', ha='center', fontsize=8)

        self.canvas_analysis.draw()

        # Textual Results
        self.text_analysis_results.config(state='normal')
        self.text_analysis_results.delete('1.0', tk.END)
        self.text_analysis_results.insert(tk.END, f"Plaintext Avalanche Effect Analysis:\n\n")
        for res in results:
            self.text_analysis_results.insert(tk.END, f"Modification Type: {res['type']}\n")
            self.text_analysis_results.insert(tk.END, f"Modification Description: {res['description']}\n")
            self.text_analysis_results.insert(tk.END, f"Original Plaintext: {res['original_plaintext']}\n")
            self.text_analysis_results.insert(tk.END, f"Modified Plaintext: {res['modified_plaintext']}\n")
            self.text_analysis_results.insert(tk.END, f"Original Ciphertext: {res['ciphertext_original']}\n")
            self.text_analysis_results.insert(tk.END, f"Modified Ciphertext: {res['ciphertext_modified']}\n")
            self.text_analysis_results.insert(tk.END, f"Hamming Distance: {res['hamming_distance']}\n")
            self.text_analysis_results.insert(tk.END, f"Avalanche Effect: {res['avalanche_percentage']:.2f}%\n")
            self.text_analysis_results.insert(tk.END, "-"*80 + "\n")
        self.text_analysis_results.config(state='disabled')

    def avalanche_effect_key(self):
        """Analyze key avalanche effect"""
        if not self.cipher:
            messagebox.showwarning("Warning", "Please generate the matrix first!")
            return
        original_key = self.key.get()
        modified_key = original_key + "X"  # Add a character

        cipher_original = PlayfairCipher(original_key)
        ciphertext_original = cipher_original.encrypt("THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG")

        cipher_modified = PlayfairCipher(modified_key)
        ciphertext_modified = cipher_modified.encrypt("THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG")

        # Calculate Hamming distance
        distance = self.hamming_distance(ciphertext_original, ciphertext_modified)
        total = max(len(ciphertext_original), len(ciphertext_modified))
        avalanche_percentage = (distance / total) * 100

        # Visualization
        self.ax_analysis.cla()
        labels = ['Differences']
        data = [distance]
        self.ax_analysis.bar(labels, data, color='orange')
        self.ax_analysis.set_title('Key Avalanche Effect Analysis', color='#ffffff')
        self.ax_analysis.set_ylabel('Number of Different Characters', color='#ffffff')
        self.ax_analysis.tick_params(axis='y', colors='#ffffff')
        self.ax_analysis.set_facecolor('#1e1e1e')
        self.ax_analysis.patch.set_facecolor('#1e1e1e')
        self.ax_analysis.spines['bottom'].set_color('white')
        self.ax_analysis.spines['left'].set_color('white')
        self.ax_analysis.spines['right'].set_color('white')
        self.ax_analysis.spines['top'].set_color('white')

        # Rotate and align x-axis labels (not necessary here as there's only one label)
        for label in self.ax_analysis.get_xticklabels():
            label.set_rotation(0)
            label.set_horizontalalignment('center')
            label.set_fontsize(10)  # Adjust font size if needed

        # Adjust layout
        self.figure_analysis.tight_layout()

        self.ax_analysis.text(0, distance + 1, f"Hamming Distance: {distance}\nAvalanche Effect: {avalanche_percentage:.2f}%",
                              color='white', ha='center', fontsize=10)
        self.canvas_analysis.draw()

        # Textual Results
        self.text_analysis_results.config(state='normal')
        self.text_analysis_results.delete('1.0', tk.END)
        self.text_analysis_results.insert(tk.END, f"Key Avalanche Effect Analysis:\n\n")
        self.text_analysis_results.insert(tk.END, f"Original Key: {original_key}\n")
        self.text_analysis_results.insert(tk.END, f"Modified Key: {modified_key}\n")
        self.text_analysis_results.insert(tk.END, f"Original Ciphertext: {ciphertext_original}\n")
        self.text_analysis_results.insert(tk.END, f"Modified Ciphertext: {ciphertext_modified}\n")
        self.text_analysis_results.insert(tk.END, f"Hamming Distance: {distance}\n")
        self.text_analysis_results.insert(tk.END, f"Avalanche Effect: {avalanche_percentage:.2f}%\n")
        self.text_analysis_results.config(state='disabled')

    def frequency_analysis(self):
        """Analyze ciphertext frequency"""
        ciphertext = self.txt_ciphertext_encrypted.get('1.0', tk.END).strip()
        if not ciphertext:
            messagebox.showwarning("Warning", "Please perform encryption first!")
            return

        freq = defaultdict(int)
        for char in ciphertext:
            if char.isalpha():
                freq[char] += 1

        if not freq:
            messagebox.showwarning("Warning", "No alphabetic characters found in ciphertext!")
            return

        # Sort letters alphabetically
        letters = sorted(freq.keys())
        counts = [freq[char] for char in letters]

        # Visualization
        self.ax_analysis.cla()
        self.ax_analysis.bar(letters, counts, color='#00ff00')
        self.ax_analysis.set_title('Ciphertext Letter Frequency Analysis', color='#ffffff')
        self.ax_analysis.set_xlabel('Letters', color='#ffffff')
        self.ax_analysis.set_ylabel('Frequency', color='#ffffff')
        self.ax_analysis.grid(True, color='#555555', linestyle='--', linewidth=0.5)
        self.ax_analysis.set_facecolor('#1e1e1e')
        self.ax_analysis.patch.set_facecolor('#1e1e1e')
        self.ax_analysis.spines['bottom'].set_color('white')
        self.ax_analysis.spines['left'].set_color('white')
        self.ax_analysis.spines['right'].set_color('white')
        self.ax_analysis.spines['top'].set_color('white')

        # Rotate and align x-axis labels
        for label in self.ax_analysis.get_xticklabels():
            label.set_rotation(45)
            label.set_horizontalalignment('right')
            label.set_fontsize(8)  # Reduce font size to fit

        # Adjust layout
        self.figure_analysis.tight_layout()

        self.canvas_analysis.draw()

        # Textual Results
        self.text_analysis_results.config(state='normal')
        self.text_analysis_results.delete('1.0', tk.END)
        self.text_analysis_results.insert(tk.END, f"Ciphertext Frequency Analysis:\n\n")
        total = sum(counts)
        for char, count in zip(letters, counts):
            percentage = (count / total) * 100
            self.text_analysis_results.insert(tk.END, f"{char}: {count} times ({percentage:.2f}%)\n")
        self.text_analysis_results.config(state='disabled')

    def keyspace_analysis(self):
        """Analyze keyspace"""
        # Playfair keyspace calculation
        # Number of possible keys = 25! ≈ 1.55e+25
        keyspace = math.factorial(25)

        # Visualization
        self.ax_analysis.cla()
        self.ax_analysis.bar(['Keyspace'], [keyspace], color='#00ff00')
        self.ax_analysis.set_title('Playfair Keyspace Analysis', color='#ffffff')
        self.ax_analysis.set_ylabel('Number of Possible Keys', color='#ffffff')
        self.ax_analysis.tick_params(axis='y', colors='#ffffff')
        self.ax_analysis.set_yscale('log')
        self.ax_analysis.set_facecolor('#1e1e1e')
        self.ax_analysis.patch.set_facecolor('#1e1e1e')
        self.ax_analysis.spines['bottom'].set_color('white')
        self.ax_analysis.spines['left'].set_color('white')
        self.ax_analysis.spines['right'].set_color('white')
        self.ax_analysis.spines['top'].set_color('white')

        # Rotate and align x-axis labels (not necessary here as there's only one label)
        for label in self.ax_analysis.get_xticklabels():
            label.set_rotation(0)
            label.set_horizontalalignment('center')
            label.set_fontsize(10)  # Adjust font size if needed

        # Adjust layout
        self.figure_analysis.tight_layout()

        # Add annotation with explanation
        self.ax_analysis.text(0, keyspace / 10, f"Keyspace Size: 25! ≈ {keyspace:.2e}\n(25 factorial)",
                              color='white', ha='center', fontsize=10)

        self.canvas_analysis.draw()

        # Textual Results
        self.text_analysis_results.config(state='normal')
        self.text_analysis_results.delete('1.0', tk.END)
        self.text_analysis_results.insert(tk.END, f"Playfair Cipher Keyspace Analysis:\n\n")
        self.text_analysis_results.insert(tk.END, f"Number of Possible Keys: 25! ≈ {keyspace:.2e}\n")
        self.text_analysis_results.insert(tk.END, f"This represents an extremely large keyspace, making brute-force attacks practically infeasible.\n")
        self.text_analysis_results.config(state='disabled')

    def custom_avalanche_effect(self):
        """Analyze avalanche effect for custom modified plaintext"""
        if not self.cipher:
            messagebox.showwarning("Warning", "Please generate the matrix first!")
            return

        original_plaintext = (
            "This is a simple test message for encryption. "
            "It includes various characters, such as letters, numbers (12345), "
            "punctuation marks (!@#$%), and spaces. The goal is to evaluate the "
            "encryption algorithm's ability to handle diverse input and produce a secure ciphertext. "
            "Let's see how well the system performs under different scenarios!"
        )

        modified_plaintext = self.entry_custom_plaintext.get().strip()
        if not modified_plaintext:
            messagebox.showwarning("Warning", "Please enter a modified plaintext!")
            return

        try:
            ciphertext_original = self.cipher.encrypt(original_plaintext)
            ciphertext_modified = self.cipher.encrypt(modified_plaintext)

            # Calculate Hamming distance
            distance = self.hamming_distance(ciphertext_original, ciphertext_modified)
            total = max(len(ciphertext_original), len(ciphertext_modified))
            avalanche_percentage = (distance / total) * 100

            # Visualization
            self.ax_analysis.cla()
            labels = ['Differences']
            data = [distance]
            self.ax_analysis.bar(labels, data, color='orange')
            self.ax_analysis.set_title('Custom Avalanche Effect Analysis', color='#ffffff')
            self.ax_analysis.set_ylabel('Number of Different Characters', color='#ffffff')
            self.ax_analysis.tick_params(axis='y', colors='#ffffff')
            self.ax_analysis.set_facecolor('#1e1e1e')
            self.ax_analysis.patch.set_facecolor('#1e1e1e')
            self.ax_analysis.spines['bottom'].set_color('white')
            self.ax_analysis.spines['left'].set_color('white')
            self.ax_analysis.spines['right'].set_color('white')
            self.ax_analysis.spines['top'].set_color('white')

            # Rotate and align x-axis labels (not necessary here as there's only one label)
            for label in self.ax_analysis.get_xticklabels():
                label.set_rotation(0)
                label.set_horizontalalignment('center')
                label.set_fontsize(10)  # Adjust font size if needed

            # Adjust layout
            self.figure_analysis.tight_layout()

            self.ax_analysis.text(0, distance + 1, f"Hamming Distance: {distance}\nAvalanche Effect: {avalanche_percentage:.2f}%",
                                  color='white', ha='center', fontsize=10)
            self.canvas_analysis.draw()

            # Textual Results
            self.text_analysis_results.config(state='normal')
            self.text_analysis_results.delete('1.0', tk.END)
            self.text_analysis_results.insert(tk.END, f"Custom Avalanche Effect Analysis:\n\n")
            self.text_analysis_results.insert(tk.END, f"Original Plaintext: {original_plaintext}\n\n")
            self.text_analysis_results.insert(tk.END, f"Modified Plaintext: {modified_plaintext}\n\n")
            self.text_analysis_results.insert(tk.END, f"Original Ciphertext: {ciphertext_original}\n\n")
            self.text_analysis_results.insert(tk.END, f"Modified Ciphertext: {ciphertext_modified}\n\n")
            self.text_analysis_results.insert(tk.END, f"Hamming Distance: {distance}\n")
            self.text_analysis_results.insert(tk.END, f"Avalanche Effect: {avalanche_percentage:.2f}%\n")
            self.text_analysis_results.config(state='disabled')
        except Exception as e:
            messagebox.showerror("Error", f"Avalanche effect analysis failed: {e}")

    def hamming_distance(self, s1, s2):
        """Calculate Hamming distance between two strings"""
        if len(s1) != len(s2):
            # Pad the shorter string with spaces
            max_len = max(len(s1), len(s2))
            s1 = s1.ljust(max_len)
            s2 = s2.ljust(max_len)
        return sum(c1 != c2 for c1, c2 in zip(s1, s2))

    def show_about(self):
        """Show about information"""
        about_text = (
            "Playfair Cipher GUI\n"
            "Version: 2.0\n"
            "Author: Your Name\n"
            "Institution: Your Institution\n"
            "Email: your.email@example.com\n\n"
            "Features:\n"
            "- Key input and matrix generation\n"
            "- Plaintext encryption and ciphertext decryption (preserving symbols)\n"
            "- Avalanche Effect Analysis (Plaintext and Key)\n"
            "- Ciphertext Frequency Analysis\n"
            "- Keyspace Analysis\n"
            "- Custom Avalanche Effect Analysis\n"
            "- Visualization of analysis results\n\n"
            "License:\n"
            "This software © 2024 Your Name. All rights reserved. Do not distribute without permission."
        )
        messagebox.showinfo("About", about_text)


# === Main Program ===

def main():
    root = tk.Tk()
    app = PlayfairCipherGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
