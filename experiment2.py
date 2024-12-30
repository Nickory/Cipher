import random
import math
import string
import sys
import nltk
from collections import defaultdict
from nltk import download
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import time
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('TkAgg')
import os
from PIL import Image, ImageTk  # Pillow 库
# 确保下载所需的NLTK资源
try:
    nltk.data.find('corpora/brown')
except LookupError:
    print("正在下载NLTK的'Brown'语料库...")
    download('brown')



def generate_texts():
    types = {
        "Literature": (
            "It was the best of times, it was the worst of times, it was the age of wisdom, it was the age of foolishness, "
            "it was the epoch of belief, it was the epoch of incredulity, it was the season of Light, it was the season of Darkness, "
            "it was the spring of hope, it was the winter of despair, we had everything before us, we had nothing before us, we were all "
            "going direct to Heaven, we were all going direct the other way—in short, the period was so far like the present period, "
            "that some of its noisiest authorities insisted on its being received, for good or for evil, in the superlative degree of comparison only. "
            "These contradictions within society were reflected in literature and art, a movement fueled by both chaos and creativity. "
            "Authors struggled to capture the reality of a world in transition, where ideals and traditions were constantly challenged, "
            "yet hope persisted like the first light of dawn after a long night. The pen became a weapon of change, etching into history "
            "the voices of those seeking justice, truth, and the essence of human nature. "
            "The transformation of literature during such turbulent times often reflected a broader struggle within society itself. Writers like Charles Dickens, "
            "Victor Hugo, and Fyodor Dostoevsky navigated the murky waters of societal inequality, morality, and personal responsibility. Their works became more than stories; "
            "they were mirrors held up to society, revealing both its glory and its flaws. Meanwhile, poets like Emily Dickinson and Walt Whitman explored themes of individuality and spirituality, "
            "their words capturing the nuanced beauty of the human experience. "
            "At the heart of this literary explosion was the interplay between hope and despair. On the one hand, industrial progress promised better lives and brighter futures; "
            "on the other, it created slums, child labor, and stark divisions between the wealthy and the poor. This duality gave rise to new genres, like Gothic literature, which explored "
            "the darker corners of the human psyche. Mary Shelley's *Frankenstein* wasn't just a tale of horror; it was a commentary on scientific hubris and ethical responsibility. "
            "Similarly, the Romantic poets—Wordsworth, Keats, and Byron—celebrated nature and emotion as an antidote to the cold rationalism of their age. "
            "In modern times, literature continues to evolve, addressing issues like climate change, digital alienation, and social justice. The legacy of past writers endures, "
            "reminding us that literature is not merely a reflection of society but a tool to shape it. Through the written word, humanity has always sought to find meaning, "
            "challenge injustice, and dream of better futures. From classics to contemporary novels, literature remains the most enduring testament to human resilience, "
            "creativity, and the relentless pursuit of truth."
        ),
        "Science": (
            "The mitochondrion is a double-membrane-bound organelle found in most eukaryotic organisms. Some cells in some multicellular organisms, however, may lack them. "
            "Mitochondria generate most of the cell's supply of adenosine triphosphate (ATP), used as a source of chemical energy. Beyond energy production, mitochondria "
            "play a key role in metabolic processes, cell signaling, and apoptosis. Advances in mitochondrial research have uncovered its role in diseases such as diabetes, "
            "Parkinson's disease, and cancer. Scientists continue to unravel the complexities of mitochondrial DNA, which provides clues to the evolutionary journey of life itself. "
            "As we delve deeper, mitochondria reveal secrets not just of energy production but of life's delicate balance between survival and decline. "
            "These tiny powerhouses of the cell are central to our understanding of biology and evolution. With their own DNA, mitochondria are believed to have originated from "
            "an ancient symbiotic relationship between a proto-eukaryotic cell and a free-living bacterium. This endosymbiotic theory is supported by genetic and structural evidence, "
            "illustrating how cooperation at the cellular level paved the way for the complexity of multicellular life. The mitochondrion's ability to adapt and respond to cellular needs "
            "highlights its role as more than just an energy producer; it is a dynamic regulator of cell health and function. "
            "Recent advancements in mitochondrial research have revolutionized medicine. The discovery of mitochondrial dysfunction in diseases like Alzheimer's and ALS has opened new avenues for treatment. "
            "Targeting these organelles could lead to therapies that slow or even reverse age-related degeneration. Moreover, mitochondrial replacement therapy, though controversial, "
            "offers hope for families with mitochondrial genetic disorders. As we probe deeper into the mysteries of these organelles, we uncover not just the mechanics of life but its vulnerabilities, "
            "urging us to tread carefully as we seek to manipulate these intricate systems for human benefit. "
            "In future research, mitochondria may even hold answers to questions about longevity and the potential for extending human life. Understanding their function at deeper levels "
            "is a key step toward solving some of humanity's most pressing health challenges."
        ),
        "Technology": (
            "Artificial intelligence (AI) has rapidly transformed industries and reshaped the future of technology. From neural networks mimicking the structure of the human brain "
            "to breakthroughs in generative AI, the scope of machine intelligence continues to expand. Ethical debates surrounding AI development highlight challenges in bias, data privacy, "
            "and the implications of autonomous decision-making. While AI offers efficiency and innovation, it also raises questions about humanity's role in an increasingly automated world. "
            "The integration of AI into robotics, medical diagnostics, and environmental modeling exemplifies its potential to address global challenges, albeit with caution. "
            "The impact of AI extends far beyond automation. Machine learning algorithms now drive advancements in drug discovery, financial forecasting, and personalized education. "
            "Chatbots and virtual assistants have become ubiquitous, shaping how people interact with technology daily. Yet, as AI becomes more capable, it also raises critical ethical dilemmas. "
            "What happens when machines surpass human ability in creativity or moral decision-making? How do we ensure AI systems remain transparent and accountable? "
            "Looking to the future, AI promises to redefine our relationship with technology. Autonomous vehicles, smart cities, and predictive healthcare systems are just a few examples of how "
            "machine intelligence could improve lives. However, this potential comes with risks. As we build increasingly complex AI systems, the need for robust oversight and ethical guidelines "
            "becomes ever more pressing. In many ways, the future of AI mirrors the paradox of technology itself: a powerful tool capable of both solving and creating problems, demanding careful stewardship. "
            "The global race for AI supremacy also highlights the geopolitical implications of this technology. Governments and corporations alike must navigate a landscape where innovation could "
            "lead to both prosperity and inequality."
        ),
        "History": (
            "In 1492, Christopher Columbus embarked on a journey that changed the course of history. This voyage marked the beginning of European exploration, leading to profound cultural, "
            "social, and ecological exchanges between the Old World and the New World. Known as the Columbian Exchange, this era saw the transfer of crops, animals, technologies, and diseases. "
            "While new foods like potatoes and tomatoes revolutionized European diets, the introduction of smallpox decimated Native American populations. Columbus's legacy is both celebrated and criticized, "
            "as debates over his treatment of indigenous peoples and the consequences of colonization remain contentious. "
            "The Columbian Exchange did not only alter the diets and economies of the world but also reshaped ecosystems. Horses, cattle, and sheep introduced to the Americas transformed the landscapes, "
            "while crops such as maize and chili peppers reached Africa and Asia, fueling agricultural revolutions. However, the darker consequences of this exchange include the forced migration of millions "
            "of Africans through the transatlantic slave trade, as European powers sought labor for their colonies. This exploitation left a legacy of inequality and suffering that persists to this day. "
            "Beyond Columbus, other historical figures and events profoundly impacted the world. The Enlightenment era, with its emphasis on reason and individual rights, laid the groundwork for revolutions "
            "like those in America and France. These movements challenged monarchies and established principles of democracy and human rights. "
            "The Industrial Revolution further accelerated changes in human society, as machines replaced manual labor and urban centers grew. Innovations in transportation, such as railways and steamships, "
            "connected distant parts of the world, fostering global trade and cultural exchange. However, these advancements also led to environmental degradation and widened economic disparities. "
            "In the 20th century, two World Wars reshaped borders, ideologies, and global alliances. The Cold War that followed split the world into competing blocs, driving technological innovation while also "
            "escalating the threat of nuclear annihilation. Movements for civil rights, decolonization, and gender equality gained momentum, challenging oppressive systems and seeking a fairer future. "
            "History is not merely a collection of dates and events; it is a living tapestry of human triumphs and tragedies. Leaders rise and fall, wars ignite and resolve, and civilizations evolve, "
            "each leaving behind lessons for the future. It teaches us resilience, the dangers of hubris, and the importance of remembering our shared humanity. From ancient empires to modern democracies, "
            "history remains a fascinating story of innovation, resilience, and transformation. The challenges of today—climate change, pandemics, and social inequality—are but the latest chapters in this ongoing saga, "
            "reminding us that the story of humanity is far from over."
        ),
        "Fantasy": (
            "In the mystical realm of Eldara, ancient prophecies foretold the rise of a hero who would vanquish the darkness that plagued the land. The dragon, a symbol of chaos and fire, "
            "descended from its lair in the sky-capped peaks to wreak havoc. Villages burned, and hope dimmed, until a young warrior named Kael took up the legendary blade of his ancestors. "
            "The battle between Kael and the dragon was fierce, filled with moments of despair and flashes of brilliance. The clash of fire and steel, of courage against overwhelming odds, "
            "created a tale that would echo through time, a testament to the indomitable spirit of those who dare to stand against impossible odds. "
            "Eldara was not just a land of heroes and monsters; it was a world rich in history and magic. Long ago, the kingdom had been a beacon of prosperity, ruled by a council of wise mages who harnessed the power of the Elemental Crystals. "
            "These crystals, each representing a fundamental force—fire, water, air, and earth—maintained the balance of the realm. However, centuries before Kael's time, the Crystal of Fire was corrupted by a power-hungry sorcerer, "
            "unleashing chaos upon the land. The dragon was but one of the many horrors born from this corruption. "
            "Kael's journey was not a solitary one. Alongside him traveled a band of unlikely companions: Aria, a healer with a mysterious past; Thalric, a rogue whose quick wit often masked his deep scars; "
            "and Myrna, a mage seeking redemption for her family's betrayal. Together, they traversed enchanted forests, treacherous mountain passes, and forgotten ruins, each step bringing them closer to the dragon's lair. "
            "Their quest was not merely about defeating a monster; it was about restoring hope to a land that had almost forgotten it. "
            "In the final confrontation, Kael discovered that the dragon was not inherently evil but a guardian corrupted by the Crystal of Fire's taint. With Myrna's guidance, they devised a plan to purify the crystal, "
            "risking their lives to channel its immense power. The ritual was perilous, and the dragon fought fiercely, but in the end, Kael plunged his blade into the crystal, breaking its dark influence. "
            "The dragon, freed from its torment, ascended into the skies, leaving behind a land ready to heal. "
            "Eldara's story did not end with Kael's victory. His tale became legend, inspiring future generations to stand against darkness in all its forms. The Elemental Crystals were entrusted to new guardians, "
            "and the council of mages vowed never to allow such corruption again. Yet, whispers of ancient evils and forgotten prophecies lingered, hinting that Eldara's greatest challenges were yet to come. "
            "Fantasy worlds like Eldara remind us of the power of courage, friendship, and the enduring fight for light in the face of overwhelming darkness. They transport us to realms where imagination knows no bounds, "
            "offering both escape and inspiration."
        )
    }
    return types


# 构建四元语法模型
def build_quadgram_model():
    from nltk.corpus import brown
    quadgrams = defaultdict(int)
    total_quadgrams = 0

    for sentence in brown.sents():
        text = ' '.join(sentence).lower()
        text = ''.join(filter(str.isalpha, text))
        for i in range(len(text) - 3):
            quadgram = text[i:i+4]
            quadgrams[quadgram] += 1
            total_quadgrams += 1

    # 计算对数概率
    for quadgram in quadgrams:
        quadgrams[quadgram] = math.log10(quadgrams[quadgram] / total_quadgrams)

    # 未出现的四元组赋予最小概率
    floor = math.log10(0.01 / total_quadgrams)
    return quadgrams, floor

quadgram_model, floor = build_quadgram_model()

def apply_mapping(text, mapping):
    """
    根据映射表对文本进行解密或加密。
    """
    result = ''
    reversed_mapping = {v: k for k, v in mapping.items()}  # 反向映射
    for char in text:
        if char.isalpha():
            is_upper = char.isupper()
            char_lower = char.lower()
            if char_lower in reversed_mapping:
                mapped_char = reversed_mapping[char_lower]
            else:
                mapped_char = char_lower
            if is_upper:
                result += mapped_char.upper()
            else:
                result += mapped_char
        else:
            result += char
    return result

# 适应度函数
def fitness(text):
    text = ''.join(filter(str.isalpha, text.lower()))
    score = 0.0
    for i in range(len(text) - 3):
        quadgram = text[i:i+4]
        if quadgram in quadgram_model:
            score += quadgram_model[quadgram]
        else:
            score += floor
    return score

# 完整的解密函数，返回适应度评分和时间
def decrypt_with_annealing_full(ciphertext, original_text, quadgram_model, floor, max_iterations=10000):
    """
    完整的解密函数，返回适应度评分和时间
    """
    def swap(mapping):
        new_mapping = mapping.copy()
        a, b = random.sample(list(mapping.keys()), 2)
        new_mapping[a], new_mapping[b] = new_mapping[b], new_mapping[a]
        return new_mapping

    start_time = time.time()

    current_mapping = initial_mapping()
    current_plaintext = apply_mapping(ciphertext, current_mapping)
    current_score = fitness(current_plaintext)
    best_mapping = current_mapping.copy()
    best_score = current_score

    T = 10.0  # 初始温度
    alpha = 0.7995  # 冷却率

    accuracies = []
    fitness_scores = []
    for i in range(max_iterations):
        candidate_mapping = swap(current_mapping)
        candidate_plaintext = apply_mapping(ciphertext, candidate_mapping)
        candidate_score = fitness(candidate_plaintext)

        delta_score = candidate_score - current_score

        if delta_score > 0 or math.exp(delta_score / T) > random.random():
            current_mapping = candidate_mapping
            current_score = candidate_score
            current_plaintext = candidate_plaintext

            if current_score > best_score:
                best_mapping = current_mapping.copy()
                best_score = current_score

        matches = sum(1 for a, b in zip(original_text, current_plaintext) if a == b)
        accuracy = matches / len(original_text)
        accuracies.append(accuracy)
        fitness_scores.append(current_score)

        T *= alpha

    decrypted_text = apply_mapping(ciphertext, best_mapping)
    end_time = time.time()
    time_taken = end_time - start_time

    return best_mapping, decrypted_text, {'fitness': best_score, 'time_taken': time_taken}, accuracies, fitness_scores

def initial_mapping():
    """
    创建初始随机字母映射表。
    """
    letters = list('abcdefghijklmnopqrstuvwxyz')
    shuffled = letters[:]
    random.shuffle(shuffled)
    mapping = dict(zip(letters, shuffled))
    return mapping

class CipherCrackerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("单表替换密码破解程序")
        self.ciphertext = ''
        self.best_mapping = {}
        self.decrypted_text = ''
        self.is_cracking = False
        self.stop_cracking_flag = False  # 停止破解的标志
        self.language = '中文'  # 默认语言

        # 设置窗口大小
        self.root.geometry('1200x800')

        # 设置深色主题
        self.set_dark_theme()

        # 创建界面
        self.create_widgets()

    def set_dark_theme(self):
        # 设置深色背景和前景色
        self.root.configure(bg='#1e1e1e')
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('.', background='#1e1e1e', foreground='#ffffff', fieldbackground='#1e1e1e')
        style.configure('TButton', background='#2d2d2d', foreground='#ffffff')
        style.configure('TLabel', background='#1e1e1e', foreground='#ffffff')
        style.configure('TEntry', background='#2d2d2d', foreground='#ffffff', fieldbackground='#2d2d2d')
        style.configure('TNotebook', background='#1e1e1e', foreground='#ffffff')
        style.configure('TNotebook.Tab', background='#2d2d2d', foreground='#ffffff')
        style.map('TButton', background=[('active', '#3e3e3e')])
        style.configure('Horizontal.TProgressbar', troughcolor='#2d2d2d', background='#00ff00', lightcolor='#00ff00', darkcolor='#00ff00', bordercolor='#2d2d2d')

        # 调整菜单字体颜色
        self.menu_font = ('TkMenuFont', 10, 'normal')
        self.menu_bg = '#1e1e1e'
        self.menu_fg = '#ffffff'

    def create_widgets(self):
        # 创建菜单栏
        self.menu_bar = tk.Menu(self.root, bg=self.menu_bg, fg=self.menu_fg, font=self.menu_font)
        self.root.config(menu=self.menu_bar)

        # 添加文件菜单
        self.file_menu = tk.Menu(self.menu_bar, tearoff=0, bg=self.menu_bg, fg=self.menu_fg, font=self.menu_font)
        self.menu_bar.add_cascade(label="文件", menu=self.file_menu)
        self.file_menu.add_command(label="退出", command=self.root.quit)

        # 添加语言菜单
        self.language_menu = tk.Menu(self.menu_bar, tearoff=0, bg=self.menu_bg, fg=self.menu_fg, font=self.menu_font)
        self.menu_bar.add_cascade(label="语言", menu=self.language_menu)
        self.language_menu.add_command(label="中文", command=lambda: self.change_language('中文'))
        self.language_menu.add_command(label="English", command=lambda: self.change_language('English'))

        # 添加帮助菜单
        self.help_menu = tk.Menu(self.menu_bar, tearoff=0, bg=self.menu_bg, fg=self.menu_fg, font=self.menu_font)
        self.menu_bar.add_cascade(label="帮助", menu=self.help_menu)
        self.help_menu.add_command(label="关于", command=self.show_about)

        # 初始化文本内容，根据语言设置
        self.init_texts()

        # 添加标签和文本框
        self.tab_control = ttk.Notebook(self.root)
        self.tab_encrypt = ttk.Frame(self.tab_control)
        self.tab_decrypt = ttk.Frame(self.tab_control)
        self.tab_crack = ttk.Frame(self.tab_control)
        self.tab_test = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab_encrypt, text=self.texts['encrypt_tab'])
        self.tab_control.add(self.tab_decrypt, text=self.texts['decrypt_tab'])
        self.tab_control.add(self.tab_crack, text=self.texts['crack_tab'])
        self.tab_control.add(self.tab_test, text=self.texts['test_tab'])
        self.tab_control.pack(expand=1, fill='both')

        # 加密标签页
        self.create_encrypt_tab()

        # 解密标签页
        self.create_decrypt_tab()

        # 破解标签页
        self.create_crack_tab()

        # 算法测试标签页
        self.create_test_tab()

    def init_texts(self):
        # 根据语言初始化文本内容
        if self.language == '中文':
            self.texts = {
                'file': '文件',
                'exit': '退出',
                'language': '语言',
                'help': '帮助',
                'about': '关于',
                'encrypt_tab': '加密',
                'decrypt_tab': '解密',
                'crack_tab': '破解',
                'test_tab': '算法测试',
                'input_plaintext': '请输入要加密的明文：',
                'encrypt': '加密',
                'encryption_key': '加密密钥（请妥善保存）：',
                'encrypted_ciphertext': '加密后的密文：',
                'input_ciphertext_decrypt': '请输入要解密的密文：',
                'input_key_mapping': '请输入密钥映射（例如 A->D B->E ...）：',
                'decrypt': '解密',
                'decrypted_plaintext': '解密后的明文：',
                'input_ciphertext_crack': '请输入要破解的密文：',
                'start_crack': '开始破解',
                'stop_crack': '停止破解',
                'decryption_result': '解密结果：',
                'current_mapping': '当前映射关系：',
                'input_first_letter': '请输入第一个字母：',
                'input_second_letter': '请输入第二个字母：',
                'swap_mapping': '交换映射',
                'fitness_chart_title': 'Fitness Score Over Iterations',  # 统一为英文
                'iterations': 'Iterations',  # 统一为英文
                'fitness_score': 'Fitness Score',  # 统一为英文
                'test_info': '点击下方按钮使用示例密文测试算法。',
                'start_test': '开始测试',
                'test_result': '测试结果：',
                'about_info': (
                    "单表替换密码破解程序\n"
                    "版本：1.4.1\n"
                    "作者：王子恒\n"
                    "学校：南京信息工程大学\n"
                    "邮箱：zhwang@nuist.edu.cn\n\n"
                    "软件功能：\n"
                    "- 加密：将明文转换为密文。\n"
                    "- 解密：使用密钥解密密文。\n"
                    "- 自动破解：基于 SABCA 算法（Simulated Annealing-Based Cipher Analysis）破解单表替换密码。\n"
                    "- 直观界面：显示破解进度及适应度变化。\n"
                    "- 支持语言切换（中文/英文）。\n\n"
                    "项目支持：\n"
                    "本项目由国家级大学生创新创业项目资助，基金号：ZR2022MF338。\n\n"
                    "算法简介：\n"
                    "本程序采用我们开发的 SABCA 算法（Simulated Annealing-Based Cipher Analysis），该算法基于模拟退火算法（Simulated Annealing Algorithm），"
                    "结合密码分析的特定需求进行了优化设计。SABCA 模拟物理退火过程，通过设定初始温度和冷却曲线，随机搜索密钥空间，以最大化破解适应度。"
                    "与传统方法相比，SABCA 具有较高的效率和较强的适应性，能够在复杂的单表替换密码环境下快速收敛到近似最优解。\n\n"
                    "版权声明：\n"
                    "本软件 © 2024 王子恒 保留所有权利。未经许可，不得复制、修改、或用于商业用途。\n\n"
                    "GitHub 网址：\n"
                    "程序源码托管于 GitHub，访问以下链接获取最新版本及更新日志：\n"
                    "https://github.com/Nickory/SABCA---Simulated-Annealing-Based-Cipher-Analysis\n\n"
                    "赞助开发：\n"
                    "如果您觉得本项目对您有帮助，欢迎通过以下方式支持作者：\n"
                    "- 微信/支付宝二维码（请访问 GitHub 项目页获取）。\n"
                    "- 在 GitHub 上 Star 本项目。\n\n"
                    "特别鸣谢：\n"
                    "感谢南京信息工程大学的支持，以及所有测试人员和贡献者的帮助！\n"
                    "特别感谢瞿治国教授的悉心指导，为本项目的开发提供了宝贵的意见与帮助。感谢王保卫教授的意见与帮助\n"
                    "您的反馈和建议是我们改进的重要动力。\n\n"
                    "使用条款：\n"
                    "本软件仅供学习与研究用途，请勿用于非法目的。用户需对使用本软件产生的后果负责。\n"
                ),
                'language_switched': '语言已切换为{}。',
                'cracking_in_progress': '正在破解，请稍候...',
                'enter_ciphertext': '请输入需要破解的密文！',
                'crack_stopped': '破解已停止。',
                'no_crack_in_progress': '当前没有正在进行的破解任务。',
                'algorithm_converged': '算法已收敛，自动停止破解。',
                'crack_completed': '破解完成！\n总耗时：{:.2f}秒',
                'please_input_ciphertext': '请输入密文和密钥！',
                'please_input_plaintext': '请输入需要加密的明文！',
                'swap_warning': '输入无效，请输入a-z范围内的字母。',
                'please_crack_first': '请先执行破解！',
                'low_fitness_restart': '适应度较低，重新开始破解（{}/5）...',
                'max_retries_reached': '已达到最大重试次数，破解失败。',

            }
        else:
            self.texts = {
                'file': 'File',
                'exit': 'Exit',
                'language': 'Language',
                'help': 'Help',
                'about': 'About',
                'encrypt_tab': 'Encrypt',
                'decrypt_tab': 'Decrypt',
                'crack_tab': 'Crack',
                'test_tab': 'Algorithm Test',
                'input_plaintext': 'Enter plaintext to encrypt:',
                'encrypt': 'Encrypt',
                'encryption_key': 'Encryption Key (Please save it safely):',
                'encrypted_ciphertext': 'Encrypted ciphertext:',
                'input_ciphertext_decrypt': 'Enter ciphertext to decrypt:',
                'input_key_mapping': 'Enter key mapping (e.g., A->D B->E ...):',
                'decrypt': 'Decrypt',
                'decrypted_plaintext': 'Decrypted plaintext:',
                'input_ciphertext_crack': 'Enter ciphertext to crack:',
                'start_crack': 'Start Cracking',
                'stop_crack': 'Stop Cracking',
                'decryption_result': 'Decryption Result:',
                'current_mapping': 'Current Mapping:',
                'input_first_letter': 'Enter first letter:',
                'input_second_letter': 'Enter second letter:',
                'swap_mapping': 'Swap Mapping',
                'fitness_chart_title': 'Fitness Score Over Iterations',
                'iterations': 'Iterations',
                'fitness_score': 'Fitness Score',
                'test_info': 'Click the button below to test the algorithm with sample ciphertext.',
                'start_test': 'Start Test',
                'test_result': 'Test Results:',
                'about_info': (
                    "Simple Substitution Cipher Cracking Program\n"
                    "Version: 1.4.1\n"
                    "Author: Ziheng Wang\n"
                    "Institution: Nanjing University of Information Science and Technology\n"
                    "Email: zhwang@nuist.edu.cn\n\n"
                    "Program Features:\n"
                    "- Encryption: Convert plaintext into ciphertext.\n"
                    "- Decryption: Decrypt ciphertext using a given key.\n"
                    "- Automatic Cracking: Break substitution ciphers using the SABCA algorithm (Simulated Annealing-Based Cipher Analysis).\n"
                    "- Intuitive Interface: Displays cracking progress and fitness changes.\n"
                    "- Multi-language Support: Chinese/English interface.\n\n"
                    "Project Support:\n"
                    "This project is funded by the China National College Student Innovation and Entrepreneurship Program, Project Number: ZR2022MF338.\n\n"
                    "Algorithm Overview:\n"
                    "The program implements our developed SABCA algorithm (Simulated Annealing-Based Cipher Analysis), which is based on the Simulated Annealing Algorithm. "
                    "SABCA is specifically optimized for cipher analysis, simulating the physical annealing process by setting initial temperatures and cooling schedules to "
                    "randomly explore the key space while maximizing cracking fitness. Compared to traditional methods, SABCA is more efficient and adaptable, "
                    "capable of rapidly converging to near-optimal solutions in complex substitution cipher scenarios.\n\n"
                    "Copyright:\n"
                    "This software © 2024 Ziheng Wang. All rights reserved. Unauthorized reproduction, modification, or commercial use is prohibited.\n\n"
                    "GitHub Repository:\n"
                    "The source code is hosted on GitHub. Visit the following link for the latest version and changelog:\n"
                    "https://github.com/Nickory/SABCA---Simulated-Annealing-Based-Cipher-Analysis\n\n"
                    "Support Development:\n"
                    "If you find this project helpful, please consider supporting the author:\n"
                    "- Use WeChat/Alipay QR codes (available on the GitHub project page).\n"
                    "- Star the project on GitHub.\n\n"
                    "Acknowledgments:\n"
                    "Special thanks to Nanjing University of Information Science and Technology for their support, and to all testers and contributors who helped improve this program. "
                    "Particular gratitude goes to Professor Zhiguo Qu for his invaluable guidance and suggestions during the development of this project. "
                    "Your feedback and suggestions are crucial for further improvements.\n\n"
                    "Terms of Use:\n"
                    "This software is intended for educational and research purposes only. It must not be used for illegal activities. Users are responsible for any consequences arising from its use.\n"
                ),
                'language_switched': 'Language switched to {}.',
                'cracking_in_progress': 'Cracking in progress, please wait...',
                'enter_ciphertext': 'Please enter the ciphertext to crack!',
                'crack_stopped': 'Cracking has been stopped.',
                'no_crack_in_progress': 'No cracking in progress.',
                'algorithm_converged': 'Algorithm has converged, auto-stopping cracking.',
                'crack_completed': 'Cracking completed!\nTotal time: {:.2f} seconds',
                'please_input_ciphertext': 'Please enter the ciphertext and key!',
                'please_input_plaintext': 'Please enter the plaintext to encrypt!',
                'swap_warning': 'Invalid letters, please enter letters between a-z.',
                'please_crack_first': 'Please perform cracking first!',
                'low_fitness_restart': 'Low fitness score, restarting cracking ({}/5)...',
                'max_retries_reached': 'Maximum retries reached, cracking failed.',
            }

    def create_encrypt_tab(self):
        # 明文输入框
        self.lbl_plaintext = ttk.Label(self.tab_encrypt, text=self.texts['input_plaintext'])
        self.lbl_plaintext.pack()
        self.txt_plaintext = scrolledtext.ScrolledText(self.tab_encrypt, width=80, height=10, bg='#2d2d2d',
                                                       fg='#00ff00', insertbackground='#ffffff')
        self.txt_plaintext.pack()

        # 字数统计标签
        self.lbl_word_count_plaintext = ttk.Label(self.tab_encrypt, text="Word count: 0", background="#1e1e1e",
                                                  foreground="#ffffff")
        self.lbl_word_count_plaintext.pack()

        # 绑定字数统计
        self.txt_plaintext.bind("<<Modified>>",
                                lambda e: self.update_word_count(self.txt_plaintext, self.lbl_word_count_plaintext))

        # 加密按钮
        self.btn_encrypt = ttk.Button(self.tab_encrypt, text=self.texts['encrypt'], command=self.encrypt_text)
        self.btn_encrypt.pack(pady=5)

        # 密钥显示
        self.lbl_key = ttk.Label(self.tab_encrypt, text=self.texts['encryption_key'])
        self.lbl_key.pack()
        self.txt_key = tk.Text(self.tab_encrypt, width=80, height=2, bg='#2d2d2d', fg='#00ff00',
                               insertbackground='#ffffff')
        self.txt_key.pack()

        # 密文显示
        self.lbl_ciphertext_encrypted = ttk.Label(self.tab_encrypt, text=self.texts['encrypted_ciphertext'])
        self.lbl_ciphertext_encrypted.pack()
        self.txt_ciphertext_encrypted = scrolledtext.ScrolledText(self.tab_encrypt, width=80, height=10, bg='#2d2d2d',
                                                                  fg='#00ff00', insertbackground='#ffffff')
        self.txt_ciphertext_encrypted.pack()

        # 字数统计标签
        self.lbl_word_count_ciphertext = ttk.Label(self.tab_encrypt, text="Word count: 0", background="#1e1e1e",
                                                   foreground="#ffffff")
        self.lbl_word_count_ciphertext.pack()

        # 绑定字数统计
        self.txt_ciphertext_encrypted.bind("<<Modified>>",
                                           lambda e: self.update_word_count(self.txt_ciphertext_encrypted,
                                                                            self.lbl_word_count_ciphertext))

    def create_decrypt_tab(self):
        # 密文输入框
        self.lbl_ciphertext_decrypt = ttk.Label(self.tab_decrypt, text=self.texts['input_ciphertext_decrypt'])
        self.lbl_ciphertext_decrypt.pack()
        self.txt_ciphertext_decrypt = scrolledtext.ScrolledText(self.tab_decrypt, width=80, height=10, bg='#2d2d2d',
                                                                fg='#00ff00', insertbackground='#ffffff')
        self.txt_ciphertext_decrypt.pack()

        # 字数统计标签
        self.lbl_word_count_ciphertext_decrypt = ttk.Label(self.tab_decrypt, text="Word count: 0", background="#1e1e1e",
                                                           foreground="#ffffff")
        self.lbl_word_count_ciphertext_decrypt.pack()

        # 绑定字数统计
        self.txt_ciphertext_decrypt.bind("<<Modified>>", lambda e: self.update_word_count(self.txt_ciphertext_decrypt,
                                                                                              self.lbl_word_count_ciphertext_decrypt))

        # 密钥输入框
        self.lbl_key_decrypt = ttk.Label(self.tab_decrypt, text=self.texts['input_key_mapping'])
        self.lbl_key_decrypt.pack()
        self.entry_key_decrypt = ttk.Entry(self.tab_decrypt, width=80)
        self.entry_key_decrypt.pack()

        # 解密按钮
        self.btn_decrypt = ttk.Button(self.tab_decrypt, text=self.texts['decrypt'], command=self.decrypt_text)
        self.btn_decrypt.pack(pady=5)

        # 明文显示
        self.lbl_plaintext_decrypted = ttk.Label(self.tab_decrypt, text=self.texts['decrypted_plaintext'])
        self.lbl_plaintext_decrypted.pack()
        self.txt_plaintext_decrypted = scrolledtext.ScrolledText(self.tab_decrypt, width=80, height=10, bg='#2d2d2d',
                                                                 fg='#00ff00', insertbackground='#ffffff')
        self.txt_plaintext_decrypted.pack()

        # 字数统计标签
        self.lbl_word_count_plaintext_decrypted = ttk.Label(self.tab_decrypt, text="Word count: 0",
                                                            background="#1e1e1e", foreground="#ffffff")
        self.lbl_word_count_plaintext_decrypted.pack()

        # 绑定字数统计
        self.txt_plaintext_decrypted.bind("<<Modified>>", lambda e: self.update_word_count(self.txt_plaintext_decrypted,
                                                                                               self.lbl_word_count_plaintext_decrypted))

    def create_crack_tab(self):
        # 密文输入框
        self.lbl_ciphertext_crack = ttk.Label(self.tab_crack, text=self.texts['input_ciphertext_crack'])
        self.lbl_ciphertext_crack.pack()
        self.txt_ciphertext_crack = scrolledtext.ScrolledText(self.tab_crack, width=80, height=10, bg='#2d2d2d',
                                                              fg='#00ff00', insertbackground='#ffffff')
        self.txt_ciphertext_crack.pack()

        # 字数统计标签
        self.lbl_word_count_ciphertext_crack = ttk.Label(self.tab_crack, text="Word count: 0", background="#1e1e1e",
                                                         foreground="#ffffff")
        self.lbl_word_count_ciphertext_crack.pack()

        # 绑定字数统计
        self.txt_ciphertext_crack.bind("<<Modified>>", lambda e: self.update_word_count(self.txt_ciphertext_crack,
                                                                                            self.lbl_word_count_ciphertext_crack))

        # 按钮框架
        self.frame_buttons = ttk.Frame(self.tab_crack)
        self.frame_buttons.pack(pady=5)

        # 开始破解按钮
        self.btn_crack = ttk.Button(self.frame_buttons, text=self.texts['start_crack'], command=self.start_cracking)
        self.btn_crack.pack(side=tk.LEFT, padx=5)

        # 停止破解按钮
        self.btn_stop = ttk.Button(self.frame_buttons, text=self.texts['stop_crack'], command=self.stop_cracking)
        self.btn_stop.pack(side=tk.LEFT, padx=5)

        # 进度条
        self.progress = ttk.Progressbar(self.tab_crack, orient='horizontal', length=400, mode='determinate', maximum=100, style='Horizontal.TProgressbar')
        self.progress.pack(pady=5)

        # 解密结果显示
        self.lbl_decrypted = ttk.Label(self.tab_crack, text=self.texts['decryption_result'])
        self.lbl_decrypted.pack()
        self.txt_decrypted = scrolledtext.ScrolledText(self.tab_crack, width=80, height=10, bg='#2d2d2d', fg='#00ff00', insertbackground='#ffffff')
        self.txt_decrypted.pack()

        # 映射关系显示
        self.lbl_mapping = ttk.Label(self.tab_crack, text=self.texts['current_mapping'])
        self.lbl_mapping.pack()
        self.txt_mapping = tk.Text(self.tab_crack, width=80, height=2, bg='#2d2d2d', fg='#00ff00', insertbackground='#ffffff')
        self.txt_mapping.pack()

        # 交换字母映射
        self.frame_swap = ttk.Frame(self.tab_crack)
        self.frame_swap.pack(pady=5)
        self.lbl_letter1 = ttk.Label(self.frame_swap, text=self.texts['input_first_letter'])
        self.lbl_letter1.pack(side=tk.LEFT)
        self.entry_letter1 = ttk.Entry(self.frame_swap, width=5)
        self.entry_letter1.pack(side=tk.LEFT)
        self.lbl_letter2 = ttk.Label(self.frame_swap, text=self.texts['input_second_letter'])
        self.lbl_letter2.pack(side=tk.LEFT)
        self.entry_letter2 = ttk.Entry(self.frame_swap, width=5)
        self.entry_letter2.pack(side=tk.LEFT)
        self.btn_swap = ttk.Button(self.frame_swap, text=self.texts['swap_mapping'], command=self.swap_letters)
        self.btn_swap.pack(side=tk.LEFT, padx=5)

        # 添加可视化图表（统一使用英文）
        self.figure = plt.Figure(figsize=(6, 4), dpi=100, facecolor='#1e1e1e')
        self.ax = self.figure.add_subplot(111)
        self.ax.set_facecolor('#1e1e1e')
        self.ax.set_title('Fitness Score Over Iterations', color='#ffffff')  # 统一为英文
        self.ax.set_xlabel('Iterations', color='#ffffff')  # 统一为英文
        self.ax.set_ylabel('Fitness Score', color='#ffffff')  # 统一为英文
        self.ax.tick_params(axis='x', colors='#ffffff')
        self.ax.tick_params(axis='y', colors='#ffffff')
        self.ax.grid(True, color='#555555')
        self.canvas = FigureCanvasTkAgg(self.figure, master=self.tab_crack)
        self.canvas.get_tk_widget().pack()

        # 存储适应度评分
        self.scores = []
        self.iterations = []

    def create_test_tab(self):
        # 测试说明（统一为英文）
        self.lbl_test_info = ttk.Label(self.tab_test, text=self.texts['test_info'])
        self.lbl_test_info.pack(pady=5)

        # 开始测试按钮
        self.btn_test = ttk.Button(self.tab_test, text=self.texts['start_test'], command=self.start_test)
        self.btn_test.pack(pady=5)

        # 进度条
        self.test_progress = ttk.Progressbar(self.tab_test, orient='horizontal', length=400, mode='determinate', maximum=100, style='Horizontal.TProgressbar')
        self.test_progress.pack(pady=5)

        # 测试结果显示
        self.lbl_test_result = ttk.Label(self.tab_test, text=self.texts['test_result'])
        self.lbl_test_result.pack()
        self.txt_test_result = scrolledtext.ScrolledText(self.tab_test, width=80, height=10, bg='#2d2d2d', fg='#00ff00', insertbackground='#ffffff')
        self.txt_test_result.pack()

        # 可视化图表（统一使用英文）
        self.figure_test = plt.Figure(figsize=(6, 4), dpi=100, facecolor='#1e1e1e')
        self.ax_accuracy = self.figure_test.add_subplot(211)
        self.ax_accuracy.set_facecolor('#1e1e1e')
        self.ax_accuracy.set_title('Accuracy Over Iterations', color='#ffffff')  # 统一为英文
        self.ax_accuracy.set_xlabel('Iterations', color='#ffffff')  # 统一为英文
        self.ax_accuracy.set_ylabel('Accuracy', color='#ffffff')  # 统一为英文
        self.ax_accuracy.tick_params(axis='x', colors='#ffffff')
        self.ax_accuracy.tick_params(axis='y', colors='#ffffff')
        self.ax_accuracy.grid(True, color='#555555')

        self.ax_fitness = self.figure_test.add_subplot(212)
        self.ax_fitness.set_facecolor('#1e1e1e')
        self.ax_fitness.set_title('Fitness Score Over Iterations', color='#ffffff')  # 统一为英文
        self.ax_fitness.set_xlabel('Iterations', color='#ffffff')  # 统一为英文
        self.ax_fitness.set_ylabel('Fitness Score', color='#ffffff')  # 统一为英文
        self.ax_fitness.tick_params(axis='x', colors='#ffffff')
        self.ax_fitness.tick_params(axis='y', colors='#ffffff')
        self.ax_fitness.grid(True, color='#555555')

        # 调整子图之间的间距
        self.figure_test.subplots_adjust(hspace=0.5)  # hspace 参数控制垂直方向的间距

        self.canvas_test = FigureCanvasTkAgg(self.figure_test, master=self.tab_test)
        self.canvas_test.get_tk_widget().pack()

    def start_test(self):
        # 禁用开始测试按钮，防止重复点击
        self.btn_test.config(state='disabled')
        # 重置进度条和结果显示
        self.test_progress['value'] = 0
        self.txt_test_result.delete("1.0", tk.END)
        self.ax_accuracy.cla()
        self.ax_fitness.cla()

        # 设置图表属性（统一为英文）
        self.ax_accuracy.set_facecolor('#1e1e1e')
        self.ax_accuracy.set_title('Accuracy Over Iterations', color='#ffffff')  # 统一为英文
        self.ax_accuracy.set_xlabel('Iterations', color='#ffffff')  # 统一为英文
        self.ax_accuracy.set_ylabel('Accuracy', color='#ffffff')  # 统一为英文
        self.ax_accuracy.tick_params(axis='x', colors='#ffffff')
        self.ax_accuracy.tick_params(axis='y', colors='#ffffff')
        self.ax_accuracy.grid(True, color='#555555')

        self.ax_fitness.set_facecolor('#1e1e1e')
        self.ax_fitness.set_title('Fitness Score Over Iterations', color='#ffffff')  # 统一为英文
        self.ax_fitness.set_xlabel('Iterations', color='#ffffff')  # 统一为英文
        self.ax_fitness.set_ylabel('Fitness Score', color='#ffffff')  # 统一为英文
        self.ax_fitness.tick_params(axis='x', colors='#ffffff')
        self.ax_fitness.tick_params(axis='y', colors='#ffffff')
        self.ax_fitness.grid(True, color='#555555')

        self.canvas_test.draw()

        # 启动测试线程
        threading.Thread(target=self.run_tests_and_visualize_gui).start()

    def run_tests_and_visualize_gui(self):
        # 更新进度条
        total_tests = 15  # 5种类型 * 3种长度
        current_test = 0

        quadgram_model, floor = build_quadgram_model()
        texts = generate_texts()
        lengths = [600, 800, 1000]

        for text_type, original_text in texts.items():
            ciphertext_mapping = initial_mapping()
            ciphertext = apply_mapping(original_text, ciphertext_mapping)

            for length in lengths:
                if self.stop_cracking_flag:
                    break
                test_original = original_text[:length]
                test_cipher = ciphertext[:length]
                best_map, decrypted_text, best_score, accuracies, fitness_scores = decrypt_with_annealing_full(test_cipher, test_original, quadgram_model, floor, max_iterations=10000)

                # 更新测试结果文本框
                result = f"Text Type: {text_type}, Length: {length} words\nTime Taken: {best_score['time_taken']:.2f} seconds\nFitness Score: {best_score['fitness']}\nDecrypted Text Preview:\n{decrypted_text[:500]}\n\n"
                self.txt_test_result.insert(tk.END, result)
                self.txt_test_result.see(tk.END)

                # 更新图表
                self.ax_accuracy.plot(range(1, len(accuracies) + 1), accuracies, label=f'{text_type} ({length} words)')
                self.ax_fitness.plot(range(1, len(fitness_scores) + 1), fitness_scores, label=f'{text_type} ({length} words)')

                # 更新进度条
                current_test += 1
                progress = (current_test / total_tests) * 100
                self.test_progress['value'] = progress
                self.root.update_idletasks()

        # 完成测试，更新图例和启用开始按钮
        self.ax_accuracy.legend(loc='lower right', fontsize=8)
        self.ax_fitness.legend(loc='lower right', fontsize=8)
        self.canvas_test.draw()

        self.btn_test.config(state='normal')
        messagebox.showinfo("Test Completed", "Algorithm testing has been completed.")

    def stop_cracking(self):
        # 设置停止标志
        self.stop_cracking_flag = True
        self.is_cracking = False
        messagebox.showinfo("", self.texts['crack_stopped'])

    def encrypt_text(self):
        plaintext = self.txt_plaintext.get("1.0", tk.END).strip()
        if not plaintext:
            messagebox.showwarning("", self.texts['please_input_plaintext'])
            return
        letters = list(string.ascii_lowercase)
        shuffled_letters = letters[:]
        random.shuffle(shuffled_letters)
        key_mapping = dict(zip(letters, shuffled_letters))
        ciphertext_encrypted = ''
        for char in plaintext:
            if char.isalpha():
                is_upper = char.isupper()
                char_lower = char.lower()
                mapped_char = key_mapping[char_lower]
                if is_upper:
                    ciphertext_encrypted += mapped_char.upper()
                else:
                    ciphertext_encrypted += mapped_char
            else:
                ciphertext_encrypted += char
        # 显示密钥和密文
        key_str = ' '.join([f"{k.upper()}->{v.upper()}" for k, v in sorted(key_mapping.items())])
        self.txt_key.delete("1.0", tk.END)
        self.txt_key.insert(tk.END, key_str)
        self.txt_ciphertext_encrypted.delete("1.0", tk.END)
        self.txt_ciphertext_encrypted.insert(tk.END, ciphertext_encrypted)

    def decrypt_text(self):
        ciphertext = self.txt_ciphertext_decrypt.get("1.0", tk.END).strip()
        key_input = self.entry_key_decrypt.get().strip()
        if not ciphertext or not key_input:
            messagebox.showwarning("", self.texts['please_input_ciphertext'])
            return
        key_pairs = key_input.split()
        key_mapping = {}
        for pair in key_pairs:
            if '->' in pair:
                try:
                    k, v = pair.upper().split('->')
                    key_mapping[v.lower()] = k.lower()  # 保持算法一致
                except ValueError:
                    continue  # 忽略无效的映射
        plaintext_decrypted = ''
        for char in ciphertext:
            if char.isalpha():
                is_upper = char.isupper()
                char_lower = char.lower()
                if char_lower in key_mapping:
                    mapped_char = key_mapping[char_lower]
                else:
                    mapped_char = char_lower
                if is_upper:
                    plaintext_decrypted += mapped_char.upper()
                else:
                    plaintext_decrypted += mapped_char
            else:
                plaintext_decrypted += char
        self.txt_plaintext_decrypted.delete("1.0", tk.END)
        self.txt_plaintext_decrypted.insert(tk.END, plaintext_decrypted)

    def start_cracking(self):
        if self.is_cracking:
            messagebox.showinfo("", self.texts['cracking_in_progress'])
            return
        self.ciphertext = self.txt_ciphertext_crack.get("1.0", tk.END).strip()
        if not self.ciphertext:
            messagebox.showwarning("", self.texts['enter_ciphertext'])
            return
        self.is_cracking = True
        self.stop_cracking_flag = False  # 重置停止标志
        self.progress['value'] = 0
        self.scores = []  # 重置评分列表
        self.iterations = []  # 重置迭代次数列表
        self.ax.cla()
        self.ax.set_facecolor('#1e1e1e')
        self.ax.set_title('Fitness Score Over Iterations', color='#ffffff')  # 统一为英文
        self.ax.set_xlabel('Iterations', color='#ffffff')  # 统一为英文
        self.ax.set_ylabel('Fitness Score', color='#ffffff')  # 统一为英文
        self.ax.tick_params(axis='x', colors='#ffffff')
        self.ax.tick_params(axis='y', colors='#ffffff')
        self.ax.grid(True, color='#555555')
        self.canvas.draw()
        self.root.update_idletasks()
        self.retry_count = 0  # 重试计数器
        threading.Thread(target=self.decrypt_with_annealing_gui).start()

    def decrypt_with_annealing_gui(self, max_iterations=10000):
        """
        使用模拟退火算法破解密文（GUI版本）。
        """
        start_time = time.time()  # 记录开始时间

        max_retries = 5  # 最大重试次数
        while self.retry_count < max_retries and not self.stop_cracking_flag:
            current_mapping = initial_mapping()
            current_plaintext = apply_mapping(self.ciphertext, current_mapping)
            current_score = fitness(current_plaintext)
            best_mapping = current_mapping.copy()
            best_score = current_score

            T = 10.0  # 初始温度
            alpha = 0.8995  # 冷却率

            no_improve_count = 0  # 未提升的迭代次数计数
            max_no_improve = 3000  # 如果3000次迭代未提升，则认为已收敛

            for i in range(max_iterations):
                if not self.is_cracking or self.stop_cracking_flag:
                    break
                candidate_mapping = self.swap(current_mapping)
                candidate_plaintext = apply_mapping(self.ciphertext, candidate_mapping)
                candidate_score = fitness(candidate_plaintext)

                delta_score = candidate_score - current_score

                if delta_score > 0 or math.exp(delta_score / T) > random.random():
                    current_mapping = candidate_mapping
                    current_score = candidate_score
                    current_plaintext = candidate_plaintext

                    if current_score > best_score:
                        best_mapping = current_mapping.copy()
                        best_score = current_score
                        self.best_mapping = best_mapping
                        self.decrypted_text = apply_mapping(self.ciphertext, best_mapping)
                        # 更新解密结果和映射关系
                        self.update_decryption()
                        no_improve_count = 0  # 重置未提升计数
                    else:
                        no_improve_count += 1
                else:
                    no_improve_count += 1

                T *= alpha

                # 更新进度条
                progress_value = ((i + 1) / max_iterations) * 100
                self.progress['value'] = progress_value

                # 更新适应度评分列表
                self.scores.append(best_score)
                self.iterations.append(i + 1)

                # 更新可视化曲线
                if (i + 1) % 100 == 0:
                    self.ax.cla()
                    self.ax.set_facecolor('#1e1e1e')
                    self.ax.set_title('Fitness Score Over Iterations', color='#ffffff')  # 统一为英文
                    self.ax.set_xlabel('Iterations', color='#ffffff')  # 统一为英文
                    self.ax.set_ylabel('Fitness Score', color='#ffffff')  # 统一为英文
                    self.ax.tick_params(axis='x', colors='#ffffff')
                    self.ax.tick_params(axis='y', colors='#ffffff')
                    self.ax.plot(self.iterations, self.scores, color='#00ff00')
                    self.ax.grid(True, color='#555555')
                    self.canvas.draw()

                self.root.update_idletasks()

                # 如果长时间未提升，认为已收敛，自动暂停
                if no_improve_count >= max_no_improve:
                    break

            self.is_cracking = False

            # 判断适应度是否过低，若过低则重试
            if best_score < -25000:
                self.retry_count += 1
                if self.retry_count < max_retries:
                    messagebox.showinfo("", self.texts['low_fitness_restart'].format(self.retry_count))
                    self.is_cracking = True
                    self.progress['value'] = 0
                    self.scores = []
                    self.iterations = []
                    self.ax.cla()
                    self.ax.set_facecolor('#1e1e1e')
                    self.ax.set_title('Fitness Score Over Iterations', color='#ffffff')  # 统一为英文
                    self.ax.set_xlabel('Iterations', color='#ffffff')  # 统一为英文
                    self.ax.set_ylabel('Fitness Score', color='#ffffff')  # 统一为英文
                    self.ax.tick_params(axis='x', colors='#ffffff')
                    self.ax.tick_params(axis='y', colors='#ffffff')
                    self.ax.grid(True, color='#555555')
                    self.canvas.draw()
                    continue
                else:
                    messagebox.showinfo("", self.texts['max_retries_reached'])
                    break
            else:
                end_time = time.time()  # 记录结束时间
                time_taken = end_time - start_time
                messagebox.showinfo("", self.texts['crack_completed'].format(time_taken))
                self.progress['value'] = 100  # 进度条填满
                break

    def update_decryption(self):
        self.txt_decrypted.delete("1.0", tk.END)
        self.txt_decrypted.insert(tk.END, self.decrypted_text[:1000])  # 显示前1000个字符

        # 显示映射关系
        mapping_str = ' '.join([f"{k.upper()}->{v.upper()}" for k, v in sorted(self.best_mapping.items())])
        self.txt_mapping.delete("1.0", tk.END)
        self.txt_mapping.insert(tk.END, mapping_str)

    def update_word_count(self, text_widget, label_widget):
        """
        Update the word count for a given text widget.
        """
        content = text_widget.get("1.0", tk.END).strip()
        word_count = len(content.split())  # 统计单词数量
        label_widget.config(text=f"Word count: {word_count}")  # 更新标签显示
        text_widget.edit_modified(False)  # 重置修改标志

    def swap(self, mapping):
        """
        交换映射表中的两个字母
        """
        new_mapping = mapping.copy()
        a, b = random.sample(list(new_mapping.keys()), 2)
        new_mapping[a], new_mapping[b] = new_mapping[b], new_mapping[a]
        return new_mapping

    def swap_letters(self):
        if not self.best_mapping:
            messagebox.showwarning("", self.texts['please_crack_first'])
            return
        letter1 = self.entry_letter1.get().lower()
        letter2 = self.entry_letter2.get().lower()
        if letter1 in self.best_mapping and letter2 in self.best_mapping and len(letter1) == 1 and len(letter2) == 1 and letter1.isalpha() and letter2.isalpha():
            self.best_mapping[letter1], self.best_mapping[letter2] = self.best_mapping[letter2], self.best_mapping[letter1]
            # 更新解密结果
            self.decrypted_text = apply_mapping(self.ciphertext, self.best_mapping)
            self.update_decryption()
        else:
            messagebox.showwarning("", self.texts['swap_warning'])

    def show_about(self):
        messagebox.showinfo(self.texts['about'], self.texts['about_info'])

    def change_language(self, lang):
        """
        Change the application language.
        """
        self.language = lang
        self.init_texts()
        self.update_texts()
        messagebox.showinfo("", self.texts['language_switched'].format(lang))

    def update_texts(self):
        """
        Update all UI texts based on the current language.
        """
        # Rebuild menu bar with updated labels
        self.menu_bar.delete(0, 'end')  # Remove existing menu entries

        # File menu
        self.file_menu = tk.Menu(self.menu_bar, tearoff=0, bg=self.menu_bg, fg=self.menu_fg, font=self.menu_font)
        self.file_menu.add_command(label=self.texts['exit'], command=self.root.quit)
        self.menu_bar.add_cascade(label=self.texts['file'], menu=self.file_menu)

        # Language menu
        self.language_menu = tk.Menu(self.menu_bar, tearoff=0, bg=self.menu_bg, fg=self.menu_fg, font=self.menu_font)
        self.language_menu.add_command(label="English", command=lambda: self.change_language('English'))
        self.language_menu.add_command(label="中文", command=lambda: self.change_language('中文'))
        self.menu_bar.add_cascade(label=self.texts['language'], menu=self.language_menu)

        # Help menu
        self.help_menu = tk.Menu(self.menu_bar, tearoff=0, bg=self.menu_bg, fg=self.menu_fg, font=self.menu_font)
        self.help_menu.add_command(label=self.texts['about'], command=self.show_about)
        self.menu_bar.add_cascade(label=self.texts['help'], menu=self.help_menu)

        # Update tab labels
        self.tab_control.tab(0, text=self.texts['encrypt_tab'])
        self.tab_control.tab(1, text=self.texts['decrypt_tab'])
        self.tab_control.tab(2, text=self.texts['crack_tab'])
        self.tab_control.tab(3, text=self.texts['test_tab'])

        # Update labels and buttons in each tab
        self.lbl_plaintext.config(text=self.texts['input_plaintext'])
        self.btn_encrypt.config(text=self.texts['encrypt'])
        self.lbl_key.config(text=self.texts['encryption_key'])
        self.lbl_ciphertext_encrypted.config(text=self.texts['encrypted_ciphertext'])

        self.lbl_ciphertext_decrypt.config(text=self.texts['input_ciphertext_decrypt'])
        self.btn_decrypt.config(text=self.texts['decrypt'])
        self.lbl_plaintext_decrypted.config(text=self.texts['decrypted_plaintext'])

        self.lbl_ciphertext_crack.config(text=self.texts['input_ciphertext_crack'])
        self.btn_crack.config(text=self.texts['start_crack'])
        self.btn_stop.config(text=self.texts['stop_crack'])
        self.lbl_decrypted.config(text=self.texts['decryption_result'])

        self.lbl_test_info.config(text=self.texts['test_info'])
        self.btn_test.config(text=self.texts['start_test'])
        self.lbl_test_result.config(text=self.texts['test_result'])

    def mainloop(self):
        self.root.mainloop()


import tkinter as tk
from PIL import Image, ImageTk
import os

import tkinter as tk
from PIL import Image, ImageTk
import os


import tkinter as tk
from PIL import Image, ImageTk
import os

def main():
    """
    主函数：启动文字动画 -> 图片动画 -> 主程序。
    """
    def start_main_app():
        """
        启动主应用窗口。
        """
        root.destroy()  # 销毁动画窗口
        main_root = tk.Tk()
        main_root.geometry("1200x800")  # 设置主窗口大小
        main_root.title("单表替换密码破解程序")

        # 设置窗口图标（使用 .ico 文件）
        project_dir = os.path.dirname(os.path.abspath(__file__))
        logo_path = os.path.join(project_dir, "logo.ico")

        # 确保图标文件存在
        if os.path.exists(logo_path):
            main_root.iconbitmap(logo_path)  # 设置窗口图标为 .ico 文件

        # 设置窗口主题为深色
        main_root.configure(bg="#1e1e1e")

        # 启动主程序逻辑
        app = CipherCrackerApp(main_root)  # 启动主应用逻辑
        app.mainloop()

    def show_logo_after_text_animation():
        """
        在文字动画完成后调用图片动画。
        """
        canvas.delete("all")  # 清除文字动画的内容
        show_logo_animation(canvas, root, start_main_app)

    # 创建启动窗口
    root = tk.Tk()
    root.overrideredirect(True)  # 去掉窗口边框
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    win_width, win_height = 800, 600
    position = f"{win_width}x{win_height}+{(screen_width - win_width) // 2}+{(screen_height - win_height) // 2}"
    root.geometry(position)  # 设置窗口大小和位置
    root.configure(bg="#1e1e1e")  # 设置背景色

    # 创建共享的画布
    canvas = tk.Canvas(root, width=win_width, height=win_height, bg="#1e1e1e", highlightthickness=0)
    canvas.pack()

    # 启动文字动画
    show_text_animation(canvas, root, show_logo_after_text_animation)

    root.mainloop()


def show_text_animation(canvas, root, on_complete):
    """
    显示文字动画，逐行显示程序信息，中英双语。
    """
    # 程序信息文字（中英双语）
    info_lines = [
        ("单表替换密码破解程序", "Simple Substitution Cipher Cracking Program"),
        ("版本：1.3", "Version: 1.3"),
        ("作者：Ziheng Wang", "Email: zhwang@nuist.edu.cn"),
        ("南京信息工程大学", "Nanjing University of Information Science and Technology"),
        ("算法：SABCA (基于模拟退火分析算法)", "Algorithm: SABCA (Simulated Annealing-Based Cipher Analysis)"),
        ("项目资助：国家级大学生创新创业项目 ZR2022MF338", "Funded by: National Innovation Program ZR2022MF338"),
    ]

    # 动态计算字体和间距
    win_width, win_height = 800, 600
    total_lines = len(info_lines) * 2  # 中英文为两行
    max_font_size = 28  # 最大字体大小
    min_font_size = 18  # 最小字体大小
    font_size = max(min(win_height // (total_lines * 2), max_font_size), min_font_size)
    line_spacing = font_size + 10  # 行间距基于字体大小动态调整

    # 字体设置
    font_cn = ("Arial", font_size, "bold")  # 中文字体
    font_en = ("Arial", int(font_size * 0.8))  # 英文字体（稍小）
    start_y = (win_height - line_spacing * total_lines) // 2  # 文字顶部开始位置，居中显示

    def show_next_line(index=0):
        if index < len(info_lines):
            cn_text, en_text = info_lines[index]

            # 中英文分别绘制
            y_position_cn = start_y + index * line_spacing * 2
            y_position_en = y_position_cn + line_spacing
            cn_text_id = canvas.create_text(
                win_width // 2,
                y_position_cn,
                text=cn_text,
                font=font_cn,
                fill="#111111",  # 初始颜色较暗
                anchor="center",
            )
            en_text_id = canvas.create_text(
                win_width // 2,
                y_position_en,
                text=en_text,
                font=font_en,
                fill="#111111",  # 初始颜色较暗
                anchor="center",
            )

            # 淡入效果
            def fade_in_text(text_id, step=0):
                if step <= 10:
                    brightness = int(17 * step)  # 从暗到亮（0x11 到 0xff）
                    color = f"#{brightness:02x}ff{brightness:02x}"  # 亮度影响红和绿分量
                    canvas.itemconfig(text_id, fill=color)
                    root.after(50, lambda: fade_in_text(text_id, step + 1))

            fade_in_text(cn_text_id)  # 中文淡入
            fade_in_text(en_text_id)  # 英文淡入
            root.after(600, lambda: show_next_line(index + 1))  # 显示下一行文字

        else:
            root.after(1000, on_complete)  # 文字动画结束后调用图片动画

    show_next_line()


def show_logo_animation(canvas, root, on_complete):
    """
    显示图片渐入动画，展示 logo。
    """
    # 获取项目目录并加载 logo
    project_dir = os.path.dirname(os.path.abspath(__file__))
    logo_path = os.path.join(project_dir, "logo.png")

    # 加载 logo 图片
    pil_image = Image.open(logo_path)
    img_width, img_height = pil_image.size
    scale = min(800 / img_width, 600 / img_height)
    resized_image = pil_image.resize((int(img_width * scale), int(img_height * scale)), Image.Resampling.LANCZOS)
    logo_img = ImageTk.PhotoImage(resized_image)
    logo_img_id = canvas.create_image(400, 300, image=logo_img)

    # 保持图像引用以避免垃圾回收
    canvas.image = logo_img  # 这里保存引用

    # 渐变动画
    def fade_in(step=0):
        if step <= 10:  # 渐变步数
            alpha = int(255 * (step / 10))  # 透明度从 0 到 255
            faded_image = resized_image.copy()
            faded_image.putalpha(alpha)
            tk_img = ImageTk.PhotoImage(faded_image)
            canvas.itemconfig(logo_img_id, image=tk_img)
            canvas.image = tk_img  # 防止图像被垃圾回收
            root.after(100, lambda: fade_in(step + 1))  # 递归调用实现动画
        else:
            root.after(1000, on_complete)  # 1秒后回调到主程序

    fade_in()


if __name__ == "__main__":
    main()



