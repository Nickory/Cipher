# Cipher - Application Cryptography Experiments

This repository contains a collection of six experiments required for the Application Cryptography course at **Nanjing University of Information Science & Technology (NUIST)**. Each experiment is designed with a **Graphical User Interface (GUI)** for enhanced usability and interactive learning. The experiments encompass core cryptographic techniques, making this project an excellent tool for mastering the theory and practical applications of cryptography.

本项目包含南京信息工程大学应用密码学课程所需的六个实验。每个实验都配备了图形用户界面 (GUI)，以便于直观的学习和实践。项目涵盖了密码学的核心概念，为学习和掌握密码学理论与实际应用提供了便捷的工具。

## Features
- **User-Friendly GUI**: Each cryptography experiment comes with an intuitive graphical interface that simplifies complex operations, making the learning process interactive and engaging.
- **Comprehensive Learning Tool**: This repository includes six diverse experiments, allowing a holistic exploration of cryptographic algorithms, from classical ciphers to modern encryption standards.
- **Visualization of Results**: Many experiments provide graphical representations of key results, helping to better understand the algorithms' performance and behavior.

## Experiments

### Experiment 1: Extended Euclidean Algorithm / 扩展欧几里得算法

#### **Description**
This experiment demonstrates the implementation of the **Extended Euclidean Algorithm** to calculate the **Greatest Common Divisor (GCD)** of two integers. It also finds the coefficients that satisfy **Bézout's identity**. The performance and intermediate steps are visualized to deepen understanding.

#### **Key Visualizations**
The following images showcase important results from the experiment:

<p align="center">
    <img src="images/image1.png" alt="Convergence of a and b" width="24%" style="margin: 0 1%" />
    <img src="images/image5.png" alt="Step Count Heatmap" width="24%" style="margin: 0 1%" />
    <img src="images/image6.png" alt="Time Complexity Analysis" width="24%" style="margin: 0 1%" />
    <img src="images/image7.png" alt="Sensitivity Analysis" width="24%" style="margin: 0 1%" />
</p>

<p align="center">
    <b>Figure 1:</b> Convergence of Values and Quotient Analysis &nbsp;&nbsp; 
    <b>Figure 2:</b> Step Count Heatmap &nbsp;&nbsp; 
    <b>Figure 3:</b> Time Complexity Analysis &nbsp;&nbsp; 
    <b>Figure 4:</b> Sensitivity Analysis
</p>

---

### Experiment 2: Substitution Cipher / 单表密码

#### **Description**
This experiment focuses on the implementation of the **Substitution Cipher**. It allows you to **encrypt** and **decrypt** messages and includes an analysis of the letter frequency distribution in ciphertexts. This is useful to understand the cipher's vulnerabilities to frequency analysis attacks.

#### **GUI Preview**
<p align="center">
    <img src="images/experiment2-gui.png" alt="Experiment 2 GUI" width="60%" />
</p>

---

### Experiment 3: Playfair Cipher / Playfair密码

#### **Description**
The **Playfair Cipher** experiment involves implementing the cipher and testing its encryption and decryption mechanisms. Additionally, it explores the **avalanche effect** of the cipher, analyzing how small changes in the input can result in drastic changes in the output.

#### **GUI Preview**
<p align="center">
    <img src="images/experiment3-gui.png" alt="Experiment 3 GUI" width="60%" />
</p>

---

### Experiment 4: Feistel Algorithm / Feistel算法

#### **Description**
This experiment demonstrates the **Feistel Cipher**, which is widely used in symmetric encryption algorithms. You will learn to implement the Feistel structure and test its security properties, including its **avalanche effect** and resistance to differential cryptanalysis.

#### **GUI Preview**
<p align="center">
    <img src="images/experiment4-gui.png" alt="Experiment 4 GUI" width="60%" />
</p>

---

### Experiment 5: AES Algorithm / AES算法

#### **Description**
This experiment focuses on the implementation of the **Advanced Encryption Standard (AES)** algorithm. Using Python’s cryptographic libraries, the experiment explores AES in different modes, with a special focus on **CTR (Counter) mode**. Performance and behavior analysis is also included.

#### **GUI Preview**
<p align="center">
    <img src="images/experiment5-gui.png" alt="Experiment 5 GUI" width="60%" />
</p>

---

### Experiment 6: RSA Algorithm / RSA算法

#### **Description**
The **RSA Algorithm** experiment demonstrates the public-key encryption process. Key concepts include **key generation** (using large prime numbers), **encryption**, and **decryption**. The experiment also explores performance metrics of RSA encryption in real-world scenarios.

#### **GUI Preview**
<p align="center">
    <img src="images/experiment6-gui.png" alt="Experiment 6 GUI" width="60%" />
</p>

---

## License

This project is licensed under the **Creative Commons Attribution-NoDerivatives (CC BY-ND)** license. You are free to share the code, but **you cannot modify it**. Please refer to the [LICENSE](LICENSE) file for more details.

## Acknowledgements

This project was developed for the **Application Cryptography** course at **Nanjing University of Information Science & Technology (NUIST)**. Special thanks to **Professor Zhiguo Qu** for his valuable guidance throughout the project.  
We would also like to express our gratitude to **Professor Baowei Wang** for his support, and the project is funded by the **National College Student Innovation and Entrepreneurship Project**, Fund Number: **ZR2022MF338**.

---

## Installation

To install and run the experiments locally, follow these steps:

1. **Clone the repository**:
    ```bash
    git clone https://github.com/yourusername/cryptography-experiments.git
    ```

2. **Navigate to the project directory**:
    ```bash
    cd cryptography-experiments
    ```

3. **Install the required dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

4. **Run the experiments**:
    ```bash
    python experiment1.py  # For the first experiment
    python experiment2.py  # For the second experiment
    # Repeat for other experiments
    ```

---

## Contributing

Feel free to fork the repository, make improvements, and submit pull requests. All contributions are welcome to help improve the project and enhance the learning experience for others.

---

## Contact

For any questions or suggestions, feel free to contact the project maintainers:

- **Ziheng Wang** (Author)
    - Email: zhwang@nuist.edu.cn
    - University: **South East Technological University, Ireland**
