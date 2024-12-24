import matplotlib.pyplot as plt
import numpy as np

# Extended Euclidean Algorithm
def extended_gcd(a, b):
    steps = []  # To record steps
    while b != 0:
        q = a // b
        r = a % b  # Modulo operator
        # Standardize remainder to handle negative inputs
        if r < 0:
            r += abs(b)
        steps.append((a, b, q, r))
        a, b = b, r
    steps.append((a, b, 0, 0))  # Final step
    return abs(a), steps  # Return absolute GCD

# Visualize Robustness Analysis (Heatmap)
def visualize_robustness(a_range, b_range):
    step_counts = []
    for a in a_range:
        row = []
        for b in b_range:
            _, steps = extended_gcd(a, b)
            row.append(len(steps))
        step_counts.append(row)

    step_counts = np.array(step_counts)
    plt.figure(figsize=(8, 6))
    plt.imshow(step_counts, extent=(b_range[0], b_range[-1], a_range[0], a_range[-1]), origin="lower", cmap="coolwarm", aspect='auto')
    plt.colorbar(label="Number of Steps")
    plt.xlabel("b values")
    plt.ylabel("a values")
    plt.title("Step Count Heatmap for Extended Euclidean Algorithm")
    plt.show()

def analyze_time_complexity():
    # Generate input sizes (powers of 2 for clear recursive depth)
    input_sizes = [2**i for i in range(5, 21)]  # 2^5 to 2^20
    step_counts = []

    # Test each input size with meaningful pairs
    for n in input_sizes:
        _, steps = extended_gcd(n, n // 2)  # Pair with n and n/2
        step_counts.append(len(steps))

    # Plot observed steps against input size
    plt.figure(figsize=(8, 6))
    plt.loglog(input_sizes, step_counts, marker='o', label="Observed Steps")
    plt.xlabel("Input Size (log scale)")
    plt.ylabel("Number of Steps (log scale)")
    plt.title("Time Complexity Analysis of Extended Euclidean Algorithm (Corrected)")
    plt.grid(True, which="both", linestyle="--", linewidth=0.5)
    plt.legend()
    plt.show()


# Sensitivity Analysis (Line Plot)
def sensitivity_analysis(base_a, base_b, perturbations):
    gcd_results = []
    step_counts = []
    for delta in perturbations:
        perturbed_b = base_b + delta
        gcd, steps = extended_gcd(base_a, perturbed_b)
        gcd_results.append(gcd)
        step_counts.append(len(steps))

    plt.figure(figsize=(8, 6))
    plt.plot(perturbations, step_counts, label="Number of Steps", marker='o')
    plt.xlabel("Perturbation to b")
    plt.ylabel("Steps")
    plt.title(f"Sensitivity Analysis (a={base_a}, b={base_b})")
    plt.axvline(0, color="gray", linestyle="--", linewidth=0.8)
    plt.legend()
    plt.grid(True, linestyle="--", alpha=0.6)
    plt.show()

# Recursive Path Visualization (Arrows)
def visualize_recursion_path(a, b):
    _, steps = extended_gcd(a, b)
    x = [step[0] for step in steps]
    y = [step[1] for step in steps]

    plt.figure(figsize=(8, 6))
    for i in range(len(x) - 1):
        plt.arrow(x[i], y[i], x[i + 1] - x[i], y[i + 1] - y[i], head_width=5, length_includes_head=True, color="blue", alpha=0.7)

    plt.scatter(x, y, color="red", label="Intermediate Steps")
    plt.xlabel("a values")
    plt.ylabel("b values")
    plt.title(f"Recursive Path for Extended Euclidean Algorithm (a={a}, b={b})")
    plt.legend()
    plt.grid(True, linestyle="--", alpha=0.6)
    plt.show()

# Compare Input Conditions (Box Plot)
def compare_inputs():
    random_steps = [len(extended_gcd(np.random.randint(1, 1000), np.random.randint(1, 1000))[1]) for _ in range(100)]
    coprime_steps = [len(extended_gcd(i, i + 1)[1]) for i in range(1, 100)]

    plt.boxplot([random_steps, coprime_steps], labels=["Random Inputs", "Coprime Inputs"])
    plt.ylabel("Number of Steps")
    plt.title("Comparison of Input Conditions")
    plt.grid(True, linestyle="--", alpha=0.6)
    plt.show()

# Main Execution
if __name__ == "__main__":
    print("=== Robustness Analysis (Heatmap) ===")
    a_range = np.arange(-1000, 1001, 100)
    b_range = np.arange(-1000, 1001, 100)
    visualize_robustness(a_range, b_range)

    print("=== Time Complexity Analysis ===")
    analyze_time_complexity()

    print("=== Sensitivity Analysis ===")
    base_a = 100
    base_b = 50
    perturbations = np.arange(-20, 21, 1)
    sensitivity_analysis(base_a, base_b, perturbations)

    print("=== Recursive Path Visualization ===")
    visualize_recursion_path(120, 80)

    print("=== Input Condition Comparison ===")
    compare_inputs()
