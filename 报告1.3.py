import matplotlib.pyplot as plt
import numpy as np

# Extended Euclidean Algorithm
def extended_gcd(a, b):
    steps = []  # To record steps
    while b != 0:
        q = a // b
        r = a % b  # Modulo operator
        if r < 0:
            r += abs(b)  # Handle negative remainders
        steps.append((a, b, q, r))
        a, b = b, r
    steps.append((a, b, 0, 0))  # Final step
    return abs(a), steps  # Return absolute GCD

# Time Complexity Analysis with Diverse and Dense Sampling
def analyze_time_complexity_dense():
    # Input sizes: Logarithmic sampling with increased density
    input_sizes = [10**i for i in range(1, 7)]  # Large scale testing
    dense_sizes = [int(10**(i + j/5)) for i in range(1, 6) for j in range(5)]  # Dense sampling

    results = {
        "Mutually Prime": [],
        "Powers of 2": [],
        "Half Input": [],
        "Random Input": [],
    }

    # Mutually Prime Input
    for n in dense_sizes:
        _, steps = extended_gcd(n, n - 1)
        results["Mutually Prime"].append(len(steps))

    # Powers of 2 Input
    for n in dense_sizes:
        _, steps = extended_gcd(n, n // 2)
        results["Powers of 2"].append(len(steps))

    # Half Input (n and n//2 + 1)
    for n in dense_sizes:
        _, steps = extended_gcd(n, n // 2 + 1)
        results["Half Input"].append(len(steps))

    # Random Input
    np.random.seed(42)  # For reproducibility
    for n in dense_sizes:
        a = np.random.randint(n // 2, n)
        b = np.random.randint(1, n // 2)
        _, steps = extended_gcd(a, b)
        results["Random Input"].append(len(steps))

    # Visualization
    plt.figure(figsize=(12, 8))
    for key, steps in results.items():
        plt.plot(dense_sizes, steps, marker='o', label=key, alpha=0.8, linestyle='--')

    # Enhancements
    plt.xscale('log')
    plt.yscale('log')
    plt.xlabel("Input Size (log scale)", fontsize=14)
    plt.ylabel("Number of Steps (log scale)", fontsize=14)
    plt.title("Time Complexity Analysis of Extended Euclidean Algorithm\nwith Diverse and Dense Sampling", fontsize=16)
    plt.grid(True, which="both", linestyle="--", alpha=0.7)
    plt.legend(fontsize=12)
    plt.tight_layout()
    plt.show()

# Run the enhanced analysis
if __name__ == "__main__":
    analyze_time_complexity_dense()
