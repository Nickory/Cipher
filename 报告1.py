import matplotlib.pyplot as plt
import numpy as np

# Extended Euclidean Algorithm
def extended_gcd(a, b):
    """Extended Euclidean Algorithm: Compute gcd(a, b) and Bézout coefficients (X, Y)"""
    steps = []  # To record steps
    while b != 0:
        q = a // b
        r = a % b
        if r < 0:
            r += abs(b)  # Handle negative remainders
        steps.append((a, b, q, r))
        a, b = b, r
    steps.append((a, b, 0, 0))  # Final step

    # Back-substitution to compute Bézout coefficients
    gcd = abs(a)
    x, y = 1, 0  # Initialize Bézout coefficients for gcd(a, 0) = a
    for i in reversed(range(len(steps) - 1)):
        a, b, q, r = steps[i]
        x, y = y, x - q * y
    return gcd, x, y, steps

# Visualize the process of Extended Euclidean Algorithm
def plot_euclidean_process(steps):
    a_values = [step[0] for step in steps]
    b_values = [step[1] for step in steps]
    q_values = [step[2] for step in steps]
    r_values = [step[3] for step in steps]

    fig, ax = plt.subplots(2, 1, figsize=(10, 8))

    # Line plot for a and b values
    ax[0].plot(range(len(a_values)), a_values, label="a values", marker='o')
    ax[0].plot(range(len(b_values)), b_values, label="b values", marker='o', linestyle='--')
    ax[0].set_title("Convergence of a and b")
    ax[0].set_xlabel("Steps")
    ax[0].set_ylabel("Values")
    ax[0].legend()
    ax[0].grid(True)

    # Bar plot for q and r values
    width = 0.4
    indices = np.arange(len(q_values))
    ax[1].bar(indices - width/2, q_values, width, label="q (quotient)")
    ax[1].bar(indices + width/2, r_values, width, label="r (remainder)")
    ax[1].set_title("Quotient and Remainder at Each Step")
    ax[1].set_xlabel("Steps")
    ax[1].set_ylabel("Values")
    ax[1].legend()
    ax[1].grid(True)

    plt.tight_layout()
    plt.show()

# Display table of steps
def display_steps_table(steps):
    print(f"{'Step':<6}{'a':<10}{'b':<10}{'q (a//b)':<12}{'r (a%b)':<10}")
    print("=" * 48)
    for i, (a, b, q, r) in enumerate(steps):
        print(f"{i:<6}{a:<10}{b:<10}{q:<12}{r:<10}")

# Main program
def main():
    while True:
        try:
            print("\nEnter two integers a and b (separated by space, non-numeric input to exit):")
            a, b = map(int, input().split())
            gcd, x, y, steps = extended_gcd(a, b)
            print(f"\nGreatest Common Divisor (gcd): {gcd}")
            print(f"Bézout coefficients: X = {x}, Y = {y}")
            print(f"Verification: {a}*{x} + {b}*{y} = {gcd}\n")
            display_steps_table(steps)
            plot_euclidean_process(steps)
        except ValueError:
            print("Invalid input or exiting the program.")
            break

# Run the program
main()
