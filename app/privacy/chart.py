"""
app/privacy/chart.py
========================

Generates a chart showing the privacy-utility trade-off across different
epsilon values -- the concrete, visual version of "smaller epsilon means
more noise" from differential_privacy.py's docstring. Separated into its
own file so the core privacy logic (differential_privacy.py) has no
plotting dependency at all -- matplotlib is only imported here, by
whatever code actually wants a chart.
"""

import matplotlib

matplotlib.use("Agg")  # non-interactive backend -- this runs on a server, never a display
import matplotlib.pyplot as plt

from app.privacy.differential_privacy import add_laplace_noise

DEFAULT_EPSILON_VALUES = [0.1, 0.5, 1.0, 2.0, 5.0, 10.0]


def measure_average_noise_magnitude(epsilon: float, true_value: float = 1000, trials: int = 200) -> float:
    """
    Runs the noise mechanism many times at a fixed epsilon and averages
    the absolute deviation from the true value -- a single noisy sample is
    random and could misleadingly land close to zero by chance; averaging
    over many trials gives a stable, representative measure of "how much
    noise does this epsilon level actually add."
    """
    total_deviation = 0.0
    for _ in range(trials):
        noisy = add_laplace_noise(true_value, epsilon)
        total_deviation += abs(noisy - true_value)
    return total_deviation / trials


def generate_privacy_utility_chart(output_path: str, epsilon_values: list[float] | None = None) -> str:
    """
    Saves a PNG chart plotting average noise magnitude against epsilon --
    visually, this always slopes downward (higher epsilon = less noise =
    more accurate/"more utility", at the cost of a weaker privacy
    guarantee), because that trade-off is mathematically guaranteed by
    the mechanism, not just an empirical tendency for this exercise.
    """
    epsilon_values = epsilon_values or DEFAULT_EPSILON_VALUES
    noise_magnitudes = [measure_average_noise_magnitude(eps) for eps in epsilon_values]

    figure, axis = plt.subplots(figsize=(8, 5))
    axis.plot(epsilon_values, noise_magnitudes, marker="o")
    axis.set_xlabel("epsilon (ε) — smaller means stronger privacy guarantee")
    axis.set_ylabel("average noise magnitude (lower = more accurate)")
    axis.set_title("Privacy-Utility Trade-off (Laplace Mechanism)")
    axis.grid(True, alpha=0.3)

    figure.tight_layout()
    figure.savefig(output_path)
    plt.close(figure)

    return output_path
