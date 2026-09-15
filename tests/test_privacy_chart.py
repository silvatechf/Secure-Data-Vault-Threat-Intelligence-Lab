"""
tests/test_privacy_chart.py
==============================
"""

from app.privacy.chart import generate_privacy_utility_chart, measure_average_noise_magnitude


class TestNoiseMeasurement:
    def test_smaller_epsilon_produces_larger_measured_noise(self):
        """The empirical measurement function itself must reflect the same trade-off the chart is meant to visualize."""
        small_epsilon_noise = measure_average_noise_magnitude(epsilon=0.1, trials=300)
        large_epsilon_noise = measure_average_noise_magnitude(epsilon=5.0, trials=300)
        assert small_epsilon_noise > large_epsilon_noise


class TestChartGeneration:
    def test_chart_file_is_created(self, tmp_path):
        output_path = str(tmp_path / "privacy_chart.png")
        result_path = generate_privacy_utility_chart(output_path, epsilon_values=[0.5, 1.0, 5.0])

        assert result_path == output_path
        assert (tmp_path / "privacy_chart.png").exists()
        assert (tmp_path / "privacy_chart.png").stat().st_size > 0

    def test_chart_file_is_a_valid_png(self, tmp_path):
        output_path = str(tmp_path / "chart.png")
        generate_privacy_utility_chart(output_path, epsilon_values=[1.0, 2.0])

        with open(output_path, "rb") as f:
            header = f.read(8)
        # Every valid PNG file starts with this exact 8-byte signature.
        assert header == b"\x89PNG\r\n\x1a\n"
