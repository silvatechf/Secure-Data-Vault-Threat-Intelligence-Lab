"""
tests/test_differential_privacy.py
======================================
"""

import statistics

import pytest

from app.privacy.differential_privacy import (
    KAnonymityViolation,
    add_laplace_noise,
    check_k_anonymity,
    generate_private_report,
    laplace_noise,
)


class TestLaplaceNoise:
    def test_noise_is_never_exactly_zero_across_many_samples(self):
        """A real random mechanism -- vanishingly unlikely for every one of many samples to be exactly zero."""
        samples = [laplace_noise(scale=1.0) for _ in range(100)]
        assert any(sample != 0 for sample in samples)

    def test_noise_is_centered_near_zero_on_average(self):
        """
        Laplace(0, scale) has mean 0 -- over MANY samples, the average
        should land close to zero, even though any single sample can be
        far from it. Uses a generous tolerance since this is a
        statistical property, not an exact one.
        """
        samples = [laplace_noise(scale=1.0) for _ in range(5000)]
        assert abs(statistics.mean(samples)) < 0.2

    def test_larger_scale_produces_larger_average_magnitude(self):
        """Directly reflects the epsilon/scale relationship -- more scale (lower epsilon) means more noise, on average."""
        small_scale_samples = [abs(laplace_noise(scale=0.5)) for _ in range(2000)]
        large_scale_samples = [abs(laplace_noise(scale=5.0)) for _ in range(2000)]
        assert statistics.mean(large_scale_samples) > statistics.mean(small_scale_samples)


class TestAddLaplaceNoise:
    def test_noisy_value_differs_from_true_value(self):
        noisy = add_laplace_noise(true_value=1000, epsilon=1.0)
        assert noisy != 1000

    def test_zero_epsilon_is_rejected(self):
        with pytest.raises(ValueError):
            add_laplace_noise(true_value=1000, epsilon=0)

    def test_negative_epsilon_is_rejected(self):
        with pytest.raises(ValueError):
            add_laplace_noise(true_value=1000, epsilon=-1.0)

    def test_smaller_epsilon_produces_more_noise_on_average(self):
        """THE CORE PRIVACY-UTILITY TRADE-OFF, proven statistically: smaller epsilon (more privacy) must mean more noise (less accuracy)."""
        true_value = 1000
        small_epsilon_deviations = [
            abs(add_laplace_noise(true_value, epsilon=0.1) - true_value) for _ in range(2000)
        ]
        large_epsilon_deviations = [
            abs(add_laplace_noise(true_value, epsilon=5.0) - true_value) for _ in range(2000)
        ]
        assert statistics.mean(small_epsilon_deviations) > statistics.mean(large_epsilon_deviations)


class TestKAnonymity:
    def test_dataset_satisfying_k_anonymity_has_no_violations(self):
        records = [{"zip": "10001", "age_group": "30s"} for _ in range(10)]
        violations = check_k_anonymity(records, ["zip", "age_group"], k=5)
        assert violations == []

    def test_unique_combination_is_flagged_as_a_violation(self):
        records = [{"zip": "10001", "age_group": "30s"} for _ in range(10)] + [
            {"zip": "99999", "age_group": "90s"}  # a group of exactly 1
        ]
        violations = check_k_anonymity(records, ["zip", "age_group"], k=5)
        assert len(violations) == 1
        assert violations[0].group_size == 1
        assert violations[0].quasi_identifier_values == {"zip": "99999", "age_group": "90s"}

    def test_group_exactly_at_the_threshold_is_not_a_violation(self):
        records = [{"zip": "10001", "age_group": "30s"} for _ in range(5)]  # exactly k=5
        violations = check_k_anonymity(records, ["zip", "age_group"], k=5)
        assert violations == []

    def test_group_one_below_the_threshold_is_a_violation(self):
        records = [{"zip": "10001", "age_group": "30s"} for _ in range(4)]  # one short of k=5
        violations = check_k_anonymity(records, ["zip", "age_group"], k=5)
        assert len(violations) == 1
        assert violations[0].group_size == 4

    def test_multiple_distinct_violations_are_all_reported(self):
        records = (
            [{"zip": "10001", "age_group": "30s"} for _ in range(10)]  # safe group
            + [{"zip": "20002", "age_group": "40s"}]  # violation 1
            + [{"zip": "30003", "age_group": "50s"}]  # violation 2
        )
        violations = check_k_anonymity(records, ["zip", "age_group"], k=5)
        assert len(violations) == 2


class TestGeneratePrivateReport:
    def test_report_includes_true_and_noisy_count(self):
        records = [{"zip": "10001", "age_group": "30s"} for _ in range(20)]
        report = generate_private_report(records, ["zip", "age_group"], epsilon=1.0, k=5)
        assert report.true_count == 20
        assert report.noisy_count != report.true_count

    def test_report_surfaces_k_anonymity_violations(self):
        records = [{"zip": "10001", "age_group": "30s"} for _ in range(10)] + [
            {"zip": "unique", "age_group": "unique"}
        ]
        report = generate_private_report(records, ["zip", "age_group"], epsilon=1.0, k=5)
        assert len(report.k_anonymity_violations) == 1

    def test_clean_dataset_produces_no_violations(self):
        records = [{"zip": "10001", "age_group": "30s"} for _ in range(20)]
        report = generate_private_report(records, ["zip", "age_group"], epsilon=1.0, k=5)
        assert report.k_anonymity_violations == []
