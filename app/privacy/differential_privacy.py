"""
app/privacy/differential_privacy.py
=======================================

EX-14: differential privacy for aggregate reports. Adds calibrated random
noise to statistics BEFORE they're returned, so individual users'
contributions to an aggregate can't be reverse-engineered, while the
aggregate itself stays close enough to the true value to still be useful.

WHY AGGREGATION ALONE ISN'T ENOUGH PRIVACY
------------------------------------------------
"We only show aggregate stats, never individual records" sounds safe, but
isn't automatically. Classic example: if a report shows "average account
age of active users: 3.2 years" today, and after one specific user
deletes their account it shows "3.1 years" tomorrow, you've learned
something about that specific user's account age by comparing two
"safe," aggregate-only numbers. This is called a DIFFERENCING ATTACK, and
it's a real, well-documented technique for de-anonymizing aggregate data.

WHAT DIFFERENTIAL PRIVACY ACTUALLY GUARANTEES
--------------------------------------------------
A mechanism is differentially private if its output distribution barely
changes whether or not any single individual's data is included. Formally,
epsilon (ε) controls exactly how much "barely" means: smaller ε = stronger
privacy guarantee = more noise = less accurate output. Larger ε = weaker
guarantee = less noise = more accurate output. This is a real,
irreducible trade-off, not a bug to engineer around -- more privacy
mathematically requires accepting more noise, and reporting one without
the other is misleading.

WHY THE LAPLACE MECHANISM SPECIFICALLY
--------------------------------------------
For numeric ("counting") queries, adding noise drawn from a Laplace
distribution (calibrated to the query's "sensitivity" -- how much one
person's data could change the true answer -- and to epsilon) is the
standard, provably-correct mechanism for achieving differential privacy.
Other mechanisms exist for other query types; Laplace is specifically
right for the count/sum-style aggregate reports this module produces.
"""

import math
import secrets
from dataclasses import dataclass

# secrets.SystemRandom() is a random.Random subclass backed by os.urandom
# (the OS's cryptographically secure RNG), not Python's default
# Mersenne-Twister generator. This matters specifically here: if the noise
# added by a differential privacy mechanism were generated with a
# predictable PRNG, an attacker who reconstructed the generator's internal
# state could subtract out the noise and recover the true value --
# silently defeating the entire privacy guarantee this module exists to
# provide. This is a real, documented concern in DP literature, not a
# generic "always use secrets" habit applied without reason.
_secure_random = secrets.SystemRandom()


def laplace_noise(scale: float) -> float:
    """
    Samples from a Laplace(0, scale) distribution using inverse transform
    sampling: for u uniform on (-0.5, 0.5), -scale * sign(u) * ln(1 - 2|u|)
    is Laplace-distributed. Implemented directly rather than pulling in
    numpy for one distribution this project doesn't otherwise need.
    """
    u = _secure_random.random() - 0.5
    return -scale * math.copysign(1, u) * math.log(1 - 2 * abs(u))


def add_laplace_noise(true_value: float, epsilon: float, sensitivity: float = 1.0) -> float:
    """
    Returns a noisy version of `true_value` that satisfies epsilon
    differential privacy for a query with the given sensitivity.
    Sensitivity is "how much could one person's presence/absence change
    this statistic" -- for a simple count, that's 1 (one person is either
    counted or not); for a sum bounded to a known range, it's that range's
    width. Scale = sensitivity / epsilon: smaller epsilon or higher
    sensitivity both mean more noise, which follows directly from the
    trade-off described in the module docstring.
    """
    if epsilon <= 0:
        raise ValueError("epsilon must be positive -- zero or negative epsilon is not meaningful.")

    scale = sensitivity / epsilon
    return true_value + laplace_noise(scale)


@dataclass
class KAnonymityViolation:
    quasi_identifier_values: dict
    group_size: int
    required_k: int


def check_k_anonymity(
    records: list[dict], quasi_identifiers: list[str], k: int = 5
) -> list[KAnonymityViolation]:
    """
    k-anonymity: every combination of quasi-identifier values (fields
    that aren't directly identifying alone -- zip code, birth year,
    gender -- but can uniquely identify someone in combination, per the
    well-known "87% of Americans are uniquely identified by zip + birth
    date + gender" result) must be shared by at least k records. A group
    of size 1 means that one record is uniquely singled out by those
    fields alone, regardless of what other, more sensitive fields
    (medical condition, salary) sit alongside it in the same row.

    Returns every group that violates the k-anonymity requirement (group
    size < k) -- an empty list means the dataset satisfies k-anonymity for
    the given quasi-identifiers.
    """
    groups: dict[tuple, int] = {}
    group_values: dict[tuple, dict] = {}

    for record in records:
        key = tuple(record.get(field) for field in quasi_identifiers)
        groups[key] = groups.get(key, 0) + 1
        group_values[key] = {field: record.get(field) for field in quasi_identifiers}

    violations = []
    for key, size in groups.items():
        if size < k:
            violations.append(
                KAnonymityViolation(
                    quasi_identifier_values=group_values[key], group_size=size, required_k=k
                )
            )

    return violations


@dataclass
class PrivateAggregateReport:
    true_count: int
    noisy_count: float
    epsilon: float
    k_anonymity_violations: list[KAnonymityViolation]


def generate_private_report(
    records: list[dict], quasi_identifiers: list[str], epsilon: float = 1.0, k: int = 5
) -> PrivateAggregateReport:
    """
    Produces one report combining both privacy techniques this module
    implements: a differentially-private noisy count of the records, and
    a k-anonymity check across the given quasi-identifiers. Both checks
    run independently -- differential privacy protects the released
    STATISTIC, k-anonymity is a property of the underlying DATASET itself
    -- a real system would use both together, as this function does,
    rather than treating either alone as sufficient.
    """
    true_count = len(records)
    noisy_count = add_laplace_noise(true_count, epsilon)
    violations = check_k_anonymity(records, quasi_identifiers, k)

    return PrivateAggregateReport(
        true_count=true_count,
        noisy_count=noisy_count,
        epsilon=epsilon,
        k_anonymity_violations=violations,
    )
