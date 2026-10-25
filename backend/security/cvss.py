import math
import re
from typing import Dict

def cvss_roundup(val: float) -> float:
    """Standard CVSS v3.1 roundup function."""
    int_input = round(val * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    else:
        return (math.floor(int_input / 10000) + 1) / 10.0

def parse_vector(vector_str: str) -> Dict[str, str]:
    """Extracts key-value metrics from a CVSS vector string."""
    clean_vector = vector_str.strip().split()[0]
    parts = clean_vector.split("/")
    metrics = {}
    for part in parts:
        if ":" in part:
            k, v = part.split(":", 1)
            metrics[k.upper()] = v.upper()
    return metrics

def cvss_score(vector: str) -> float:
    """
    Computes the CVSS v3.1 Base Score from a vector string.
    Example: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N -> 5.3
    """
    metrics = parse_vector(vector)
    
    # Attack Vector
    av_weights = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    # Attack Complexity
    ac_weights = {"L": 0.77, "H": 0.44}
    # User Interaction
    ui_weights = {"N": 0.85, "R": 0.62}
    # Confidentiality / Integrity / Availability
    cia_weights = {"H": 0.56, "L": 0.22, "N": 0.0}

    s = metrics.get("S", "U")
    
    # Privileges Required depends on Scope
    pr = metrics.get("PR", "N")
    if s == "C":
        pr_weights = {"N": 0.85, "L": 0.68, "H": 0.50}
    else:
        pr_weights = {"N": 0.85, "L": 0.62, "H": 0.27}

    av = av_weights.get(metrics.get("AV", "N"), 0.85)
    ac = ac_weights.get(metrics.get("AC", "L"), 0.77)
    pr_val = pr_weights.get(pr, 0.85)
    ui = ui_weights.get(metrics.get("UI", "N"), 0.85)

    c = cia_weights.get(metrics.get("C", "N"), 0.0)
    i = cia_weights.get(metrics.get("I", "N"), 0.0)
    a = cia_weights.get(metrics.get("A", "N"), 0.0)

    # Calculate ISS (Impact Sub-Score)
    iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))

    # Calculate Impact
    if s == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    # Calculate Exploitability
    exploitability = 8.22 * av * ac * pr_val * ui

    # Base Score calculation
    if impact <= 0:
        return 0.0

    if s == "U":
        score = min(impact + exploitability, 10.0)
    else:
        score = min(1.08 * (impact + exploitability), 10.0)

    return cvss_roundup(score)

def format_cvss(vector: str) -> str:
    """Returns vector formatted with the computed score, e.g. 'CVSS:3.1/... (5.3)'"""
    clean_vec = vector.strip().split()[0]
    score = cvss_score(clean_vec)
    return f"{clean_vec} ({score:.1f})"
