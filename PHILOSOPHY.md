# The Philosophy of ATOMIC

> *"A scanner that lists vulnerabilities is a clerk.
> A scanner that argues for them is an engineer."*

This document is the **philosophical contract** of the ATOMIC framework.
It explains *why* the scanner is built the way it is, and what we mean
when we call ATOMIC a "philosophical security engineer" rather than a
fuzzer with a UI on top.

It complements `LOGIC_MAP.md` (which describes *what* the code does).
Where the two disagree, both are wrong until reconciled.

---

## 1. Foundational Axioms

ATOMIC tests against eight **named principles**. Every active probe is
required to declare which principle(s) it is challenging. Findings that
cannot be tied back to a principle are downgraded to `INFO`.

We adopt the eight Saltzer–Schroeder design principles as our base set,
plus three modern additions, encoded in `core/philosophy.py` as
`Principle` enum values:

| Code | Principle                     | Source                  |
|------|-------------------------------|-------------------------|
| P1   | Economy of mechanism          | Saltzer & Schroeder '75 |
| P2   | Fail-safe defaults            | Saltzer & Schroeder '75 |
| P3   | Complete mediation            | Saltzer & Schroeder '75 |
| P4   | Open design                   | Saltzer & Schroeder '75 |
| P5   | Separation of privilege       | Saltzer & Schroeder '75 |
| P6   | Least privilege               | Saltzer & Schroeder '75 |
| P7   | Least common mechanism        | Saltzer & Schroeder '75 |
| P8   | Psychological acceptability   | Saltzer & Schroeder '75 |
| M1   | Zero trust                    | NIST SP 800-207         |
| M2   | Assume breach                 | Lipner '15              |
| M3   | Defense in depth              | NSA/IATF                |

Concrete vulnerability families map to violated principles:

* SQLi, XXE, deserialization → **P3** (complete mediation of input)
* IDOR, broken authz → **P3 + P6** (mediation + least privilege)
* CORS wildcard, JWT `alg:none` → **P2** (fail-safe defaults)
* SSRF → **P3 + P5** (mediation across trust zones)
* Hardcoded creds, secret leaks → **M1** (zero trust)

---

## 2. Security Properties as First-Class Types

Vulnerability *classes* are an artifact of how we test. The *target* is
always a security property the system claims to uphold.

`core/philosophy.py` defines `SecurityProperty`:

* **CIA**: confidentiality, integrity, availability
* **AAA**: authentication, authorization, accountability
* Plus: non-repudiation, freshness (anti-replay), isolation

A finding is **a counterexample to a claimed property**. The reporting
layer phrases findings as:

> *"Property `Authorization-of-Object(/users/{id})` is violated:
> request as user A returns user B's data when `id=B` (IDOR)."*

This phrasing is intentional. It forces the reader (and the scanner)
to think in terms of what the system is *supposed to do*, not just
what payload happened to "work".

---

## 3. Falsifiability Comes Before Confidence

Every probe ATOMIC issues is paired with a **falsifying observation**:
the result that, if seen, *disproves* the hypothesis.

Without a falsifying observation, a probe is not a test, it is a
guess. This is encoded in `core/hypothesis.py::Hypothesis`:

```python
Hypothesis(
    property_violated=SecurityProperty.INTEGRITY,
    attack_class="sqli",
    target=("https://x/api?id=1", "id"),
    expected_observation="response time ≥ 4s on SLEEP(5) payload",
    falsifying_observation="response time stays within ±0.5σ of baseline",
    prior=0.15,                  # P(SQLi | parameter named 'id')
)
```

The scan engine prefers **decisive tests**: experiments that maximally
discriminate between "vulnerable" and "not vulnerable". For a
`time-based` SQLi hypothesis, the decisive test is the timing oracle
with a control payload of equal length and shape, run N times,
compared via Mann–Whitney U with α=0.01.

Heuristic substring matches ("response contains `sql`") are accepted
as evidence only as **corroboration**, never as proof.

---

## 4. Evidence Standard: the Three-Way Test

A finding is upgraded from `INFO` only if **at least two** of three
independent oracles agree, and **none** of them is the substring
oracle alone:

| Oracle           | Question answered                          |
|------------------|---------------------------------------------|
| Timing           | "Did response time differ in a way no clean control reproduces?" |
| Diff             | "Did the normalized response body differ from the baseline?" |
| Reflection       | "Did the payload appear unencoded in a context that grants it semantics?" |
| Error            | "Did the server's error message betray the engine?" |
| OOB              | "Did the target reach a callback we control?" |
| Behavior         | "Did the application's *next* response demonstrate state change?" |

The OOB oracle is the gold standard: a server that calls home cannot
deny it. ATOMIC supports OOB callbacks via the
`ATOMIC_OOB_CALLBACK_HOST` env var; absent that, OOB oracles are
disabled rather than silently ignored.

Evidence chains are **append-only and HMAC-signed**
(`core/evidence_ledger.py`). A deletion or reorder breaks the chain
and is detectable. This is for our own discipline, not for
cryptographic court-admissibility — we want every finding to be
fully replayable from its own ledger entries.

---

## 5. Belief, Not Score

ATOMIC tracks `posterior` belief in each hypothesis, not a flat
confidence score. After each oracle observation `o`:

```
posterior = (likelihood(o | H) * prior) /
            (likelihood(o | H) * prior + likelihood(o | ¬H) * (1 - prior))
```

The next hypothesis update uses this posterior as its prior. This
means:

* A weak signal can never push a low-prior finding above 0.5 alone.
* Two independent strong signals quickly drive belief above 0.9.
* A *negative* observation (control payload also produced the
  signal) actively *lowers* belief — false positives self-correct
  instead of accumulating.

Severity is then derived from `posterior × CVSS-baseline-for-class`,
attenuated as already implemented in `core/emit.py::_confidence_to_cvss`.

---

## 6. Composition Reasoning: the Causal DAG

Vulnerabilities rarely live alone. A reflected XSS plus a missing
HttpOnly flag plus a session cookie scoped to `/` is *not* three low
findings — it is one high finding because the composition is the
attack.

`core/causal_correlator.py` builds a **causal DAG** over findings:

* Nodes are `CanonicalFinding` IDs.
* Edges are typed: `enables`, `amplifies`, `same-root-cause`.
* The DAG is annotated with MITRE ATT&CK technique IDs as edge
  predicates.
* The framework computes for each finding:
  * `kill_chain_depth` — longest path ending at this finding;
  * `blast_radius` — maximum reachable impact through composition.

A leaf finding with high `blast_radius` is reported above an
isolated CRITICAL with `blast_radius=0`, because the leaf is
load-bearing for several other attacks.

---

## 7. Calibration Discipline

A scanner whose 90% confidence findings are right 60% of the time is
broken, no matter how many CVEs it claims. ATOMIC's
`core/learning.py` tracks **Brier score** and **expected calibration
error (ECE)** per vuln family. When a family's ECE drifts above
0.15, the scoring weights for that family are auto-demoted in
`core/scorer.py` until calibration recovers.

This is the discipline that turns "AI-powered" from a marketing
phrase into a feedback loop.

---

## 8. Reporting as Argument

A report is not a list. A report is an **argument** that the system
under test fails to uphold a stated security property, supported by
reproducible evidence. ATOMIC's report sections, in order:

1. **Claim** — the violated property, in plain English.
2. **Hypothesis** — the formal hypothesis that motivated the test.
3. **Decisive test** — the experiment performed, with control.
4. **Observations** — ledger-signed evidence entries.
5. **Counterfactual** — control results that *did not* trigger the
   oracle, demonstrating that the cause is the input, not the system.
6. **Composition** — the causal DAG slice this finding belongs to.
7. **Remediation** — the principle that, if applied, would close
   the gap.

Findings without sections 1, 3, and 5 do not qualify as HIGH or
above. They may still appear under `INFO` with the explicit label
*"unverified signal."*

---

## 9. What ATOMIC Refuses to Pretend

* It does not pretend a substring of "sql" in an error page is a
  confirmed SQL injection.
* It does not pretend a one-shot timing spike is a time-based blind.
* It does not pretend an LLM hallucination is a CVE.
* It does not pretend severity equals impact without a property
  claim and a counterfactual.

When ATOMIC cannot *argue* for a finding, it labels the finding as
**unverified** and lets the human engineer decide. Calibration is
worth more than coverage.

---

## 10. How to Engage With This Layer

The philosophy layer is **opt-in** and additive:

```bash
python main.py -t https://target.com --philosophy
```

When enabled:

* `core/hypothesis.py::HypothesisEngine` runs after `context_intel`
  and before `prioritization`, generating per-(url, param)
  hypotheses with priors derived from the intelligence bundle.
* `ScanPriorityQueue` is reordered by **expected information
  gain** rather than by raw priority alone.
* `core/oracle.py` oracles run inside the verifier, replacing the
  single `safe_test_value` retest with a controlled A/B over N
  control payloads.
* `core/evidence_ledger.py` records every observation; reports
  attach the signed slice for each finding.
* `core/causal_correlator.py` augments the existing structural
  correlator without replacing it.

When **disabled**, none of this code runs and the existing pipeline
is byte-for-byte identical to its previous behaviour.

---

## 11. Reading List

The implementation in this layer draws on, but does not paraphrase
from, the following works. They are listed here because every
serious security engineer is expected to have read them.

* Saltzer & Schroeder, *The Protection of Information in Computer
  Systems*, 1975.
* Lampson, *Computer Security in the Real World*, 2004.
* McGraw, *Software Security: Building Security In*, 2006.
* Howard & LeBlanc, *Writing Secure Code*, 2nd ed., 2003.
* Anderson, *Security Engineering*, 3rd ed., 2020.
* NIST SP 800-207, *Zero Trust Architecture*, 2020.
* Popper, *The Logic of Scientific Discovery*, 1959 — for the
  falsifiability discipline.
* Pearl, *Causality*, 2nd ed., 2009 — for the causal DAG.

---

*Last updated: ATOMIC Framework v11.0 ("TITAN").*
