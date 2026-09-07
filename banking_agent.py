"""Console banking complaint triage agent.

This is a transparent first-pass classifier, not a substitute for a trained
complaints handler or legal advice. It deliberately returns review flags when
the text is ambiguous or a high-risk signal is present.
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict, dataclass
from typing import Iterable


@dataclass(frozen=True)
class TriageResult:
    category: str
    confidence: str
    vulnerability_indicators: list[str]
    escalation_path: list[str]
    regulatory_obligations: list[str]
    immediate_actions: list[str]
    review_required: bool


CATEGORY_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Fraud or unauthorised transaction", ("fraud", "scam", "stolen", "unauthorised", "unauthorized", "didn't make", "did not make", "card payment")),
    ("Payment failure or transfer", ("payment failed", "transfer", "bank transfer", "standing order", "direct debit", "cash withdrawal", "atm", "declined")),
    ("Financial difficulty", ("can't afford", "cannot afford", "financial difficulty", "debt", "arrears", "overdrawn", "payment holiday", "hardship")),
    ("Access or service", ("locked out", "login", "app", "branch", "call", "wait", "accessible", "can't access", "cannot access")),
    ("Fees or charges", ("fee", "fees", "charge", "charged", "interest rate", "commission")),
    ("Data or privacy", ("personal data", "privacy", "gdpr", "data breach", "identity", "information")),
    ("Product or advice", ("mortgage", "loan", "credit card", "insurance", "investment", "mis-sold", "mis sold", "advice")),
    ("Complaint handling", ("complaint", "formal complaint", "ombudsman", "final response", "not resolved")),
)

VULNERABILITY_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Financial difficulty", ("can't afford", "cannot afford", "debt", "arrears", "food bank", "homeless", "hardship", "redundant")),
    ("Health or disability", ("disabled", "disability", "mental health", "depressed", "ill", "hospital", "dementia", "hearing", "visually impaired")),
    ("Age-related support", ("elderly", "old", "pensioner", "retired", "carer")),
    ("Bereavement or life event", ("bereaved", "bereavement", "died", "death", "divorce", "domestic abuse")),
    ("Coercion or safeguarding", ("coerced", "forced", "abusive", "partner made me", "someone is threatening", "exploitation")),
    ("Digital or communication barrier", ("can't read", "cannot read", "no internet", "language barrier", "interpreter", "can't use the app", "cannot use the app")),
)


def _contains_any(text: str, phrases: Iterable[str]) -> bool:
    return any(
        re.search(r"(?<!\w)" + re.escape(phrase) + r"(?!\w)", text)
        for phrase in phrases
    )


def _classify_category(text: str) -> tuple[str, str]:
    scores = {
        category: sum(text.count(phrase) for phrase in phrases)
        for category, phrases in CATEGORY_RULES
    }
    best_category, best_score = max(scores.items(), key=lambda item: item[1])
    if best_score == 0:
        return "Other or unclear", "low"
    tied = sum(score == best_score for score in scores.values()) > 1
    return best_category, "medium" if tied or best_score == 1 else "high"


def _regulatory_obligations(category: str, indicators: list[str], text: str) -> list[str]:
    obligations = ["FCA DISP: record, investigate, acknowledge and respond within applicable complaint time limits."]
    if category == "Fraud or unauthorised transaction" or "Coercion or safeguarding" in indicators:
        obligations.append("Payment Services Regulations / PSR: investigate payment liability and apply applicable fraud reimbursement rules.")
    if "Financial difficulty" in indicators or category == "Financial difficulty":
        obligations.append("FCA Consumer Duty: assess foreseeable harm and provide appropriate support for customers in difficulty.")
    if indicators:
        obligations.append("FCA vulnerability guidance and Consumer Duty: make reasonable adjustments and avoid foreseeable harm.")
    if category == "Data or privacy" or _contains_any(text, ("data breach", "personal data", "gdpr")):
        obligations.append("UK GDPR / Data Protection Act 2018: contain, assess and report a personal-data incident where required.")
    if _contains_any(text, ("discriminat", "reasonable adjustment", "accessible")):
        obligations.append("Equality Act 2010: consider reasonable adjustments and avoid discriminatory treatment.")
    return obligations


def triage_complaint(complaint: str) -> TriageResult:
    """Return an explainable triage decision for one customer complaint."""
    text = re.sub(r"\s+", " ", complaint.strip().lower())
    if not text:
        raise ValueError("Complaint text cannot be empty.")

    category, confidence = _classify_category(text)
    indicators = [
        indicator
        for indicator, phrases in VULNERABILITY_RULES
        if _contains_any(text, phrases)
    ]

    escalation = ["Complaints team: log the complaint, preserve evidence and issue a clear owner and response deadline."]
    actions = ["Acknowledge the complaint and confirm the customer's preferred contact method."]
    if category == "Fraud or unauthorised transaction":
        escalation.insert(0, "Fraud operations: secure the account, authenticate safely and investigate disputed transactions urgently.")
        actions.extend(["Do not ask the customer to disclose a PIN, password or one-time passcode.", "Check whether payments should be stopped or recalled."])
    if indicators:
        escalation.insert(0, "Vulnerability specialist: offer reasonable adjustments, a safe contact route and proportionate support.")
        actions.append("Ask only what support is needed; do not require proof of vulnerability before making an adjustment.")
    if "Coercion or safeguarding" in indicators:
        escalation.insert(0, "Safeguarding lead: use a safe contact plan and follow the bank's safeguarding and financial-abuse procedure.")
        actions.append("Avoid contacting the customer in a way that could alert a suspected abuser.")
    if category == "Data or privacy":
        escalation.insert(0, "Data protection officer: assess access, containment, rights and breach-reporting requirements.")
    if category == "Other or unclear":
        escalation.append("Human review: clarify the customer's desired outcome before assigning a specialist queue.")
    return TriageResult(
        category=category,
        confidence=confidence,
        vulnerability_indicators=indicators or ["None detected from the text; do not treat this as proof of no vulnerability."],
        escalation_path=escalation,
        regulatory_obligations=_regulatory_obligations(category, indicators, text),
        immediate_actions=actions,
        review_required=confidence != "high" or bool(indicators) or category == "Other or unclear",
    )


def _print_result(result: TriageResult) -> None:
    print(f"\nCategory: {result.category} ({result.confidence} confidence)")
    print("Vulnerability indicators:")
    for item in result.vulnerability_indicators:
        print(f"  - {item}")
    print("Required escalation path:")
    for item in result.escalation_path:
        print(f"  - {item}")
    print("Regulatory obligations to check:")
    for item in result.regulatory_obligations:
        print(f"  - {item}")
    print("Immediate actions:")
    for item in result.immediate_actions:
        print(f"  - {item}")
    print(f"Human review required: {'yes' if result.review_required else 'no'}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Triage banking complaints from the console.")
    parser.add_argument("complaint", nargs="?", help="Complaint text; omit to use interactive mode.")
    parser.add_argument("--json", action="store_true", dest="as_json", help="Output machine-readable JSON.")
    args = parser.parse_args()

    complaint = args.complaint
    if complaint is None:
        print("Banking complaint triage agent. Type 'quit' to exit.")
        while True:
            try:
                complaint = input("\nComplaint> ")
            except (EOFError, KeyboardInterrupt):
                print()
                return
            if complaint.strip().lower() in {"quit", "exit"}:
                return
            try:
                result = triage_complaint(complaint)
            except ValueError as error:
                print(f"Error: {error}")
                continue
            _print_result(result)
        return

    result = triage_complaint(complaint)
    if args.as_json:
        print(json.dumps(asdict(result), indent=2))
    else:
        _print_result(result)


if __name__ == "__main__":
    main()
