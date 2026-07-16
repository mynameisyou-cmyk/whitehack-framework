#!/usr/bin/env python3
"""Validate and render Whitehack Integrity Cases without third-party packages."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any, Iterable


MAX_CASE_BYTES = 5 * 1024 * 1024
TOP_LEVEL = {
    "schema_version",
    "case",
    "authorization",
    "intent",
    "components",
    "boundaries",
    "invariants",
    "threats",
    "controls",
    "evidence",
    "decisions",
    "residual_risks",
}
CASE_STATUSES = {"draft", "reviewed", "accepted", "superseded"}
AUTH_STATUSES = {"authorized", "not_required", "unknown"}
TRUST_LEVELS = {"trusted", "partially_trusted", "untrusted", "external"}
PRIORITIES = {"low", "medium", "high", "critical"}
LIKELIHOODS = {"unlikely", "possible", "likely", "observed"}
CONTROL_TYPES = {"preventive", "detective", "corrective", "recovery"}
EVIDENCE_KINDS = {"test", "probe", "review", "trace", "config", "analysis"}
EVIDENCE_RESULTS = {"pass", "fail", "inconclusive"}
RISK_DISPOSITIONS = {"accept", "mitigate", "transfer", "avoid", "investigate"}

CASE_ID_RE = re.compile(r"^IC-[A-Z0-9][A-Z0-9-]*$")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
COMPONENT_ID_RE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
SECTION_ID_RES = {
    "boundaries": re.compile(r"^B[0-9]+$"),
    "invariants": re.compile(r"^I[0-9]+$"),
    "threats": re.compile(r"^T[0-9]+$"),
    "controls": re.compile(r"^C[0-9]+$"),
    "evidence": re.compile(r"^E[0-9]+$"),
    "decisions": re.compile(r"^D[0-9]+$"),
    "residual_risks": re.compile(r"^R[0-9]+$"),
}
SECRET_PATTERNS = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\bsk_live_[A-Za-z0-9]{16,}\b"),
)


class DuplicateKeyError(ValueError):
    """Raised when JSON contains a key whose earlier value would be hidden."""


@dataclass(frozen=True)
class ValidationResult:
    errors: tuple[str, ...]
    warnings: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.errors


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def load_case(path: Path) -> dict[str, Any]:
    """Load a bounded UTF-8 JSON object, rejecting duplicate keys."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ValueError(f"cannot read {path}: {exc}") from exc
    if size > MAX_CASE_BYTES:
        raise ValueError(
            f"case is {size} bytes; limit is {MAX_CASE_BYTES} bytes"
        )
    try:
        raw = path.read_text(encoding="utf-8")
        value = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except (OSError, UnicodeError, json.JSONDecodeError, DuplicateKeyError) as exc:
        raise ValueError(f"invalid Integrity Case JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError("Integrity Case root must be a JSON object")
    return value


def _object(
    value: Any,
    path: str,
    required: set[str],
    allowed: set[str],
    errors: list[str],
) -> dict[str, Any]:
    if not isinstance(value, dict):
        errors.append(f"{path}: expected object")
        return {}
    for key in sorted(required - value.keys()):
        errors.append(f"{path}: missing required field {key!r}")
    for key in sorted(value.keys() - allowed):
        errors.append(f"{path}: unknown field {key!r}")
    return value


def _string(obj: dict[str, Any], key: str, path: str, errors: list[str]) -> str | None:
    value = obj.get(key)
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{path}.{key}: expected non-empty string")
        return None
    return value.strip()


def _enum(
    obj: dict[str, Any],
    key: str,
    path: str,
    allowed: set[str],
    errors: list[str],
) -> str | None:
    value = _string(obj, key, path, errors)
    if value is not None and value not in allowed:
        errors.append(
            f"{path}.{key}: {value!r} is not one of {', '.join(sorted(allowed))}"
        )
        return None
    return value


def _string_list(
    obj: dict[str, Any],
    key: str,
    path: str,
    errors: list[str],
    *,
    allow_empty: bool = False,
) -> list[str]:
    value = obj.get(key)
    if not isinstance(value, list):
        errors.append(f"{path}.{key}: expected array")
        return []
    if not value and not allow_empty:
        errors.append(f"{path}.{key}: expected at least one item")
    result: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            errors.append(f"{path}.{key}[{index}]: expected non-empty string")
            continue
        result.append(item.strip())
    if len(result) != len(set(result)):
        errors.append(f"{path}.{key}: duplicate items are not allowed")
    return result


def _rows(
    case: dict[str, Any], key: str, errors: list[str], *, allow_empty: bool = False
) -> list[dict[str, Any]]:
    value = case.get(key)
    if not isinstance(value, list):
        errors.append(f"{key}: expected array")
        return []
    if not value and not allow_empty:
        errors.append(f"{key}: expected at least one item")
    result: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            errors.append(f"{key}[{index}]: expected object")
            continue
        result.append(item)
    return result


def _date_value(value: Any, path: str, errors: list[str]) -> date | None:
    if not isinstance(value, str):
        errors.append(f"{path}: expected ISO date YYYY-MM-DD")
        return None
    try:
        parsed = date.fromisoformat(value)
    except ValueError:
        errors.append(f"{path}: expected real ISO date YYYY-MM-DD")
        return None
    if value != parsed.isoformat():
        errors.append(f"{path}: expected canonical ISO date YYYY-MM-DD")
        return None
    return parsed


def _section_id(
    row: dict[str, Any],
    section: str,
    path: str,
    seen: set[str],
    errors: list[str],
) -> str | None:
    value = _string(row, "id", path, errors)
    if value is None:
        return None
    if not SECTION_ID_RES[section].fullmatch(value):
        errors.append(f"{path}.id: invalid {section} identifier {value!r}")
    if value in seen:
        errors.append(f"{path}.id: duplicate identifier {value!r}")
    seen.add(value)
    return value


def _all_strings(value: Any, path: str = "") -> Iterable[tuple[str, str]]:
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else key
            yield from _all_strings(child, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _all_strings(child, f"{path}[{index}]")


def validate_case(case: dict[str, Any]) -> ValidationResult:
    """Validate structure, references, and intent-to-evidence traceability."""
    errors: list[str] = []
    warnings: list[str] = []

    for key in sorted(TOP_LEVEL - case.keys()):
        errors.append(f"root: missing required field {key!r}")
    for key in sorted(case.keys() - TOP_LEVEL):
        errors.append(f"root: unknown field {key!r}")
    if case.get("schema_version") != "1.0":
        errors.append("schema_version: expected '1.0'")

    metadata = _object(
        case.get("case"),
        "case",
        {"id", "title", "version", "status", "owners", "last_reviewed"},
        {"id", "title", "version", "status", "owners", "last_reviewed"},
        errors,
    )
    case_id = _string(metadata, "id", "case", errors)
    if case_id and not CASE_ID_RE.fullmatch(case_id):
        errors.append("case.id: expected IC- followed by uppercase letters, digits, or hyphens")
    _string(metadata, "title", "case", errors)
    version = _string(metadata, "version", "case", errors)
    if version and not VERSION_RE.fullmatch(version):
        errors.append("case.version: expected semantic version N.N.N")
    status = _enum(metadata, "status", "case", CASE_STATUSES, errors) or "draft"
    _string_list(metadata, "owners", "case", errors)
    reviewed_at = _date_value(metadata.get("last_reviewed"), "case.last_reviewed", errors)
    if reviewed_at and reviewed_at > date.today():
        warnings.append("case.last_reviewed: date is in the future")

    authorization = _object(
        case.get("authorization"),
        "authorization",
        {"status", "scope", "evidence_reference", "expires", "excluded_actions"},
        {"status", "scope", "evidence_reference", "expires", "excluded_actions"},
        errors,
    )
    auth_status = _enum(
        authorization, "status", "authorization", AUTH_STATUSES, errors
    )
    _string(authorization, "scope", "authorization", errors)
    _string(authorization, "evidence_reference", "authorization", errors)
    _string_list(authorization, "excluded_actions", "authorization", errors)
    expires_value = authorization.get("expires")
    expires = None
    if expires_value is not None:
        expires = _date_value(expires_value, "authorization.expires", errors)

    mature = status in {"reviewed", "accepted"}
    if auth_status == "unknown":
        message = "authorization.status: permission is unknown; do not perform active testing"
        (errors if mature else warnings).append(message)
    if expires and expires < date.today():
        message = "authorization.expires: authorization has expired"
        (errors if mature else warnings).append(message)

    intent = _object(
        case.get("intent"),
        "intent",
        {"purpose", "safety_properties", "non_goals"},
        {"purpose", "safety_properties", "non_goals"},
        errors,
    )
    _string(intent, "purpose", "intent", errors)
    _string_list(intent, "safety_properties", "intent", errors)
    _string_list(intent, "non_goals", "intent", errors)

    component_rows = _rows(case, "components", errors)
    component_ids: set[str] = set()
    component_required = {"id", "name", "kind", "trust", "description"}
    for index, raw in enumerate(component_rows):
        path = f"components[{index}]"
        row = _object(raw, path, component_required, component_required, errors)
        component_id = _string(row, "id", path, errors)
        if component_id:
            if not COMPONENT_ID_RE.fullmatch(component_id):
                errors.append(f"{path}.id: expected lowercase kebab-case identifier")
            if component_id in component_ids:
                errors.append(f"{path}.id: duplicate identifier {component_id!r}")
            component_ids.add(component_id)
        _string(row, "name", path, errors)
        _string(row, "kind", path, errors)
        _enum(row, "trust", path, TRUST_LEVELS, errors)
        _string(row, "description", path, errors)

    boundary_rows = _rows(case, "boundaries", errors)
    boundary_ids: set[str] = set()
    boundary_required = {
        "id", "from", "to", "carrier", "trust_change", "entry_points", "data"
    }
    for index, raw in enumerate(boundary_rows):
        path = f"boundaries[{index}]"
        row = _object(raw, path, boundary_required, boundary_required, errors)
        _section_id(row, "boundaries", path, boundary_ids, errors)
        source = _string(row, "from", path, errors)
        destination = _string(row, "to", path, errors)
        for field, value in (("from", source), ("to", destination)):
            if value and value not in component_ids:
                errors.append(f"{path}.{field}: unknown component {value!r}")
        _string(row, "carrier", path, errors)
        _string(row, "trust_change", path, errors)
        _string_list(row, "entry_points", path, errors)
        _string_list(row, "data", path, errors)

    invariant_rows = _rows(case, "invariants", errors)
    invariant_ids: set[str] = set()
    invariant_required = {"id", "statement", "rationale", "failure_impact", "priority"}
    for index, raw in enumerate(invariant_rows):
        path = f"invariants[{index}]"
        row = _object(raw, path, invariant_required, invariant_required, errors)
        _section_id(row, "invariants", path, invariant_ids, errors)
        _string(row, "statement", path, errors)
        _string(row, "rationale", path, errors)
        _string(row, "failure_impact", path, errors)
        _enum(row, "priority", path, PRIORITIES, errors)

    threat_rows = _rows(case, "threats", errors)
    threat_ids: set[str] = set()
    targeted_invariants: set[str] = set()
    threat_required = {
        "id", "actor", "scenario", "preconditions", "targets", "likelihood", "impact"
    }
    for index, raw in enumerate(threat_rows):
        path = f"threats[{index}]"
        row = _object(raw, path, threat_required, threat_required, errors)
        _section_id(row, "threats", path, threat_ids, errors)
        actor = _string(row, "actor", path, errors)
        if actor and actor not in component_ids:
            errors.append(f"{path}.actor: unknown component {actor!r}")
        _string(row, "scenario", path, errors)
        _string_list(row, "preconditions", path, errors)
        targets = _string_list(row, "targets", path, errors)
        for target in targets:
            if target not in invariant_ids:
                errors.append(f"{path}.targets: unknown invariant {target!r}")
            else:
                targeted_invariants.add(target)
        _enum(row, "likelihood", path, LIKELIHOODS, errors)
        _enum(row, "impact", path, PRIORITIES, errors)

    control_rows = _rows(case, "controls", errors)
    control_ids: set[str] = set()
    controls_by_invariant: dict[str, set[str]] = {item: set() for item in invariant_ids}
    control_required = {"id", "type", "intent", "implementation", "enforces", "limitations"}
    for index, raw in enumerate(control_rows):
        path = f"controls[{index}]"
        row = _object(raw, path, control_required, control_required, errors)
        control_id = _section_id(row, "controls", path, control_ids, errors)
        _enum(row, "type", path, CONTROL_TYPES, errors)
        _string(row, "intent", path, errors)
        _string_list(row, "implementation", path, errors)
        enforces = _string_list(row, "enforces", path, errors)
        _string_list(row, "limitations", path, errors, allow_empty=True)
        for invariant_id in enforces:
            if invariant_id not in invariant_ids:
                errors.append(f"{path}.enforces: unknown invariant {invariant_id!r}")
            elif control_id:
                controls_by_invariant[invariant_id].add(control_id)

    evidence_rows = _rows(case, "evidence", errors)
    evidence_ids: set[str] = set()
    pass_refs: set[str] = set()
    known_verifiable = invariant_ids | control_ids
    evidence_required = {
        "id", "kind", "claim", "artifact", "result", "observed_at", "verifies"
    }
    for index, raw in enumerate(evidence_rows):
        path = f"evidence[{index}]"
        row = _object(raw, path, evidence_required, evidence_required, errors)
        _section_id(row, "evidence", path, evidence_ids, errors)
        _enum(row, "kind", path, EVIDENCE_KINDS, errors)
        _string(row, "claim", path, errors)
        _string(row, "artifact", path, errors)
        result = _enum(row, "result", path, EVIDENCE_RESULTS, errors)
        observed = _date_value(row.get("observed_at"), f"{path}.observed_at", errors)
        if observed and observed > date.today():
            warnings.append(f"{path}.observed_at: date is in the future")
        verifies = _string_list(row, "verifies", path, errors)
        for reference in verifies:
            if reference not in known_verifiable:
                errors.append(f"{path}.verifies: unknown invariant or control {reference!r}")
            elif result == "pass":
                pass_refs.add(reference)

    decision_rows = _rows(case, "decisions", errors, allow_empty=True)
    decision_ids: set[str] = set()
    decision_required = {"id", "context", "choice", "rationale", "consequences"}
    for index, raw in enumerate(decision_rows):
        path = f"decisions[{index}]"
        row = _object(raw, path, decision_required, decision_required, errors)
        _section_id(row, "decisions", path, decision_ids, errors)
        _string(row, "context", path, errors)
        _string(row, "choice", path, errors)
        _string(row, "rationale", path, errors)
        _string_list(row, "consequences", path, errors)

    risk_rows = _rows(case, "residual_risks", errors, allow_empty=True)
    risk_ids: set[str] = set()
    risk_required = {
        "id", "statement", "owner", "disposition", "review_by", "related", "next_action"
    }
    for index, raw in enumerate(risk_rows):
        path = f"residual_risks[{index}]"
        row = _object(raw, path, risk_required, risk_required, errors)
        _section_id(row, "residual_risks", path, risk_ids, errors)
        _string(row, "statement", path, errors)
        _string(row, "owner", path, errors)
        disposition = _enum(row, "disposition", path, RISK_DISPOSITIONS, errors)
        review_value = row.get("review_by")
        if review_value is not None:
            review_by = _date_value(review_value, f"{path}.review_by", errors)
            if review_by and review_by < date.today() and disposition != "accept":
                warnings.append(f"{path}.review_by: review is overdue")
        elif disposition != "accept":
            warnings.append(f"{path}.review_by: active residual risk has no review date")
        related = _string_list(row, "related", path, errors, allow_empty=True)
        for invariant_id in related:
            if invariant_id not in invariant_ids:
                errors.append(f"{path}.related: unknown invariant {invariant_id!r}")
        _string(row, "next_action", path, errors)

    for invariant_id in sorted(invariant_ids):
        mapped_controls = controls_by_invariant.get(invariant_id, set())
        if not mapped_controls:
            errors.append(f"traceability: invariant {invariant_id} has no implementing control")
            continue
        supported = invariant_id in pass_refs or any(
            control_id in pass_refs for control_id in mapped_controls
        )
        if not supported:
            message = f"traceability: invariant {invariant_id} has no passing evidence"
            (errors if mature else warnings).append(message)
        if invariant_id not in targeted_invariants:
            warnings.append(f"traceability: invariant {invariant_id} is not targeted by a threat")

    for control_id in sorted(control_ids):
        if control_id not in pass_refs:
            message = f"traceability: control {control_id} has no passing evidence"
            (errors if mature else warnings).append(message)

    placeholder_paths: list[str] = []
    for path, value in _all_strings(case):
        if any(pattern.search(value) for pattern in SECRET_PATTERNS):
            errors.append(f"{path}: looks like secret material; remove it from the case")
        lowered = value.lower()
        if "replace-me" in lowered or "replace this" in lowered or "<replace" in lowered:
            placeholder_paths.append(path)
        if value.startswith(("/Users/", "/home/")):
            warnings.append(f"{path}: absolute user path may reveal private environment details")
    if placeholder_paths:
        warnings.append(
            "starter placeholder text remains at: " + ", ".join(placeholder_paths)
        )

    return ValidationResult(tuple(dict.fromkeys(errors)), tuple(dict.fromkeys(warnings)))


def _md(value: Any) -> str:
    """Escape untrusted case text for a compact Markdown table/cell."""
    text = str(value)
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    text = text.replace("|", "\\|").replace("\r", " ").replace("\n", "<br>")
    return text


def _join(values: Iterable[Any]) -> str:
    rendered = [_md(value) for value in values]
    return ", ".join(rendered) if rendered else "—"


def _index_by_id(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {row["id"]: row for row in rows}


def assurance_counts(case: dict[str, Any]) -> dict[str, int]:
    """Return deterministic traceability counts used by CLI and tests."""
    invariants = _index_by_id(case["invariants"])
    controls = _index_by_id(case["controls"])
    passing_refs = {
        reference
        for item in case["evidence"]
        if item["result"] == "pass"
        for reference in item["verifies"]
    }
    mapped: dict[str, list[str]] = {key: [] for key in invariants}
    for control in controls.values():
        for invariant_id in control["enforces"]:
            if invariant_id in mapped:
                mapped[invariant_id].append(control["id"])
    supported = 0
    for invariant_id, control_ids in mapped.items():
        if control_ids and (
            invariant_id in passing_refs
            or any(control_id in passing_refs for control_id in control_ids)
        ):
            supported += 1
    return {
        "invariants": len(invariants),
        "supported_invariants": supported,
        "controls": len(controls),
        "supported_controls": sum(key in passing_refs for key in controls),
        "evidence": len(case["evidence"]),
        "passing_evidence": sum(item["result"] == "pass" for item in case["evidence"]),
        "residual_risks": len(case["residual_risks"]),
    }


def render_case(case: dict[str, Any], source_name: str = "Integrity Case") -> str:
    """Render a validated case as a compact, portable Markdown dashboard."""
    metadata = case["case"]
    authorization = case["authorization"]
    counts = assurance_counts(case)
    invariant_pct = round(
        100 * counts["supported_invariants"] / counts["invariants"]
    ) if counts["invariants"] else 0
    control_pct = round(
        100 * counts["supported_controls"] / counts["controls"]
    ) if counts["controls"] else 0

    controls_by_invariant: dict[str, list[str]] = {
        row["id"]: [] for row in case["invariants"]
    }
    threats_by_invariant: dict[str, list[str]] = {
        row["id"]: [] for row in case["invariants"]
    }
    evidence_by_reference: dict[str, list[str]] = {}
    for control in case["controls"]:
        for invariant_id in control["enforces"]:
            controls_by_invariant.setdefault(invariant_id, []).append(control["id"])
    for threat in case["threats"]:
        for invariant_id in threat["targets"]:
            threats_by_invariant.setdefault(invariant_id, []).append(threat["id"])
    for item in case["evidence"]:
        marker = f"{item['id']}:{item['result']}"
        for reference in item["verifies"]:
            evidence_by_reference.setdefault(reference, []).append(marker)

    lines = [
        f"# Assurance dashboard — {_md(metadata['title'])}",
        "",
        f"> Generated from `{_md(source_name)}`. Structural traceability is not a security guarantee.",
        "",
        "## At a glance",
        "",
        "| Case | Version | Status | Owners | Last reviewed | Authorization |",
        "|------|---------|--------|--------|---------------|---------------|",
        "| "
        + " | ".join(
            [
                _md(metadata["id"]),
                _md(metadata["version"]),
                _md(metadata["status"]),
                _join(metadata["owners"]),
                _md(metadata["last_reviewed"]),
                _md(authorization["status"]),
            ]
        )
        + " |",
        "",
        "| Invariant support | Control support | Evidence | Residual risks |",
        "|-------------------|-----------------|----------|----------------|",
        "| "
        + " | ".join(
            [
                f"{counts['supported_invariants']}/{counts['invariants']} ({invariant_pct}%)",
                f"{counts['supported_controls']}/{counts['controls']} ({control_pct}%)",
                f"{counts['passing_evidence']}/{counts['evidence']} passing",
                str(counts["residual_risks"]),
            ]
        )
        + " |",
        "",
        "## Intention",
        "",
        _md(case["intent"]["purpose"]),
        "",
        "**Safety properties**",
        "",
    ]
    lines.extend(f"- {_md(item)}" for item in case["intent"]["safety_properties"])
    lines.extend(["", "**Non-goals**", ""])
    lines.extend(f"- {_md(item)}" for item in case["intent"]["non_goals"])

    lines.extend(
        [
            "",
            "## Authorization boundary",
            "",
            f"- **Status:** {_md(authorization['status'])}",
            f"- **Scope:** {_md(authorization['scope'])}",
            f"- **Evidence reference:** {_md(authorization['evidence_reference'])}",
            f"- **Expires:** {_md(authorization['expires'] or 'not time-limited')}",
            f"- **Excluded actions:** {_join(authorization['excluded_actions'])}",
            "",
            "## Trust boundaries",
            "",
            "| ID | From → to | Carrier | Trust change | Entry points | Data |",
            "|----|-----------|---------|--------------|--------------|------|",
        ]
    )
    for boundary in case["boundaries"]:
        lines.append(
            "| "
            + " | ".join(
                [
                    _md(boundary["id"]),
                    f"{_md(boundary['from'])} → {_md(boundary['to'])}",
                    _md(boundary["carrier"]),
                    _md(boundary["trust_change"]),
                    _join(boundary["entry_points"]),
                    _join(boundary["data"]),
                ]
            )
            + " |"
        )

    lines.extend(
        [
            "",
            "## Invariant trace",
            "",
            "| ID | Priority | Invariant | Threats | Controls | Evidence | State |",
            "|----|----------|-----------|---------|----------|----------|-------|",
        ]
    )
    passing_refs = {
        reference
        for item in case["evidence"]
        if item["result"] == "pass"
        for reference in item["verifies"]
    }
    for invariant in case["invariants"]:
        invariant_id = invariant["id"]
        control_ids = controls_by_invariant.get(invariant_id, [])
        markers = list(evidence_by_reference.get(invariant_id, []))
        for control_id in control_ids:
            markers.extend(evidence_by_reference.get(control_id, []))
        supported = bool(control_ids) and (
            invariant_id in passing_refs
            or any(control_id in passing_refs for control_id in control_ids)
        )
        lines.append(
            "| "
            + " | ".join(
                [
                    _md(invariant_id),
                    _md(invariant["priority"]),
                    _md(invariant["statement"]),
                    _join(threats_by_invariant.get(invariant_id, [])),
                    _join(control_ids),
                    _join(dict.fromkeys(markers)),
                    "supported" if supported else "gap",
                ]
            )
            + " |"
        )

    lines.extend(
        [
            "",
            "## Controls and implementation",
            "",
            "| ID | Type | Intention | Implementation | Enforces | Limitations |",
            "|----|------|-----------|----------------|----------|-------------|",
        ]
    )
    for control in case["controls"]:
        lines.append(
            "| "
            + " | ".join(
                [
                    _md(control["id"]),
                    _md(control["type"]),
                    _md(control["intent"]),
                    _join(control["implementation"]),
                    _join(control["enforces"]),
                    _join(control["limitations"]),
                ]
            )
            + " |"
        )

    lines.extend(
        [
            "",
            "## Evidence",
            "",
            "| ID | Result | Kind | Claim | Artifact | Verifies | Observed |",
            "|----|--------|------|-------|----------|----------|----------|",
        ]
    )
    for item in case["evidence"]:
        lines.append(
            "| "
            + " | ".join(
                [
                    _md(item["id"]),
                    _md(item["result"]),
                    _md(item["kind"]),
                    _md(item["claim"]),
                    _md(item["artifact"]),
                    _join(item["verifies"]),
                    _md(item["observed_at"]),
                ]
            )
            + " |"
        )

    lines.extend(["", "## Residual risk", ""])
    if case["residual_risks"]:
        lines.extend(
            [
                "| ID | Disposition | Risk | Owner | Review by | Next action |",
                "|----|-------------|------|-------|-----------|-------------|",
            ]
        )
        for risk in case["residual_risks"]:
            lines.append(
                "| "
                + " | ".join(
                    [
                        _md(risk["id"]),
                        _md(risk["disposition"]),
                        _md(risk["statement"]),
                        _md(risk["owner"]),
                        _md(risk["review_by"] or "not scheduled"),
                        _md(risk["next_action"]),
                    ]
                )
                + " |"
            )
    else:
        lines.append("No residual risks documented.")

    lines.extend(["", "## Decisions", ""])
    if case["decisions"]:
        for decision in case["decisions"]:
            lines.extend(
                [
                    f"### {_md(decision['id'])} — {_md(decision['choice'])}",
                    "",
                    f"- **Context:** {_md(decision['context'])}",
                    f"- **Rationale:** {_md(decision['rationale'])}",
                    f"- **Consequences:** {_join(decision['consequences'])}",
                    "",
                ]
            )
    else:
        lines.append("No decisions documented.")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _write_atomic(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _print_result(path: Path, result: ValidationResult) -> None:
    for warning in result.warnings:
        print(f"WARN {path}: {warning}", file=sys.stderr)
    for error in result.errors:
        print(f"ERROR {path}: {error}", file=sys.stderr)


def _load_and_validate(path: Path) -> tuple[dict[str, Any] | None, ValidationResult]:
    try:
        case = load_case(path)
    except ValueError as exc:
        return None, ValidationResult((str(exc),), ())
    return case, validate_case(case)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate and render Whitehack Integrity Cases."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_parser = subparsers.add_parser(
        "validate", help="validate one or more JSON cases"
    )
    validate_parser.add_argument("cases", nargs="+", type=Path)

    render_parser = subparsers.add_parser(
        "render", help="render one validated case as Markdown"
    )
    render_parser.add_argument("case", type=Path)
    render_parser.add_argument("--output", "-o", type=Path)

    args = parser.parse_args(argv)
    if args.command == "validate":
        failed = False
        for path in args.cases:
            case, result = _load_and_validate(path)
            _print_result(path, result)
            if result.ok and case is not None:
                counts = assurance_counts(case)
                print(
                    f"OK {path}: {counts['supported_invariants']}/"
                    f"{counts['invariants']} invariants supported; "
                    f"{counts['supported_controls']}/{counts['controls']} controls evidenced"
                )
            else:
                failed = True
        return 1 if failed else 0

    path = args.case
    case, result = _load_and_validate(path)
    _print_result(path, result)
    if not result.ok or case is None:
        return 1
    rendered = render_case(case, path.name)
    if args.output:
        try:
            if args.output.resolve() == path.resolve():
                print("ERROR: refusing to overwrite the source case", file=sys.stderr)
                return 1
            _write_atomic(args.output, rendered)
        except OSError as exc:
            print(f"ERROR: cannot write {args.output}: {exc}", file=sys.stderr)
            return 1
        print(f"WROTE {args.output}")
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
