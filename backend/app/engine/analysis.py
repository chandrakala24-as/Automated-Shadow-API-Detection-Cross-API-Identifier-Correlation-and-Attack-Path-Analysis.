"""Classification and authentication/authorisation analysis."""
from __future__ import annotations

from typing import Any

from .identifiers import redact
from .models import ANONYMOUS, INVALID, Endpoint, Finding, Identity, Observation
from .normalize import VERSION_RE, split_path
from .ownership import is_privileged, listed_objects

OLD_MARKERS = {"old", "legacy", "deprecated", "beta", "backup"}
VOLATILE_KEYS = {"timestamp", "time", "now", "requestid", "request_id", "generated_at",
                 "generatedat", "nonce", "traceid", "trace_id"}


def _version(template: str) -> int | None:
    for part in split_path(template):
        match = VERSION_RE.match(part)
        if match:
            return int(match.group(1))
    return None


def classify(endpoints: list[Endpoint], has_spec: bool) -> None:
    versions = [v for e in endpoints if e.in_spec and not e.spec_deprecated
                and (v := _version(e.template)) is not None]
    newest = max(versions, default=None)
    for e in endpoints:
        if not has_spec:
            e.classification = "unclassified" if e.live else "candidate"
        elif e.in_spec:
            if not e.live:
                e.classification = "unverified"
            else:
                e.classification = "zombie" if e.spec_deprecated else "documented"
        elif not e.live:
            e.classification = "candidate"
        else:
            version = _version(e.template)
            old = (version is not None and newest is not None and version < newest) or any(
                p.lower() in OLD_MARKERS for p in split_path(e.template))
            e.classification = "zombie" if old else "shadow"


def _strip(node: Any) -> Any:
    if isinstance(node, dict):
        return {k: _strip(v) for k, v in node.items() if k.lower() not in VOLATILE_KEYS}
    if isinstance(node, list):
        return [_strip(v) for v in node]
    return node


def same_data(a: Observation, b: Observation) -> bool:
    return a.has_data and b.has_data and _strip(a.body) == _strip(b.body)


def evidence(obs: Observation, note: str) -> dict:
    return {"note": note, "identity": obs.identity, "request": f"GET {obs.url_path}",
            "status": obs.status, "response": redact(obs.body)}


def _categories(*observations: Observation) -> list[str]:
    return sorted({c for o in observations for c in o.sensitive})


def analyse(endpoints: list[Endpoint], observations: list[Observation],
            identities: list[Identity], owners: dict) -> list[Finding]:
    users = {i.name for i in identities if i.role == "user"}
    admins = {i.name for i in identities if i.role == "admin"}
    grouped: dict[str, dict[tuple, dict[str, Observation]]] = {}
    for obs in observations:
        key = tuple(sorted(obs.values.items()))
        grouped.setdefault(obs.endpoint, {}).setdefault(key, {})[obs.identity] = obs

    listed = listed_objects({e.label: e for e in endpoints}, observations, users)

    findings: list[Finding] = []
    for endpoint in endpoints:
        found: dict[str, Finding] = {}

        def keep(finding: Finding) -> None:
            old = found.get(finding.type)
            if old is None or (old.confidence != "confirmed" and finding.confidence == "confirmed"):
                found[finding.type] = finding

        for values, by_actor in grouped.get(endpoint.label, {}).items():
            anon, bogus = by_actor.get(ANONYMOUS), by_actor.get(INVALID)
            anon_open = bool(anon and anon.has_data)

            # Authentication: data returned without any credentials.
            if anon_open and not endpoint.spec_public:
                strong = bool(anon.sensitive) or any(same_data(anon, by_actor[u])
                                                     for u in users if u in by_actor and endpoint.inputs)
                keep(Finding(
                    "MISSING_AUTHENTICATION", endpoint.label,
                    "Data is returned without authentication",
                    "A request with no credentials received data. The endpoint is not declared "
                    "public in the specification.",
                    "Require authentication on this route and deny by default at the gateway. "
                    "If it is meant to be public, declare `security: []` in the specification.",
                    "API2:2023 Broken Authentication", "confirmed" if strong else "review",
                    ANONYMOUS, [evidence(anon, "Request sent without credentials")],
                    _categories(anon)))

            # Authentication: anonymous is refused but a worthless token is accepted.
            if (bogus and bogus.has_data and anon and anon.status in (401, 403)
                    and not endpoint.spec_public):
                keep(Finding(
                    "INVALID_TOKEN_ACCEPTED", endpoint.label, "An invalid token is accepted",
                    "The endpoint refuses requests without credentials but accepts a made-up token, "
                    "so the token is not being verified.",
                    "Verify the token signature, issuer, audience and expiry on every request.",
                    "API2:2023 Broken Authentication", "confirmed", ANONYMOUS,
                    [evidence(anon, "No credentials: refused"),
                     evidence(bogus, "Made-up token: accepted")], _categories(bogus)))

            if anon_open or (bogus and bogus.has_data):
                continue  # authorisation checks are meaningless when anyone can get in

            # Function level authorisation.
            if is_privileged(endpoint) and not endpoint.spec_public:
                for user in sorted(users):
                    obs = by_actor.get(user)
                    if not (obs and obs.has_data):
                        continue
                    reference = next((by_actor[a] for a in sorted(admins)
                                      if a in by_actor and same_data(by_actor[a], obs)), None)
                    proof = [evidence(obs, "Normal user reaches an administrative route")]
                    if reference:
                        proof.append(evidence(reference, "Administrator receives the same data"))
                    keep(Finding(
                        "BFLA", endpoint.label, "A normal user can call an administrative function",
                        "This route is administrative, and a non-admin account received data from it."
                        + ("" if reference else " No matching administrator response was available "
                           "for comparison, so please review it."),
                        "Enforce a role check on the server for every administrative route.",
                        "API5:2023 Broken Function Level Authorization",
                        "confirmed" if reference else "review", user, proof, _categories(obs)))
                continue

            # Object level authorisation.
            if not endpoint.inputs or endpoint.spec_public:
                continue
            value_map = dict(values)
            keys = [(i.entity, value_map.get(i.name, "")) for i in endpoint.inputs]
            holders = {owners[k] for k in keys if k in owners}
            if len(holders) != 1:
                continue
            victim = holders.pop()
            owner_obs = by_actor.get(victim)
            if not owner_obs:
                continue
            for attacker in sorted(users - {victim}):
                obs = by_actor.get(attacker)
                if not (obs and same_data(owner_obs, obs)):
                    continue
                # A matching response is only "confirmed" with proof that the object is private.
                # An ID that was merely referenced by a private record is not proof.
                private = (bool(obs.sensitive)
                           or any(r.entity == "user" and owners.get(r.key) == victim
                                  for r in obs.ids)
                           or all(k in listed for k in keys if k in owners))
                keep(Finding(
                    "BOLA", endpoint.label, "One user can read another user's object (BOLA/IDOR)",
                    f"'{attacker}' requested an object belonging to '{victim}' and received the same "
                    "data as the owner. The server does not check object ownership.",
                    "Check on the server that the authenticated user owns, or has been granted, the "
                    "requested object. Random identifiers alone are not access control.",
                    "API1:2023 Broken Object Level Authorization",
                    "confirmed" if private else "review", attacker,
                    [evidence(owner_obs, f"Baseline: owner '{victim}'"),
                     evidence(obs, f"Cross-user access by '{attacker}'")], _categories(obs)))

        # Secrets in any successful response.
        leaky = sorted((o for o in observations if o.endpoint == endpoint.label
                        and o.has_data and "secrets" in o.sensitive and o.identity != INVALID),
                       key=lambda o: o.identity != ANONYMOUS)
        if leaky:
            obs = leaky[0]
            keep(Finding(
                "SECRET_EXPOSURE", endpoint.label, "Response exposes secret values",
                f"The response contains secret fields: {', '.join(obs.sensitive['secrets'])}.",
                "Remove secrets from API responses, return only the fields clients need, "
                "and rotate any exposed secret.",
                "API3:2023 Broken Object Property Level Authorization",
                "confirmed", obs.identity, [evidence(obs, "Secret fields are masked here")],
                _categories(obs)))
        findings.extend(found.values())

        if endpoint.classification in ("shadow", "zombie"):
            zombie = endpoint.classification == "zombie"
            findings.append(Finding(
                "ZOMBIE_API" if zombie else "SHADOW_API", endpoint.label,
                "Old API version is still live" if zombie else "Undocumented API is live",
                f"Discovered through: {', '.join(sorted(endpoint.sources))}. "
                + ("It is deprecated or older than the documented version." if zombie
                   else "It does not appear in the specification."),
                "Retire the route if it is unused. Otherwise document it, assign an owner and "
                "apply the same security controls as other routes.",
                "API9:2023 Improper Inventory Management", "confirmed", "n/a", [],
                sorted(endpoint.sensitive)))
    return findings
