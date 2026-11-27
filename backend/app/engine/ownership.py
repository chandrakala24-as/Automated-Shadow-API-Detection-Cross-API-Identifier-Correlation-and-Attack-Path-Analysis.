"""Work out which test user owns each identifier, using only differential evidence."""
from __future__ import annotations

from .models import Endpoint, Identity, Observation

PRIVILEGED_SEGMENTS = {"admin", "administrator", "management", "manage"}

Key = tuple[str, str]


def is_privileged(endpoint: Endpoint) -> bool:
    return endpoint.spec_admin or any(
        part.lower() in PRIVILEGED_SEGMENTS for part in endpoint.template.split("/"))


def shared_objects(endpoints: dict[str, Endpoint], observations: list[Observation],
                   users: set[str]) -> set[Key]:
    """Objects that a documented, non-sensitive listing shows to several users by design.

    Undocumented, privileged or sensitive listings never make an object "shared",
    otherwise a leaking endpoint would hide the vulnerabilities it enables.
    """
    seen: dict[Key, set[str]] = {}
    for obs in observations:
        endpoint = endpoints[obs.endpoint]
        if (obs.identity not in users or not obs.has_data or endpoint.inputs
                or not endpoint.in_spec or is_privileged(endpoint) or obs.sensitive):
            continue
        for ref in obs.ids:
            if ref.primary:
                seen.setdefault(ref.key, set()).add(obs.identity)
    return {key for key, who in seen.items() if len(who) > 1}


def listed_objects(endpoints: dict[str, Endpoint], observations: list[Observation],
                   users: set[str]) -> set[Key]:
    """Objects that appear as records themselves (not as references) in a parameterless
    response. Together with single-user ownership this is strong proof of a private object.
    """
    return {ref.key for obs in observations
            if obs.identity in users and obs.ok and not endpoints[obs.endpoint].inputs
            for ref in obs.ids if ref.primary}


def compute_owners(endpoints: dict[str, Endpoint], observations: list[Observation],
                   identities: list[Identity]) -> dict[Key, str]:
    users = {i.name for i in identities if i.role == "user"}
    shared = shared_objects(endpoints, observations, users)

    # 1. Direct evidence: the same parameterless endpoint shows a value to one user only.
    per_endpoint: dict[str, dict[str, set[Key]]] = {}
    for obs in observations:
        if obs.identity in users and obs.ok and not endpoints[obs.endpoint].inputs:
            per_endpoint.setdefault(obs.endpoint, {}).setdefault(obs.identity, set()).update(
                ref.key for ref in obs.ids)
    claims: dict[Key, set[str]] = {}
    for by_user in per_endpoint.values():
        if len(by_user) < 2:
            continue
        for user, keys in by_user.items():
            others = set().union(*(v for u, v in by_user.items() if u != user))
            for key in keys - others:
                claims.setdefault(key, set()).add(user)
    owners = {k: next(iter(v)) for k, v in claims.items() if len(v) == 1 and k not in shared}
    ambiguous = {k for k, v in claims.items() if len(v) > 1}

    # 2. Propagation: references inside a user's own object belong to that user.
    changed = True
    while changed:
        changed = False
        for obs in observations:
            endpoint = endpoints[obs.endpoint]
            if obs.identity not in users or not obs.has_data or not endpoint.inputs:
                continue
            keys = [(i.entity, obs.values.get(i.name, "")) for i in endpoint.inputs]
            if not all(owners.get(k) == obs.identity for k in keys):
                continue
            for ref in obs.ids:
                if ref.key not in owners and ref.key not in shared and ref.key not in ambiguous:
                    owners[ref.key] = obs.identity
                    changed = True
    return owners
