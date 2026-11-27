"""Send read-only requests as every identity and record what each one can see."""
from __future__ import annotations

import itertools
import json
import secrets
from urllib.parse import quote

from .identifiers import extract
from .models import ANONYMOUS, INVALID, Endpoint, Identity, Observation
from .normalize import Inventory
from .ownership import compute_owners
from .scope import ScopedClient, is_unsafe_route

MAX_VALUES_PER_OWNER = 2
MAX_COMBINATIONS = 12
MAX_ROUNDS = 6


def invalid_headers(identities: list[Identity]) -> dict[str, str]:
    """Same header names as a real user, with worthless values."""
    template = identities[0].headers if identities else {}
    result = {}
    for name, value in template.items():
        lowered = name.lower()
        if lowered == "authorization":
            scheme = value.split(" ", 1)[0] if " " in value else ""
            result[name] = f"{scheme} shadowapi-invalid-token".strip()
        elif lowered == "cookie":
            result[name] = "; ".join(
                f"{c.split('=')[0].strip()}=shadowapi-invalid" for c in value.split(";") if c.strip())
        else:
            result[name] = "shadowapi-invalid-token"
    return result or {"Authorization": "Bearer shadowapi-invalid-token"}


class Prober:
    def __init__(self, client: ScopedClient, inventory: Inventory,
                 identities: list[Identity]) -> None:
        self.client = client
        self.inventory = inventory
        self.identities = identities
        self.observations: list[Observation] = []
        self._cache: set[tuple] = set()
        self._missing: dict[str, tuple[int, str]] = {}
        self._probe_headers = {ANONYMOUS: {}, INVALID: invalid_headers(identities),
                               **{i.name: i.headers for i in identities}}

    def calibrate(self) -> None:
        """Learn what 'route does not exist' looks like for each identity."""
        path = f"/api/shadowapi-{secrets.token_hex(8)}"
        for name, headers in self._probe_headers.items():
            result = self.client.get(path, headers=headers)
            if result:
                self._missing[name] = (result[0], result[2].replace(path, ""))

    def request(self, endpoint: Endpoint, identity: str, values: dict[str, str],
                record: bool = True) -> Observation | None:
        """`record=False` is for existence probes that must not count as test results."""
        key = (endpoint.label, identity, tuple(sorted(values.items())))
        if record and key in self._cache:
            return None
        path, params = endpoint.template, {}
        for item in endpoint.inputs:
            if item.location == "path":
                path = path.replace("{" + item.name + "}", quote(values[item.name], safe=""))
            else:
                params[item.name] = values[item.name]
        if any(v in (".", "..") for v in values.values()) or is_unsafe_route(path):
            return None
        if record:
            self._cache.add(key)
        result = self.client.get(path, headers=self._probe_headers[identity], params=params or None)
        if result is None:
            return None
        status, _, text = result
        try:
            body = json.loads(text)
        except (json.JSONDecodeError, RecursionError):
            body = None
        missing = self._missing.get(identity)
        not_found = bool(missing and status == missing[0] and text.replace(path, "") == missing[1])
        url_path = path + ("?" + "&".join(f"{k}={v}" for k, v in params.items()) if params else "")
        obs = Observation(endpoint.label, identity, dict(values), url_path, status, body,
                          matches_not_found=not_found)
        if obs.ok and body is not None:
            obs.ids, obs.sensitive = extract(body, endpoint)
        # 404/405 and the "unknown route" answer do not prove that a route exists.
        if not not_found and status not in (404, 405) and status < 500:
            endpoint.live = True
            endpoint.statuses.add(status)
            for category, names in obs.sensitive.items():
                merged = set(endpoint.sensitive.get(category, [])) | set(names)
                endpoint.sensitive[category] = sorted(merged)
        if record:
            self.observations.append(obs)
        return obs

    def _candidates(self, endpoint: Endpoint, owners: dict) -> list[dict[str, str]]:
        """Input value combinations worth testing: a few per owner, never mixed owners."""
        harvested: dict[str, list[str]] = {}
        for obs in self.observations:
            for ref in obs.ids:
                bucket = harvested.setdefault(ref.entity, [])
                if ref.value not in bucket:
                    bucket.append(ref.value)
        options = []
        for item in endpoint.inputs:
            pool = sorted(endpoint.samples.get(item.name, set())) + harvested.get(item.entity, [])
            counts: dict[str | None, int] = {}
            chosen = []
            for value in dict.fromkeys(pool):
                owner = owners.get((item.entity, value))
                if counts.get(owner, 0) < MAX_VALUES_PER_OWNER:
                    counts[owner] = counts.get(owner, 0) + 1
                    chosen.append((value, owner))
            if not chosen:
                return []
            options.append(chosen)
        combos = []
        for combo in itertools.islice(itertools.product(*options), 500):
            if len({owner for _, owner in combo if owner}) <= 1:
                combos.append({i.name: v for i, (v, _) in zip(endpoint.inputs, combo)})
            if len(combos) >= MAX_COMBINATIONS:
                break
        return combos

    def testable(self) -> list[Endpoint]:
        result = []
        for endpoint in self.inventory.all():
            if endpoint.method != "GET":
                endpoint.skip_reason = f"{endpoint.method} is not sent: scanning is read-only."
            elif is_unsafe_route(endpoint.template):
                endpoint.skip_reason = "Route name suggests a side effect."
            else:
                result.append(endpoint)
        return result

    def run(self, progress=lambda done: None) -> None:
        """Request endpoints repeatedly, feeding newly found identifiers into the next round."""
        actors = [i.name for i in self.identities] + [ANONYMOUS, INVALID]
        for round_number in range(MAX_ROUNDS):
            before = len(self.observations)
            by_label = {e.label: e for e in self.inventory.all()}
            owners = compute_owners(by_label, self.observations, self.identities)
            for endpoint in self.testable():
                combos = self._candidates(endpoint, owners) if endpoint.inputs else [{}]
                for values in combos:
                    for actor in actors:
                        self.request(endpoint, actor, values)
            progress((round_number + 1) / MAX_ROUNDS)
            if len(self.observations) == before:
                break
        for endpoint in self.testable():
            if endpoint.inputs and not any(o.endpoint == endpoint.label for o in self.observations):
                endpoint.skip_reason = "No value was found for its parameters."
