"""State-based attack path search over requests that really succeeded.

The attacker's state is the set of a victim's identifiers they have learned. A request is
possible only when ALL of its inputs are already known (AND condition). Every step is backed
by an actual response, so no step is hypothetical.
"""
from __future__ import annotations

from .models import ANONYMOUS, AttackPath, Endpoint, Finding, Identity, Observation
from .risk import impact_of, severity

MAX_STEPS = 6
MAX_PATHS = 50
WEAKNESS_NAMES = {
    "BOLA": "BOLA/IDOR", "BFLA": "broken function-level authorization",
    "MISSING_AUTHENTICATION": "missing authentication",
    "INVALID_TOKEN_ACCEPTED": "invalid token accepted", "SECRET_EXPOSURE": "secret exposure",
}


def find_paths(endpoints: list[Endpoint], observations: list[Observation],
               findings: list[Finding], identities: list[Identity],
               owners: dict) -> list[AttackPath]:
    by_label = {e.label: e for e in endpoints}
    weaknesses: dict[str, list[Finding]] = {}
    for finding in findings:
        if finding.type not in ("SHADOW_API", "ZOMBIE_API") and finding.confidence == "confirmed":
            weaknesses.setdefault(finding.endpoint, []).append(finding)

    users = [i.name for i in identities if i.role == "user"]
    best: dict[tuple, AttackPath] = {}
    for attacker in [ANONYMOUS] + users:
        mine = [o for o in observations if o.identity == attacker and o.has_data]
        for victim in users:
            if victim == attacker:
                continue
            order, options, depth = _explore(mine, by_label, owners, victim)
            candidates: dict[str, list[tuple[frozenset, list[int], dict]]] = {}
            for goal, obs in enumerate(order):
                if obs.endpoint not in weaknesses or not options[goal]:
                    continue
                for chain, parents in _chains(goal, options, order):
                    if 2 <= len(chain) <= MAX_STEPS:
                        route = frozenset(order[n].endpoint for n in chain)
                        # Order by depth so every step comes after the steps it relies on.
                        nodes = sorted(chain, key=lambda n: (depth[n], n))
                        candidates.setdefault(obs.endpoint, []).append((route, nodes, parents))
            for found in candidates.values():
                for route, nodes, parents in found:
                    # Drop routes that only add unnecessary calls to a shorter route.
                    if any(other < route for other, _, _ in found):
                        continue
                    path = _describe(nodes, order, parents, by_label, weaknesses,
                                     attacker, victim)
                    key = (path.steps[-1]["endpoint"], route)
                    if key not in best:  # anonymous is searched first: least privilege wins
                        best[key] = path
    ranked = sorted(best.values(), key=lambda p: (-p.score, len(p.steps), p.title))
    return ranked[:MAX_PATHS]


def _explore(mine, by_label, owners, victim):
    """Breadth-first expansion of what the attacker can learn about one victim.

    Returns the usable requests, the alternative sources of each request's inputs
    (one per producing endpoint) and the depth of each request.
    """
    known: dict[tuple, dict[str, tuple[int, str]]] = {}
    order: list[Observation] = []
    options: list[dict] = []
    depth: list[int] = []
    used: set[int] = set()
    progressed = True
    while progressed:
        progressed = False
        frontier = []
        for index, obs in enumerate(mine):
            if index in used:
                continue
            needs = [(i.entity, obs.values.get(i.name, ""))
                     for i in by_label[obs.endpoint].inputs]
            if all(k in known for k in needs):
                frontier.append((index, obs, needs))
        # One BFS level at a time, so a source is always shallower than its consumer.
        snapshot = {k: dict(v) for k, v in known.items()}
        for index, obs, needs in frontier:
            used.add(index)
            progressed = True
            sources = {k: snapshot[k] for k in needs}
            level = 1 + max((min(depth[s] for s, _ in v.values()) for v in sources.values()),
                            default=0)
            position = len(order)
            order.append(obs)
            options.append(sources)
            depth.append(level)
            if level < MAX_STEPS:
                for ref in obs.ids:
                    if owners.get(ref.key) == victim and ref.value not in obs.values.values():
                        known.setdefault(ref.key, {}).setdefault(
                            obs.endpoint, (position, ref.field_name))
    return order, options, depth


def _chains(goal, options, order, limit: int = 24):
    """All alternative derivations of a request, as (nodes, parents) pairs."""
    memo: dict[int, list] = {}

    def build(node: int) -> list:
        if node not in memo:
            partial = [(frozenset([node]), {node: {}})]
            for key, sources in options[node].items():
                extended = []
                for source, field_name in sources.values():
                    for chain, parents in build(source):
                        for current, mapping in partial:
                            merged = {**mapping, **parents}
                            merged[node] = {**mapping[node], key: (source, field_name)}
                            extended.append((current | chain, merged))
                partial = sorted(extended, key=lambda item: len(item[0]))[:limit]
            memo[node] = partial
        return memo[node]

    return build(goal)


def _describe(chain, order, parents, by_label, weaknesses, attacker, victim) -> AttackPath:
    steps = []
    for number, node in enumerate(chain, 1):
        obs = order[node]
        endpoint = by_label[obs.endpoint]
        uses = [{"entity": entity, "field": field_name,
                 "from_step": chain.index(source) + 1}
                for (entity, _), (source, field_name) in parents[node].items()]
        gains = []
        for later in chain:
            for (entity, _), (source, field_name) in parents[later].items():
                if source == node:
                    gains.append({"entity": entity, "field": field_name})
        steps.append({
            "number": number, "endpoint": obs.endpoint, "request": f"GET {obs.url_path}",
            "status": obs.status, "classification": endpoint.classification,
            "uses": uses, "gains": [dict(t) for t in {tuple(g.items()) for g in gains}],
            "weaknesses": sorted({f.type for f in weaknesses.get(obs.endpoint, [])}),
            "data": sorted(obs.sensitive),
        })
    goal = order[chain[-1]]
    categories = sorted({c for node in chain for c in order[node].sensitive})
    weak = sum(bool(s["weaknesses"]) for s in steps)
    hidden = any(s["classification"] in ("shadow", "zombie") for s in steps)
    score = round(40 * impact_of(sorted(goal.sensitive))
                  + (30 if attacker == ANONYMOUS else 25)
                  + min(15, 8 * weak) + (12 if hidden else 4) - 2 * max(0, len(steps) - 3))
    score = max(0, min(100, score))
    actor = "An unauthenticated attacker" if attacker == ANONYMOUS else f"The normal user '{attacker}'"
    sentences = []
    for step in steps:
        used = ", ".join(f"{u['field']} from step {u['from_step']}" for u in step["uses"])
        text = f"Step {step['number']}: call {step['endpoint']}"
        if used:
            text += f" using {used}"
        if step["weaknesses"]:
            names = ", ".join(WEAKNESS_NAMES.get(w, w) for w in step["weaknesses"])
            text += f" (weakness: {names})"
        sentences.append(text + ".")
    data = ", ".join(sorted(goal.sensitive)) or "protected"
    narrative = f"{actor} can reach {data} data belonging to '{victim}'. " + " ".join(sentences)
    start = steps[0]["endpoint"].split(" ", 1)[1]
    end = goal.endpoint.split(" ", 1)[1]
    title = f"{len(steps)}-step path to {data} data: {start} to {end}"
    return AttackPath(title, attacker, victim, steps, categories, score, severity(score), narrative)
