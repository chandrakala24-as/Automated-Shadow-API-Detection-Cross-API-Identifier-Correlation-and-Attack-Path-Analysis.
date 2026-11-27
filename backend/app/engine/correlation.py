"""Cross-API identifier correlation: which API produces a value another API consumes."""
from __future__ import annotations

from .identifiers import specificity
from .models import ANONYMOUS, INVALID, Endpoint, Link, Observation

THRESHOLD = 0.5


def correlate(endpoints: list[Endpoint], observations: list[Observation]) -> list[Link]:
    produced: dict[str, list[tuple[str, str, str, str]]] = {}  # value -> producer details
    for obs in observations:
        if obs.has_data and obs.identity not in (INVALID,):
            for ref in obs.ids:
                # A response that merely echoes its own input did not "produce" the value.
                if ref.value in obs.values.values():
                    continue
                produced.setdefault(ref.value, []).append(
                    (obs.endpoint, ref.entity, ref.field_name, obs.identity))

    accepted: dict[tuple[str, str], list[Observation]] = {}
    for obs in observations:
        if obs.has_data and obs.identity not in (ANONYMOUS, INVALID):
            for name, value in obs.values.items():
                accepted.setdefault((obs.endpoint, name), []).append(obs)

    best: dict[tuple, Link] = {}
    for consumer in endpoints:
        for item in consumer.inputs:
            uses = accepted.get((consumer.label, item.name), [])
            seen_in_traffic = consumer.samples.get(item.name, set())
            tried = {o.values[item.name] for o in uses} | seen_in_traffic
            for value in sorted(tried):
                for producer, entity, field_name, _ in produced.get(value, []):
                    if producer == consumer.label:
                        continue
                    score, reasons = 0.0, []
                    if entity == item.entity:
                        score += 0.40
                        reasons.append(f"Names agree: '{field_name}' and '{item.name}' "
                                       f"both refer to '{entity}'")
                    if value in seen_in_traffic:
                        score += 0.20 * specificity(value)
                        reasons.append("The same value appears in imported traffic or client code")
                    matching = [o for o in uses if o.values[item.name] == value]
                    if matching:
                        # Small integers collide by chance, so they earn less credit.
                        score += 0.25 + 0.10 * specificity(value)
                        reasons.append("Verified: the consumer accepted the produced value "
                                       "and returned data")
                        if any(r.value == value and r.entity == item.entity
                               for o in matching for r in o.ids):
                            score += 0.10
                            reasons.append("The consumer's response refers back to the same object")
                        score += 0.10 * specificity(value)
                    score = round(min(score, 0.99), 2)
                    if score < THRESHOLD or (entity != item.entity and not matching):
                        continue
                    key = (producer, consumer.label, field_name, item.name)
                    if key not in best or score > best[key].confidence:
                        best[key] = Link(producer, consumer.label, item.entity, field_name,
                                         item.name, score, reasons, value)
    return sorted(best.values(), key=lambda l: (-l.confidence, l.producer, l.consumer))
