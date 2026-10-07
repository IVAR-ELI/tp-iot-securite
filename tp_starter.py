"""
TP Sécurité IoT (version longue, ~10-13h) — Squelette de démarrage
====================================================================
Complétez les fonctions marquées TODO, dans l'ordre du document
TP_securite_iot.md. Chaque section du fichier correspond à une partie
de l'énoncé.
"""

import json
import re
import math
import hashlib
import hmac as hmac_lib
from collections import defaultdict, Counter


# ============================================================
# PARTIE 2 — PARSERS PROTOCOLAIRES
# ============================================================
ZIGBEE_LINE_RE = re.compile(r"topic '([^']+)',\s*payload '(\{.*\})'")
def parse_zigbee_line(line: str) -> dict | None:
    m = ZIGBEE_LINE_RE.search(line)
    if not m:
        return None
    topic, payload_raw = m.groups()
    device = topic.split("/", 1)[1] if "/" in topic else topic
    try:
        payload = json.loads(payload_raw)
    except json.JSONDecodeError:
        return None
    return {"device": device, "payload": payload}


ZWAVE_VALUE_RE = re.compile(
    r"\[Node (\d+)\] Value updated: (\d+)-(\d+)-(.+?) (-?[\d.]+) => (-?[\d.]+)"
)
def parse_zwave_line(line: str) -> dict | None:
    m = ZWAVE_VALUE_RE.search(line)
    if not m:
        return None
    node, command_class, endpoint, field, old_value, new_value = m.groups()
    return {
        "device_id": f"node_{int(node):03d}",
        "command_class": int(command_class),
        "endpoint": int(endpoint),
        "field": field,
        "old_value": float(old_value),
        "new_value": float(new_value),
    }


def parse_ha_line(line: str) -> dict | None:
    line = line.strip()
    if not line:
        return None
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None

    state_raw = obj.get("state")
    try:
        state_value = float(state_raw)
    except (TypeError, ValueError):
        state_value = None

    return {
        "entity_id": obj.get("entity_id"),
        "state_raw": state_raw,
        "state_value": state_value,
        "unit": obj.get("unit"),
        "friendly_name": obj.get("friendly_name"),
        "last_updated": obj.get("last_updated"),
    }


# ============================================================
# PARTIE 3 — NORMALISATION SÉMANTIQUE
# ============================================================

ZIGBEE_KNOWN_FIELDS = {
    "power": "power",
    "current": "current",
    "voltage": "voltage",
    "energy": "energy",
    "battery": "battery",
    "linkquality": "link_quality",
}

# Champs à considérer comme "safety_critical" : voir Exercice 3.4.
# Un événement marqué ainsi doit toujours passer, quel que soit le
# filtre deadband (Property 2 du papier de recherche associé).
SAFETY_CRITICAL_FIELDS = {"alarm", "tamper", "contact"}


def normalize_zigbee(parsed: dict) -> list[dict]:
    device_id = parsed["device"]
    payload = parsed["payload"]
    events = []
    handled_fields = set()

    # 3.3 : champs safety-critical, traités en premier
    for field in SAFETY_CRITICAL_FIELDS:
        if field in payload:
            events.append({
                "device_id": device_id,
                "protocol": "zigbee",
                "metric_name": field,
                "metric_value": None,
                "safety_critical": True,
                "raw": payload,
            })
            handled_fields.add(field)

    # 3.1 : cas de base
    for raw_field, metric_name in ZIGBEE_KNOWN_FIELDS.items():
        if raw_field in payload:
            events.append({
                "device_id": device_id,
                "protocol": "zigbee",
                "metric_name": metric_name,
                "metric_value": float(payload[raw_field]) if isinstance(payload[raw_field], (int, float)) else None,
                "safety_critical": False,
                "raw": payload,
            })
            handled_fields.add(raw_field)

    # 3.2 : préservation des champs inconnus
    for raw_field, value in payload.items():
        if isinstance(value, (dict, list)):
            continue  # sous-document : conserve dans "raw"
        if raw_field not in handled_fields:
            events.append({
                "device_id": device_id,
                "protocol": "zigbee",
                "metric_name": f"unknown_{raw_field}",
                "metric_value": None,
                "safety_critical": False,
                "raw": payload,
            })

    return events


HA_UNIT_TO_METRIC = {
    "W": "power", "V": "voltage", "A": "current",
    "kWh": "energy", "lx": "illuminance",
}


def normalize_zwave(parsed: dict) -> list[dict]:
    """Exercice 3.4 : un seul evenement par ligne Z-Wave."""
    metric_name = re.sub(r"[ -]", "_", parsed["field"].lower())
    return [{
        "device_id": parsed["device_id"],
        "protocol": "zwave",
        "metric_name": metric_name,
        "metric_value": parsed["new_value"],
        "safety_critical": False,
        "raw": parsed,
    }]


def normalize_ha(parsed: dict) -> list[dict]:
    """Exercice 3.4 : un seul evenement par ligne Home Assistant."""
    entity_id = parsed["entity_id"]
    metric_name = HA_UNIT_TO_METRIC.get(parsed["unit"])
    if metric_name is None:
        # unite inconnue ou absente : on preserve sous unknown_<entite>
        metric_name = "unknown_" + entity_id.split(".", 1)[-1]
    return [{
        "device_id": entity_id,
        "protocol": "ha",
        "metric_name": metric_name,
        "metric_value": parsed["state_value"],
        "safety_critical": False,
        "raw": parsed,
    }]


# ============================================================
# PARTIE 4 — PARSER STREAMING (fichiers volumineux)
# ============================================================

def naive_ha_load(path: str):
    """
    Tentative naïve : charger tout le fichier avec json.load().
    Utilisée en Partie 4 uniquement pour CONSTATER l'échec — ne modifiez
    pas cette fonction, elle est censée lever une exception sur un
    fichier HA réel (objets JSON concaténés, pas un tableau unique).
    """
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def streaming_parse_ha(path: str):
    """Exercice 4.2 : generateur, un objet JSON top-level a la fois."""
    buf = ""
    depth = 0
    with open(path, encoding="utf-8") as f:
        for line in f:
            if depth == 0 and not line.strip():
                continue  # lignes vides entre deux objets
            buf += line
            depth += line.count("{") - line.count("}")
            if depth == 0 and buf.strip():
                yield json.loads(buf)
                buf = ""


# ============================================================
# PARTIE 5 — FILTRE DEADBAND
# ============================================================

def deadband_filter(events: list[dict], delta: float) -> list[dict]:
    """Exercices 5.1 et 5.2 : deadband par (device_id, metric_name)."""
    last_sent = {}  # derniere valeur TRANSMISE pour chaque (appareil, metrique)
    kept = []
    for e in events:
        # 5.1 : un evenement critique passe toujours
        # 5.2 : un evenement sans valeur numerique (unknown_*) passe aussi,
        #       il n'y a rien a comparer et on ne jette jamais un champ inconnu
        if e["safety_critical"] or e["metric_value"] is None:
            kept.append(e)
            continue
        key = (e["device_id"], e["metric_name"])
        value = e["metric_value"]
        if key not in last_sent or abs(value - last_sent[key]) >= delta:
            kept.append(e)
            last_sent[key] = value
    return kept


# ============================================================
# PARTIE 6 — RÈGLES DE DÉTECTION DE BASE
# ============================================================

def detect_power_surge(events: list[dict], threshold_w: float = 2000) -> list[dict]:
    """Exercice 6.1 : puissance normalisee au-dessus du seuil."""
    alerts = []
    for e in events:
        value = e["metric_value"]
        if e["metric_name"] == "power" and value is not None and value > threshold_w:
            alerts.append({
                "rule": "power_surge",
                "device_id": e["device_id"],
                "metric_value": value,
                "threshold": threshold_w,
            })
    return alerts


def detect_replay(events: list[dict], window: int = 3) -> list[dict]:
    """Exercice 6.2 : `window` valeurs numeriques identiques d'affilee."""
    alerts = []
    # (device_id, metric_name) -> [derniere valeur, longueur de la serie, deja alerte]
    state = {}
    for e in events:
        value = e["metric_value"]
        if value is None:
            continue  # pas un candidat pour un rejeu de valeur numerique
        key = (e["device_id"], e["metric_name"])
        s = state.get(key)
        if s is not None and s[0] == value:
            s[1] += 1
        else:
            s = state[key] = [value, 1, False]
        if s[1] >= window and not s[2]:
            alerts.append({
                "rule": "replay",
                "device_id": e["device_id"],
                "metric_name": e["metric_name"],
                "metric_value": value,
                "repeats": window,
            })
            s[2] = True  # une seule alerte par rafale
    return alerts


def detect_rogue_device(events: list[dict], known_devices: set[str]) -> list[dict]:
    """Exercice 6.3 : une alerte par appareil absent de la baseline."""
    alerts = []
    already_alerted = set()
    for e in events:
        device = e["device_id"]
        if device not in known_devices and device not in already_alerted:
            already_alerted.add(device)
            alerts.append({"rule": "rogue_device", "device_id": device})
    return alerts


def detect_event_storm(events: list, window_events: int = 20,
                        max_per_device: int = 8) -> list[dict]:
    """
    Exercice 6.4 : un appareil qui occupe trop de place dans la fenetre
    glissante des `window_events` derniers MESSAGES (tous appareils confondus).
    `events` = liste des device_id au niveau message brut (str), ou dicts
    avec une cle "device_id". Une alerte par rafale.
    """
    from collections import deque

    alerts = []
    window = deque()
    counts = Counter()
    in_storm = set()
    for position, item in enumerate(events):
        device = item if isinstance(item, str) else item["device_id"]
        if len(window) == window_events:
            counts[window.popleft()] -= 1
        window.append(device)
        counts[device] += 1
        if counts[device] > max_per_device:
            if device not in in_storm:
                in_storm.add(device)
                alerts.append({
                    "rule": "event_storm",
                    "device_id": device,
                    "count_in_window": counts[device],
                    "position": position,
                })
        else:
            in_storm.discard(device)  # re-arme : la rafale est terminee
    return alerts


# ============================================================
# PARTIE 8 — PSEUDONYMISATION HMAC
# ============================================================

def naive_hash_device_id(name: str) -> str:
    """Exercice 8.1 : hash simple (a ne PAS utiliser en prod)."""
    return hashlib.sha256(name.encode()).hexdigest()[:20]


def hmac_pseudonymize(protocol: str, name: str, secret: bytes) -> str:
    """
    Exercice 8.3 : HMAC-SHA256(secret, "protocol:name")[:20].
    Le secret reste local a la passerelle, jamais transmis au SOC.
    """
    message = f"{protocol}:{name}".encode()
    return hmac_lib.new(secret, message, hashlib.sha256).hexdigest()[:20]


def dictionary_attack(observed_hashes: set[str], dictionary: list[str], hash_fn) -> dict:
    """
    Exercice 8.2 : attaque par dictionnaire. On precalcule hash_fn(guess)
    pour chaque nom devine, puis on cherche les hashs observes dans la table.
    Retourne {hash_observe: nom_retrouve}.
    """
    table = {hash_fn(guess): guess for guess in dictionary}
    return {h: table[h] for h in observed_hashes if h in table}


# ============================================================
# PARTIE 9 — DÉTECTION PAR ENTROPIE (canaux cachés)
# ============================================================

def shannon_entropy(s: str) -> float:
    """Exercice 9.1 : H(v) = -somme(p_c * log2(p_c)) sur les caracteres de s."""
    if not s:
        return 0.0
    n = len(s)
    return max(0.0, -sum((c / n) * math.log2(c / n) for c in Counter(s).values()))


def detect_high_entropy_unknown(events: list[dict], threshold: float = 4.5,
                                 min_length: int = 8) -> list[dict]:
    """
    Exercice 9.2 : champs inconnus (unknown_*) dont la valeur brute est une
    chaine d'au moins `min_length` caracteres et d'entropie > `threshold`.
    """
    alerts = []
    for e in events:
        name = e["metric_name"]
        if not name.startswith("unknown_") or e["metric_value"] is not None:
            continue
        field = name[len("unknown_"):]
        value = e["raw"].get(field)
        if not isinstance(value, str) or len(value) < min_length:
            continue
        entropy = shannon_entropy(value)
        if entropy > threshold:
            alerts.append({
                "rule": "high_entropy",
                "device_id": e["device_id"],
                "field": field,
                "entropy": round(entropy, 2),
                "value": value,
            })
    return alerts


# ============================================================
# PARTIE 10 — EXTENSION MITRE (A10-A15)
# ============================================================

MITRE_ARTIFACT_LABELS = {
    "unmapped_linux_cmd": "A10 Privilege Escalation",
    "unmapped_net_cmd": "A11 Reverse Shell",
    "unmapped_persist_cmd": "A12 Persistence Cron/Systemd",
    "unmapped_cred_access": "A13 Credential Access",
    "unmapped_download_cmd": "A14 Command and Control / Dropper",
    "unmapped_lateral_cmd": "A15 Lateral Movement",
}


def detect_mitre_artifact(events: list[dict]) -> list[dict]:
    """
    Exercice 10.1 : champs inconnus dont le nom commence par un prefixe
    de MITRE_ARTIFACT_LABELS (unmapped_linux_cmd, unmapped_net_cmd, ...).
    S'appuie sur la preservation des champs inconnus (Partie 3).
    """
    alerts = []
    for e in events:
        name = e["metric_name"]
        if not name.startswith("unknown_"):
            continue
        field = name[len("unknown_"):]
        for prefix, label in MITRE_ARTIFACT_LABELS.items():
            if field.startswith(prefix):
                alerts.append({
                    "rule": "mitre",
                    "technique": label,
                    "device_id": e["device_id"],
                    "field": field,
                    "value": e["raw"].get(field),
                })
                break
    return alerts


# ============================================================
# PARTIE 11 — PIPELINE COMPLET ET ÉVALUATION À GRANDE ÉCHELLE
# ============================================================

def run_pipeline(zigbee_path, zwave_path=None, delta=1.0, known_devices=None,
                  power_threshold=2000):
    """
    Exercice 11.1 : pipeline complet.
    parsing -> normalisation -> deadband -> detection (power surge, replay,
    rogue device, event storm, entropie, MITRE). Retourne un dictionnaire
    de metriques.
    """
    events = []
    message_ids = []  # un device_id par MESSAGE Zigbee brut (pour event storm)

    with open(zigbee_path, encoding="utf-8") as f:
        for line in f:
            parsed = parse_zigbee_line(line)
            if parsed:
                message_ids.append(parsed["device"])
                events += normalize_zigbee(parsed)

    if zwave_path:
        with open(zwave_path, encoding="utf-8") as f:
            for line in f:
                parsed = parse_zwave_line(line)
                if parsed:
                    events += normalize_zwave(parsed)

    filtered = deadband_filter(events, delta)
    n_raw = len(events)
    n_filtered = len(filtered)
    unknown = sum(1 for e in events if e["metric_name"].startswith("unknown_"))
    no_value = sum(1 for e in events if e["metric_value"] is None)
    devices = {e["device_id"] for e in events}

    rogue = detect_rogue_device(filtered, known_devices) if known_devices else []

    return {
        "events_raw": n_raw,
        "events_unknown": unknown,                 # nom commencant par unknown_
        "events_without_value": no_value,          # metric_value None
        "pct_without_value": round(100 * no_value / n_raw, 1) if n_raw else 0.0,
        "events_after_deadband": n_filtered,
        "reduction_pct": round(100 * (1 - n_filtered / n_raw), 1) if n_raw else 0.0,
        "distinct_devices": len(devices),
        "alerts_power_surge": len(detect_power_surge(filtered, power_threshold)),
        "alerts_replay_before_deadband": len(detect_replay(events)),
        "alerts_replay_after_deadband": len(detect_replay(filtered)),
        "alerts_rogue_device": len(rogue),
        "alerts_event_storm": len(detect_event_storm(message_ids)),
        "alerts_high_entropy": len(detect_high_entropy_unknown(filtered)),
        "alerts_mitre": len(detect_mitre_artifact(filtered)),
    }


if __name__ == "__main__":
    KNOWN_DEVICES = {
        "zigbee_prise_5", "zigbee-switch-inwall-4", "zigbee-alarm-1",
        "zigbee-pir-1", "node_002", "node_003",
    }
    # Décommentez au fur et à mesure de votre progression :
    # result = run_pipeline("data/zigbee_large_sample.log",
    #                        "data/zwave_large_sample.log",
    #                        delta=1.0, known_devices=KNOWN_DEVICES)
    # print(result)
    pass
