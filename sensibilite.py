from tp_starter import (parse_zigbee_line, parse_zwave_line, parse_ha_line,
                        normalize_zigbee, normalize_zwave, normalize_ha,
                        deadband_filter)

events = []
for line in open("data/zigbee_sample.log"):
    p = parse_zigbee_line(line)
    if p:
        events += normalize_zigbee(p)
for line in open("data/zwave_sample.log"):
    p = parse_zwave_line(line)
    if p:
        events += normalize_zwave(p)
for line in open("data/ha_sample.jsonl"):
    p = parse_ha_line(line)
    if p:
        events += normalize_ha(p)

print(f"Evenements normalises (3 petits fichiers) : {len(events)}")
print(f"{'delta':>6} | {'restants':>8} | {'% filtre':>8}")
for delta in (0.5, 1.0, 2.0, 5.0):
    kept = deadband_filter(events, delta)
    pct = 100 * (1 - len(kept) / len(events))
    print(f"{delta:>6} | {len(kept):>8} | {pct:>7.1f}%")
