from tp_starter import parse_zigbee_line, parse_zwave_line, parse_ha_line

with open("data/zigbee_sample.log") as f:
    results = [parse_zigbee_line(l) for l in f]
print("Zigbee:", sum(r is not None for r in results), "/", len(results), "(10 attendus)")

with open("data/zwave_sample.log") as f:
    results = [parse_zwave_line(l) for l in f]
print("Z-Wave:", sum(r is not None for r in results), "/", len(results), "(9 attendus)")

with open("data/ha_sample.jsonl") as f:
    results = [parse_ha_line(l) for l in f]
print("HA:", sum(r is not None for r in results), "/", len(results), "(14 attendus)")
