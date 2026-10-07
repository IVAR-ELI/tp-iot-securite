from tp_starter import naive_hash_device_id, dictionary_attack

vrais = ["zigbee_prise_5", "zigbee-switch-inwall-4", "zigbee-alarm-1", "zigbee-pir-1"]
observed = {naive_hash_device_id(n) for n in vrais}

# dictionnaire d'une trentaine de noms plausibles (conventions courantes)
dico = (
    [f"zigbee_prise_{i}" for i in range(1, 11)]
    + [f"zigbee-switch-inwall-{i}" for i in range(1, 7)]
    + [f"zigbee-alarm-{i}" for i in range(1, 5)]
    + [f"zigbee-pir-{i}" for i in range(1, 5)]
    + ["zigbee-contact-1", "zigbee-contact-2", "zigbee-bulb-1",
       "zigbee-bulb-2", "zigbee-temp-1", "zigbee-temp-2"]
)

trouves = dictionary_attack(observed, dico, naive_hash_device_id)
print(f"Dictionnaire : {len(dico)} noms devines")
print(f"Appareils retrouves : {len(trouves)} / {len(vrais)}")
for h, nom in trouves.items():
    print(f"  {h} -> {nom}")
