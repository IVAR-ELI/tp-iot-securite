import secrets
from tp_starter import hmac_pseudonymize, dictionary_attack

vrais = ["zigbee_prise_5", "zigbee-switch-inwall-4", "zigbee-alarm-1", "zigbee-pir-1"]

# cote passerelle : le secret est genere une fois et reste local
secret = secrets.token_bytes(32)
observed = {hmac_pseudonymize("zigbee", n, secret) for n in vrais}
print("Pseudonymes envoyes au SOC :")
for n in vrais:
    print(f"  {n:24s} -> {hmac_pseudonymize('zigbee', n, secret)}")

# meme dictionnaire de 30 noms que pour l'exercice 8.2
dico = (
    [f"zigbee_prise_{i}" for i in range(1, 11)]
    + [f"zigbee-switch-inwall-{i}" for i in range(1, 7)]
    + [f"zigbee-alarm-{i}" for i in range(1, 5)]
    + [f"zigbee-pir-{i}" for i in range(1, 5)]
    + ["zigbee-contact-1", "zigbee-contact-2", "zigbee-bulb-1",
       "zigbee-bulb-2", "zigbee-temp-1", "zigbee-temp-2"]
)

# attaquant SANS le secret (il essaie avec un secret vide)
sans = dictionary_attack(observed, dico, lambda n: hmac_pseudonymize("zigbee", n, b""))
print(f"\nAttaquant sans le secret : {len(sans)} / {len(vrais)} retrouves")

# controle : si l'attaquant avait le secret, tout serait casse
avec = dictionary_attack(observed, dico, lambda n: hmac_pseudonymize("zigbee", n, secret))
print(f"Attaquant avec le secret : {len(avec)} / {len(vrais)} retrouves (controle)")
