import base64
import hashlib
from tp_starter import shannon_entropy as H

SEUIL = 4.5

exemples = {
    "adresse MAC / IEEE (hex)": "0x70b3d52b60047743",
    "UUID": "123e4567-e89b-12d3-a456-426614174000",
    "hash firmware SHA-256 en hexa": hashlib.sha256(b"firmware-v2.1").hexdigest(),
    "hash firmware SHA-256 en base64": base64.b64encode(
        hashlib.sha256(b"firmware-v2.1").digest()).decode(),
    "blob exfiltre (base64, 9.2)": "aGVsbG8tdGhpcy1pcy1hLWhpZGRlbi1jaGFubmVsLXBheWxvYWQ=",
    "meme message encode en hexa": b"hello-this-is-a-hidden-channel-payload".hex(),
}

print(f"{'champ':34s} {'longueur':>8s} {'entropie':>9s}  > {SEUIL} ?")
for nom, valeur in exemples.items():
    h = H(valeur)
    print(f"{nom:34s} {len(valeur):8d} {h:9.2f}  {'OUI' if h > SEUIL else 'non'}")
