from tp_starter import hmac_pseudonymize

secret = b"secret-de-test"

# 1. Stabilite : meme entree, meme secret -> meme pseudonyme
a = hmac_pseudonymize("zigbee", "zigbee_prise_5", secret)
b = hmac_pseudonymize("zigbee", "zigbee_prise_5", secret)
print("1. Stabilite :", a == b, "|", a)

# 2. Separation par protocole : meme nom nettoye, protocoles differents
z = hmac_pseudonymize("zigbee", "prise_5", secret)
w = hmac_pseudonymize("zwave", "prise_5", secret)
print("2. Separation :", z != w)
print("   zigbee:prise_5 ->", z)
print("   zwave:prise_5  ->", w)

# 3. Ordre de grandeur du risque de collision (paradoxe des anniversaires)
bits = 20 * 4  # 20 caracteres hexadecimaux = 80 bits
for n in (100, 1_000, 1_000_000):
    p = n * (n - 1) / 2 / 2**bits
    print(f"3. {n:>9,} appareils : P(collision) ~ {p:.2e}")
