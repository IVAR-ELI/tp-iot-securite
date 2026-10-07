import tracemalloc
from tp_starter import streaming_parse_ha

PATH = "data/ha_large_sample.txt"

# 1) streaming : un objet a la fois
tracemalloc.start()
for obj in streaming_parse_ha(PATH):
    pass
_, peak_stream = tracemalloc.get_traced_memory()
tracemalloc.stop()

# 2) tout charger : tous les objets gardes en memoire
tracemalloc.start()
tout = list(streaming_parse_ha(PATH))
_, peak_all = tracemalloc.get_traced_memory()
tracemalloc.stop()

print(f"Pic en streaming    : {peak_stream:,} octets")
print(f"Pic en tout charger : {peak_all:,} octets")
print(f"Gain streaming      : {peak_all / peak_stream:.0f}x")
