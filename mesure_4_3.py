import tracemalloc
import os
from tp_starter import streaming_parse_ha

PATH = "data/ha_large_sample.txt"

tracemalloc.start()
for obj in streaming_parse_ha(PATH):
    pass
current, peak = tracemalloc.get_traced_memory()
tracemalloc.stop()

file_size = os.path.getsize(PATH)
print(f"Taille du fichier : {file_size:,} octets")
print(f"Pic memoire trace : {peak:,} octets")
print(f"Ratio : {file_size / peak:.0f}x")
