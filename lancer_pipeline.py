from tp_starter import run_pipeline

K = {"zigbee_prise_5", "zigbee-switch-inwall-4", "zigbee-alarm-1",
     "zigbee-pir-1", "node_002", "node_003"}

r = run_pipeline("data/zigbee_large_sample.log", "data/zwave_large_sample.log",
                 delta=1.0, known_devices=K)
for k, v in r.items():
    print(f"{k}: {v}")
