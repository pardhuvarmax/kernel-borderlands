# output

Generated datasets from `../collect.py` -> `../label.py` -> `../split.py`: `labeled.csv`, `train.csv`, `val.csv`, `test.csv`. This is the **legacy offline table** (ADFA-LD-derived) the shipped PPO checkpoints were trained on; its engineered `event_type` is label-derived, so results on it are not evidence of live performance. The sensor-derived corpus is in [`../../../datasets/attack-lab/`](../../../datasets/attack-lab/).
