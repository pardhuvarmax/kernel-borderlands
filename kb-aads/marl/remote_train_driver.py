"""
Driver script for running Containment's RL training on a remote `colab` CLI
session (see kb-aads/marl/COLAB_CLI_TRAINING.md). Not meant to be run
locally — assumes env.py and train_containment.py have already been
uploaded to /content on the remote VM, and train/val/test CSVs are at
/content/data/.

Reuses build_config()/evaluate() from train_containment.py rather than
duplicating training logic, so there's one source of truth for how
Containment's policy is actually trained.
"""
import os
import shutil
import sys

sys.path.insert(0, "/content")
os.chdir("/content")

import ray
from train_containment import build_config, evaluate

DATA_DIR = "/content/data"
train_csv = os.path.join(DATA_DIR, "train.csv")
val_csv = os.path.join(DATA_DIR, "val.csv")
test_csv = os.path.join(DATA_DIR, "test.csv")

ray.init(ignore_reinit_error=True)
config = build_config(train_csv)
algo = config.build()

print("[train] baseline (untrained) policy on val set:")
evaluate(algo, val_csv)

ITERATIONS = 60
for i in range(ITERATIONS):
    result = algo.train()
    if (i + 1) % 5 == 0 or i == 0:
        r = result.get("env_runners", {}).get("episode_return_mean", float("nan"))
        print(f"[train] iter {i + 1}/{ITERATIONS}  episode_return_mean={r:.3f}")

print("[train] trained policy on val set:")
evaluate(algo, val_csv)

CKPT_DIR = "/content/containment_ppo"
algo.save(CKPT_DIR)
print(f"[train] checkpoint saved to {CKPT_DIR}")

print("[train] held-out test set evaluation:")
evaluate(algo, test_csv)

shutil.make_archive("/content/containment_ppo_checkpoint", "zip", CKPT_DIR)
print("READY: /content/containment_ppo_checkpoint.zip")
