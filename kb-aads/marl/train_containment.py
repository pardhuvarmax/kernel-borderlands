#!/usr/bin/env python3
"""
Phase 2 (scoped) — RLlib PPO training loop for the Containment agent.

Meant to run on Colab/Jupyter (no local GPU on the dev machine, per project
decision — RL on this small tabular env is CPU-fine either way, per
marl/README.md's GPU section, but training runs on Colab as requested).
kb-aads/marl/train_containment.ipynb wraps this same logic with upload/
download cells for Colab; this .py file is the reproducible, checked-in
script the roadmap's Phase 2 acceptance criteria asks for.

Usage (Colab or local):
    python train_containment.py --data-dir /path/to/scripts/dataset/output
"""
import argparse
import os

import numpy as np
import pandas as pd
import ray
from ray.rllib.algorithms.ppo import PPOConfig

from env import ContainmentEnv

LEVEL_NAMES = ["NONE", "CGROUP", "SECCOMP", "NAMESPACE", "TERMINATE"]


def build_config(train_csv: str):
    return (
        PPOConfig()
        .environment(ContainmentEnv, env_config={"csv_path": train_csv})
        .framework("torch")
        .env_runners(num_env_runners=1)
        .training(lr=5e-4, train_batch_size=2000, minibatch_size=256, num_epochs=10)
    )


def evaluate(algo, csv_path: str, n_samples: int = 2000):
    """Offline accuracy/confusion check against a held-out split."""
    df = pd.read_csv(csv_path)
    if len(df) > n_samples:
        df = df.sample(n_samples, random_state=0)

    correct = 0
    per_class_total = {name: 0 for name in LEVEL_NAMES}
    per_class_correct = {name: 0 for name in LEVEL_NAMES}
    under_contain = 0

    module = algo.get_module()
    import torch

    for _, row in df.iterrows():
        obs = np.array([row["score"], row["zone"], row["uid_is_root"],
                         row["score_delta"], row["event_type"]], dtype=np.float32)
        target = int(row["target_containment"])

        with torch.no_grad():
            out = module.forward_inference({"obs": torch.from_numpy(obs).unsqueeze(0)})
            logits = out["action_dist_inputs"]
            action = int(torch.argmax(logits, dim=-1).item())

        per_class_total[LEVEL_NAMES[target]] += 1
        if action == target:
            correct += 1
            per_class_correct[LEVEL_NAMES[target]] += 1
        elif action < target:
            under_contain += 1

    n = len(df)
    print(f"[eval] overall accuracy: {correct}/{n} ({100 * correct / n:.1f}%)")
    print(f"[eval] under-containment rate: {under_contain}/{n} ({100 * under_contain / n:.1f}%)")
    for name in LEVEL_NAMES:
        total = per_class_total[name]
        if total:
            acc = 100 * per_class_correct[name] / total
            print(f"[eval]   {name:10s}: {per_class_correct[name]}/{total} ({acc:.1f}%)")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--data-dir",
        default=os.path.join(os.path.dirname(__file__), "..", "..", "scripts", "dataset", "output"),
    )
    parser.add_argument("--iterations", type=int, default=40)
    parser.add_argument(
        "--checkpoint-dir",
        default=os.path.join(os.path.dirname(__file__), "checkpoints", "containment_ppo"),
    )
    args = parser.parse_args()

    train_csv = os.path.join(args.data_dir, "train.csv")
    val_csv = os.path.join(args.data_dir, "val.csv")
    test_csv = os.path.join(args.data_dir, "test.csv")

    ray.init(ignore_reinit_error=True)
    config = build_config(train_csv)
    algo = config.build()

    print("[train] baseline (untrained) policy on val set:")
    evaluate(algo, val_csv)

    for i in range(args.iterations):
        result = algo.train()
        if (i + 1) % 5 == 0 or i == 0:
            reward = result.get("env_runners", {}).get("episode_return_mean", float("nan"))
            print(f"[train] iter {i + 1}/{args.iterations}  episode_return_mean={reward:.3f}")

    print("[train] trained policy on val set:")
    evaluate(algo, val_csv)

    os.makedirs(os.path.dirname(args.checkpoint_dir), exist_ok=True)
    algo.save(args.checkpoint_dir)
    print(f"[train] checkpoint saved to {args.checkpoint_dir}")

    print("[train] final held-out test set evaluation:")
    evaluate(algo, test_csv)

    ray.shutdown()


if __name__ == "__main__":
    main()
