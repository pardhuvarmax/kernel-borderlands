#!/usr/bin/env python3
"""
Phase 0 (scoped) — stratified train/val/test split of labeled.csv.

Stratifies by `category` (not a plain shuffle-split) because two classes
(r2l, u2r) are heavily underrepresented in NSL-KDD — a non-stratified split
risks a test set with zero u2r rows, which would make TERMINATE-decision
accuracy unmeasurable.
"""
import csv
import os
import random

INPUT_PATH = os.path.join(os.path.dirname(__file__), "output", "labeled.csv")
OUT_DIR = os.path.join(os.path.dirname(__file__), "output")

TRAIN_FRAC = 0.7
VAL_FRAC = 0.15
# remainder (0.15) goes to test


def main(seed: int = 42):
    random.seed(seed)
    by_category = {}
    with open(INPUT_PATH) as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames
        for row in reader:
            by_category.setdefault(row["category"], []).append(row)

    train, val, test = [], [], []
    for cat, rows in by_category.items():
        random.shuffle(rows)
        n = len(rows)
        n_train = int(n * TRAIN_FRAC)
        n_val = int(n * VAL_FRAC)
        train += rows[:n_train]
        val += rows[n_train:n_train + n_val]
        test += rows[n_train + n_val:]

    random.shuffle(train)
    random.shuffle(val)
    random.shuffle(test)

    for name, rows in [("train", train), ("val", val), ("test", test)]:
        path = os.path.join(OUT_DIR, f"{name}.csv")
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        print(f"[split] {name}: {len(rows)} rows -> {path}")


if __name__ == "__main__":
    main()
