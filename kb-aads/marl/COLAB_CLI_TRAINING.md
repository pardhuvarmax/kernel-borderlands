# Training Containment's RL policy via `colab` CLI

Step-by-step commands to run on your own machine (in `kernel-borderlands/`,
this repo's root) now that `colab sessions` has authenticated successfully.
This provisions a real Colab VM, installs deps, uploads the dataset +
training code, runs the actual PPO training there, and pulls the trained
checkpoint back — no manual notebook upload needed.

Run every command below from the repo root (`kernel-borderlands/`).

## 1. Provision a session

```bash
colab new -s kb-containment
```

CPU-only (no `--gpu`/`--tpu` flag) — this env is small tabular data, doesn't
need acceleration, and most account tiers don't get GPU quota anyway.

## 2. Install dependencies on the VM

```bash
colab install -s kb-containment "ray[rllib]>=2.9.0" gymnasium torch pandas
```

## 3. Upload the training code and dataset

```bash
colab upload -s kb-containment kb-aads/marl/env.py /content/env.py
colab upload -s kb-containment kb-aads/marl/train_containment.py /content/train_containment.py

echo "import os; os.makedirs('/content/data', exist_ok=True)" | colab exec -s kb-containment

colab upload -s kb-containment scripts/dataset/output/train.csv /content/data/train.csv
colab upload -s kb-containment scripts/dataset/output/val.csv /content/data/val.csv
colab upload -s kb-containment scripts/dataset/output/test.csv /content/data/test.csv
```

## 4. Run training

```bash
colab exec -s kb-containment -f kb-aads/marl/remote_train_driver.py --timeout 1800
```

`remote_train_driver.py` reuses `train_containment.py`'s `build_config()`/
`evaluate()` (uploaded in step 3) so there's one source of truth for the
training logic — it just points paths at `/content` instead of the repo's
local layout. Expect to see baseline (untrained) accuracy on the val set,
then rising accuracy every 5 iterations, then a final held-out test-set
report. `--timeout 1800` gives it 30 minutes of headroom — 60 PPO
iterations on this small env should finish well under that on CPU.

If it times out or you want more iterations, edit `ITERATIONS` in
`kb-aads/marl/remote_train_driver.py` before re-running step 4 (no need to
redo steps 1-3 — the session and uploaded files persist).

## 5. Pull the checkpoint back

```bash
colab download -s kb-containment /content/containment_ppo_checkpoint.zip scripts/zips/containment_ppo_checkpoint.zip

mkdir -p kb-aads/marl/checkpoints
unzip -o scripts/zips/containment_ppo_checkpoint.zip -d kb-aads/marl/checkpoints/containment_ppo
```

## 6. Stop the session (don't skip — idle VMs burn compute units)

```bash
colab stop -s kb-containment
```

## 7. Verify it's wired up

```bash
cd kb-aads
source venv/bin/activate
python3 -c "
import ray
ray.init(ignore_reinit_error=True)
from agents.containment import ContainmentAgent

agent = ContainmentAgent.remote('containment-verify')
ray.get(agent.receive_message.remote({
    'type': 'CONTAIN', 'pid': 4242,
    'obs': {'score': 90.0, 'zone': 2, 'uid_is_root': 1, 'score_delta': 60.0, 'event_type': 3},
}))
ray.get(agent.process_messages.remote())
print(ray.get(agent.get_status.remote()))
ray.shutdown()
"
```

You should see `last_action` reference the containment level the trained
policy chose (not `no model loaded`). If it still says `model_loaded:
False`, double check `kb-aads/marl/checkpoints/containment_ppo/` actually
has a `learner_group/learner/rl_module/default_policy/` subdirectory after
step 5's unzip.
