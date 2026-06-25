# Multi-Agent Reinforcement Learning

MARL system for agent policy learning and optimization.

## Framework
- Ray RLlib 2.x
- Gymnasium environment
- PyTorch policy networks

## Reward Signals
- True Positive:  +1.0 (correctly identified threat)
- False Positive: -0.5 (legitimate process contained)
- True Negative:  +0.1 (safe process correctly ignored)
- False Negative: -1.0 (missed threat)

## Training Pipeline
1. Collect outcomes from production decisions
2. Compute reward signals per agent
3. Update policy networks via RLlib
4. Validate new policy with kb-checker
5. Deploy to production agents

## Fine-tuned Model
Base: Phi-3 Mini / Qwen2.5 3B (QLoRA fine-tuned)
Domain: Security reasoning over behavioral event sequences
