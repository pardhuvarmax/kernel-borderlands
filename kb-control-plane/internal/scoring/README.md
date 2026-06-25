# Behavioral Scoring Engine (BSE)

Computes per-process risk scores using weighted composite dimensions.

## Dimensions (Table 4.2 from KB document)
| Dimension        | Weight |
|------------------|--------|
| Syscall Entropy  | 25%    |
| Privilege Delta  | 20%    |
| Lineage Anomaly  | 20%    |
| Memory Behavior  | 15%    |
| Network Behavior | 10%    |
| File Access      | 10%    |

## EMA Smoothing
S_t = α * s_t + (1 - α) * S_{t-1}
Default α = 0.3
