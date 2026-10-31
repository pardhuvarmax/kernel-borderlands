# detection

`exfil.go`: the slow-exfiltration / beaconing detector (Shannon-entropy timing analysis plus CUSUM volume-shift), run on the control plane so the sensor pays no CPU for it. Design: [`../../../docs/development/control-aads/dev-exfiltration-detection.md`](../../../docs/development/control-aads/dev-exfiltration-detection.md). Tests: `exfil_test.go`.
