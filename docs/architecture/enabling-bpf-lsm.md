# Guide: Enabling BPF LSM on Linux

This guide describes how to configure the Linux Security Module (LSM) boot parameters to enable the BPF LSM (`bpf_lsm`) framework, enabling authoritative in-kernel policy block verdicts.

---

## 1. Check Kernel Compile Options
Before attempting configuration, ensure your Linux kernel was built with BPF LSM support enabled. Run:
```bash
grep CONFIG_BPF_LSM /boot/config-$(uname -r)
```
You should see:
```text
CONFIG_BPF_LSM=y
```
*(If it is not set to `y`, you must upgrade or compile a kernel with this option active).*

---

## 2. Inspect Active LSM List
To see which security modules are currently active in the kernel, run:
```bash
cat /sys/kernel/security/lsm
```
*   **Disabled State**: `lockdown,capability,landlock,yama,apparmor`
*   **Enabled State**: `lockdown,capability,landlock,yama,apparmor,bpf`

If `bpf` is not listed, proceed with the bootloader configuration below.

---

## 3. Modify Boot Parameters (Grub)

1.  Open the Grub configuration file as `root`:
    ```bash
    sudo nano /etc/default/grub
    ```
2.  Locate the line beginning with `GRUB_CMDLINE_LINUX_DEFAULT` (usually contains `"quiet splash"`).
3.  Append the `lsm` boot parameter to the options:
    ```text
    GRUB_CMDLINE_LINUX_DEFAULT="quiet splash lsm=landlock,lockdown,yama,apparmor,bpf"
    ```
4.  Save and exit (`Ctrl+O`, `Enter`, `Ctrl+X`).

---

## 4. Regenerate Grub Configuration & Reboot
Update the system bootloader configuration to apply the command line changes:
```bash
sudo update-grub
```
Once the update completes, reboot the host:
```bash
sudo reboot
```

---

## 5. Verify Activation
After the system restarts, verify that `bpf` is listed among the active security modules:
```bash
cat /sys/kernel/security/lsm
```
You should now see `bpf` at the end of the output list.

---

## 6. The LSM Hook in Kernel Borderlands

**Correction, 2026-08-30**: this section previously described `kb_lsm_file_open` as "pre-staged" with autoload set to `false`, requiring a manual code edit to activate. That's no longer true — `kb-core/userspace/sensor/kbd_sensor.c`'s `main()` already sets all three of these to `true` unconditionally:
```c
bpf_program__set_autoload(skel->progs.kb_ssl_write, true);
bpf_program__set_autoload(skel->progs.kb_go_tls_write, true);
bpf_program__set_autoload(skel->progs.kb_lsm_file_open, true);
```
No manual activation step is needed — as long as the host supports and has enabled BPF LSM (§1–§5 above), `sudo ./build/kbd_sensor` loads `kb_lsm_file_open` into the kernel automatically, enabling Ring 0 file access blocks. If BPF LSM isn't enabled on the host, the LSM program simply fails to attach at startup (check `kbd_sensor`'s startup log) rather than silently doing nothing — §1–§5 above is what fixes that.
