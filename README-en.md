# Baseband-guard

**[简体中文](README.md)** | English<br>

A lightweight **LSM (Linux Security Module)** for the Android kernel, designed to block unauthorized writes to critical partitions/device nodes at the system level. This reduces the risk of malicious or accidental tampering with critical components such as the baseband and boot chain. The project is currently in **WIP** (Work in Progress) status.

[![Channel](https://img.shields.io/badge/Follow-Telegram-blue.svg?logo=telegram)](https://t.me/Baseband_guard)
[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-orange.svg?logo=gnu)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)

---

## Table of Contents

- [Background & Goals](#background--goals)
- [Key Features](#key-features)
- [How It Works (Brief)](#how-it-works-brief)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [Contribution Guidelines](#contribution-guidelines)
- [License](#license)

---

## Background & Goals

On mobile devices, the **baseband and boot chain** are high-value targets. Once overwritten by malicious data or unintended tools, they may cause irreversible **soft-brick/hard-brick** issues, or even pose **communication security risks**.  
**Baseband-guard** installs kernel-level LSM hooks in the **write path** to protect high-risk device nodes/partitions, helping developers/system builders enforce a **minimal, default-deny** security strategy.

---

## Key Features

- **Kernel-level Interception**: Blocks write attempts to protected targets at the system level via LSM hooks, preventing user-space bypass.  
- **Lightweight & Easy to Integrate**: Provides `Kconfig`, `Makefile`, and `setup.sh` for simple integration into Android kernel trees.  
- **Maintainability**: Uses `kernel_compat.h` for compatibility splitting across kernel versions.  
- **Configurable**: The list of protected targets and matching rules can be maintained in the source (see `baseband_guard.c`).  

---

## How It Works (Brief)

Baseband-guard, as an **LSM module**, installs hooks in the kernel’s file write path (e.g., block device nodes, `by-name` partition devices). When a **write** operation matches the protection rules, it is denied and logged in the kernel, supporting **traceability** and **quick troubleshooting**.

> This design relies on the Linux LSM framework and common Android partition/device access paths. See `baseband_guard.c` for implementation details.

---

## Requirements

- Android kernel source tree (AOSP/common or vendor kernel tree)  
- A cross-compilation toolchain compatible with the target kernel version  
- Permission to enable custom `Kconfig` items and rebuild kernel/boot images  

---

## Quick Start

1. **Run setup script**: Simply run the following in your kernel source directory:  
   ```bash
   wget -O- https://github.com/vc-teahouse/Baseband-guard/raw/main/setup.sh | bash
   ```

2. **Enable kernel config**: In `menuconfig` / `defconfig`, enable:  
   ```text
   CONFIG_BBG=y
   ```
   **TIPS OF CONFIG_LSM**
   - if you are using local compile, please follow setup.sh output to manually modify your defconfig(Note: make sure the `gawk` was installed into your system)
   - if you are using Github Action to compile your kernel, you can add this command to your compile workflow
     ```bash
     sed -i '/^config LSM$/,/^help$/{ /^[[:space:]]*default/ { /baseband_guard/! s/lockdown/lockdown,baseband_guard/ } }' security/Kconfig
     ```
     **WARN** This method will cause setup.sh --cleanup remove ALL LSM Kconfig defaults settings, so it only recommend for automatically build script 

3. **Build & package**: Rebuild the kernel and `boot/vendor_boot` images according to your workflow, then flash to a test device.

4. **Verify**: Simulate writes on protected targets to confirm they are denied and logged.

---

## Contribution Guidelines

- Include test platform and changes in submissions.  
- Follow kernel coding style (function naming, log levels, error handling).  
- Update `kernel_compat.h` if adding new compatibility macros.  

---

## License

This project is licensed under **GPL-2.0**. See `LICENSE` for details.  

---

### Repository

- GitHub: [vc-teahouse/Baseband-guard](https://github.com/vc-teahouse/Baseband-guard)
