# Baseband-guard

**`简体中文`** | [English](README-en.md)<br>

一个面向 Android 内核的轻量级 **LSM模块（Linux Security Module）**，用于从内核层面阻止对关键分区/设备节点的非法写入，降低基带、引导链等关键组件被恶意/误操作篡改的风险

[![Channel](https://img.shields.io/badge/Follow-Telegram-blue.svg?logo=telegram)](https://t.me/Baseband_guard)
[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-orange.svg?logo=gnu)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)

---

## 目录

- [背景与目标](#背景与目标)
- [主要特性](#主要特性)
- [工作原理（简要）](#工作原理简要)
- [环境要求](#环境要求)
- [快速开始](#快速开始)
- [许可证](#许可证)

---

## 背景与目标

**基带与引导链** 属于高价值目标。一旦被写入恶意数据或被非预期工具覆盖，可能导致不可逆的**软砖/硬砖**，甚至引发**通信安全风险**。  
**Baseband-guard** 通过内核 LSM 钩子在**写路径**进行拦截，对高风险目标设备节点/分区进行保护，辅助开发者/系统构建者实现**最小可用、默认拒绝**的安全策略。

---

## 主要特性

- **内核态拦截**：通过 LSM 在内核层面拦截对受保护目标的写入尝试，避免用户态绕过。  
- **轻量易集成**：提供 `Kconfig`、`Makefile` 与 `setup.sh`，便于集成到 Android 内核树中构建。  
- **可维护性**：通过 `kernel_compat.h` 做兼容性拆分，降低不同内核版本适配负担。  
- **可配置**：受保护目标列表与匹配策略可在源码中维护（详见 `baseband_guard.c`，请依据你的产品需求调整）。

---

## 工作原理（简要）

Baseband-guard 作为 **LSM** 模块在关键文件写入路径安装钩子（例如对块设备节点、by-name 分区设备等），当检测到命中保护规则的**写**操作时进行拒绝，并在内核日志中记录事件，支持问题**可追溯**与**快速定位**。

> 该设计依赖 Linux LSM 框架与 Android 常见的分区/设备访问路径；具体实现细节见 `baseband_guard.c`。

---

## 环境要求

- Android 内核源码树（AOSP/common 或厂商内核树）  
- 可用的交叉编译工具链（与目标内核版本匹配）  
- 具备启用自定义 `Kconfig` 项与重新编译内核/boot 镜像的权限

---

## 快速开始

1. **运行脚本**：只需在内核源码目录下运行以下指令：
   ```bash
   wget -O- https://github.com/vc-teahouse/Baseband-guard/raw/main/setup.sh | bash
   ```

2. **启用内核配置**：在 `menuconfig` / `defconfig` 中开启：
   ```text
   CONFIG_BBG=y
   ```
   **CONFIG_LSM 特别说明**
   - 如果你正在使用本地编译，请参阅setup.sh执行后的输出手动修改您的defconfig(Note: 请确保`gawk`已安装至你的系统环境)
   - 如果你正在使用Github Action云编译，可在构建脚本中添加
     ```bash
     sed -i '/^config LSM$/,/^help$/{ /^[[:space:]]*default/ { /baseband_guard/! s/lockdown/lockdown,baseband_guard/ } }' security/Kconfig
     ```     
     **警告** 此方法会导致执行setup.sh --cleanup时出现LSM Kconfig配置中default全部被删除的问题，故只推荐用于自动化脚本编译

3. **编译与打包**：按你的项目流程重新构建内核与 `boot/vendor_boot` 镜像，并刷入测试设备。

4. **验证**：在受保护目标上模拟写入，确认被拒绝并产生日志。

## 贡献指南

- 提交前请说明测试平台与修改内容。  
- 遵守内核风格（函数命名、日志等级、错误路径处理）。  
- 若涉及兼容性宏，请更新 `kernel_compat.h`。

---

## 许可证

本项目采用 **GPL-2.0** 许可证，详见 `LICENSE`。

---


### 本项目仓库地址

- GitHub: [vc-teahouse/Baseband-guard](https://github.com/vc-teahouse/Baseband-guard)
