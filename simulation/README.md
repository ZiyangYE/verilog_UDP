# Verilator RMII TAP Simulation

**Warning:** This simulation environment is intended for functional validation. It is not cycle-accurate to the target board clocking and PHY behavior.

## Features

- Verilator-based simulation for the original `udp_18k/src/udp.sv`
- RMII <-> Linux TAP bridge for host-side network interaction
- Comprehensive ARP/ICMP/UDP regression script with core and wire-level checks
- Uses `force` in simulation top to bypass PHY readiness sequencing

## Files

- `sim_top.sv`: simulation top wrapper instantiating original `udp`
- `sim_main.cpp`: C++ testbench (TAP bridge + RMII packet injection/collection)
- `test_interact.py`: layered regression script (core checks + extended diagnostics)
- `Makefile`: build/run targets

## Build and Run

```bash
cd simulation
make
python3 test_interact.py
```

If privileged TAP operations are required, authorize once manually before running tests:

```bash
sudo -v
```

Then run regression normally from `simulation/`.

## Regression Modes

- Core checks: ARP resolution, ICMP basic ping, UDP basic roundtrip
- Extended checks: ICMP wire-level verification, UDP matrix test, UDP wire header verification, negative behavior check, UDP stress test

Default mode is strict (`SIM_STRICT=1`), which means extended check failures cause non-zero exit.

Useful environment variables:

- `SIM_STRICT` (`1` or `0`)
- `SIM_UDP_MATRIX` (e.g. `2,4,8,16,32,64,128`)
- `SIM_UDP_STRESS` (e.g. `40`)

## Network Defaults

- DUT IP: `192.168.15.14`
- Host TAP IP: `192.168.15.1/24`
- DUT UDP port: `11451`
- Behavior: UDP payload is sent back to source IP and source port + 1

## Interface and Compatibility

- RMII only (100M path)
- Simulation is Linux-oriented due to TAP usage
- SystemVerilog + Verilator flow

## Notes

- PHY SMI handling is bypassed for simulation startup
- This flow focuses on ARP/UDP functional testing prior to hardware deployment

## Author

LAKKA/JA_P_S

# Verilator RMII TAP 仿真

**警告：**该仿真环境用于功能验证，不等价于目标板级时钟和 PHY 行为的严格周期级仿真。

## 功能

- 基于 Verilator 的原始 `udp_18k/src/udp.sv` 仿真
- RMII 与 Linux TAP 虚拟网卡双向桥接
- 覆盖 ARP/ICMP/UDP 的分层回归脚本（核心项 + 线级扩展项）
- 在仿真顶层通过 `force` 绕过 PHY ready 初始化等待

## 文件

- `sim_top.sv`：仿真顶层封装，直接实例化原始 `udp`
- `sim_main.cpp`：C++ 测试台（TAP 桥接 + RMII 注入/采集）
- `test_interact.py`：分层回归脚本（核心门禁 + 扩展诊断）
- `Makefile`：构建/运行目标

## 构建与运行

```bash
cd simulation
make
python3 test_interact.py
```

非 root 用户下，`test_interact.py` 会先执行一次 `sudo -v`，随后复用 sudo ticket 启动仿真。

## 回归模式

- 核心项：ARP 解析、ICMP 基础连通、UDP 基础回环
- 扩展项：ICMP 线级校验、UDP 矩阵测试、UDP 线级头检查、负向行为检查、UDP 压力测试

默认 strict 模式为 `SIM_STRICT=1`，扩展项失败会返回非零。

可选参数：

- `SIM_STRICT`（`1` 或 `0`）
- `SIM_UDP_MATRIX`（如 `2,4,8,16,32,64,128`）
- `SIM_UDP_STRESS`（如 `40`）

## 默认网络参数

- DUT IP：`192.168.15.14`
- 主机 TAP IP：`192.168.15.1/24`
- DUT UDP 端口：`11451`
- 行为：UDP 负载回发到源 IP、源端口 + 1

## 接口与兼容性

- 仅 RMII（100M 路径）
- 由于使用 TAP，仿真流程面向 Linux
- SystemVerilog + Verilator 流程

## 说明

- 仿真启动阶段绕过了 PHY SMI 初始化流程
- 该流程主要用于上板前的 ARP/UDP 功能验证

## 作者

LAKKA/JA_P_S

# Verilator RMII TAP シミュレーション

**警告:** このシミュレーション環境は機能検証向けです。ターゲット基板のクロック/PHY 動作に対する厳密なサイクル一致は保証しません。

## 機能

- 元の `udp_18k/src/udp.sv` を Verilator でシミュレーション
- RMII と Linux TAP 仮想 NIC の双方向ブリッジ
- ARP/ICMP/UDP を対象としたレイヤ型回帰スクリプト（コア + 拡張）
- シミュレーショントップで `force` を使って PHY ready 待機をバイパス

## ファイル

- `sim_top.sv`: 元の `udp` を直接インスタンスするトップラッパ
- `sim_main.cpp`: C++ テストベンチ（TAP ブリッジ + RMII 注入/回収）
- `test_interact.py`: レイヤ型回帰スクリプト（コア判定 + 拡張診断）
- `Makefile`: ビルド/実行ターゲット

## ビルドと実行

```bash
cd simulation
make
python3 test_interact.py
```

非 root ユーザーの場合、`test_interact.py` は最初に `sudo -v` を実行し、その後 sudo チケットを再利用してシミュレータを起動します。

## 回帰モード

- コア項目: ARP 解決、ICMP 基本疎通、UDP 基本ラウンドトリップ
- 拡張項目: ICMP ワイヤ検証、UDP 行列テスト、UDP ヘッダ検証、負系挙動検証、UDP ストレステスト

既定の strict モードは `SIM_STRICT=1` で、拡張項目失敗時は非ゼロ終了になります。

主な環境変数:

- `SIM_STRICT`（`1` または `0`）
- `SIM_UDP_MATRIX`（例: `2,4,8,16,32,64,128`）
- `SIM_UDP_STRESS`（例: `40`）

## 既定ネットワーク設定

- DUT IP: `192.168.15.14`
- ホスト TAP IP: `192.168.15.1/24`
- DUT UDP ポート: `11451`
- 動作: UDP ペイロードを送信元 IP・送信元ポート + 1 に返送

## インターフェースと互換性

- RMII のみ（100M パス）
- TAP 利用のため Linux 向け
- SystemVerilog + Verilator フロー

## 補足

- シミュレーション起動時は PHY SMI 初期化をバイパス
- 本フローは実機投入前の ARP/UDP 機能検証を目的とする

## 作者

LAKKA/JA_P_S
