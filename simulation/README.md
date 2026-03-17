# Verilator RMII TAP Simulation

**Warning:** This simulation environment is intended for functional validation. It is not cycle-accurate to the target board clocking and PHY behavior.

## Features

- Verilator-based simulation for the original `udp_18k/src/udp.sv`
- RMII <-> Linux TAP bridge for host-side network interaction
- UDP interaction test script with one-time sudo authorization flow
- Uses `force` in simulation top to bypass PHY readiness sequencing

## Files

- `sim_top.sv`: simulation top wrapper instantiating original `udp`
- `sim_main.cpp`: C++ testbench (TAP bridge + RMII packet injection/collection)
- `test_interact.py`: automatic interaction test script
- `Makefile`: build/run targets

## Build and Run

```bash
cd simulation
make
python3 test_interact.py
```

For non-root users, `test_interact.py` performs `sudo -v` once, then reuses the sudo ticket to start the simulator.

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
- 带一次 sudo 授权流程的 UDP 自动交互测试脚本
- 在仿真顶层通过 `force` 绕过 PHY ready 初始化等待

## 文件

- `sim_top.sv`：仿真顶层封装，直接实例化原始 `udp`
- `sim_main.cpp`：C++ 测试台（TAP 桥接 + RMII 注入/采集）
- `test_interact.py`：自动交互测试脚本
- `Makefile`：构建/运行目标

## 构建与运行

```bash
cd simulation
make
python3 test_interact.py
```

非 root 用户下，`test_interact.py` 会先执行一次 `sudo -v`，随后复用 sudo ticket 启动仿真。

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
- sudo 一回認証フロー付き UDP 自動連携テストスクリプト
- シミュレーショントップで `force` を使って PHY ready 待機をバイパス

## ファイル

- `sim_top.sv`: 元の `udp` を直接インスタンスするトップラッパ
- `sim_main.cpp`: C++ テストベンチ（TAP ブリッジ + RMII 注入/回収）
- `test_interact.py`: 自動連携テストスクリプト
- `Makefile`: ビルド/実行ターゲット

## ビルドと実行

```bash
cd simulation
make
python3 test_interact.py
```

非 root ユーザーの場合、`test_interact.py` は最初に `sudo -v` を実行し、その後 sudo チケットを再利用してシミュレータを起動します。

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
