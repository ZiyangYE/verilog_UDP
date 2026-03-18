# UDP and ARP Implementation

**Warning:** This code was written by the author while highly intoxicated, therefore it is rather messy, though functional. The author takes no responsibility for any issues within the code.

## Features

The code includes the following functionalities:

- ARP reception and response, as well as ARP request
- UDP packet sending and reception
- Generation and verification of UDP checksum

*Note:* The code is suitable for IPv4 only.

The Verilog file for the UDP interface can be found at: `udp_18k/src/udp.sv`

In the top-level file of this project, the IP address of the FPGA is set to `192.168.15.14`.

This code will send received packets to the source port +1 of the source address.

## Testing

`udp_test.py` includes a test case, which has been tested on Linux but not on Windows. For this test case, please set the local IP address to `192.168.15.15`. Many abnormal terminations of the test case are due to the inability to open ports or the failure to timely listen to received packets. If necessary, please add a delay.

## Verilator Simulation

This repository also includes a Verilator + TAP virtual NIC simulation under `simulation/`.

- Build: `cd simulation && make`
- Manually authorize sudo once: `sudo -v`
- Run comprehensive regression: `cd simulation && python3 test_interact.py`

The simulation bridges RMII traffic to a Linux TAP interface and can be used for ARP/ICMP/UDP functional verification before FPGA deployment.

### Regression Profile

`simulation/test_interact.py` is now a layered regression suite:

- Core checks (must pass): ARP resolution, ICMP ping basic reachability, UDP basic roundtrip
- Extended checks: ICMP wire-level header/checksum validation, UDP multi-size matrix, UDP wire header inspection, negative behavior check, UDP stress test

Strict mode is enabled by default:

- `SIM_STRICT=1` (default): any extended check failure returns non-zero
- `SIM_STRICT=0`: core checks gate pass/fail, extended checks are reported as diagnostics

Useful tuning knobs:

- `SIM_UDP_MATRIX` (comma-separated payload sizes), default: `2,4,8,16,32,64,128`
- `SIM_UDP_STRESS` (number of stress packets), default: `40`

## Interface and Compatibility

This code uses an RMII interface, and is only suitable for 100M Ethernet, not suitable for 10M Ethernet.

The serial management interface of this code is only suitable for RTL8201. It configures the CRS/CRS_DV pin as RXDV function, waits for the connection to be established, sets the `phy_rdy` bit (i.e., sets the ready interface), and then can start working. This logic could be modified for other PHY chips if needed.

This code is written in System Verilog and is not compatible with Verilog 2005.

## Clock Generation and Usage

The code uses Gowin's PLL to generate a 1MHz clock and does not use any primitives apart from this.

## Warranty and Issues

This code comes with no warranty, but if you encounter any bugs, please feel free to raise an issue.

## Usage and Attribution

This code is free to use, but please retain the author information.

## Author

LAKKA/JA_P_S

# UDP 和 ARP 实现

**警告：**这段代码是作者在烂醉如泥的状态下编写的，因此可能显得混乱，但基本上功能是正常的。作者对代码中的任何问题不承担责任。

## 功能

这段代码包括以下功能：

- ARP 接收和回复，以及 ARP 请求
- UDP 包的发送和接收
- UDP 校验和的生成和验证

*注意：* 该代码仅适用于 IPv4。

UDP 接口的 Verilog 文件可以在这里找到：`udp_18k/src/udp.sv`

在本项目的顶级文件中，FPGA 的 IP 地址设为 `192.168.15.14`。

这段代码会将接收到的数据包发送到源地址的源端口 +1 的端口。

## 测试

`udp_test.py` 包含了一个测试用例，已在 Linux 上测试，但未在 Windows 上测试。对于这个测试用例，请将本地 IP 地址设置为 `192.168.15.15`。测试用例的异常结束很多来自于端口无法打开以及没有来得及监听到收到的包，如果需要的话，请增加延时。

## Verilator 仿真

仓库中还提供了基于 Verilator + TAP 虚拟网卡的仿真环境，位于 `simulation/`。

- 构建：`cd simulation && make`
- 手动进行一次 sudo 授权：`sudo -v`
- 运行完整回归：`cd simulation && python3 test_interact.py`

该仿真会把 RMII 流量桥接到 Linux TAP 接口，可在上板前完成 ARP/ICMP/UDP 功能验证。

### 回归分层说明

`simulation/test_interact.py` 当前为分层回归：

- 核心项（必须通过）：ARP 解析、ICMP 基础连通、UDP 基础回环
- 扩展项：ICMP 线级校验、UDP 多尺寸矩阵、UDP 线级报文头检查、负向行为检查、UDP 压力测试

严格模式默认开启：

- `SIM_STRICT=1`（默认）：任一扩展项失败即返回非零
- `SIM_STRICT=0`：仅核心项决定通过与否，扩展项作为诊断信息输出

常用参数：

- `SIM_UDP_MATRIX`（逗号分隔的负载长度）
- `SIM_UDP_STRESS`（压力包数量）

## 接口和兼容性

这段代码使用 RMII 接口，仅适用于 100M 以太网，不适用于 10M 以太网。

这段代码的串行管理接口仅适用于 RTL8201。它将 CRS/CRS_DV 引脚配置为 RXDV 功能，等待连接建立后，设置 `phy_rdy` 位（即设置 ready 接口），然后可以开始工作。如果需要，可以修改此逻辑以用于其他 PHY 芯片。

这段代码使用 System Verilog 编写，不兼容于 Verilog 2005。

## 时钟生成和使用

这段代码使用 Gowin 的 PLL 生成一个 1MHz 的时钟，除此之外没有使用任何原语。

## 保修和问题

这段代码不提供任何保修，但如果你发现任何问题，请随时提出问题。

## 使用和归属

这段代码可以免费使用，但请保留作者信息。

## 作者

LAKKA/JA_P_S

# UDPおよびARPの実装

**警告:** このコードは作者が泥酔状態で書かれましたので、非常に混乱していますが、基本的には機能します。作者はコード内の問題について一切の責任を負いません。

## 特徴

このコードには以下の機能が含まれています：

- ARP受信と応答、およびARPリクエスト
- UDPパケットの送信と受信
- UDPチェックサムの生成と検証

*注意:* このコードはIPv4専用です。

UDPインターフェイスのVerilogファイルは、`udp_18k/src/udp.sv`にあります。

このプロジェクトのトップレベルのファイルで、FPGAのIPアドレスは`192.168.15.14`に設定されています。

このコードは、受信したパケットを送信元アドレスの送信元ポート+1のポートに送信します。

## テスト

`udp_test.py`にはテストケースが含まれており、Linux上でテストされていますが、Windows上ではテストされていません。このテストケースを使用する場合は、ローカルIPアドレスを`192.168.15.15`に設定してください。テストケースの異常終了の多くは、ポートが開かれない、または受信したパケットをタイムリーにリッスンできないことに起因します。必要であれば、遅延を追加してください。

## Verilatorシミュレーション

このリポジトリには、`simulation/` 配下に Verilator + TAP 仮想 NIC シミュレーション環境も含まれます。

- ビルド: `cd simulation && make`
- 事前に sudo を一回認証: `sudo -v`
- 総合回帰の実行: `cd simulation && python3 test_interact.py`

このシミュレーションは RMII トラフィックを Linux TAP インターフェースにブリッジし、FPGA 実機投入前の ARP/ICMP/UDP 機能検証に利用できます。

### 回帰プロファイル

`simulation/test_interact.py` はレイヤ構成の回帰スイートです。

- コア項目（必須）: ARP 解決、ICMP 基本疎通、UDP 基本ラウンドトリップ
- 拡張項目: ICMP ワイヤレベル検証、UDP サイズ行列テスト、UDP ヘッダ検証、負系挙動チェック、UDP ストレステスト

既定では strict モード有効:

- `SIM_STRICT=1`（既定）: 拡張項目失敗で非ゼロ終了
- `SIM_STRICT=0`: コア項目のみで合否判定、拡張項目は診断出力

主なチューニング項目:

- `SIM_UDP_MATRIX`（カンマ区切りのペイロードサイズ）
- `SIM_UDP_STRESS`（ストレス送信数）

## インターフェイスと互換性

このコードはRMIIインターフェイスを使用し、100M Ethernet専用であり、10M Ethernetには適していません。

このコードのシリアル管理インターフェイスはRTL8201専用です。これはCRS/CRS_DVピンをRXDV機能として設定し、接続が確立されるのを待ってから`phy_rdy`ビットを設定（つまり、readyインターフェイスを設定）し、その後作業を開始します。必要であれば、このロジックは他のPHYチップに対して修正可能です。

このコードはSystem Verilogで記述されており、Verilog 2005とは互換性がありません。

## クロック生成と使用

このコードはGowinのPLLを使用して1MHzのクロックを生成し、それ以外のプリミティブは使用していません。

## 保証と問題

このコードには保証はありませんが、バグを発見した場合は気軽に問題を提出してください。

## 使用と帰属

このコードは自由に使用することができますが、作者の情報を保持してください。

## 作者

LAKKA/JA_P_S
