`include "rmii.svh"

/*
 * UDP core usage example / UDP 核使用示例 / UDP コア使用例
 *
 * 中文：本顶层把 udp.sv 配置成一个 UDP Echo 设备。收到一帧后，它读取 4 个
 *       32 位接收头字段，把 payload 原样送入发送缓存，最后提交发送请求。
 * English: This top level configures udp.sv as a UDP echo device. For every
 *          received frame it reads four 32-bit RX header words, copies the
 *          payload into the TX staging buffer, and finally commits the frame.
 * 日本語：このトップは udp.sv を UDP Echo デバイスとして使用します。受信した
 *         4 個の 32-bit ヘッダを読み、payload を TX バッファへコピーしてから
 *         送信要求を確定します。
 *
 * 中文：示例行为是返回到“源 IP、源端口 + 1”，本地发送源端口固定为 11451。
 * English: The example replies to source IP and source port + 1; the local TX
 *          source port is fixed at 11451.
 * 日本語：返信先は「送信元 IP、送信元ポート + 1」で、ローカル送信元ポートは
 *         11451 に固定されています。
 */
module top(
    input clk,
    input rst,

    rmii netrmii,
    output phyrst,

    output[5:0] led
);

// 中文：LED 跑马灯只用于观察主时钟和复位是否正常，与网络协议无关。
// English: The rotating LED pattern only indicates clock/reset activity; it is unrelated to networking.
// 日本語：LED の巡回表示はクロックとリセットの確認用であり、ネットワーク処理とは無関係です。
logic[5:0] rled;
logic[23:0] ckdiv;
assign led = rled;

always_ff@(posedge clk or negedge rst)begin
    if(rst == 1'b0)begin
        rled <= 5'b00001;
        ckdiv <= 24'd0;
    end else begin
        ckdiv <= ckdiv + 24'd1;
        if(ckdiv == 24'd0)
            rled <= {rled[4:0],rled[5]};
    end
end

/*
 * PHY management clock / PHY 管理时钟 / PHY 管理クロック
 *
 * 中文：udp.sv 使用 clk1m 驱动 MDC/SMI 初始化；真正的收发数据使用 PHY 提供的
 *       50 MHz RMII 参考时钟，而不是这里的 clk6m。
 * English: udp.sv uses clk1m for MDC/SMI initialization. Packet RX/TX runs on
 *          the PHY-provided 50 MHz RMII reference clock, not clk6m here.
 * 日本語：udp.sv は clk1m を MDC/SMI 初期化に使用します。パケット送受信は
 *         clk6m ではなく、PHY からの 50 MHz RMII 参照クロックで動作します。
 */
logic clk1m;
logic clk6m;
PLL_6M PLL6m(
    .clkout(clk6m),
    .clkoutd(clk1m),
    .clkin(clk)
);

logic clk50m;
logic ready;

/*
 * RX streaming interface / RX 流接口 / RX ストリームインターフェース
 *
 * 中文：rx_*_av 由 udp.sv 拉高，表示当前输出有效；本顶层只有在能够接收时才拉高
 *       rx_*_rdy。一个数据项仅在 av && rdy 同时为 1 的时钟沿被消费。
 * English: udp.sv asserts rx_*_av when an output item is valid. This top asserts
 *          rx_*_rdy only when it can consume that item. Transfer occurs on a
 *          clock edge where av && rdy are both high.
 * 日本語：rx_*_av は udp.sv が有効データを示す信号です。このトップは受信可能な
 *         ときだけ rx_*_rdy を立て、av && rdy が同時に High のクロックで転送します。
 */
logic rx_head_av;
logic[31:0] rx_head;
logic rx_data_av;
logic[7:0] rx_data;
logic rx_head_rdy;
logic rx_data_rdy;

/*
 * TX staging and commit interface / TX 缓存与提交接口 / TX バッファ・確定インターフェース
 *
 * 中文：发送分为两个严格有序的阶段：
 *       1. tx_data_rdy 为 1 时，用 tx_data_av 逐字节写入完整 payload；
 *       2. payload 全部写完后，等待 tx_req_rdy，再把 tx_req 拉高一个周期。
 *       tx_req 是“提交整帧”，不能在 payload 尚未写完时提前发出。
 * English: Transmission has two ordered phases:
 *          1. While tx_data_rdy is high, write the complete payload byte by byte
 *             using tx_data_av.
 *          2. After the complete payload is staged, wait for tx_req_rdy and pulse
 *             tx_req for one cycle.
 *          tx_req commits the whole frame and must not precede the final byte.
 * 日本語：送信は次の 2 段階を必ずこの順序で行います。
 *         1. tx_data_rdy が High の間に、tx_data_av で payload 全体を 1 byte ずつ格納。
 *         2. 全 byte の格納後、tx_req_rdy を待って tx_req を 1 cycle だけ High にする。
 *         tx_req はフレーム全体の確定なので、最後の byte より前に出してはいけません。
 */
logic [31:0] tx_ip;
logic [15:0] tx_dst_port;
logic tx_req;
logic [7:0] tx_data;
logic tx_data_av;
logic tx_req_rdy;
logic tx_data_rdy;

logic [15:0] rx_payload_len;
logic [15:0] rx_payload_count;

/*
 * udp.sv configuration / udp.sv 参数配置 / udp.sv パラメータ設定
 *
 * 中文：ip_adr 和 mac_adr 是 FPGA 自身地址。ARP 时间参数按 50 MHz 工作时钟计数。
 *       ready 只有在 PHY 初始化和链路检查完成后才为 1；用户逻辑应在 ready=0 时
 *       保持复位或停止访问流接口。
 * English: ip_adr and mac_adr are the FPGA's own addresses. ARP time parameters
 *          count 50 MHz cycles. ready becomes high after PHY initialization/link
 *          checks; user logic should remain reset or stop using streams while low.
 * 日本語：ip_adr と mac_adr は FPGA 自身のアドレスです。ARP 時間パラメータは
 *         50 MHz cycle 単位です。PHY 初期化とリンク確認が終わると ready が High に
 *         なり、Low の間はユーザ回路をリセットするかストリームアクセスを停止します。
 */
udp #(
    .ip_adr({8'd192,8'd168,8'd15,8'd14}),
    .mac_adr({8'h06,8'h00,8'hAA,8'hBB,8'h0C,8'hDD}),

    .arp_refresh_interval(50000000*15), // 15 seconds    
    .arp_max_life_time(50000000*30) // 30 seconds
)udp_inst(
    .clk1m(clk1m),
    .rst(rst),

    // 中文：udp.sv 导出的 RMII 50 MHz 数据域时钟和协议栈就绪信号。
    // English: RMII 50 MHz data-domain clock and stack-ready output from udp.sv.
    // 日本語：udp.sv から出力される RMII 50 MHz データクロックとスタック ready 信号。
    .clk50m(clk50m),
    .ready(ready),

    // 中文/English/日本語：RMII PHY 接口 / RMII PHY interface / RMII PHY インターフェース
    .netrmii(netrmii),

    // 中文：PHY 低有效复位输出。English: Active-low PHY reset output. 日本語：PHY の Low-active reset 出力。
    .phyrst(phyrst),

    // 中文/English/日本語：接收头与 payload / RX header and payload / RX header・payload
    .rx_head_rdy_i(rx_head_rdy),
    .rx_head_av_o(rx_head_av),
    .rx_head_o(rx_head),
    .rx_data_rdy_i(rx_data_rdy),
    .rx_data_av_o(rx_data_av),
    .rx_data_o(rx_data),

    // 中文：发送元数据、payload 输入，以及两阶段发送握手。
    // English: TX metadata, payload input, and the two-phase TX handshake.
    // 日本語：TX metadata、payload 入力、および 2 段階 TX handshake。
    .tx_ip_i(tx_ip),
    .tx_src_port_i(16'd11451),
    .tx_dst_port_i(tx_dst_port),
    .tx_req_i(tx_req),
    .tx_data_i(tx_data),
    .tx_data_av_i(tx_data_av),
    .tx_req_rdy_o(tx_req_rdy),
    .tx_data_rdy_o(tx_data_rdy)
);

/*
 * Payload forwarding / Payload 转发 / Payload 転送
 *
 * 中文：状态 5 中，只要 RX 有有效字节且 TX 缓存可接收，就在同一时钟沿完成一次
 *       RX 消费和 TX 写入。这里不能再附加 tx_req_rdy 条件：tx_req_rdy 表示下游
 *       能否提交“整帧”，而 tx_data_rdy 才表示能否缓存当前 payload 字节。
 * English: In state 5, one RX byte is consumed and written to the TX staging
 *          buffer whenever RX is valid and TX can accept data. Do not gate this
 *          with tx_req_rdy: tx_req_rdy controls whole-frame commit, whereas
 *          tx_data_rdy controls payload-byte staging.
 * 日本語：state 5 では RX byte が有効かつ TX バッファが受信可能な場合、同じ
 *         クロックで RX 消費と TX 書き込みを行います。tx_req_rdy はフレーム全体の
 *         確定用、tx_data_rdy は payload byte 格納用なので、両者を混同しません。
 */
always_comb begin
    rx_data_rdy <= tx_state == 5 && tx_data_rdy
                   && rx_payload_count < rx_payload_len;
    tx_data <= rx_data;
    tx_data_av <= rx_data_av && rx_data_rdy;
end

byte tx_state;

/*
 * RX header format: four 32-bit words per accepted frame
 * 每帧 RX 头格式：4 个 32 位字 / RX header 形式：1 frame あたり 32-bit × 4 word
 *
 *   word 0 = source IPv4 address
 *            源 IPv4 地址
 *            送信元 IPv4 address
 *   word 1 = destination IPv4 address
 *            目的 IPv4 地址
 *            宛先 IPv4 address
 *   word 2 = {source UDP port, destination UDP port}
 *            {源 UDP 端口, 目的 UDP 端口}
 *            {送信元 UDP port, 宛先 UDP port}
 *   word 3 = {IPv4 identification, payload byte length}
 *            {IPv4 标识, payload 字节数}
 *            {IPv4 identification, payload byte 数}
 *
 * 中文：本例保留 word 0 作为回复目标 IP，忽略 word 1，把 word 2 的源端口加 1
 *       作为回复目标端口，并使用 word 3 的低 16 位限制 payload 转发长度。
 * English: This example keeps word 0 as the reply IP, ignores word 1, uses the
 *          source port from word 2 plus one, and takes word 3[15:0] as the exact
 *          number of payload bytes to forward.
 * 日本語：この例では word 0 を返信先 IP として保持し、word 1 は無視します。
 *         word 2 の送信元 port + 1 を返信先 port とし、word 3[15:0] の byte 数だけ
 *         payload を転送します。
 *
 * State sequence / 状态顺序 / 状態遷移:
 *   0       wait for a complete RX header / 等待完整 RX 头 / RX header 待ち
 *   1..4    consume and decode four header words / 读取并解析 4 个头字段 / 4 word を読出し・解析
 *   5       forward exactly payload_len bytes / 精确转发 payload_len 字节 / payload_len byte を転送
 *   6       wait for frame capacity and pulse tx_req / 等待整帧容量并提交 / 容量待ち後 tx_req を pulse
 */

always_ff@(posedge clk50m or negedge ready)begin
    if(ready == 0)begin
        tx_state <= 0;
        rx_head_rdy <= 1'b0;
        tx_req <= 1'b0;
        rx_payload_len <= 16'd0;
        rx_payload_count <= 16'd0;
    end else begin
        tx_req <= 1'b0;
        rx_head_rdy <= 1'b0;

        case(tx_state)
            0:begin
                // 中文：rx_head_av 只会在 CRC 正确并且整帧已经提交到 RX FIFO 后出现。
                // English: rx_head_av appears only after a CRC-valid frame is committed to the RX FIFO.
                // 日本語：rx_head_av は CRC 正常の frame が RX FIFO に確定された後だけ High になります。
                if(rx_head_av)begin
                    tx_state <= 1;
                    rx_head_rdy <= 1'b1;
                end
            end
            1:begin
                // 中文：保存源 IP，回复时把它作为目的 IP。
                // English: Save the source IP and use it as the reply destination.
                // 日本語：送信元 IP を保存し、返信の宛先 IP として使用します。
                rx_head_rdy <= 1'b1;
                tx_ip <= rx_head;
                tx_state <= 2;
            end
            2:begin
                // 中文：消费但忽略原目的 IP。English: Consume and ignore the original destination IP.
                // 日本語：元の宛先 IP は読み進めますが、この Echo 例では使用しません。
                rx_head_rdy <= 1'b1;
                tx_state <= 3;
            end
            3:begin
                // 中文：word 2 高 16 位是源端口；本例回复到源端口 + 1。
                // English: Word 2[31:16] is the source port; reply to source port + 1.
                // 日本語：word 2[31:16] は送信元 port で、返信先はその port + 1 です。
                rx_head_rdy <= 1'b1;
                tx_dst_port <= rx_head[31:16] + 16'd1;
                tx_state <= 4;
            end
            4:begin
                // 中文：最后一个头字段的低 16 位是 payload 长度，单位为字节。
                // English: The low 16 bits of the final header word are payload length in bytes.
                // 日本語：最後の header word の下位 16 bit は byte 単位の payload 長です。
                rx_payload_len <= rx_head[15:0];
                rx_payload_count <= 16'd0;
                tx_state <= 5;
            end
            5:begin
                // 中文：零长度 payload 直接进入提交阶段；否则严格转发指定字节数。
                // English: A zero-length payload skips directly to commit; otherwise forward the exact count.
                // 日本語：payload 長 0 は直ちに確定段階へ進み、それ以外は指定 byte 数だけ転送します。
                if(rx_payload_len == 0)begin
                    tx_state <= 6;
                end else if(rx_data_av && rx_data_rdy)begin
                    rx_payload_count <= rx_payload_count + 16'd1;
                    if(rx_payload_count + 16'd1 == rx_payload_len)
                        tx_state <= 6;
                end
            end
            6:begin
                // 中文：tx_req_rdy 会同时检查生成器空闲以及头/数据 FIFO 能否容纳完整帧。
                //       因此只在这里脉冲 tx_req，不会产生只写入半帧的情况。
                // English: tx_req_rdy checks generator idle state and complete-frame capacity in both
                //          header/data FIFOs. Pulsing tx_req only here prevents partial-frame commits.
                // 日本語：tx_req_rdy は generator の空き状態と header/data FIFO の 1 frame 分の
                //         空き容量を確認します。ここだけで tx_req を pulse するため半端な frame は入りません。
                if(tx_req_rdy)begin
                    tx_req <= 1'b1;
                    tx_state <= 0;
                end
            end
        endcase
    end
end




endmodule

