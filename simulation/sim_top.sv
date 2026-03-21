`include "rmii.svh"

module sim_top (
    input  logic        clk,
    input  logic        rst,
    input  logic        rmii_clk50m,
    input  logic        rmii_rx_crs,
    input  logic [1:0]  rmii_rxd,
    output logic [1:0]  rmii_txd,
    output logic        rmii_txen,
    output logic        rmii_mdc,
    output logic        ready_o
);

    tri mdio_pullup;
    assign mdio_pullup = 1'b1;

    rmii netrmii(
        .clk50m(rmii_clk50m),
        .rx_crs(rmii_rx_crs),
        .mdc(rmii_mdc),
        .txen(rmii_txen),
        .mdio(mdio_pullup),
        .txd(rmii_txd),
        .rxd(rmii_rxd)
    );

    logic phyrst;

    logic clk50m;
    logic ready;

    logic rx_head_av;
    logic [31:0] rx_head;
    logic rx_data_av;
    logic rx_data_rdy;
    logic [7:0] rx_data;
    logic rx_head_rdy;

    logic [31:0] tx_ip;
    logic [15:0] tx_dst_port;
    logic tx_req;
    logic [7:0] tx_data;
    logic tx_data_av;
    logic tx_req_rdy;
    logic tx_data_rdy;

    assign ready_o = ready;

    udp #(
        .ip_adr({8'd192,8'd168,8'd15,8'd14}),
        .mac_adr({8'h06,8'h00,8'hAA,8'hBB,8'h0C,8'hDD}),
        .arp_refresh_interval(50000000*15),
        .arp_max_life_time(50000000*30)
    ) udp_inst(
        .clk1m(clk),
        .rst(rst),
        .clk50m(clk50m),
        .ready(ready),
        .netrmii(netrmii),
        .phyrst(phyrst),
        .rx_head_rdy_i(rx_head_rdy),
        .rx_head_av_o(rx_head_av),
        .rx_head_o(rx_head),
        .rx_data_rdy_i(rx_data_rdy),
        .rx_data_av_o(rx_data_av),
        .rx_data_o(rx_data),
        .tx_ip_i(tx_ip),
        .tx_src_port_i(16'd11451),
        .tx_dst_port_i(tx_dst_port),
        .tx_req_i(tx_req),
        .tx_data_i(tx_data),
        .tx_data_av_i(tx_data_av),
        .tx_req_rdy_o(tx_req_rdy),
        .tx_data_rdy_o(tx_data_rdy)
    );

    // Use force to bypass PHY init sequencing in simulation.
    always_comb begin
        force udp_inst.phy_rdy = rst;
        force udp_inst.rphyrst = rst;
    end

    always_comb begin
        rx_data_rdy <= tx_data_rdy;
        tx_data <= rx_data;
        tx_data_av <= rx_data_av && tx_data_rdy;
    end

    byte tx_state;
    always_ff @(posedge clk50m or negedge ready) begin
        if(ready == 0) begin
            tx_state <= 0;
            rx_head_rdy <= 1'b0;
        end else begin
            tx_req <= 1'b0;
            rx_head_rdy <= 1'b0;
            case(tx_state)
                0: if(rx_head_av) begin
                        tx_state <= 1;
                        rx_head_rdy <= 1'b1;
                   end
                1: begin
                        rx_head_rdy <= 1'b1;
                        tx_ip <= rx_head;
                        tx_state <= 2;
                   end
                2: begin
                        rx_head_rdy <= 1'b1;
                        tx_state <= 3;
                   end
                3: begin
                        rx_head_rdy <= 1'b1;
                        tx_dst_port <= rx_head[31:16] + 16'd1;
                        tx_state <= 4;
                   end
                4: tx_state <= 5;
                5: if(tx_req_rdy && rx_data_av == 1'b0) begin
                        tx_req <= 1'b1;
                        tx_state <= 0;
                   end
            endcase
        end
    end

endmodule
