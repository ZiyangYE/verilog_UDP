################################################################################
# Verilator simulation Makefile
# Targets:
#   make          – build the simulator
#   make run      – build and run (requires sudo for TAP)
#   make clean    – remove build artefacts
################################################################################

SRC_DIR  := ../udp_18k/src
SIM_DIR  := .

# Verilator flags
VFLAGS   := --sv --cc --exe \
            --build \
            -Wall \
            --Wno-WIDTHTRUNC \
            --Wno-WIDTHEXPAND \
            --Wno-INITIALDLY \
            --Wno-MULTIDRIVEN \
            --Wno-BLKSEQ \
            --Wno-TIMESCALEMOD \
            --Wno-DECLFILENAME \
            --Wno-WIDTHCONCAT \
            --Wno-UNUSEDSIGNAL \
            --Wno-COMBDLY \
            --Wno-SYNCASYNCNET \
            --Wno-EOFNEWLINE \
            --Wno-VARHIDDEN \
            --Mdir obj_dir \
            --top-module sim_top

# Source files
RTL_SRCS := $(SRC_DIR)/udp.sv \
            $(SIM_DIR)/sim_top.sv

CPP_MAIN := $(SIM_DIR)/sim_main.cpp

.PHONY: all run clean

all: obj_dir/Vsim_top

obj_dir/Vsim_top: $(RTL_SRCS) $(CPP_MAIN)
	verilator $(VFLAGS) \
        -I$(SRC_DIR) \
        $(SRC_DIR)/udp.sv \
	    $(SIM_DIR)/sim_top.sv \
	    $(CPP_MAIN) \
	    -o Vsim_top

run: all
	@echo "Running simulation (requires CAP_NET_ADMIN / root for TAP)..."
	sudo ./obj_dir/Vsim_top udptap

clean:
	rm -rf obj_dir
