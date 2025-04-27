#!/bin/bash

cp arch/riscv/configs/starfive_visionfive2_defconfig .config
make ARCH=riscv olddefconfig
make ARCH=riscv -j$(nproc) bindeb-pkg
