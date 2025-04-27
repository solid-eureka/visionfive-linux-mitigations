# USE ONLY FOR RESEARCH PURPOSES

## Build

via [rvspace.org](https://rvspace.org/en/project/VisionFive2_Debian_Wiki_202302_Release#updating-linux-kernel-in-image),
see `./build.sh`:

```bash
cp arch/riscv/configs/starfive_visionfive2_defconfig .config
make ARCH=riscv olddefconfig
make ARCH=riscv -j$(nproc) bindeb-pkg
```

## Install

After building, there will be `.deb`-packages in the parent directory.

Install them, e.g., with
`dpkg -i *.deb`

Change the boot default via `sudo nano /boot/extlinux/extlinux.conf` to boot the new kernel, e.g., `l1`.

Reboot and pray (`sudo shutdown -r now`).
