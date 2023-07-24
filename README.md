KeycardAccess
===

Installation instructions
---

1. Download `keymaker-esp32-4M-x.y.z.bin` or `gate-esp32-4M-x.y.z.bin`
2. Install `esptool` for flashing:
    ```shell
    pip3 install esptool
    ```
3. Flash using:
   ```shell
   esptool.py write_flash 0x0 keymaker-esp32-4M-x.y.z.bin
   ```
4. Connect and interact with
   ```shell
   screen /dev/ttyUSB0 115200
   ```
   (reboot the device to make sure the screen prompt is visible).