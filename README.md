KeycardAccess
===

Installation instructions
---
You will need an ESP32 with at least 4MB of flash.

1. Download `ka-keymaker-esp32-x.y.z.bin` or `ka-gate-esp32-x.y.z.bin`
2. Install `esptool` for flashing:
    ```shell
    pip3 install esptool
    ```
3. Flash using:
   ```shell
   esptool.py write_flash 0x0 ka-keymaker-esp32-x.y.z.bin
   ```
4. Connect and interact with
   ```shell
   screen /dev/ttyUSB0 115200
   ```
   (reboot the device to make sure the screen prompt is visible).