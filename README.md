# ESPTouchCatcher - eWeLinkESPT
eWeLinkESPT is a tool to decode and decrypt the WiFi network credentials transmitted to an ESP-based IoT device supported by the *eWeLink* mobile application. This tool reverses the eWeLink own implementation of the *ESP Touch* protocol, which is used by-default in the WiFi pairing process of the sonoff and many other IoT devices.
This tool has been tested with the Android (v4.0.3 and v4.4.1) and iOS (v3.15.0) *eWeLink* application versions.

### Requirements
```sh
python3, pyshark
```
### Use 
Run in a terminal:
```sh
$ sudo ./eWeLinkESPT.py
```
then wait for or lauch a "Quick Pairing" association through the eWeLink mobile application

### Todos

 - Loop cyclically over all the WiFi channels
 - Improve code styling

License
----

MIT