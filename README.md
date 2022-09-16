# ptpmeasure: A measurement tool for PTP/ST 2110/ST 2022-6

ptpmeasure is a simple tool to sanity-check ST 2110/2022-6 streams and make measurements relative to PTP. It has minimal dependencies and allows for multi-day measurements without the need to create large packet and unwieldy packet captures. Nor does it require many dependencies.

## Getting Started

### Dependencies

* [bitstream](https://code.videolan.org/videolan/bitstream)
* libpcap development headers (e.g On Ubuntu/Debian run `apt install libpcap-dev`

### Supported Network Cards

* Any network card with hardware timestamping of all packets with a VSS Ethernet Trailer such as the Silicom PE310G2TSI9P
* Any network card with hardware timestamping of all packets via “adapter_unsynced” such as the Mellanox ConnectX5

### Initial setup

* For VSS trailer cards, use the provided vendor tools to lock the card to PTP
* For "adapter_unsynced" , use a command such as `ptp4l -m -q -i p9p1 -f ~/ptp-smpte.conf -s` where "ptp-smpte.conf" contains configuration matching your PTP configuration

## Using the tool

### Video

To measure a 2110-20 29.97fps video flow from 238.16.1.10:5000 on NIC "eth3.38" in “adapter_unsynced” (`--mellanox`) mode:

`sudo ./ptpmeasure 238.16.1.10 5000 eth3.38 --mellanox --2110-video --fps 30000/1001 --interlaced`

An output like this will be generated:

    2022-09-16 21:30:28+0100: First Packet arrived 0.616 ms after ideal,  RTP-PTP offset -11.111us (-1 rtp).
    2022-09-16 21:30:28+0100: First Packet arrived 0.630 ms after ideal,  RTP-PTP offset 0.000us (0 rtp).
    2022-09-16 21:30:28+0100: First Packet arrived 0.615 ms after ideal,  RTP-PTP offset -11.111us (-1 rtp).
   
Note for gapped output the first packet arriving ~600us after ideal is normal 
    
## Audio

To measure a 2110-30 audio flow from 238.16.1.11:5002 on NIC "eth3.38" in “adapter_unsynced” (`--mellanox`) mode:

`sudo ./ptpmeasure 238.16.1.11 5002 eth3.38 --mellanox`

An output like this will be generated:

    2022-09-16 21:34:20+0100: RTP-PTP offset -291.666667 us. Audio samples 96
    2022-09-16 21:34:20+0100: RTP-PTP offset -270.833333 us. Audio samples 96
    2022-09-16 21:34:20+0100: RTP-PTP offset -270.833333 us. Audio samples 96

