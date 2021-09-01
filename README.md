# wirestripper

![Continuous integration](https://github.com/simeonmiteff/wirestripper/actions/workflows/actions-rs.yml/badge.svg) ![crates.io](https://img.shields.io/crates/v/wirestripper) ![docs.io](https://docs.rs/wirestripper/badge.svg)

![wirestripper.webp](https://raw.githubusercontent.com/simeonmiteff/wirestripper/main/wirestripper.webp)

## Introduction
The `wirestripper` command line utility (and associated library) in this crate offer functions
for parsing and validating ethernet packet (a.k.a. Hilscher netANALYZER transparent mode PCAP link-type
/ raw ethernet PHY-level) records. It can extract ethernet frames from these files and write them as normal
PCAP (thernet link-type) files.
### 802.3 Packets
In the IEEE 802.3 specification, a "frame" is what systems and network folks normally think of as 
an ethernet frame (layer 2 payload), plus a 4-byte trailer CRC32 checksum (FCS - the
frame check sequence) at the end. This, however, is an incomplete picture of ethernet.

The exact wire representation of ethernet is media/speed dependent and complicated by various
encoders and scramblers that transform an ethernet bit-stream to suit the physical link. Inside an ethernet
switch or network interface, the lowest level _normalised_ view of ethernet traffic is provided by the PHY (toward the MAC)
and this includes the 7-byte preamble and 1-byte start-of-frame delimiter (SFD).

The diagram below shows this layout (adapted from 3.1.1 in the 802.3 spec):

```text
                 +---------------------------+ <-
        7 OCTETS | PREAMBLE                  |  |
                 +---------------------------+  |
         1 OCTET | SFD                       |  |
                 +---------------------------+  | <- <-
        6 OCTETS | DESTINATION ADDRESS       |  |  |  |
                 +---------------------------+  |  |  |
        6 OCTETS | SOURCE ADDRESS            |  |  |  |
                 +---------------------------+  |  |  |
        2 OCTETS | LENGTH/TYPE               |  |  |  |
                 +---------------------------+  |  |  |
  48 to N OCTETS | MAC CLIENT DATA + PADDING |  |  |  |
                 +---------------------------+  |  | <-
        4 OCTETS | FRAME CHECK SEQUENCE      |  |  |  |
                 +---------------------------+ <- <-  |
                                                |  |  +-- "Layer-2, as you know and love it."
                                                |  |
                                                |  +-- FRAME
                                                |
                                                +-- PACKET
```

Note the terminology:
- The `FRAME` corresponds to an ethernet frame (including FCS)
- The `PACKET` is the full/raw message as received from the PHY

I was taught that "packets" refer to layer-3 while "frames" are layer-2, but this is clearly
incorrect! To avoid confusion, `wirestripper` employs the above terms, and also uses the term "record" to describe 
entries in PCAP files.

The minimum _packet_ length is thus 72 bytes (7+1+6+6+2+46+4), and the minimum _frame_ length is 64.

### netANALYZER PCAP link-type

PCAP ethernet link-type records strictly contain 802.3 "frames", and optionally include the FCS. The only way
(known to me) to represent a trace of an ethernet "packet" in a PCAP file is with the [netANALYZER link-type](https://www.tcpdump.org/linktypes/LINKTYPE_NETANALYZER.html).

`wirestripper` decodes and manipulates PCAP files of this type.

## Rationale 

`wirestripper` began as a tool to extract ethernet frames from netANALYZER PCAP files and write them
to plain ethernet PCAP files. `wireshark` [specifically doesn't dissect](https://github.com/wireshark/wireshark/blob/d6d7dd1e5664810b368231d03d56465112e3d82e/epan/dissectors/packet-netanalyzer.c#L407)
the frame embedded in transparent-mode netANALYZER PCAP files. The non-transparent netANALYZER mode isn't interesting
(since such records are equivalent to ethernet link-type records with the FCS included). 

While this task is trivial to do with the `editcap` [tool](https://www.wireshark.org/docs/man-pages/editcap.html)
specifying a fixed offset (4 bytes), that approach doesn't work with packets with short or long preambles, which are arguably 
the interesting ones (otherwise why bother with the PHY-level/"packet" representation?).

Instead `wirestripper` decodes the netANALYZER header and sanity checks it against the packet, then searches
for the SFD to find the start of the frame.

## Building

To install the latest version of `wirestripper`, ensure you have a [Rust toolchain installed](https://rustup.rs/), then run:

```shell
cargo install wirestripper
```

Or, to build from source (binary in `target/release/wirestripper`): 

```shell
cargo build --release
```

## Usage

`wirestripper` has two modes/subcommands:

- `strip` extracts ethernet frames into a new PCAP file (optionally skipping those with invalid headers);
- `check` validates netANALYZER headers (and optionally lists the valid errors relating to each packet)

For details, run `wirestripper --help`.

Here are example runs with a sample input file (included in `sample_pcap/full.pcap`):
```text
$ tshark -r sample_pcap/full.pcap 
    1   0.000000              →              netANALYZER 76 Frame captured in transparent mode
    2   0.006093              →              netANALYZER 72 Frame captured in transparent mode
    3   0.006191              →              netANALYZER 114 Frame captured in transparent mode
    4   0.012506              →              netANALYZER 110 Frame captured in transparent mode
    5   0.201069              →              netANALYZER 55 Frame captured in transparent mode
    6   1.001812              →              netANALYZER 114 Frame captured in transparent mode
    7   1.004180              →              netANALYZER 110 Frame captured in transparent mode
    8   1.795137              →              netANALYZER 55 Frame captured in transparent mode
    9   2.003375              →              netANALYZER 114 Frame captured in transparent mode
   10   2.005742              →              netANALYZER 110 Frame captured in transparent mode
   
$ wirestripper --input-file sample_pcap/full.pcap strip --output-file /tmp/demo.pcap
Processed 10 records with 0 errors.

$ tshark -r /tmp/demo.pcap
    1 0.000000000 0e:2b:7c:ff:d4:b2 → Broadcast    ARP 64 Who has 192.168.7.4? Tell 192.168.7.1
    2 0.006093000 12:55:55:00:01:2d → 0e:2b:7c:ff:d4:b2 ARP 64 192.168.7.4 is at 12:55:55:00:01:2d
    3 0.006191000  192.168.7.1 → 192.168.7.4  ICMP 102 Echo (ping) request  id=0x0816, seq=7/1792, ttl=64
    4 0.012506000  192.168.7.4 → 192.168.7.1  ICMP 102 Echo (ping) reply    id=0x0816, seq=7/1792, ttl=32 (request in 3)
    5 0.201069000 7a:4d:94:fa:87:61 → Broadcast    ARP 46 Who has 192.168.7.1? Tell 192.168.7.13
    6 1.001812000  192.168.7.1 → 192.168.7.4  ICMP 102 Echo (ping) request  id=0x0816, seq=8/2048, ttl=64
    7 1.004180000  192.168.7.4 → 192.168.7.1  ICMP 102 Echo (ping) reply    id=0x0816, seq=8/2048, ttl=32 (request in 6)
    8 1.795137000 7a:4d:94:fa:87:61 → Broadcast    ARP 46 Who has 192.168.7.1? Tell 192.168.7.13
    9 2.003375000  192.168.7.1 → 192.168.7.4  ICMP 102 Echo (ping) request  id=0x0816, seq=9/2304, ttl=64
   10 2.005742000  192.168.7.4 → 192.168.7.1  ICMP 102 Echo (ping) reply    id=0x0816, seq=9/2304, ttl=32 (request in 9)
   
$ wirestripper --input-file sample_pcap/full.pcap strip --output-file /tmp/demo.pcap --strict
Record 1 is OK, will strip it normally.
Skipping record 2 due to netANALYZER record header validation error, re-run with "check" subcommand for details.
Record 3 is OK, will strip it normally.
Skipping record 4 due to netANALYZER record header validation error, re-run with "check" subcommand for details.
Skipping record 5 due to netANALYZER record header validation error, re-run with "check" subcommand for details.
Record 6 is OK, will strip it normally.
Skipping record 7 due to netANALYZER record header validation error, re-run with "check" subcommand for details.
Skipping record 8 due to netANALYZER record header validation error, re-run with "check" subcommand for details.
Record 9 is OK, will strip it normally.
Skipping record 10 due to netANALYZER record header validation error, re-run with "check" subcommand for details.
Processed 10 records with 6 errors.

$ tshark -r /tmp/demo.pcap
    1 0.000000000 0e:2b:7c:ff:d4:b2 → Broadcast    ARP 64 Who has 192.168.7.4? Tell 192.168.7.1
    2 0.006191000  192.168.7.1 → 192.168.7.4  ICMP 102 Echo (ping) request  id=0x0816, seq=7/1792, ttl=64
    3 1.001812000  192.168.7.1 → 192.168.7.4  ICMP 102 Echo (ping) request  id=0x0816, seq=8/2048, ttl=64
    4 2.003375000  192.168.7.1 → 192.168.7.4  ICMP 102 Echo (ping) request  id=0x0816, seq=9/2304, ttl=64
    
$ wirestripper --input-file sample_pcap/full.pcap check

Record 2 is invalid, here are the issues:
	 - Header preamble-too-short error flag is false, but preamble is 3 bytes long (normal is 7 bytes)
Header: Header {
    reserved: 0,
    frame_length: 68,
    port_number: 1,
    header_version: 1,
    transparent_mode: true,
    port_type: Ethernet,
    errors: ErrorFlags {
        preamble_too_long: false,
        preamble_too_short: false,
        frame_too_short: false,
        sfd_not_found: false,
        frame_too_long: false,
        fcs_incorrect: false,
        alignment_problem: false,
        mii_receive_error: false,
    },
}
PCAP record contents:
Length: 72 (0x48) bytes
0000:   00 46 44 00  55 55 55 d5  0e 2b 7c ff  d4 b2 12 55   .FD.UUU..+|....U
0010:   55 00 01 2d  08 06 00 01  08 00 06 04  00 02 12 55   U..-...........U
0020:   55 00 01 2d  c0 a8 07 04  0e 2b 7c ff  d4 b2 c0 a8   U..-.....+|.....
0030:   07 01 00 00  00 00 00 00  00 00 00 00  00 00 00 00   ................
0040:   00 00 00 00  e6 0b 7d 1e                             ......}.

<snip>
Processed 10 records with 6 errors.    
```

If we manufacture a record (a copy of record 1 above, included in `sample_pcap/record1.pcap`), but we corrupt the FCS
and set the FCS error flag, the `check` command finds the record is valid:

```text
$ wirestripper --input-file sample_pcap/record1.pcap check

Processed 1 records with 0 errors.
```
To list the errors correctly indicated, we can pass the `--verbose` flag to `check`: 

```text
$ wirestripper --input-file sample_pcap/record1.pcap check --verbose
Record 1 is valid.
Here are known errors in the packet:
	 - fcs incorrect

Processed 1 records with 0 errors.
```

Finally, if we `strip` this record, `tshark` agrees that the FCS is incorrect:

```text
$ wirestripper --input-file sample_pcap/record1.pcap strip --output-file /tmp/demo1.pcap
Processed 1 records with 0 errors.

$ tshark -r /tmp/demo1.pcap 
    1 0.000000000 0e:2b:7c:ff:d4:b2 → Broadcast    ARP 64 Who has 192.168.7.4? Tell 192.168.7.1 [ETHERNET FRAME CHECK SEQUENCE INCORRECT]
```

## Limitations

`wirestripper` does not support:
- netANALYZER non-transparent mode
- netANALYSER version 2 headers
- netANALYSER GPIO capture mode

PCAP samples included and all input used for testing and development were generated by a (currently unpublished) C++ program. I don't 
have access to Hilscher netANALYZER hardware or software. If you're using `wirestripper` with netANALYZER itself, please let me know
how it goes!

I'm happy to accept PRs, and also PCAP traces or hardware :smirk:

## License and attribution

`wirestripper` is licensed under the Mozilla Public License 2.0. Please see `LICENSE` for details.

The [wire stripper tool image](https://commons.wikimedia.org/wiki/File:Wire_stripper.png) is copyright [Tiia Monto](https://commons.wikimedia.org/wiki/User:Kulmalukko) and reproduced here under [this license](https://creativecommons.org/licenses/by-sa/4.0/deed.en).
