// Copyright 2021 Simeon Miteff

#![doc = include_str!("../README.md")]

use byteorder::{LittleEndian, ReadBytesExt};
use crc32fast::Hasher;
use std::convert::TryFrom;
use thiserror::Error;

/// WirestripperError is the single error type for the wirestripper crate API
#[derive(Error, Debug, PartialEq)]
pub enum WirestripperError {
    /// Wirestripper doesn't support netANALYZER non-transparent mode records
    #[error("Wirestripper doesn't support netANALYZER non-transparent mode records")]
    OpaqueModeUnsupported,
    /// Wirestripper doesn't support netANALYZER records with header version {0}
    #[error("Wirestripper doesn't support netANALYZER records with header version {0}")]
    HeaderVersionUnsupported(u8),
    /// PCAP record too short to have valid netANALYZER header
    #[error("PCAP record too short to have valid netANALYZER header")]
    RecordTooShort,
    /// netANALYZER GPIO mode is unsupported
    #[error("netANALYZER GPIO mode is unsupported")]
    GPIOModeUnsupported,
    /// "PCAP record too short to have valid FCS
    #[error("PCAP record too short to have valid FCS")]
    RecordTooShortForFCS,
    /// Invalid value for packet length: {header_value} (data is {packet_length} bytes)
    #[error("Invalid value for packet length: {header_value} (data is {packet_length} bytes)")]
    InvalidFrameLength {
        header_value: usize,
        packet_length: usize,
    },
    /// expected first non-preamble byte to be SFD (0xD5), but got {0}
    #[error("expected first non-preamble byte to be SFD (0xD5), but got {0}")]
    NoSFDAfterPreamble(u8),
    /// SFD not found in 802.3 frame
    #[error("SFD not found in 802.3 frame")]
    NoSFDFound,
    /// Header FCS error flag is {0} but that isn't correct (our result={1})
    #[error("Header FCS error flag is {0} but that isn't correct (our result={1})")]
    FCSErrorError(bool, bool),
    /// Header SFD error flag ({0}) doesn't match (SFD is present at offset {1})
    #[error("Header SFD error flag ({0}) doesn't match (SFD is present at offset {1})")]
    SFDErrorError(bool, usize),
    /// Header frame-too-short error flag is {0}, but frame is {1} bytes long (normal is >= 64 bytes)
    #[error("Header frame-too-short error flag is {0}, but frame is {1} bytes long (normal is >= 64 bytes)")]
    FrameTooShortErrorError(bool, usize),
    /// Header preamble-too-short error flag is {0}, but preamble is {1} bytes long (normal is 7 bytes)
    #[error("Header preamble-too-short error flag is {0}, but preamble is {1} bytes long (normal is 7 bytes)")]
    PreambleTooShortErrorError(bool, usize),
    /// Header preamble-too-long error flag is {0}, but preamble is {1} bytes long (normal is 7 bytes)
    #[error("Header preamble-too-long error flag is {0}, but preamble is {1} bytes long (normal is 7 bytes)")]
    PreambleTooLongErrorError(bool, usize),
    /// Header reserved bits are not zero ({0}) but record is version 1, not 2
    #[error("Header reserved bits are not zero ({0}) but record is version 1, not 2")]
    ReservedBitsNonZero(u8),
    /// Invalid combination of error flags ({0})
    #[error("Invalid combination of error flags ({0:?})")]
    InvalidErrorFlagCombination(ErrorFlags),
    /// "Generic header decoding error
    #[error("Generic header decoding error")]
    DecodeError,
}

/// PortType represents the two types of Hilscher netANALYZER input ports.
#[derive(PartialEq, Debug)]
pub enum PortType {
    /// Normal Ethernet (i.e. 802.3 "packets")
    Ethernet,
    /// Hilscher netANALYZER hardware specific - not supported
    GPIO,
}

/// ErrorFlags contains the 8 error flags bits decoded from the netANALYZER header.
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct ErrorFlags {
    /// Packet preamble is longer than 7 bytes
    pub preamble_too_long: bool,
    /// Packet preamble shorter than 7 bytes
    pub preamble_too_short: bool,
    /// Ethernet frame is shorter than 64 bytes
    pub frame_too_short: bool,
    ///  SFD (start of frame delimiter) not found in the packet
    pub sfd_not_found: bool,
    /// Ethernet frame is too long (how does netANALYZER know this?)
    pub frame_too_long: bool,
    /// Incorrect FCS = frame check sequence (CRC32)
    pub fcs_incorrect: bool,
    /// Indicates an alignment error detected in the hardware
    pub alignment_problem: bool,
    /// The PHY signaled a receiver error (MII RX_ER)
    pub mii_receive_error: bool,
}

/// Header contains the decoded netANALYZER header
#[derive(Debug)]
pub struct Header {
    pub(crate) reserved: u8,
    /// 12 bit frame length - from the first byte after SFD, up to and including the FCS
    pub frame_length: u16,
    /// 2 bit port number (netANALYZER hardware input port)
    pub port_number: u8,
    /// 4 bit header version. Only v1 is supported (v2 exists)
    pub header_version: u8,
    /// Transparent mode flag (wirestripper only supports this mode) = including preamble anf SFD
    pub transparent_mode: bool,
    /// Port type flag is 0 for Ethernet (only supported type)
    pub port_type: PortType,
    /// 8 error flags bits decoded into a struct of bools, from the netANALYZER header
    pub errors: ErrorFlags,
}

impl Header {
    /// Decode the 4-byte netANALYZER header into a Header struct
    pub fn from_bytes(mut b: &[u8]) -> Header {
        let w = b.read_u32::<LittleEndian>().unwrap();

        // See: https://www.tcpdump.org/linktypes/LINKTYPE_NETANALYZER.html
        Header {
            reserved: (w >> 28) as u8,
            frame_length: ((w >> 16) & 0x0fff) as u16,
            port_number: ((w >> 14) & 0x3) as u8,
            header_version: ((w >> 10) & 0xf) as u8,
            transparent_mode: ((w >> 9) & 0x1) == 0x1,
            port_type: match (w >> 8) & 0x1 {
                0 => PortType::Ethernet,
                1 => PortType::GPIO,
                _ => panic!("impossible for 1-bit port_type to have > 2 values"),
            },
            errors: ErrorFlags {
                preamble_too_long: w & 0x80 != 0,
                preamble_too_short: w & 0x40 != 0,
                frame_too_short: w & 0x20 != 0,
                sfd_not_found: w & 0x10 != 0,
                frame_too_long: w & 0x8 != 0,
                fcs_incorrect: w & 0x4 != 0,
                alignment_problem: w & 0x2 != 0,
                mii_receive_error: w & 0x1 != 0,
            },
        }
    }
}

/// Record is the decoded form of the full netANALYZER PCAP link-type record
#[derive(Debug)]
pub struct Record {
    /// The netANALYZER header, decoded
    pub header: Header,
    /// has_error is true if any of header.errors members are true
    has_error: bool,
    /// packet is the full/faw 802.3 Ethernet packet in bytes (preamble through to FCS)
    packet: Vec<u8>,
    /// if present in the packet, sfd_offset is the byte offset of the SFD within the packet
    sfd_offset: usize,
}

impl Record {
    /// report_errors returns a vector of strings describing all the errors in the record, or None
    pub fn report_errors(&self) -> Option<Vec<String>> {
        if self.has_error {
            let mut errors: Vec<String> = Vec::new();

            if self.header.errors.preamble_too_long {
                errors.push(format!("preamble too long ({})", self.sfd_offset))
            }

            if self.header.errors.preamble_too_short {
                errors.push(format!("preamble too short ({})", self.sfd_offset))
            }

            if self.header.errors.frame_too_short {
                errors.push(format!("frame too short ({})", self.packet.len()))
            }

            if self.header.errors.sfd_not_found {
                errors.push("sfd not found)".to_string())
            }

            if self.header.errors.frame_too_long {
                errors.push(format!("frame too long ({})", self.packet.len()))
            }

            if self.header.errors.fcs_incorrect {
                errors.push("fcs incorrect".to_string())
            }

            if self.header.errors.alignment_problem {
                errors.push("alignment problem".to_string())
            }

            if self.header.errors.alignment_problem {
                errors.push("mii receive error".to_string())
            }

            return Some(errors);
        }

        None
    }

    /// validate_header checks that the error flags in the header are consistent with
    /// what can actually be seen in the Packet. It returns `()` or `Vec<WirestripperError>`.
    pub fn validate_header(&self) -> Result<(), Vec<WirestripperError>> {
        let mut errors = Vec::new();

        // mii_receive_problem: trust it is valid
        // alignment_problem: trust it is valid

        // fcs_incorrect
        let fcs_problem = !self.fcs_is_valid();
        if self.header.errors.fcs_incorrect ^ fcs_problem {
            errors.push(WirestripperError::FCSErrorError(
                self.header.errors.fcs_incorrect,
                fcs_problem,
            ));
        }

        // frame_too_long: unsure how Hilscher's product determines this...
        // They could be parsing up the protocol stack but that could be
        // unreliable, so we won't attempt to validate this.

        // sfd_not_found
        let sfd_problem = self.sfd_offset == 0;
        if self.header.errors.sfd_not_found ^ sfd_problem {
            errors.push(WirestripperError::SFDErrorError(
                self.header.errors.sfd_not_found,
                self.sfd_offset,
            ));
        }

        // frame_too_short
        let frame_too_short = self.frame().len() < 64;
        if self.header.errors.frame_too_short ^ frame_too_short {
            errors.push(WirestripperError::FrameTooShortErrorError(
                self.header.errors.frame_too_short,
                self.frame().len(),
            ));
        }

        // preamble_too_short
        let preamble_too_short = self.sfd_offset < 7;
        if self.header.errors.preamble_too_short ^ preamble_too_short {
            errors.push(WirestripperError::PreambleTooShortErrorError(
                self.header.errors.preamble_too_short,
                self.sfd_offset,
            ));
        }

        // preamble_too_long
        let preamble_too_long = self.sfd_offset > 7;
        if self.header.errors.preamble_too_long ^ preamble_too_long {
            errors.push(WirestripperError::PreambleTooLongErrorError(
                self.header.errors.preamble_too_long,
                self.sfd_offset,
            ));
        }

        // frame_length
        if self.header.frame_length as usize != self.packet.len() {
            errors.push(WirestripperError::InvalidFrameLength {
                header_value: self.header.frame_length as usize,
                packet_length: self.packet.len(),
            });
        }

        // reserved - used in version 2 records, which we don't support
        if self.header.reserved != 0 {
            errors.push(WirestripperError::ReservedBitsNonZero(self.header.reserved));
        }

        if (self.header.errors.preamble_too_long && self.header.errors.preamble_too_short)
            || (self.header.errors.frame_too_long && self.header.errors.frame_too_short)
            || (self.header.errors.sfd_not_found && self.header.errors.preamble_too_long)
        {
            errors.push(WirestripperError::InvalidErrorFlagCombination(
                self.header.errors,
            ));
        }

        if !errors.is_empty() {
            return Err(errors);
        }

        Ok(())
    }

    /// fcs returns a reference to the 4 FCS bytes at the end of the frame
    pub fn fcs(&self) -> &[u8] {
        &self.packet[0..self.sfd_offset]
    }

    /// packet returns a reference to the full 802.3 packet's bytes (preamble up to/including FCS)
    pub fn packet(&self) -> &[u8] {
        &self.packet
    }

    /// frame returns a reference to the Ethernet frame's bytes (including FCS)
    pub fn frame(&self) -> &[u8] {
        &self.packet[self.sfd_offset + 1..self.packet.len()]
    }

    /// frame_without_fcs returns a reference to the Ethernet frame's bytes (excluding FCS)
    pub fn frame_without_fcs(&self) -> &[u8] {
        &self.packet[self.sfd_offset + 1..self.packet.len() - 4]
    }

    /// fcs_is_valid returns true if the frame's CRC32 checksum is valid
    pub fn fcs_is_valid(&self) -> bool {
        let frame_fcs = self
            .packet
            .windows(4)
            .last()
            .unwrap()
            .read_u32::<LittleEndian>()
            .unwrap();

        let mut hasher = Hasher::new();
        hasher.update(&self.packet[self.sfd_offset + 1..self.packet.len() - 4]);
        let computed_fcs = hasher.finalize();

        frame_fcs == computed_fcs
    }

    /// any_error_flags_set returns the logical OR of all the netANALYZER header error flags
    pub fn any_error_flags_set(&self) -> bool {
        self.has_error
    }
}

impl TryFrom<&[u8]> for Record {
    type Error = WirestripperError;

    /// try_from decodes a slice of bytes into a netANALYZER PCAP link-type record structure
    fn try_from(data: &[u8]) -> Result<Self, WirestripperError> {
        // If there aren't at least 4 bytes, then we can't decode
        if data.len() < 4 {
            return Err(WirestripperError::RecordTooShort);
        }

        // If there aren't at least 8 bytes, then there can't be an FCS
        // Note: technically if the length is == 8 then the FCS could be valid
        //       but it would probably be meaningless. Oh well...
        if data.len() < 8 {
            return Err(WirestripperError::RecordTooShortForFCS);
        }

        let header = Header::from_bytes(&data[0..4]);

        // Not interesting to the author at this point, contact him
        // if you need this.
        if !header.transparent_mode {
            return Err(WirestripperError::OpaqueModeUnsupported);
        }

        // Version 2 is not interesting to the author at this point,
        // contact him if you need it.
        if header.header_version != 1 {
            return Err(WirestripperError::HeaderVersionUnsupported(
                header.header_version,
            ));
        }

        // GPIO ports are not interesting to the author at this point,
        // contact him if you need them.
        if header.port_type == PortType::GPIO {
            return Err(WirestripperError::GPIOModeUnsupported);
        }

        let has_error = data[0] != 0;

        let mut preamble_byte_count: u8 = 0;

        let frame_iter = data.iter().skip(4);

        let mut sfd_offset = 0usize;

        for (i, b) in frame_iter.enumerate() {
            if *b != 0x55u8 {
                if *b != 0xd5u8 {
                    return Err(WirestripperError::NoSFDAfterPreamble(*b));
                }
                sfd_offset = i;
                break;
            }

            preamble_byte_count += 1;
        }

        if preamble_byte_count == 0 {
            return Err(WirestripperError::NoSFDFound);
        }

        Ok(Record {
            header,
            has_error,
            sfd_offset,
            packet: data[4..data.len()].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{ErrorFlags, Header, PortType, Record, WirestripperError};
    use pretty_hex::pretty_hex;
    use std::convert::TryFrom;

    /// test_header_sample checks basic netANALYZER header decoding from a sample
    #[test]
    fn test_header_sample() {
        let test: [u8; 4] = [0x0, 0x6, 0x48, 0x0];
        let h = Header::from_bytes(&test[..]);
        assert!(!h.errors.mii_receive_error);
        assert!(!h.errors.alignment_problem);
        assert!(!h.errors.fcs_incorrect);
        assert!(!h.errors.frame_too_long);
        assert!(!h.errors.sfd_not_found);
        assert!(!h.errors.frame_too_short);
        assert!(!h.errors.preamble_too_short);
        assert!(!h.errors.preamble_too_long);
        assert_eq!(h.port_type, PortType::Ethernet);
        assert!(h.transparent_mode);
        assert_eq!(h.header_version, 1);
        assert_eq!(h.port_number, 0);
        assert_eq!(h.frame_length, 72);
        assert_eq!(h.reserved, 0);
        println!("{:?}", h)
    }

    /// test_header_errors_msb checks the MSB bit in the error bitfield decodes as expected
    #[test]
    fn test_header_errors_msb() {
        let test: [u8; 4] = [0x80, 0x6, 0x48, 0x00];
        let h = Header::from_bytes(&test[..]);
        println!("Test header bytes: {}", pretty_hex(&test));
        assert!(h.errors.preamble_too_long);
        assert!(!h.errors.mii_receive_error);
    }

    /// test_header_errors_lsb checks the LSB bit in the error bitfield decodes as expected
    #[test]
    fn test_header_errors_lsb() {
        let test: [u8; 4] = [0x01, 0x6, 0x48, 0x00];
        let h = Header::from_bytes(&test[..]);
        assert!(!h.errors.preamble_too_long);
        assert!(h.errors.mii_receive_error);
    }

    /// test_header_port0 checks that the port number bits are where we expect them
    #[test]
    fn test_header_port0() {
        let test: [u8; 4] = [0x0, 0x6, 0x7a, 0x0];
        let h = Header::from_bytes(&test[..]);
        assert_eq!(h.port_number, 0);
    }

    /// test_header_port1 checks that the port number bits are where we expect them
    #[test]
    fn test_header_port1() {
        let test: [u8; 4] = [0x0, 0x46, 0x44, 0x0];
        let h = Header::from_bytes(&test[..]);
        assert_eq!(h.port_number, 1);
    }

    const GOOD_SAMPLE_RECORD: [u8; 76] = [
        0x00u8, 0x06u8, 0x48u8, 0x00u8, 0x55u8, 0x55u8, 0x55u8, 0x55u8, 0x55u8, 0x55u8, 0x55u8,
        0xd5u8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0x0eu8, 0x2bu8, 0x7cu8, 0xffu8,
        0xd4u8, 0xb2u8, 0x08u8, 0x06u8, 0x00u8, 0x01u8, 0x08u8, 0x00u8, 0x06u8, 0x04u8, 0x00u8,
        0x01u8, 0x0eu8, 0x2bu8, 0x7cu8, 0xffu8, 0xd4u8, 0xb2u8, 0xc0u8, 0xa8u8, 0x07u8, 0x01u8,
        0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0xc0u8, 0xa8u8, 0x07u8, 0x04u8, 0x00u8,
        0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8,
        0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x97u8, 0xa2u8, 0xc3u8, 0x13u8,
    ];

    /// test_record_sample checks the whole record decoding with a known-good sample record
    #[test]
    fn test_record_sample() {
        let r = Record::try_from(&GOOD_SAMPLE_RECORD[..]).unwrap();
        r.validate_header().unwrap();
        assert!(!r.any_error_flags_set());
        assert!(r.fcs_is_valid());
    }

    const BAD_SAMPLE_RECORD: [u8; 76] = [
        0xc0u8, 0x06u8, 0x48u8, 0x00u8, 0x55u8, 0x55u8, 0x55u8, 0x55u8, 0x55u8, 0x55u8, 0x55u8,
        0xd5u8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0x0eu8, 0x2bu8, 0x7cu8, 0xffu8,
        0xd4u8, 0xb2u8, 0x08u8, 0x06u8, 0x00u8, 0x01u8, 0x08u8, 0x00u8, 0x06u8, 0x04u8, 0x00u8,
        0x01u8, 0x0eu8, 0x2bu8, 0x7cu8, 0xffu8, 0xd4u8, 0xb2u8, 0xc0u8, 0xa8u8, 0x07u8, 0x01u8,
        0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0xc0u8, 0xa8u8, 0x07u8, 0x04u8, 0x00u8,
        0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8,
        0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x97u8, 0xa2u8, 0xc3u8, 0x13u8,
    ];

    /// test_record_badcombo checks that Record::validate_header() detects invalid combinations
    /// of netANALYZER header error flags
    #[test]
    fn test_record_badcombo() {
        let r = Record::try_from(&BAD_SAMPLE_RECORD[..]).unwrap();
        match r.validate_header() {
            Err(e) => {
                let bad_flags = ErrorFlags {
                    preamble_too_long: true,
                    preamble_too_short: true,
                    frame_too_short: false,
                    sfd_not_found: false,
                    frame_too_long: false,
                    fcs_incorrect: false,
                    alignment_problem: false,
                    mii_receive_error: false,
                };

                assert!(e.contains(&WirestripperError::InvalidErrorFlagCombination(bad_flags)))
            }
            Ok(_) => {
                panic!("there must be errors!")
            }
        }
    }
}
