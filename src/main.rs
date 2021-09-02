// Copyright 2021 Simeon Miteff

use anyhow::{Context, Result};
use clap::{App, AppSettings, Arg, SubCommand};
use pretty_hex::pretty_hex;
use rpcap::read::PcapReader;
use rpcap::write::{PcapWriter, WriteOptions};
use rpcap::{CapturedPacket, Linktype};
use std::convert::TryFrom;
use std::fs::File;
use std::io::BufReader;
use std::io::BufWriter;
use std::process::exit;

fn main() -> Result<()> {
    let arg = App::new("wirestripper").
        version("0.1.4").
        author("Simeon Miteff <simeon@miteff.co>").
        about("Read Ethernet packet (a.k.a. Hilscher netANALYZER transparent mode PCAP link-type\n\
                / raw Ethernet PHY-level) PCAP files, write Ethernet link-type PCAP files.").
        setting(AppSettings::SubcommandRequiredElseHelp).
        arg(Arg::with_name("input").
            short("i").
            long("input-file").
            value_name("INPUT").
            help("Specifies the input netANALYZER link-type PCAP file").
            required(true).
            validator(|v| if std::path::Path::new(&v).exists() {
                    Ok(())
                } else {
                    Err(format!("input file {} not found", v))
            }).
            takes_value(true)
        ).subcommand(
        SubCommand::with_name("strip").
            about("Write valid frames (only) to an Ethernet link-type pcap file (stripped out of \
            netANALYZER link-type records)").
            arg(Arg::with_name("output").
                short("o").
                long("output-file").
                value_name("OUTPUT").
                help("Sets the output Ethernet link-type pcap file for output frames").
                required(true).
                takes_value(true)
            ).
            arg(Arg::with_name("strict").
                short("s").
                long("strict").
                help("Skip PCAP records with invalid netANALYZER headers").
                required(false).
                takes_value(false)
            )
        ).subcommand(
        SubCommand::with_name("check").
            about("Check netANALYZER transparent mode PCAP link-type records").
            arg(Arg::with_name("verbose").
                short("v").
                long("verbose").
                help("Don't just check for consistency, but report errors").
                required(false).
                takes_value(false)
            )
    ).get_matches();

    let infile_name = arg
        .value_of("input")
        .context("Unable to get input file name from --input-file argument")?;
    let infile =
        File::open(infile_name).context(format!("Unable to open input file {}", infile_name))?;
    let reader = BufReader::new(infile);
    let mut pcapr = PcapReader::new(reader)
        .context(format!("Problem reading {} as a PCAP file", infile_name))?;

    if pcapr.get_linktype() != u32::from(Linktype::NETANALYZER_TRANSPARENT) {
        println!(
            "Unsupported input pcap link type {}. Expecting NETANALYZER_TRANSPARENT, aborting.",
            pcapr.get_linktype()
        );
        exit(1);
    }

    let cmd_strip = arg.subcommand_matches("strip");
    let cmd_check = arg.subcommand_matches("check");

    let mut pcapw = match cmd_strip {
        Some(strip_arg) => {
            let outfile_name = strip_arg
                .value_of("output")
                .context("Unable to get output file name from --output-file argument")?;
            let outfile = File::create(outfile_name)
                .context(format!("Unable to open output file {}", outfile_name))?;
            let writer = BufWriter::new(outfile);
            Some(
                PcapWriter::new(
                    writer,
                    WriteOptions {
                        snaplen: pcapr.get_snaplen(),
                        linktype: u32::from(Linktype::ETHERNET),
                    },
                )
                .context("Unable to create PCAP writer")?,
            )
        }
        None => None,
    };

    let mut record_count = 0usize;
    let mut error_count = 0usize;

    while let Some(pcap_record) = pcapr.next().context("problem reading PCAP record")? {
        record_count += 1;

        let record = match wirestripper::Record::try_from(pcap_record.data) {
            Ok(frame) => frame,
            Err(e) => {
                println!(
                    "Problem decoding PCAP record {} into netANALYZER record: {:?}",
                    record_count, e
                );
                println!("PCAP record contents:\n{}", pretty_hex(&pcap_record.data));
                println!();

                error_count += 1;

                continue;
            }
        };

        if cmd_strip.is_some() {
            if let Some(c) = cmd_strip {
                if c.is_present("strict") {
                    match record.validate_header() {
                        Err(_) => {
                            println!(
                                "Skipping record {} due to netANALYZER record header validation \
                        error, re-run with \"check\" subcommand for details.",
                                record_count
                            );

                            error_count += 1;

                            continue;
                        }
                        Ok(()) => {
                            println!("Record {} is OK, will strip it normally.", record_count)
                        }
                    }
                }
            }

            let ethernet = record.frame();

            if let Some(ref mut w) = pcapw {
                w.write(&CapturedPacket {
                    time: pcap_record.time,
                    data: ethernet,
                    orig_len: ethernet.len(),
                })
                .context("failed to write packet to output file")?
            } else {
                unreachable!();
            }
        }

        if cmd_check.is_some() {
            match record.validate_header() {
                Ok(()) => {
                    if let Some(c) = cmd_check {
                        if c.is_present("verbose") {
                            println!("Record {} is valid.", record_count);
                        }
                    }
                }
                Err(errors) => {
                    println!("Record {} is invalid, here are the issues:", record_count);
                    for e in errors {
                        println!("\t - {}", e)
                    }
                    println!("Header: {:#?}", record.header);
                    println!("PCAP record contents:\n{}", pretty_hex(&pcap_record.data));

                    error_count += 1;
                }
            }

            if let Some(c) = cmd_check {
                if c.is_present("verbose") {
                    if let Some(reports) = record.report_errors() {
                        println!("Here are known errors in the packet:");
                        for item in reports {
                            println!("\t - {}", item);
                        }
                    }
                }
            }
            println!();
        }
    }

    println!(
        "Processed {} records with {} errors.",
        record_count, error_count
    );

    if let Some(ref mut w) = pcapw {
        w.flush()?
    }

    if error_count != 0 {
        exit(1);
    }

    Ok(())
}
