package com.packetanalyzer;

import com.packetanalyzer.engine.DpiEngine;
import com.packetanalyzer.parser.PacketParser;
import com.packetanalyzer.reader.PcapReader;

import com.packetanalyzer.types.ParsedPacket;
import com.packetanalyzer.types.RawPacket;

import java.text.SimpleDateFormat;
import java.util.Date;

public class Main {
    private static void printPacketSummary(ParsedPacket pkt, int packetNum) {
        Date time = new Date(pkt.timestampSec * 1000L);
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        
        System.out.printf("\n========== Packet #%d ==========\n", packetNum);
        System.out.printf("Time: %s.%06d\n", sdf.format(time), pkt.timestampUsec);
        
        System.out.println("\n[Ethernet]");
        System.out.printf("  Source MAC:      %s\n", pkt.srcMac);
        System.out.printf("  Destination MAC: %s\n", pkt.destMac);
        System.out.printf("  EtherType:       0x%04x", pkt.etherType);
        
        if (pkt.etherType == com.packetanalyzer.types.Constants.ETHERTYPE_IPV4) System.out.print(" (IPv4)");
        else if (pkt.etherType == com.packetanalyzer.types.Constants.ETHERTYPE_IPV6) System.out.print(" (IPv6)");
        else if (pkt.etherType == com.packetanalyzer.types.Constants.ETHERTYPE_ARP) System.out.print(" (ARP)");
        System.out.println();
        
        if (pkt.hasIp) {
            System.out.printf("\n[IPv%d]\n", pkt.ipVersion);
            System.out.printf("  Source IP:      %s\n", pkt.srcIp);
            System.out.printf("  Destination IP: %s\n", pkt.destIp);
            System.out.printf("  Protocol:       %s\n", PacketParser.protocolToString(pkt.protocol));
            System.out.printf("  TTL:            %d\n", pkt.ttl);
        }
        
        if (pkt.hasTcp) {
            System.out.println("\n[TCP]");
            System.out.printf("  Source Port:      %d\n", pkt.srcPort);
            System.out.printf("  Destination Port: %d\n", pkt.destPort);
            System.out.printf("  Sequence Number:  %d\n", pkt.seqNumber);
            System.out.printf("  Ack Number:       %d\n", pkt.ackNumber);
            System.out.printf("  Flags:            %s\n", PacketParser.tcpFlagsToString(pkt.tcpFlags));
        }
        
        if (pkt.hasUdp) {
            System.out.println("\n[UDP]");
            System.out.printf("  Source Port:      %d\n", pkt.srcPort);
            System.out.printf("  Destination Port: %d\n", pkt.destPort);
        }
        
        if (pkt.payloadLength > 0) {
            System.out.println("\n[Payload]");
            System.out.printf("  Length: %d bytes\n", pkt.payloadLength);
            
            System.out.print("  Preview: ");
            int previewLen = Math.min(pkt.payloadLength, 32);
            for (int i = 0; i < previewLen; i++) {
                System.out.printf("%02x ", pkt.packetData[pkt.payloadOffset + i] & 0xFF);
            }
            if (pkt.payloadLength > 32) System.out.print("...");
            System.out.println();
        }
    }

    private static void printUsage() {
        System.out.println("Usage: java com.packetanalyzer.Main [options]");
        System.out.println("\nModes:");
        System.out.println("  parse <pcap_file> [max_packets]     - Parse and print packet summaries");
        System.out.println("  dpi <input_pcap> <output_pcap>      - Run Deep Packet Inspection Engine");
    }

    public static void main(String[] args) {
        System.out.println("====================================");
        System.out.println("     Packet Analyzer v1.0 (Java)");
        System.out.println("====================================\n");
        
        if (args.length < 2) {
            printUsage();
            System.exit(1);
        }
        
        String mode = args[0];
        
        if (mode.equals("parse")) {
            String filename = args[1];
            int maxPackets = -1;
            if (args.length >= 3) {
                maxPackets = Integer.parseInt(args[2]);
            }
            
            PcapReader reader = new PcapReader();
            if (!reader.open(filename)) {
                System.exit(1);
            }
            
            System.out.println("\n--- Reading packets ---");
            
            RawPacket rawPacket = new RawPacket();
            ParsedPacket parsedPacket = new ParsedPacket();
            int packetCount = 0;
            int parseErrors = 0;
            
            while (reader.readNextPacket(rawPacket)) {
                packetCount++;
                
                if (PacketParser.parse(rawPacket, parsedPacket)) {
                    printPacketSummary(parsedPacket, packetCount);
                } else {
                    System.err.println("Warning: Failed to parse packet #" + packetCount);
                    parseErrors++;
                }
                
                if (maxPackets > 0 && packetCount >= maxPackets) {
                    System.out.println("\n(Stopped after " + maxPackets + " packets)");
                    break;
                }
            }
            
            System.out.println("\n====================================");
            System.out.println("Summary:");
            System.out.println("  Total packets read:  " + packetCount);
            System.out.println("  Parse errors:        " + parseErrors);
            System.out.println("====================================");
            
            reader.close();
            
        } else if (mode.equals("dpi")) {
            if (args.length < 3) {
                printUsage();
                System.exit(1);
            }
            
            String inputFile = args[1];
            String outputFile = args[2];
            
            DpiEngine.Config config = new DpiEngine.Config();
            config.numLoadBalancers = 2; // Default
            config.fpsPerLb = 4; // Default
            
            for (int i = 3; i < args.length; i++) {
                if (args[i].equals("--block-app") && i + 1 < args.length) {
                    config.blockApps.add(args[++i]);
                } else if (args[i].equals("--block-domain") && i + 1 < args.length) {
                    config.blockDomains.add(args[++i]);
                } else if (args[i].equals("--block-ip") && i + 1 < args.length) {
                    config.blockIps.add(args[++i]);
                } else if (args[i].equals("--lbs") && i + 1 < args.length) {
                    config.numLoadBalancers = Integer.parseInt(args[++i]);
                } else if (args[i].equals("--fps") && i + 1 < args.length) {
                    config.fpsPerLb = Integer.parseInt(args[++i]);
                } else if (args[i].equals("--json") && i + 1 < args.length) {
                    config.jsonOutput = args[++i];
                }
            }
            
            System.out.println("╔══════════════════════════════════════════════════════════════╗");
            System.out.println("║              DPI ENGINE v2.0 (Multi-threaded)                ║");
            System.out.println("╠══════════════════════════════════════════════════════════════╣");
            System.out.printf("║ Load Balancers: %2d    FPs per LB: %2d    Total FPs: %2d       ║\n", 
                              config.numLoadBalancers, config.fpsPerLb, config.numLoadBalancers * config.fpsPerLb);
            System.out.println("╚══════════════════════════════════════════════════════════════╝\n");
            
            DpiEngine engine = new DpiEngine(config);
            if (!engine.processFile(inputFile, outputFile)) {
                System.err.println("Failed to process PCAP file through DPI engine");
                System.exit(1);
            }
            
        } else {
            System.err.println("Unknown mode: " + mode);
            printUsage();
            System.exit(1);
        }
    }
}
