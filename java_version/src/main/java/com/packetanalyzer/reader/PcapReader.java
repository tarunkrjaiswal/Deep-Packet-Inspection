package com.packetanalyzer.reader;

import com.packetanalyzer.types.PcapGlobalHeader;
import com.packetanalyzer.types.RawPacket;

import java.io.DataInputStream;
import java.io.EOFException;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class PcapReader {
    private static final long PCAP_MAGIC = 0xa1b2c3d4L;
    private static final long PCAP_MAGIC_NSEC = 0xa1b23c4dL;

    private DataInputStream file;
    private PcapGlobalHeader globalHeader;
    private ByteOrder byteOrder = ByteOrder.LITTLE_ENDIAN;
    private boolean isNsec = false;

    public boolean open(String filename) {
        close();
        try {
            file = new DataInputStream(new FileInputStream(filename));
            
            byte[] headerBytes = new byte[24];
            file.readFully(headerBytes);
            
            ByteBuffer bb = ByteBuffer.wrap(headerBytes);
            bb.order(ByteOrder.LITTLE_ENDIAN);
            long magic = Integer.toUnsignedLong(bb.getInt(0));
            
            if (magic == PCAP_MAGIC || magic == PCAP_MAGIC_NSEC) {
                byteOrder = ByteOrder.LITTLE_ENDIAN;
            } else {
                bb.order(ByteOrder.BIG_ENDIAN);
                magic = Integer.toUnsignedLong(bb.getInt(0));
                if (magic == PCAP_MAGIC || magic == PCAP_MAGIC_NSEC) {
                    byteOrder = ByteOrder.BIG_ENDIAN;
                } else {
                    System.err.println("Error: Invalid PCAP magic number: 0x" + Long.toHexString(magic));
                    close();
                    return false;
                }
            }
            
            if (magic == PCAP_MAGIC_NSEC) {
                isNsec = true;
            }
            
            bb.getInt(); // advance past magic number
            
            globalHeader = new PcapGlobalHeader();
            globalHeader.magicNumber = magic;
            globalHeader.versionMajor = Short.toUnsignedInt(bb.getShort());
            globalHeader.versionMinor = Short.toUnsignedInt(bb.getShort());
            globalHeader.thisZone = bb.getInt();
            globalHeader.sigFigs = Integer.toUnsignedLong(bb.getInt());
            globalHeader.snapLen = Integer.toUnsignedLong(bb.getInt());
            globalHeader.network = Integer.toUnsignedLong(bb.getInt());
            
            System.out.println("Opened PCAP file: " + filename);
            System.out.println("  Version: " + globalHeader.versionMajor + "." + globalHeader.versionMinor);
            System.out.println("  Snaplen: " + globalHeader.snapLen + " bytes");
            System.out.println("  Link type: " + globalHeader.network + (globalHeader.network == 1 ? " (Ethernet)" : ""));
            
            return true;
        } catch (IOException e) {
            System.err.println("Error: Could not open file: " + filename);
            return false;
        }
    }

    public void close() {
        if (file != null) {
            try {
                file.close();
            } catch (IOException ignored) {}
            file = null;
        }
    }

    public boolean readNextPacket(RawPacket packet) {
        if (file == null) return false;
        
        try {
            byte[] headerBytes = new byte[16];
            file.readFully(headerBytes);
            
            ByteBuffer bb = ByteBuffer.wrap(headerBytes);
            bb.order(byteOrder);
            
            packet.tsSec = Integer.toUnsignedLong(bb.getInt());
            packet.tsUsec = Integer.toUnsignedLong(bb.getInt());
            packet.inclLen = Integer.toUnsignedLong(bb.getInt());
            packet.origLen = Integer.toUnsignedLong(bb.getInt());
            
            if (packet.inclLen > globalHeader.snapLen || packet.inclLen > 65535) {
                System.err.println("Error: Invalid packet length: " + packet.inclLen);
                return false;
            }
            
            packet.data = new byte[(int) packet.inclLen];
            file.readFully(packet.data);
            
            return true;
        } catch (EOFException e) {
            return false;
        } catch (IOException e) {
            System.err.println("Error: Could not read packet data");
            return false;
        }
    }

    public PcapGlobalHeader getGlobalHeader() {
        return globalHeader;
    }
}
