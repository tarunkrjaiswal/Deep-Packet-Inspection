package com.packetanalyzer.parser;

import com.packetanalyzer.types.Constants;
import com.packetanalyzer.types.ParsedPacket;
import com.packetanalyzer.types.RawPacket;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class PacketParser {
    public static boolean parse(RawPacket raw, ParsedPacket parsed) {
        parsed.hasIp = false;
        parsed.hasTcp = false;
        parsed.hasUdp = false;
        parsed.payloadLength = 0;
        parsed.payloadOffset = 0;
        
        parsed.timestampSec = raw.tsSec;
        parsed.timestampUsec = raw.tsUsec;
        parsed.packetData = raw.data;
        
        ByteBuffer bb = ByteBuffer.wrap(raw.data);
        bb.order(ByteOrder.BIG_ENDIAN); // Network byte order is Big Endian
        
        int offset = 0;
        
        if (!parseEthernet(bb, parsed)) {
            return false;
        }
        
        offset += 14;
        
        if (parsed.etherType == Constants.ETHERTYPE_IPV4) {
            int ipHeaderLen = parseIPv4(bb, parsed, offset);
            if (ipHeaderLen <= 0) return false;
            
            offset += ipHeaderLen;
            
            if (parsed.protocol == Constants.PROTO_TCP) {
                int tcpHeaderLen = parseTCP(bb, parsed, offset);
                if (tcpHeaderLen <= 0) return false;
                offset += tcpHeaderLen;
            } else if (parsed.protocol == Constants.PROTO_UDP) {
                int udpHeaderLen = parseUDP(bb, parsed, offset);
                if (udpHeaderLen <= 0) return false;
                offset += udpHeaderLen;
            }
        }
        
        if (offset < raw.data.length) {
            parsed.payloadLength = raw.data.length - offset;
            parsed.payloadOffset = offset;
        } else {
            parsed.payloadLength = 0;
            parsed.payloadOffset = 0;
        }
        
        return true;
    }
    
    private static boolean parseEthernet(ByteBuffer bb, ParsedPacket parsed) {
        if (bb.capacity() < 14) return false;
        
        byte[] destMac = new byte[6];
        byte[] srcMac = new byte[6];
        
        bb.position(0);
        bb.get(destMac);
        bb.get(srcMac);
        
        parsed.destMac = macToString(destMac);
        parsed.srcMac = macToString(srcMac);
        parsed.etherType = Short.toUnsignedInt(bb.getShort());
        
        return true;
    }
    
    private static int parseIPv4(ByteBuffer bb, ParsedPacket parsed, int offset) {
        if (bb.capacity() < offset + 20) return -1;
        
        bb.position(offset);
        byte versionIhl = bb.get();
        parsed.ipVersion = (versionIhl >> 4) & 0x0F;
        int ihl = versionIhl & 0x0F;
        
        if (parsed.ipVersion != 4) return -1;
        
        int ipHeaderLen = ihl * 4;
        if (ipHeaderLen < 20 || bb.capacity() < offset + ipHeaderLen) return -1;
        
        bb.position(offset + 8);
        parsed.ttl = Byte.toUnsignedInt(bb.get());
        parsed.protocol = Byte.toUnsignedInt(bb.get());
        
        bb.position(offset + 12);
        int srcIp = bb.getInt();
        int destIp = bb.getInt();
        
        parsed.srcIp = ipToString(srcIp);
        parsed.destIp = ipToString(destIp);
        parsed.hasIp = true;
        
        return ipHeaderLen;
    }
    
    private static int parseTCP(ByteBuffer bb, ParsedPacket parsed, int offset) {
        if (bb.capacity() < offset + 20) return -1;
        
        bb.position(offset);
        parsed.srcPort = Short.toUnsignedInt(bb.getShort());
        parsed.destPort = Short.toUnsignedInt(bb.getShort());
        parsed.seqNumber = Integer.toUnsignedLong(bb.getInt());
        parsed.ackNumber = Integer.toUnsignedLong(bb.getInt());
        
        byte dataOffset = bb.get();
        int tcpHeaderLen = ((dataOffset >> 4) & 0x0F) * 4;
        
        parsed.tcpFlags = Byte.toUnsignedInt(bb.get());
        
        if (tcpHeaderLen < 20 || bb.capacity() < offset + tcpHeaderLen) return -1;
        
        parsed.hasTcp = true;
        
        return tcpHeaderLen;
    }
    
    private static int parseUDP(ByteBuffer bb, ParsedPacket parsed, int offset) {
        if (bb.capacity() < offset + 8) return -1;
        
        bb.position(offset);
        parsed.srcPort = Short.toUnsignedInt(bb.getShort());
        parsed.destPort = Short.toUnsignedInt(bb.getShort());
        
        parsed.hasUdp = true;
        
        return 8;
    }
    
    public static String macToString(byte[] mac) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < mac.length; i++) {
            if (i > 0) sb.append(":");
            sb.append(String.format("%02x", mac[i]));
        }
        return sb.toString();
    }
    
    public static String ipToString(int ip) {
        return ((ip >> 24) & 0xFF) + "." +
               ((ip >> 16) & 0xFF) + "." +
               ((ip >> 8) & 0xFF) + "." +
               (ip & 0xFF);
    }
    
    public static String protocolToString(int protocol) {
        switch (protocol) {
            case Constants.PROTO_ICMP: return "ICMP";
            case Constants.PROTO_TCP: return "TCP";
            case Constants.PROTO_UDP: return "UDP";
            default: return "Unknown(" + protocol + ")";
        }
    }
    
    public static String tcpFlagsToString(int flags) {
        StringBuilder sb = new StringBuilder();
        if ((flags & Constants.TCP_SYN) != 0) sb.append("SYN ");
        if ((flags & Constants.TCP_ACK) != 0) sb.append("ACK ");
        if ((flags & Constants.TCP_FIN) != 0) sb.append("FIN ");
        if ((flags & Constants.TCP_RST) != 0) sb.append("RST ");
        if ((flags & Constants.TCP_PSH) != 0) sb.append("PSH ");
        if ((flags & Constants.TCP_URG) != 0) sb.append("URG ");
        
        String result = sb.toString().trim();
        return result.isEmpty() ? "none" : result;
    }
}
