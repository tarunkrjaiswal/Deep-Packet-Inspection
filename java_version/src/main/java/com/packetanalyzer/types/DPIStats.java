package com.packetanalyzer.types;
import java.util.concurrent.atomic.AtomicLong;

public class DPIStats {
    public AtomicLong totalPackets = new AtomicLong(0);
    public AtomicLong totalBytes = new AtomicLong(0);
    public AtomicLong forwardedPackets = new AtomicLong(0);
    public AtomicLong droppedPackets = new AtomicLong(0);
    public AtomicLong tcpPackets = new AtomicLong(0);
    public AtomicLong udpPackets = new AtomicLong(0);
    public AtomicLong otherPackets = new AtomicLong(0);
    public AtomicLong activeConnections = new AtomicLong(0);
}
