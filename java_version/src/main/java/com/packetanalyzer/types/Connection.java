package com.packetanalyzer.types;

public class Connection {
    public FiveTuple tuple;
    public ConnectionState state = ConnectionState.NEW;
    public AppType appType = AppType.UNKNOWN;
    public String sni;
    
    public long packetsIn = 0;
    public long packetsOut = 0;
    public long bytesIn = 0;
    public long bytesOut = 0;
    
    public long firstSeen; // Use system time millis
    public long lastSeen;
    
    public PacketAction action = PacketAction.FORWARD;
    
    public boolean synSeen = false;
    public boolean synAckSeen = false;
    public boolean finSeen = false;
}
