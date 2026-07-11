package com.packetanalyzer.types;

public class PcapGlobalHeader {
    public long magicNumber;
    public int versionMajor;
    public int versionMinor;
    public int thisZone;
    public long sigFigs;
    public long snapLen;
    public long network;
}
