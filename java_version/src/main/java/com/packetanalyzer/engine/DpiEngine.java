package com.packetanalyzer.engine;

import com.packetanalyzer.mt.*;
import com.packetanalyzer.parser.PacketParser;
import com.packetanalyzer.reader.PcapReader;
import com.packetanalyzer.types.*;

import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.function.BiConsumer;

public class DpiEngine {

    public static class Config {
        public int numLoadBalancers = 1;
        public int fpsPerLb = 4;
        public String rulesFile = "";
        public java.util.List<String> blockApps = new java.util.ArrayList<>();
        public java.util.List<String> blockDomains = new java.util.ArrayList<>();
        public java.util.List<String> blockIps = new java.util.ArrayList<>();
        public String jsonOutput = "";
    }

    private Config config;
    private RuleManager ruleManager;
    private FPManager fpManager;
    private LBManager lbManager;
    private GlobalConnectionTable globalConnTable;

    private BlockingQueue<PacketJob> outputQueue = new LinkedBlockingQueue<>(10000);
    private volatile boolean running = false;
    private Thread outputThread;
    private FileOutputStream outputFile;

    private DPIStats stats = new DPIStats();

    public DpiEngine(Config config) {
        this.config = config;
    }

    public boolean initialize() {
        ruleManager = new RuleManager();
        if (config.rulesFile != null && !config.rulesFile.isEmpty()) {
            ruleManager.loadRules(config.rulesFile);
        }
        for (String app : config.blockApps) {
            try { ruleManager.blockApp(AppType.valueOf(app.toUpperCase())); } catch (Exception ignored) {}
        }
        for (String domain : config.blockDomains) {
            ruleManager.blockDomain(domain);
        }
        for (String ip : config.blockIps) {
            ruleManager.blockIP(ip);
        }

        BiConsumer<PacketJob, PacketAction> outputCb = this::handleOutput;

        int totalFps = config.numLoadBalancers * config.fpsPerLb;
        fpManager = new FPManager(totalFps, ruleManager, outputCb);
        lbManager = new LBManager(config.numLoadBalancers, config.fpsPerLb, fpManager.getFPs());

        globalConnTable = new GlobalConnectionTable(totalFps);
        for (int i = 0; i < totalFps; i++) {
            globalConnTable.registerTracker(i, fpManager.getFP(i).getConnectionTracker());
        }

        return true;
    }

    public void start() {
        if (running) return;
        running = true;
        
        outputThread = new Thread(this::outputThreadFunc, "Output-Thread");
        outputThread.start();
        
        fpManager.startAll();
        lbManager.startAll();
    }

    public void stop() {
        if (!running) return;
        running = false;
        
        if (lbManager != null) lbManager.stopAll();
        if (fpManager != null) fpManager.stopAll();
        
        if (outputThread != null) {
            outputThread.interrupt();
            try { outputThread.join(); } catch (InterruptedException ignored) {}
        }
    }

    public boolean processFile(String inputFile, String outputFilePath) {
        if (ruleManager == null) {
            if (!initialize()) return false;
        }
        
        try {
            outputFile = new FileOutputStream(outputFilePath);
        } catch (IOException e) {
            return false;
        }
        
        start();
        
        PcapReader reader = new PcapReader();
        if (!reader.open(inputFile)) {
            return false;
        }
        
        writeOutputHeader(reader.getGlobalHeader());
        
        RawPacket raw = new RawPacket();
        ParsedPacket parsed = new ParsedPacket();
        int packetId = 0;
        
        while (reader.readNextPacket(raw)) {
            if (!PacketParser.parse(raw, parsed)) continue;
            
            if (!parsed.hasIp || (!parsed.hasTcp && !parsed.hasUdp)) continue;
            
            PacketJob job = createPacketJob(raw, parsed, packetId++);
            
            stats.totalPackets.incrementAndGet();
            stats.totalBytes.addAndGet(raw.data.length);
            
            if (parsed.hasTcp) stats.tcpPackets.incrementAndGet();
            else if (parsed.hasUdp) stats.udpPackets.incrementAndGet();
            
            LoadBalancer lb = lbManager.getLBForPacket(job.tuple);
            try {
                lb.getInputQueue().put(job);
            } catch (InterruptedException ignored) {}
        }
        
        reader.close();
        
        try { Thread.sleep(500); } catch (InterruptedException ignored) {}
        stop();
        
        try { outputFile.close(); } catch (IOException ignored) {}
        
        System.out.println("\n╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║                      PROCESSING REPORT                       ║");
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.printf("║ Total Packets:                %-30d ║\n", stats.totalPackets.get());
        System.out.printf("║ Total Bytes:                  %-30d ║\n", stats.totalBytes.get());
        System.out.printf("║ TCP Packets:                  %-30d ║\n", stats.tcpPackets.get());
        System.out.printf("║ UDP Packets:                  %-30d ║\n", stats.udpPackets.get());
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.printf("║ Forwarded:                    %-30d ║\n", stats.forwardedPackets.get());
        System.out.printf("║ Dropped:                      %-30d ║\n", stats.droppedPackets.get());
        
        System.out.println(globalConnTable.generateReport());
        
        if (config.jsonOutput != null && !config.jsonOutput.isEmpty()) {
            globalConnTable.exportJson(config.jsonOutput, stats);
        }
        
        return true;
    }

    private PacketJob createPacketJob(RawPacket raw, ParsedPacket parsed, int packetId) {
        PacketJob job = new PacketJob();
        job.packetId = packetId;
        job.tsSec = raw.tsSec;
        job.tsUsec = raw.tsUsec;
        
        job.tuple = new FiveTuple(RuleManager.parseIP(parsed.srcIp), 
                                  RuleManager.parseIP(parsed.destIp), 
                                  parsed.srcPort, 
                                  parsed.destPort, 
                                  parsed.protocol);
        
        job.tcpFlags = parsed.tcpFlags;
        job.data = raw.data;
        
        job.ethOffset = 0;
        job.ipOffset = 14;
        
        if (job.data.length > 14) {
            int ipIhl = job.data[14] & 0x0F;
            int ipHeaderLen = ipIhl * 4;
            job.transportOffset = 14 + ipHeaderLen;
            
            if (parsed.hasTcp && job.data.length > job.transportOffset) {
                int tcpDataOffset = (job.data[job.transportOffset + 12] >> 4) & 0x0F;
                int tcpHeaderLen = tcpDataOffset * 4;
                job.payloadOffset = job.transportOffset + tcpHeaderLen;
            } else if (parsed.hasUdp) {
                job.payloadOffset = job.transportOffset + 8;
            }
            
            if (job.payloadOffset < job.data.length) {
                job.payloadLength = job.data.length - job.payloadOffset;
            }
        }
        
        return job;
    }

    private void handleOutput(PacketJob job, PacketAction action) {
        if (action == PacketAction.DROP) {
            stats.droppedPackets.incrementAndGet();
            return;
        }
        stats.forwardedPackets.incrementAndGet();
        try {
            outputQueue.put(job);
        } catch (InterruptedException ignored) {}
    }

    private void outputThreadFunc() {
        while (running || !outputQueue.isEmpty()) {
            try {
                PacketJob job = outputQueue.poll(100, TimeUnit.MILLISECONDS);
                if (job != null) {
                    writeOutputPacket(job);
                }
            } catch (InterruptedException e) {
                if (!running) break;
            }
        }
    }

    private synchronized void writeOutputHeader(PcapGlobalHeader header) {
        if (outputFile == null) return;
        try {
            ByteBuffer bb = ByteBuffer.allocate(24);
            bb.order(ByteOrder.LITTLE_ENDIAN); // Follow pcap standard
            bb.putInt((int)header.magicNumber);
            bb.putShort((short)header.versionMajor);
            bb.putShort((short)header.versionMinor);
            bb.putInt(header.thisZone);
            bb.putInt((int)header.sigFigs);
            bb.putInt((int)header.snapLen);
            bb.putInt((int)header.network);
            outputFile.write(bb.array());
        } catch (IOException ignored) {}
    }

    private synchronized void writeOutputPacket(PacketJob job) {
        if (outputFile == null) return;
        try {
            ByteBuffer bb = ByteBuffer.allocate(16);
            bb.order(ByteOrder.LITTLE_ENDIAN); // Follow pcap standard
            bb.putInt((int)job.tsSec);
            bb.putInt((int)job.tsUsec);
            bb.putInt(job.data.length);
            bb.putInt(job.data.length);
            outputFile.write(bb.array());
            outputFile.write(job.data);
        } catch (IOException ignored) {}
    }
}
