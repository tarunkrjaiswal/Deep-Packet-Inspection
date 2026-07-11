package com.packetanalyzer.mt;

import com.packetanalyzer.engine.ConnectionTracker;
import com.packetanalyzer.engine.RuleManager;
import com.packetanalyzer.parser.SniExtractor;
import com.packetanalyzer.types.*;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.function.BiConsumer;

public class FastPathProcessor {
    private int fpId;
    private BlockingQueue<PacketJob> inputQueue = new LinkedBlockingQueue<>(10000);
    private ConnectionTracker connTracker;
    private RuleManager ruleManager;
    private BiConsumer<PacketJob, PacketAction> outputCallback;
    
    private volatile boolean running = false;
    private Thread thread;
    
    private long packetsProcessed = 0;
    private long packetsForwarded = 0;
    private long packetsDropped = 0;
    private long sniExtractions = 0;
    private long classificationHits = 0;

    public FastPathProcessor(int fpId, RuleManager ruleManager, BiConsumer<PacketJob, PacketAction> outputCallback) {
        this.fpId = fpId;
        this.connTracker = new ConnectionTracker(fpId, 100000);
        this.ruleManager = ruleManager;
        this.outputCallback = outputCallback;
    }

    public void start() {
        if (running) return;
        running = true;
        thread = new Thread(this::run, "FP-Thread-" + fpId);
        thread.start();
    }

    public void stop() {
        if (!running) return;
        running = false;
        if (thread != null) {
            thread.interrupt();
            try { thread.join(); } catch (InterruptedException ignored) {}
        }
    }

    public BlockingQueue<PacketJob> getInputQueue() { return inputQueue; }
    public ConnectionTracker getConnectionTracker() { return connTracker; }

    private void run() {
        while (running) {
            try {
                PacketJob job = inputQueue.poll(100, TimeUnit.MILLISECONDS);
                if (job == null) {
                    connTracker.cleanupStale(300000);
                    continue;
                }
                
                packetsProcessed++;
                PacketAction action = processPacket(job);
                
                if (outputCallback != null) {
                    outputCallback.accept(job, action);
                }
                
                if (action == PacketAction.DROP) {
                    packetsDropped++;
                } else {
                    packetsForwarded++;
                }
            } catch (InterruptedException e) {
                if (!running) break;
            }
        }
    }

    private PacketAction processPacket(PacketJob job) {
        Connection conn = connTracker.getOrCreateConnection(job.tuple);
        if (conn == null) return PacketAction.FORWARD;
        
        connTracker.updateConnection(conn, job.data.length, true);
        
        if (job.tuple.protocol == Constants.PROTO_TCP) {
            updateTCPState(conn, job.tcpFlags);
        }
        
        if (conn.state == ConnectionState.BLOCKED) {
            return PacketAction.DROP;
        }
        
        if (conn.state != ConnectionState.CLASSIFIED && job.payloadLength > 0) {
            inspectPayload(job, conn);
        }
        
        return checkRules(job, conn);
    }

    private void inspectPayload(PacketJob job, Connection conn) {
        if (job.payloadLength == 0 || job.payloadOffset >= job.data.length) return;
        
        if (tryExtractSNI(job, conn)) return;
        if (tryExtractHTTPHost(job, conn)) return;
        
        if (job.tuple.dstPort == 53 || job.tuple.srcPort == 53) {
            String domain = SniExtractor.extractDNSQuery(job.data, job.payloadOffset, job.payloadLength);
            if (domain != null) {
                connTracker.classifyConnection(conn, AppType.DNS, domain);
                return;
            }
        }
        
        if (job.tuple.dstPort == 80) {
            connTracker.classifyConnection(conn, AppType.HTTP, "");
        } else if (job.tuple.dstPort == 443) {
            connTracker.classifyConnection(conn, AppType.HTTPS, "");
        }
    }

    private boolean tryExtractSNI(PacketJob job, Connection conn) {
        if (job.tuple.dstPort != 443 && job.payloadLength < 50) return false;
        
        String sni = SniExtractor.extractTLS(job.data, job.payloadOffset, job.payloadLength);
        if (sni != null) {
            sniExtractions++;
            AppType app = AppType.sniToAppType(sni);
            connTracker.classifyConnection(conn, app, sni);
            if (app != AppType.UNKNOWN && app != AppType.HTTPS) {
                classificationHits++;
            }
            return true;
        }
        return false;
    }

    private boolean tryExtractHTTPHost(PacketJob job, Connection conn) {
        if (job.tuple.dstPort != 80) return false;
        
        String host = SniExtractor.extractHTTPHost(job.data, job.payloadOffset, job.payloadLength);
        if (host != null) {
            AppType app = AppType.sniToAppType(host);
            connTracker.classifyConnection(conn, app, host);
            if (app != AppType.UNKNOWN && app != AppType.HTTP) {
                classificationHits++;
            }
            return true;
        }
        return false;
    }

    private PacketAction checkRules(PacketJob job, Connection conn) {
        if (ruleManager == null) return PacketAction.FORWARD;
        
        RuleManager.BlockReason reason = ruleManager.shouldBlock(
                (int)job.tuple.srcIp, (int)job.tuple.dstIp, job.tuple.dstPort, conn.appType, conn.sni);
                
        if (reason != null) {
            connTracker.blockConnection(conn);
            return PacketAction.DROP;
        }
        return PacketAction.FORWARD;
    }

    private void updateTCPState(Connection conn, int tcpFlags) {
        if ((tcpFlags & Constants.TCP_SYN) != 0) {
            if ((tcpFlags & Constants.TCP_ACK) != 0) {
                conn.synAckSeen = true;
            } else {
                conn.synSeen = true;
            }
        }
        
        if (conn.synSeen && conn.synAckSeen && ((tcpFlags & Constants.TCP_ACK) != 0)) {
            if (conn.state == ConnectionState.NEW) {
                conn.state = ConnectionState.ESTABLISHED;
            }
        }
        
        if ((tcpFlags & Constants.TCP_FIN) != 0) {
            conn.finSeen = true;
        }
        
        if ((tcpFlags & Constants.TCP_RST) != 0) {
            conn.state = ConnectionState.CLOSED;
        }
        
        if (conn.finSeen && ((tcpFlags & Constants.TCP_ACK) != 0)) {
            conn.state = ConnectionState.CLOSED;
        }
    }
    
    public FPStats getStats() {
        FPStats s = new FPStats();
        s.packetsProcessed = packetsProcessed;
        s.packetsForwarded = packetsForwarded;
        s.packetsDropped = packetsDropped;
        s.connectionsTracked = connTracker.getActiveCount();
        return s;
    }
    
    public static class FPStats {
        public long packetsProcessed;
        public long packetsForwarded;
        public long packetsDropped;
        public long connectionsTracked;
    }
}
