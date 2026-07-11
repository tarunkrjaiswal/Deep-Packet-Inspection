package com.packetanalyzer.engine;

import com.packetanalyzer.types.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

public class ConnectionTracker {
    private int fpId;
    private int maxConnections;
    private Map<FiveTuple, Connection> connections = new ConcurrentHashMap<>();
    
    private long totalSeen = 0;
    private long classifiedCount = 0;
    private long blockedCount = 0;

    public ConnectionTracker(int fpId, int maxConnections) {
        this.fpId = fpId;
        this.maxConnections = maxConnections;
    }

    public synchronized Connection getOrCreateConnection(FiveTuple tuple) {
        Connection conn = connections.get(tuple);
        if (conn != null) return conn;

        if (connections.size() >= maxConnections) {
            evictOldest();
        }

        conn = new Connection();
        conn.tuple = tuple;
        conn.state = ConnectionState.NEW;
        conn.firstSeen = System.currentTimeMillis();
        conn.lastSeen = conn.firstSeen;
        
        connections.put(tuple, conn);
        totalSeen++;
        return conn;
    }

    public Connection getConnection(FiveTuple tuple) {
        Connection conn = connections.get(tuple);
        if (conn != null) return conn;
        return connections.get(tuple.reverse());
    }

    public void updateConnection(Connection conn, int packetSize, boolean isOutbound) {
        if (conn == null) return;
        conn.lastSeen = System.currentTimeMillis();
        if (isOutbound) {
            conn.packetsOut++;
            conn.bytesOut += packetSize;
        } else {
            conn.packetsIn++;
            conn.bytesIn += packetSize;
        }
    }

    public void classifyConnection(Connection conn, AppType app, String sni) {
        if (conn == null) return;
        if (conn.state != ConnectionState.CLASSIFIED) {
            conn.appType = app;
            conn.sni = sni;
            conn.state = ConnectionState.CLASSIFIED;
            classifiedCount++;
        }
    }

    public void blockConnection(Connection conn) {
        if (conn == null) return;
        conn.state = ConnectionState.BLOCKED;
        conn.action = PacketAction.DROP;
        blockedCount++;
    }

    public void closeConnection(FiveTuple tuple) {
        Connection conn = connections.get(tuple);
        if (conn != null) {
            conn.state = ConnectionState.CLOSED;
        }
    }

    public synchronized int cleanupStale(long timeoutMs) {
        long now = System.currentTimeMillis();
        int removed = 0;
        
        Iterator<Map.Entry<FiveTuple, Connection>> it = connections.entrySet().iterator();
        while (it.hasNext()) {
            Connection conn = it.next().getValue();
            if (now - conn.lastSeen > timeoutMs || conn.state == ConnectionState.CLOSED) {
                it.remove();
                removed++;
            }
        }
        return removed;
    }

    public List<Connection> getAllConnections() {
        return new ArrayList<>(connections.values());
    }

    public int getActiveCount() {
        return connections.size();
    }

    public synchronized void clear() {
        connections.clear();
    }

    public void forEach(Consumer<Connection> callback) {
        for (Connection conn : connections.values()) {
            callback.accept(conn);
        }
    }

    private void evictOldest() {
        if (connections.isEmpty()) return;
        Connection oldest = null;
        for (Connection conn : connections.values()) {
            if (oldest == null || conn.lastSeen < oldest.lastSeen) {
                oldest = conn;
            }
        }
        if (oldest != null) {
            connections.remove(oldest.tuple);
        }
    }
    
    public TrackerStats getStats() {
        TrackerStats stats = new TrackerStats();
        stats.activeConnections = connections.size();
        stats.totalConnectionsSeen = totalSeen;
        stats.classifiedConnections = classifiedCount;
        stats.blockedConnections = blockedCount;
        return stats;
    }

    public static class TrackerStats {
        public long activeConnections;
        public long totalConnectionsSeen;
        public long classifiedConnections;
        public long blockedConnections;
    }
}
