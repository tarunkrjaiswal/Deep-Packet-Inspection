package com.packetanalyzer.engine;

import com.packetanalyzer.types.AppType;
import com.packetanalyzer.types.Connection;
import com.packetanalyzer.types.ConnectionState;
import com.packetanalyzer.types.DPIStats;

import java.util.*;

public class GlobalConnectionTable {
    private ConnectionTracker[] trackers;

    public GlobalConnectionTable(int numFps) {
        trackers = new ConnectionTracker[numFps];
    }

    public synchronized void registerTracker(int fpId, ConnectionTracker tracker) {
        if (fpId >= 0 && fpId < trackers.length) {
            trackers[fpId] = tracker;
        }
    }

    public synchronized GlobalStats getGlobalStats() {
        GlobalStats stats = new GlobalStats();
        Map<String, Long> domainCounts = new HashMap<>();

        for (ConnectionTracker tracker : trackers) {
            if (tracker == null) continue;
            
            ConnectionTracker.TrackerStats tStats = tracker.getStats();
            stats.totalActiveConnections += tStats.activeConnections;
            stats.totalConnectionsSeen += tStats.totalConnectionsSeen;
            stats.blockedConnections += tStats.blockedConnections;

            tracker.forEach(conn -> {
                stats.appDistribution.put(conn.appType, stats.appDistribution.getOrDefault(conn.appType, 0L) + 1);
                if (conn.state == ConnectionState.BLOCKED) {
                    stats.blockedApps.add(conn.appType);
                }
                if (conn.sni != null && !conn.sni.isEmpty()) {
                    domainCounts.put(conn.sni, domainCounts.getOrDefault(conn.sni, 0L) + 1);
                }
            });
        }

        List<Map.Entry<String, Long>> domainVec = new ArrayList<>(domainCounts.entrySet());
        domainVec.sort((a, b) -> Long.compare(b.getValue(), a.getValue()));
        
        int count = Math.min(domainVec.size(), 20);
        for (int i = 0; i < count; i++) {
            stats.topDomains.add(new DomainCount(domainVec.get(i).getKey(), domainVec.get(i).getValue()));
        }

        return stats;
    }

    public String generateReport() {
        GlobalStats stats = getGlobalStats();
        StringBuilder ss = new StringBuilder();
        
        ss.append("\n╔══════════════════════════════════════════════════════════════╗\n");
        ss.append("║               CONNECTION STATISTICS REPORT                   ║\n");
        ss.append("╠══════════════════════════════════════════════════════════════╣\n");
        
        ss.append(String.format("║ Active Connections:     %-37d║\n", stats.totalActiveConnections));
        ss.append(String.format("║ Total Connections Seen: %-37d║\n", stats.totalConnectionsSeen));
        ss.append(String.format("║ Blocked Connections:    %-37d║\n", stats.blockedConnections));
        
        ss.append("╠══════════════════════════════════════════════════════════════╣\n");
        ss.append("║                    APPLICATION BREAKDOWN                     ║\n");
        ss.append("╠══════════════════════════════════════════════════════════════╣\n");
        
        long total = 0;
        for (long count : stats.appDistribution.values()) {
            total += count;
        }
        
        List<Map.Entry<AppType, Long>> sortedApps = new ArrayList<>(stats.appDistribution.entrySet());
        sortedApps.sort((a, b) -> Long.compare(b.getValue(), a.getValue()));
        
        for (Map.Entry<AppType, Long> pair : sortedApps) {
            double pct = total > 0 ? (100.0 * pair.getValue() / total) : 0;
            String blockedStr = stats.blockedApps.contains(pair.getKey()) ? "(BLOCKED)" : "";
            ss.append(String.format("║ %-20s%10d (%5.1f%%) %-13s ║\n", pair.getKey().name(), pair.getValue(), pct, blockedStr));
        }
        
        if (!stats.topDomains.isEmpty()) {
            ss.append("╠══════════════════════════════════════════════════════════════╣\n");
            ss.append("║                      TOP DOMAINS                             ║\n");
            ss.append("╠══════════════════════════════════════════════════════════════╣\n");
            
            for (DomainCount dc : stats.topDomains) {
                String domain = dc.domain;
                if (domain.length() > 35) {
                    domain = domain.substring(0, 32) + "...";
                }
                ss.append(String.format("║ %-40s%10d           ║\n", domain, dc.count));
            }
        }
        
        ss.append("╚══════════════════════════════════════════════════════════════╝\n");
        return ss.toString();
    }

    public boolean exportJson(String filename, DPIStats engineStats) {
        GlobalStats stats = getGlobalStats();
        try (java.io.FileWriter writer = new java.io.FileWriter(filename)) {
            StringBuilder json = new StringBuilder();
            json.append("{\n");
            json.append("  \"engineStats\": {\n");
            json.append("    \"totalPackets\": ").append(engineStats.totalPackets.get()).append(",\n");
            json.append("    \"totalBytes\": ").append(engineStats.totalBytes.get()).append(",\n");
            json.append("    \"tcpPackets\": ").append(engineStats.tcpPackets.get()).append(",\n");
            json.append("    \"udpPackets\": ").append(engineStats.udpPackets.get()).append(",\n");
            json.append("    \"forwardedPackets\": ").append(engineStats.forwardedPackets.get()).append(",\n");
            json.append("    \"droppedPackets\": ").append(engineStats.droppedPackets.get()).append("\n");
            json.append("  },\n");
            json.append("  \"connectionStats\": {\n");
            json.append("    \"activeConnections\": ").append(stats.totalActiveConnections).append(",\n");
            json.append("    \"totalConnectionsSeen\": ").append(stats.totalConnectionsSeen).append(",\n");
            json.append("    \"blockedConnections\": ").append(stats.blockedConnections).append("\n");
            json.append("  },\n");
            
            json.append("  \"appBreakdown\": [\n");
            List<Map.Entry<AppType, Long>> sortedApps = new ArrayList<>(stats.appDistribution.entrySet());
            sortedApps.sort((a, b) -> Long.compare(b.getValue(), a.getValue()));
            for (int i = 0; i < sortedApps.size(); i++) {
                Map.Entry<AppType, Long> entry = sortedApps.get(i);
                boolean isBlocked = stats.blockedApps.contains(entry.getKey());
                json.append("    { \"app\": \"").append(entry.getKey().name()).append("\", ");
                json.append("\"count\": ").append(entry.getValue()).append(", ");
                json.append("\"blocked\": ").append(isBlocked).append(" }");
                if (i < sortedApps.size() - 1) json.append(",");
                json.append("\n");
            }
            json.append("  ],\n");
            
            json.append("  \"topDomains\": [\n");
            for (int i = 0; i < stats.topDomains.size(); i++) {
                DomainCount dc = stats.topDomains.get(i);
                json.append("    { \"domain\": \"").append(dc.domain).append("\", ");
                json.append("\"count\": ").append(dc.count).append(" }");
                if (i < stats.topDomains.size() - 1) json.append(",");
                json.append("\n");
            }
            json.append("  ]\n");
            json.append("}\n");
            
            writer.write(json.toString());
            System.out.println("Exported report to " + filename);
            return true;
        } catch (java.io.IOException e) {
            System.err.println("Failed to write JSON: " + e.getMessage());
            return false;
        }
    }

    public static class GlobalStats {
        public long totalActiveConnections = 0;
        public long totalConnectionsSeen = 0;
        public long blockedConnections = 0;
        public Map<AppType, Long> appDistribution = new EnumMap<>(AppType.class);
        public Set<AppType> blockedApps = new HashSet<>();
        public List<DomainCount> topDomains = new ArrayList<>();
    }
    
    public static class DomainCount {
        public String domain;
        public long count;
        public DomainCount(String domain, long count) {
            this.domain = domain;
            this.count = count;
        }
    }
}
