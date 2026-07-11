package com.packetanalyzer.engine;

import com.packetanalyzer.types.AppType;
import com.packetanalyzer.parser.PacketParser;
import java.io.*;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CopyOnWriteArraySet;

public class RuleManager {

    private Set<Integer> blockedIps = new CopyOnWriteArraySet<>();
    private Set<AppType> blockedApps = new CopyOnWriteArraySet<>();
    private Set<String> blockedDomains = new CopyOnWriteArraySet<>();
    private List<String> domainPatterns = new CopyOnWriteArrayList<>();
    private Set<Integer> blockedPorts = new CopyOnWriteArraySet<>();

    public static int parseIP(String ip) {
        String[] parts = ip.split("\\.");
        if (parts.length != 4) return 0;
        int result = 0;
        for (int i = 0; i < 4; i++) {
            result |= (Integer.parseInt(parts[i]) & 0xFF) << ((3 - i) * 8);
        }
        return result;
    }

    public void blockIP(int ip) {
        blockedIps.add(ip);
        System.out.println("[RuleManager] Blocked IP: " + PacketParser.ipToString(ip));
    }

    public void blockIP(String ip) {
        blockIP(parseIP(ip));
    }

    public void unblockIP(int ip) {
        blockedIps.remove(ip);
        System.out.println("[RuleManager] Unblocked IP: " + PacketParser.ipToString(ip));
    }

    public void unblockIP(String ip) {
        unblockIP(parseIP(ip));
    }

    public boolean isIPBlocked(int ip) {
        return blockedIps.contains(ip);
    }

    public List<String> getBlockedIPs() {
        List<String> res = new ArrayList<>();
        for (int ip : blockedIps) res.add(PacketParser.ipToString(ip));
        return res;
    }

    public void blockApp(AppType app) {
        blockedApps.add(app);
        System.out.println("[RuleManager] Blocked app: " + app);
    }

    public void unblockApp(AppType app) {
        blockedApps.remove(app);
        System.out.println("[RuleManager] Unblocked app: " + app);
    }

    public boolean isAppBlocked(AppType app) {
        return blockedApps.contains(app);
    }

    public List<AppType> getBlockedApps() {
        return new ArrayList<>(blockedApps);
    }

    public void blockDomain(String domain) {
        if (domain.contains("*")) {
            if (!domainPatterns.contains(domain)) domainPatterns.add(domain);
        } else {
            blockedDomains.add(domain);
        }
        System.out.println("[RuleManager] Blocked domain: " + domain);
    }

    public void unblockDomain(String domain) {
        if (domain.contains("*")) {
            domainPatterns.remove(domain);
        } else {
            blockedDomains.remove(domain);
        }
        System.out.println("[RuleManager] Unblocked domain: " + domain);
    }

    private boolean domainMatchesPattern(String domain, String pattern) {
        if (pattern.startsWith("*.")) {
            String suffix = pattern.substring(1);
            if (domain.endsWith(suffix)) return true;
            if (domain.equals(pattern.substring(2))) return true;
        }
        return false;
    }

    public boolean isDomainBlocked(String domain) {
        if (blockedDomains.contains(domain)) return true;
        
        String lowerDomain = domain.toLowerCase();
        for (String pattern : domainPatterns) {
            if (domainMatchesPattern(lowerDomain, pattern.toLowerCase())) {
                return true;
            }
        }
        return false;
    }

    public List<String> getBlockedDomains() {
        List<String> res = new ArrayList<>(blockedDomains);
        res.addAll(domainPatterns);
        return res;
    }

    public void blockPort(int port) {
        blockedPorts.add(port);
        System.out.println("[RuleManager] Blocked port: " + port);
    }

    public void unblockPort(int port) {
        blockedPorts.remove(port);
    }

    public boolean isPortBlocked(int port) {
        return blockedPorts.contains(port);
    }

    public BlockReason shouldBlock(int srcIp, int dstIp, int dstPort, AppType app, String domain) {
        if (isIPBlocked(srcIp)) return new BlockReason(BlockReasonType.IP, PacketParser.ipToString(srcIp));
        if (isIPBlocked(dstIp)) return new BlockReason(BlockReasonType.IP, PacketParser.ipToString(dstIp));
        if (isPortBlocked(dstPort)) return new BlockReason(BlockReasonType.PORT, String.valueOf(dstPort));
        if (isAppBlocked(app)) return new BlockReason(BlockReasonType.APP, app.name());
        if (domain != null && !domain.isEmpty() && isDomainBlocked(domain)) return new BlockReason(BlockReasonType.DOMAIN, domain);
        return null;
    }

    public boolean saveRules(String filename) {
        try (PrintWriter writer = new PrintWriter(new FileWriter(filename))) {
            writer.println("[BLOCKED_IPS]");
            for (String ip : getBlockedIPs()) writer.println(ip);
            
            writer.println("\n[BLOCKED_APPS]");
            for (AppType app : getBlockedApps()) writer.println(app.name());
            
            writer.println("\n[BLOCKED_DOMAINS]");
            for (String d : getBlockedDomains()) writer.println(d);
            
            writer.println("\n[BLOCKED_PORTS]");
            for (int p : blockedPorts) writer.println(p);
            
            System.out.println("[RuleManager] Rules saved to: " + filename);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    public boolean loadRules(String filename) {
        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
            String line;
            String section = "";
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) continue;
                if (line.startsWith("[")) {
                    section = line;
                    continue;
                }
                
                if (section.equals("[BLOCKED_IPS]")) blockIP(line);
                else if (section.equals("[BLOCKED_APPS]")) {
                    try {
                        blockApp(AppType.valueOf(line));
                    } catch (IllegalArgumentException ignored) {}
                }
                else if (section.equals("[BLOCKED_DOMAINS]")) blockDomain(line);
                else if (section.equals("[BLOCKED_PORTS]")) blockPort(Integer.parseInt(line));
            }
            System.out.println("[RuleManager] Rules loaded from: " + filename);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    public void clearAll() {
        blockedIps.clear();
        blockedApps.clear();
        blockedDomains.clear();
        domainPatterns.clear();
        blockedPorts.clear();
        System.out.println("[RuleManager] All rules cleared");
    }

    public enum BlockReasonType {
        IP, PORT, APP, DOMAIN
    }

    public static class BlockReason {
        public BlockReasonType type;
        public String value;
        public BlockReason(BlockReasonType type, String value) {
            this.type = type;
            this.value = value;
        }
    }
}
