package com.packetanalyzer.mt;

import com.packetanalyzer.engine.RuleManager;
import com.packetanalyzer.types.PacketAction;
import com.packetanalyzer.types.PacketJob;

import java.util.ArrayList;
import java.util.List;
import java.util.function.BiConsumer;

public class FPManager {
    private List<FastPathProcessor> fps = new ArrayList<>();

    public FPManager(int numFps, RuleManager ruleManager, BiConsumer<PacketJob, PacketAction> outputCallback) {
        for (int i = 0; i < numFps; i++) {
            fps.add(new FastPathProcessor(i, ruleManager, outputCallback));
        }
    }

    public void startAll() {
        for (FastPathProcessor fp : fps) fp.start();
    }

    public void stopAll() {
        for (FastPathProcessor fp : fps) fp.stop();
    }

    public FastPathProcessor getFP(int index) {
        return fps.get(index);
    }
    
    public List<FastPathProcessor> getFPs() {
        return fps;
    }

    public AggregatedStats getAggregatedStats() {
        AggregatedStats s = new AggregatedStats();
        for (FastPathProcessor fp : fps) {
            FastPathProcessor.FPStats fps = fp.getStats();
            s.totalProcessed += fps.packetsProcessed;
            s.totalForwarded += fps.packetsForwarded;
            s.totalDropped += fps.packetsDropped;
            s.totalConnections += fps.connectionsTracked;
        }
        return s;
    }

    public static class AggregatedStats {
        public long totalProcessed;
        public long totalForwarded;
        public long totalDropped;
        public long totalConnections;
    }
}
