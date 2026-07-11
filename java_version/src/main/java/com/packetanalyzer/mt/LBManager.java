package com.packetanalyzer.mt;

import com.packetanalyzer.types.FiveTuple;

import java.util.ArrayList;
import java.util.List;

public class LBManager {
    private List<LoadBalancer> lbs = new ArrayList<>();

    public LBManager(int numLbs, int fpsPerLb, List<FastPathProcessor> allFps) {
        for (int i = 0; i < numLbs; i++) {
            int fpStart = i * fpsPerLb;
            List<FastPathProcessor> lbFPs = new ArrayList<>();
            for (int j = 0; j < fpsPerLb; j++) {
                lbFPs.add(allFps.get(fpStart + j));
            }
            lbs.add(new LoadBalancer(i, lbFPs, fpStart));
        }
    }

    public void startAll() {
        for (LoadBalancer lb : lbs) lb.start();
    }

    public void stopAll() {
        for (LoadBalancer lb : lbs) lb.stop();
    }

    public LoadBalancer getLBForPacket(FiveTuple tuple) {
        int index = Math.abs(tuple.hashCode()) % lbs.size();
        return lbs.get(index);
    }
    
    public AggregatedStats getAggregatedStats() {
        AggregatedStats s = new AggregatedStats();
        for (LoadBalancer lb : lbs) {
            LoadBalancer.LBStats lbstats = lb.getStats();
            s.totalReceived += lbstats.packetsReceived;
            s.totalDispatched += lbstats.packetsDispatched;
        }
        return s;
    }
    
    public static class AggregatedStats {
        public long totalReceived;
        public long totalDispatched;
    }
}
