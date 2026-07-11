package com.packetanalyzer.mt;

import com.packetanalyzer.types.FiveTuple;
import com.packetanalyzer.types.PacketJob;

import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

public class LoadBalancer {
    private int lbId;
    private int fpStartId;
    private int numFps;
    private BlockingQueue<PacketJob> inputQueue = new LinkedBlockingQueue<>(10000);
    private List<FastPathProcessor> fpTargets;
    
    private volatile boolean running = false;
    private Thread thread;
    
    private long packetsReceived = 0;
    private long packetsDispatched = 0;

    public LoadBalancer(int lbId, List<FastPathProcessor> fpTargets, int fpStartId) {
        this.lbId = lbId;
        this.fpTargets = fpTargets;
        this.fpStartId = fpStartId;
        this.numFps = fpTargets.size();
    }

    public void start() {
        if (running) return;
        running = true;
        thread = new Thread(this::run, "LB-Thread-" + lbId);
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

    private void run() {
        while (running) {
            try {
                PacketJob job = inputQueue.poll(100, TimeUnit.MILLISECONDS);
                if (job == null) continue;
                
                packetsReceived++;
                int fpIndex = selectFP(job.tuple);
                
                fpTargets.get(fpIndex).getInputQueue().put(job);
                packetsDispatched++;
            } catch (InterruptedException e) {
                if (!running) break;
            }
        }
    }

    private int selectFP(FiveTuple tuple) {
        return Math.abs(tuple.hashCode()) % numFps;
    }
    
    public LBStats getStats() {
        LBStats s = new LBStats();
        s.packetsReceived = packetsReceived;
        s.packetsDispatched = packetsDispatched;
        return s;
    }
    
    public static class LBStats {
        public long packetsReceived;
        public long packetsDispatched;
    }
}
