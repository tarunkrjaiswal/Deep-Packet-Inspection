import React, { useState, useEffect } from 'react';
import { 
  Activity, ShieldAlert, ShieldCheck, 
  Network, Server, Globe2, ActivitySquare, AlertTriangle
} from 'lucide-react';
import { 
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer, 
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Legend 
} from 'recharts';
import reportData from './report.json';

const COLORS = ['#3b82f6', '#10b981', '#f59e0b', '#8b5cf6', '#ec4899', '#14b8a6', '#f43f5e', '#64748b'];

function MetricCard({ title, value, subtext, icon: Icon, colorClass }) {
  return (
    <div className="glass rounded-xl p-6 flex flex-col gap-2 relative overflow-hidden group">
      <div className={`absolute -right-4 -top-4 opacity-10 group-hover:scale-110 transition-transform ${colorClass}`}>
        <Icon size={120} />
      </div>
      <div className="flex justify-between items-center z-10">
        <h3 className="text-text-muted font-medium text-sm tracking-wider uppercase">{title}</h3>
        <Icon className={`w-5 h-5 ${colorClass}`} />
      </div>
      <div className="text-3xl font-bold text-text-main z-10 mt-2">{value}</div>
      {subtext && <div className="text-xs text-text-muted z-10 mt-1">{subtext}</div>}
    </div>
  );
}

function App() {
  // Use the imported JSON directly. 
  // This allows Vite's Hot Module Replacement (HMR) to automatically
  // refresh the page whenever report.json is overwritten by the Java engine!
  const data = reportData;

  return (
    <div className="min-h-screen bg-background text-text-main p-4 md:p-8 font-sans">
      <div className="max-w-7xl mx-auto space-y-6">
        
        {/* Header */}
        <header className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border pb-6">
          <div>
            <h1 className="text-3xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-blue-400 to-emerald-400 flex items-center gap-3">
              <ActivitySquare className="text-blue-500" size={32} />
              DPI Engine Dashboard
            </h1>
            <p className="text-text-muted mt-2 text-sm">Deep Packet Inspection & Stateful Connection Tracking</p>
          </div>
          <div className="flex gap-3">
            <span className={`glass px-4 py-2 rounded-full text-xs font-mono flex items-center gap-2 text-emerald-400`}>
              <span className={`w-2 h-2 rounded-full bg-emerald-500`}></span>
              Static Demo Environment
            </span>
          </div>
        </header>

        {/* Loading / Empty State */}
        {!data && (
           <div className="glass p-12 text-center rounded-xl text-text-muted">
             Loading dashboard data...
           </div>
        )}

        {/* Dashboard Content */}
        {data && (
          <>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
              <MetricCard 
                title="Total Packets" 
                value={data.engineStats.totalPackets.toLocaleString()} 
                subtext={`${(data.engineStats.totalBytes / 1024).toFixed(2)} KB Processed`}
                icon={Activity} 
                colorClass="text-blue-500" 
              />
              <MetricCard 
                title="Active Connections" 
                value={data.connectionStats.activeConnections.toLocaleString()} 
                subtext="Stateful flows tracked"
                icon={Network} 
                colorClass="text-purple-500" 
              />
              <MetricCard 
                title="Packets Forwarded" 
                value={data.engineStats.forwardedPackets.toLocaleString()} 
                subtext={`${((data.engineStats.forwardedPackets / data.engineStats.totalPackets) * 100).toFixed(1)}% transmission rate`}
                icon={ShieldCheck} 
                colorClass="text-emerald-500" 
              />
              <MetricCard 
                title="Blocked Connections" 
                value={data.connectionStats.blockedConnections} 
                subtext={`${data.engineStats.droppedPackets} packets dropped`}
                icon={ShieldAlert} 
                colorClass={data.connectionStats.blockedConnections > 0 ? "text-red-500" : "text-emerald-500"} 
              />
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              <div className="lg:col-span-2 space-y-6">
                <div className="glass rounded-xl p-6">
                  <h2 className="text-lg font-semibold mb-6 flex items-center gap-2">
                    <Server className="w-5 h-5 text-purple-400" />
                    Application Traffic Breakdown
                  </h2>
                  <div className="h-[300px] w-full">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart 
                        data={data.appBreakdown.filter(d => d.count > 0).sort((a, b) => b.count - a.count).slice(0, 8)} 
                        margin={{ top: 10, right: 10, left: -20, bottom: 20 }}
                      >
                        <CartesianGrid strokeDasharray="3 3" stroke="#334155" vertical={false} />
                        <XAxis 
                          dataKey="app" 
                          stroke="#94a3b8" 
                          fontSize={12} 
                          tickLine={false} 
                          axisLine={false}
                          angle={-45}
                          textAnchor="end"
                        />
                        <YAxis stroke="#94a3b8" fontSize={12} tickLine={false} axisLine={false} />
                        <Tooltip 
                          cursor={{fill: '#334155', opacity: 0.4}}
                          contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px' }}
                        />
                        <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                          {data.appBreakdown.filter(d => d.count > 0).sort((a, b) => b.count - a.count).slice(0, 8).map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={entry.blocked ? '#ef4444' : '#10b981'} />
                          ))}
                        </Bar>
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                  <div className="mt-4 flex flex-wrap gap-4 text-xs text-text-muted justify-center">
                    <div className="flex items-center gap-2"><span className="w-3 h-3 rounded-full bg-emerald-500"></span> Allowed Traffic</div>
                    <div className="flex items-center gap-2"><span className="w-3 h-3 rounded-full bg-red-500"></span> Blocked Traffic</div>
                  </div>
                </div>

                <div className="glass rounded-xl p-6">
                  <h2 className="text-lg font-semibold mb-4">L4 Protocol Distribution</h2>
                  <div className="flex justify-around items-center h-[120px]">
                    <div className="text-center">
                      <div className="text-4xl font-bold text-blue-400">{data.engineStats.tcpPackets}</div>
                      <div className="text-sm text-text-muted mt-2">TCP Packets</div>
                    </div>
                    <div className="h-full w-px bg-border"></div>
                    <div className="text-center">
                      <div className="text-4xl font-bold text-emerald-400">{data.engineStats.udpPackets}</div>
                      <div className="text-sm text-text-muted mt-2">UDP Packets</div>
                    </div>
                  </div>
                </div>
              </div>

              <div className="space-y-6">
                <div className="glass rounded-xl p-6">
                  <h2 className="text-lg font-semibold mb-6 flex items-center gap-2">
                    <Globe2 className="w-5 h-5 text-blue-400" />
                    Top Domains Detected
                  </h2>
                  <div className="space-y-4">
                    {data.topDomains.slice(0, 10).map((domain, idx) => (
                      <div key={idx} className="flex justify-between items-center group">
                        <div className="flex items-center gap-3 overflow-hidden">
                          <span className="text-text-muted text-xs font-mono w-4">{idx + 1}.</span>
                          <span className="text-sm text-text-main truncate group-hover:text-blue-400 transition-colors" title={domain.domain}>
                            {domain.domain}
                          </span>
                        </div>
                        <span className="glass px-2 py-1 rounded text-xs font-mono text-emerald-400">
                          {domain.count}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>

                {data.connectionStats.blockedConnections > 0 && (
                  <div className="glass rounded-xl p-6 border-red-500/30">
                    <h2 className="text-lg font-semibold mb-4 flex items-center gap-2 text-red-400">
                      <AlertTriangle className="w-5 h-5" />
                      Blocked Applications
                    </h2>
                    <div className="space-y-3">
                      {data.appBreakdown.filter(a => a.blocked).map((app, idx) => (
                        <div key={idx} className="flex justify-between items-center bg-red-500/10 p-3 rounded-lg border border-red-500/20">
                          <span className="font-semibold text-sm">{app.app}</span>
                          <span className="text-xs text-red-400 bg-red-500/20 px-2 py-1 rounded-full">
                            {app.count} connections
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

export default App;
