import React, { useState, useEffect, useRef, useCallback } from 'react';
import { Network, ZoomIn, ZoomOut, RefreshCw, User, Laptop, Globe, AlertTriangle, ShieldAlert, Maximize2 } from 'lucide-react';
import Card from '../common/Card';
import TechnicalDetails from '../common/TechnicalDetails';

export default function ContextGraph({ graphData = { nodes: [], edges: [] }, onSelectNode, selectedNodeId }) {
  const containerRef = useRef(null);
  const [positions, setPositions] = useState({});
  const [dimensions, setDimensions] = useState({ width: 700, height: 420 });
  const [zoomLevel, setZoomLevel] = useState(1);
  const [panOffset, setPanOffset] = useState({ x: 0, y: 0 });
  const [isDraggingNode, setIsDraggingNode] = useState(null);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });

  const nodes = graphData?.nodes || [];
  const edges = graphData?.edges || [];

  // 1. Dynamic Container Bounds Tracking via ResizeObserver
  useEffect(() => {
    if (!containerRef.current) return;
    const ro = new ResizeObserver((entries) => {
      for (let entry of entries) {
        const { width, height } = entry.contentRect;
        if (width > 0 && height > 0) {
          setDimensions({ width, height });
        }
      }
    });
    ro.observe(containerRef.current);
    return () => ro.disconnect();
  }, []);

  // 2. High-Performance Force-Directed Simulation
  const computeSimulation = useCallback(() => {
    if (!nodes || nodes.length === 0) return;

    const { width, height } = dimensions;
    let pos = {};

    // Initial radial distribution centered in the container
    nodes.forEach((n, i) => {
      const angle = (i / Math.max(nodes.length, 1)) * 2 * Math.PI;
      const radius = Math.min(width, height) * 0.32;
      pos[n.id] = {
        x: width / 2 + Math.cos(angle) * radius + (Math.random() - 0.5) * 20,
        y: height / 2 + Math.sin(angle) * radius + (Math.random() - 0.5) * 20,
        vx: 0,
        vy: 0
      };
    });

    const iterations = 200;
    let currentPos = { ...pos };

    for (let iter = 0; iter < iterations; iter++) {
      // (a) Repulsion Force (Many-Body Coulomb: Strong negative charge to prevent clumping)
      for (let i = 0; i < nodes.length; i++) {
        const u = nodes[i].id;
        const pU = currentPos[u];
        if (!pU) continue;

        for (let j = i + 1; j < nodes.length; j++) {
          const v = nodes[j].id;
          const pV = currentPos[v];
          if (!pV) continue;

          const dx = pV.x - pU.x;
          const dy = pV.y - pU.y;
          const distSq = dx * dx + dy * dy || 1;
          const dist = Math.sqrt(distSq);

          // Strong repulsion force
          const repulsionConstant = 18000;
          const force = repulsionConstant / (distSq + 200);
          const fx = (dx / dist) * force;
          const fy = (dy / dist) * force;

          pU.vx -= fx;
          pU.vy -= fy;
          pV.vx += fx;
          pV.vy += fy;

          // (b) Collision Force: treat nodes as solid objects with a protective radius
          const minDistance = 90;
          if (dist < minDistance) {
            const overlap = (minDistance - dist);
            const push = overlap * 0.45;
            const cx = (dx / dist) * push;
            const cy = (dy / dist) * push;
            pU.vx -= cx;
            pU.vy -= cy;
            pV.vx += cx;
            pV.vy += cy;
          }
        }
      }

      // (c) Link Distance & Spring Elasticity: Creates generous breathing room
      edges.forEach((edge) => {
        const pSource = currentPos[edge.source];
        const pTarget = currentPos[edge.target];
        if (!pSource || !pTarget) return;

        const dx = pTarget.x - pSource.x;
        const dy = pTarget.y - pSource.y;
        const dist = Math.sqrt(dx * dx + dy * dy) || 1;
        const idealDistance = 150; // Increased link distance
        const force = (dist - idealDistance) * 0.035;
        const fx = (dx / dist) * force;
        const fy = (dy / dist) * force;

        pSource.vx += fx;
        pSource.vy += fy;
        pTarget.vx -= fx;
        pTarget.vy -= fy;
      });

      // (d) Center Gravity & Container Centering
      nodes.forEach((n) => {
        const p = currentPos[n.id];
        if (!p) return;

        const cDx = width / 2 - p.x;
        const cDy = height / 2 - p.y;
        p.vx += cDx * 0.008;
        p.vy += cDy * 0.008;

        // Apply velocity with damping
        p.x += Math.max(-15, Math.min(15, p.vx));
        p.y += Math.max(-15, Math.min(15, p.vy));

        p.vx *= 0.82;
        p.vy *= 0.82;

        // Bounding box with safety margin
        p.x = Math.max(60, Math.min(width - 60, p.x));
        p.y = Math.max(55, Math.min(height - 55, p.y));
      });
    }

    setPositions(currentPos);
  }, [nodes, edges, dimensions]);

  useEffect(() => {
    computeSimulation();
  }, [computeSimulation]);

  // Dragging support for interactive positioning
  const handleMouseDown = (nodeId, e) => {
    e.stopPropagation();
    setIsDraggingNode(nodeId);
    setDragStart({ x: e.clientX, y: e.clientY });
  };

  const handleMouseMove = (e) => {
    if (!isDraggingNode || !positions[isDraggingNode]) return;
    const dx = (e.clientX - dragStart.x) / zoomLevel;
    const dy = (e.clientY - dragStart.y) / zoomLevel;

    setPositions((prev) => ({
      ...prev,
      [isDraggingNode]: {
        ...prev[isDraggingNode],
        x: prev[isDraggingNode].x + dx,
        y: prev[isDraggingNode].y + dy
      }
    }));
    setDragStart({ x: e.clientX, y: e.clientY });
  };

  const handleMouseUp = () => {
    setIsDraggingNode(null);
  };

  const handleResetView = () => {
    setZoomLevel(1);
    setPanOffset({ x: 0, y: 0 });
    computeSimulation();
  };

  const getNodeColor = (type = '') => {
    const t = type.toLowerCase();
    if (t.includes('user')) return { fill: '#9333ea', stroke: '#c084fc', glow: 'rgba(168, 85, 247, 0.4)', text: '#f3e8ff' };
    if (t.includes('device') || t.includes('host')) return { fill: '#0891b2', stroke: '#22d3ee', glow: 'rgba(6, 182, 212, 0.4)', text: '#ecfeff' };
    if (t.includes('ip')) return { fill: '#d97706', stroke: '#fbbf24', glow: 'rgba(245, 158, 11, 0.4)', text: '#fffbeb' };
    if (t.includes('domain') || t.includes('url')) return { fill: '#e11d48', stroke: '#fb7185', glow: 'rgba(244, 63, 94, 0.4)', text: '#fff1f2' };
    if (t.includes('process')) return { fill: '#059669', stroke: '#34d399', glow: 'rgba(16, 185, 129, 0.4)', text: '#ecfdf5' };
    if (t.includes('technique')) return { fill: '#ea580c', stroke: '#fb923c', glow: 'rgba(234, 88, 12, 0.4)', text: '#fff7ed' };
    if (t.includes('target')) return { fill: '#dc2626', stroke: '#f87171', glow: 'rgba(220, 38, 38, 0.4)', text: '#fef2f2' };
    if (t.includes('file')) return { fill: '#2563eb', stroke: '#60a5fa', glow: 'rgba(37, 99, 235, 0.4)', text: '#eff6ff' };
    if (t.includes('hash')) return { fill: '#4f46e5', stroke: '#818cf8', glow: 'rgba(79, 70, 229, 0.4)', text: '#eef2ff' };
    return { fill: '#7c3aed', stroke: '#a78bfa', glow: 'rgba(139, 92, 246, 0.4)', text: '#f5f3ff' };
  };

  return (
    <Card className="p-5">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 mb-3">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-lg bg-purple-500/10 border border-purple-500/30">
            <Network className="w-4 h-4 text-purple-400" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-white uppercase tracking-wider">
              Connected Activity Map
            </h3>
            <span className="text-[11px] font-mono text-slate-400">
              {nodes.length} Entities • {edges.length} Relationships
            </span>
          </div>
        </div>

        {/* View Controls: Zoom In, Zoom Out, Reset Center */}
        <div className="flex items-center gap-1.5 bg-slate-900/90 border border-slate-800 rounded-lg p-1">
          <button
            onClick={() => setZoomLevel((z) => Math.min(z + 0.15, 2.0))}
            className="p-1.5 text-slate-400 hover:text-white hover:bg-slate-800 rounded transition-colors"
            title="Zoom In"
          >
            <ZoomIn className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={() => setZoomLevel((z) => Math.max(z - 0.15, 0.5))}
            className="p-1.5 text-slate-400 hover:text-white hover:bg-slate-800 rounded transition-colors"
            title="Zoom Out"
          >
            <ZoomOut className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={handleResetView}
            className="p-1.5 text-slate-400 hover:text-purple-400 hover:bg-slate-800 rounded transition-colors"
            title="Recenter & Re-simulate Physics"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      <p className="text-xs text-slate-400 mb-3">
        Interactive relationship topology showing how users, devices, processes, and network addresses are connected across the threat campaign.
      </p>

      {/* Graph Visualizer Container */}
      <div 
        ref={containerRef}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseUp}
        className="w-full h-[450px] rounded-xl bg-[#060A12] border border-slate-800/80 relative overflow-hidden flex items-center justify-center select-none shadow-inner"
      >
        {/* Visual grid background */}
        <div 
          className="absolute inset-0 opacity-[0.03] pointer-events-none"
          style={{
            backgroundImage: `radial-gradient(circle, #a855f7 1px, transparent 1px)`,
            backgroundSize: '24px 24px'
          }}
        />

        {nodes.length === 0 ? (
          <div className="text-center text-xs text-slate-500 p-6 z-10">
            <Network className="w-8 h-8 mx-auto mb-2 text-slate-600 animate-pulse" />
            <span>No entity relationships available for the selected view.</span>
          </div>
        ) : (
          <svg 
            className="w-full h-full cursor-grab active:cursor-grabbing"
            style={{
              transform: `scale(${zoomLevel}) translate(${panOffset.x}px, ${panOffset.y}px)`,
              transformOrigin: 'center center',
              transition: isDraggingNode ? 'none' : 'transform 0.2s ease-out'
            }}
          >
            <defs>
              <marker
                id="arrowhead-styled"
                markerWidth="10"
                markerHeight="7"
                refX="22"
                refY="3.5"
                orient="auto"
              >
                <polygon points="0 0, 10 3.5, 0 7" fill="#64748b" />
              </marker>

              <filter id="node-glow" x="-50%" y="-50%" width="200%" height="200%">
                <feGaussianBlur stdDeviation="6" result="blur" />
                <feMerge>
                  <feMergeNode in="blur" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>
            </defs>

            {/* Edges */}
            {edges.map((edge, idx) => {
              const p1 = positions[edge.source];
              const p2 = positions[edge.target];
              if (!p1 || !p2) return null;

              const midX = (p1.x + p2.x) / 2;
              const midY = (p1.y + p2.y) / 2;

              return (
                <g key={`edge-${idx}`}>
                  <line
                    x1={p1.x}
                    y1={p1.y}
                    x2={p2.x}
                    y2={p2.y}
                    stroke="#334155"
                    strokeWidth="1.75"
                    strokeDasharray={edge.type ? '4,4' : 'none'}
                    markerEnd="url(#arrowhead-styled)"
                    className="opacity-75"
                  />
                  {edge.type && (
                    <g transform={`translate(${midX}, ${midY})`}>
                      <rect
                        x="-38"
                        y="-10"
                        width="76"
                        height="15"
                        rx="4"
                        fill="#0b1324"
                        stroke="#1e293b"
                        strokeWidth="1"
                        className="opacity-90"
                      />
                      <text
                        y="1"
                        fill="#94a3b8"
                        fontSize="8.5"
                        fontFamily="monospace"
                        fontWeight="600"
                        textAnchor="middle"
                        dominantBaseline="middle"
                      >
                        {edge.type}
                      </text>
                    </g>
                  )}
                </g>
              );
            })}

            {/* Nodes */}
            {nodes.map((node) => {
              const p = positions[node.id];
              if (!p) return null;

              const isSelected = selectedNodeId === node.id;
              const colors = getNodeColor(node.type || node.label);

              return (
                <g 
                  key={node.id} 
                  transform={`translate(${p.x}, ${p.y})`}
                  onMouseDown={(e) => handleMouseDown(node.id, e)}
                  onClick={() => onSelectNode && onSelectNode(node)}
                  className="cursor-pointer group"
                >
                  {/* Glowing Outer Ring for Selected Node */}
                  {isSelected && (
                    <circle
                      r={26}
                      fill="none"
                      stroke={colors.stroke}
                      strokeWidth={2}
                      strokeDasharray="4,4"
                      className="animate-spin"
                      style={{ animationDuration: '6s' }}
                    />
                  )}

                  {/* Main Node Circle */}
                  <circle
                    r={isSelected ? 19 : 15}
                    fill={colors.fill}
                    stroke={isSelected ? '#ffffff' : colors.stroke}
                    strokeWidth={isSelected ? 2.5 : 1.5}
                    filter="drop-shadow(0 4px 10px rgba(0,0,0,0.8))"
                    className="transition-all duration-150 hover:brightness-125"
                  />
                  
                  {/* Entity Label (Bottom) */}
                  <g transform="translate(0, 24)">
                    <rect
                      x="-50"
                      y="-2"
                      width="100"
                      height="16"
                      rx="4"
                      fill="#020617"
                      fillOpacity="0.85"
                      stroke="#1e293b"
                      strokeWidth="0.75"
                    />
                    <text
                      y="9"
                      fill="#f8fafc"
                      fontSize="9.5"
                      fontFamily="monospace"
                      fontWeight="bold"
                      textAnchor="middle"
                      dominantBaseline="middle"
                      className="select-none pointer-events-none"
                    >
                      {node.name || node.id}
                    </text>
                  </g>

                  {/* Entity Type Badge (Below Label) */}
                  <text
                    y={47}
                    fill={colors.stroke}
                    fontSize="8.5"
                    fontFamily="sans-serif"
                    fontWeight="600"
                    textAnchor="middle"
                    className="select-none pointer-events-none tracking-wider uppercase opacity-90"
                  >
                    {node.type || node.label || 'Entity'}
                  </text>
                </g>
              );
            })}
          </svg>
        )}
      </div>

      {/* Technical Details for Graph Schema */}
      <TechnicalDetails title="Context Graph Schema & Topology">
        <p className="text-slate-400 text-[11px]">
          Entity Model: Property Graph Nodes (`User`, `Host`, `IP`, `Process`, `Domain`) linked via typed relationships (`AUTHENTICATED_TO`, `RESOLVED_TO`, `EXECUTED_ON`). Physics powered by dynamic Many-Body Coulomb repulsion and collision detection.
        </p>
      </TechnicalDetails>
    </Card>
  );
}
