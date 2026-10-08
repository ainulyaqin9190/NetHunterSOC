/**
 * NetHunterSOC - Phase 7 Activity Graph & Evidence Correlation Workbench
 * Interactive graph visualization and deterministic evidence correlation
 * across canonical telemetry, detection hits, evidence, threat intel, hypotheses, and alerts.
 */

import React, { useState, useEffect, useMemo, useRef, useCallback } from 'react';
import {
  Share2,
  RefreshCw,
  Search,
  Filter,
  Maximize2,
  ZoomIn,
  ZoomOut,
  RotateCcw,
  ShieldAlert,
  Network,
  Database,
  HelpCircle,
  FileCheck2,
  User as UserIcon,
  Server,
  Globe,
  AlertTriangle,
  ArrowRight,
  Info,
  Clock,
  ChevronRight,
  CheckCircle2,
  XCircle,
  Link2,
  Layers,
  Sparkles,
  ExternalLink,
  PlusCircle,
  X,
} from 'lucide-react';
import type {
  ActivityGraphNode,
  ActivityGraphEdge,
  ActivityGraphData,
  GraphNodeType,
  GraphEdgeRelation,
  CorrelatedCandidate,
  InvestigationContextResponse,
  EvidenceRole,
} from '../types';

interface ActivityGraphWorkbenchProps {
  initialScopeId?: string;
  initialSelectedEntity?: { type: string; id: string };
  onNavigateToTelemetry?: (ip?: string) => void;
  onNavigateToDetections?: (ruleId?: string) => void;
  onNavigateToAlerts?: (alertId?: string) => void;
  onNavigateToHypothesis?: (hypothesisId?: string) => void;
  onNavigateToThreatIntel?: (observable?: string) => void;
}

const NODE_COLORS: Record<GraphNodeType, { bg: string; border: string; text: string; ring: string }> = {
  ALERT: { bg: 'bg-rose-950/80', border: 'border-rose-600', text: 'text-rose-300', ring: 'ring-rose-500' },
  HYPOTHESIS: { bg: 'bg-amber-950/80', border: 'border-amber-600', text: 'text-amber-300', ring: 'ring-amber-500' },
  EVIDENCE: { bg: 'bg-cyan-950/80', border: 'border-cyan-500', text: 'text-cyan-300', ring: 'ring-cyan-400' },
  DETECTION: { bg: 'bg-orange-950/80', border: 'border-orange-600', text: 'text-orange-300', ring: 'ring-orange-500' },
  EVENT: { bg: 'bg-sky-950/80', border: 'border-sky-600', text: 'text-sky-300', ring: 'ring-sky-400' },
  HOST: { bg: 'bg-violet-950/80', border: 'border-violet-600', text: 'text-violet-300', ring: 'ring-violet-400' },
  DOMAIN: { bg: 'bg-indigo-950/80', border: 'border-indigo-600', text: 'text-indigo-300', ring: 'ring-indigo-400' },
  THREAT_INTEL: { bg: 'bg-purple-950/80', border: 'border-purple-500', text: 'text-purple-300', ring: 'ring-purple-400' },
  ANALYST: { bg: 'bg-emerald-950/80', border: 'border-emerald-600', text: 'text-emerald-300', ring: 'ring-emerald-400' },
};

const EDGE_COLORS: Record<GraphEdgeRelation, string> = {
  OBSERVED_IN: '#818cf8', // indigo
  SOURCE_OF: '#a78bfa', // violet
  DESTINATION_OF: '#c084fc', // purple
  TRIGGERED_BY: '#f97316', // orange
  SUPPORTED_BY: '#06b6d4', // cyan
  CONTRADICTED_BY: '#f43f5e', // rose
  ENRICHED_BY: '#c084fc', // purple
  ASSOCIATED_WITH: '#38bdf8', // sky
  DOCUMENTED_BY: '#10b981', // emerald
};

export const ActivityGraphWorkbench: React.FC<ActivityGraphWorkbenchProps> = ({
  initialScopeId = 'global',
  initialSelectedEntity,
  onNavigateToTelemetry,
  onNavigateToDetections,
  onNavigateToAlerts,
  onNavigateToHypothesis,
  onNavigateToThreatIntel,
}) => {
  // Graph Data State
  const [graphData, setGraphData] = useState<ActivityGraphData | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [syncing, setSyncing] = useState<boolean>(false);
  const [lastSynced, setLastSynced] = useState<string>('');

  // Selected Node & Context Panel State
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [contextData, setContextData] = useState<InvestigationContextResponse | null>(null);
  const [loadingContext, setLoadingContext] = useState<boolean>(false);

  // Configuration & Filters
  const [scopeId, setScopeId] = useState<string>(initialScopeId);
  const [temporalWindow, setTemporalWindow] = useState<number>(60);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [activeNodeFilter, setActiveNodeFilter] = useState<Set<GraphNodeType>>(
    new Set(['ALERT', 'HYPOTHESIS', 'EVIDENCE', 'DETECTION', 'EVENT', 'HOST', 'DOMAIN', 'THREAT_INTEL', 'ANALYST'])
  );
  const [activeRelationFilter, setActiveRelationFilter] = useState<Set<GraphEdgeRelation>>(
    new Set([
      'OBSERVED_IN',
      'SOURCE_OF',
      'DESTINATION_OF',
      'TRIGGERED_BY',
      'SUPPORTED_BY',
      'CONTRADICTED_BY',
      'ENRICHED_BY',
      'ASSOCIATED_WITH',
      'DOCUMENTED_BY',
    ])
  );

  // Canvas Viewport Pan & Zoom
  const [zoom, setZoom] = useState<number>(1);
  const [pan, setPan] = useState<{ x: number; y: number }>({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState<boolean>(false);
  const [dragStart, setDragStart] = useState<{ x: number; y: number }>({ x: 0, y: 0 });
  const svgRef = useRef<SVGSVGElement | null>(null);

  // Evidence Promotion Modal State
  const [promoteCandidate, setPromoteCandidate] = useState<CorrelatedCandidate | null>(null);
  const [promoteRole, setPromoteRole] = useState<EvidenceRole>('SUPPORTING');
  const [promoteHypothesisId, setPromoteHypothesisId] = useState<string>('');
  const [promoteRationale, setPromoteRationale] = useState<string>('');
  const [promoting, setPromoting] = useState<boolean>(false);
  const [hypothesesList, setHypothesesList] = useState<Array<{ id: string; title: string }>>([]);

  // Fetch Hypotheses for evidence modal
  const fetchHypotheses = useCallback(async () => {
    try {
      const res = await fetch('/api/hypotheses');
      if (res.ok) {
        const data = await res.json();
        setHypothesesList(Array.isArray(data) ? data : (data.hypotheses || []));
      }
    } catch {
      // silently ignore
    }
  }, []);

  // Fetch Graph from Backend
  const fetchGraph = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      params.set('scopeId', scopeId);
      const res = await fetch(`/api/graph?${params.toString()}`);
      if (res.ok) {
        const data: ActivityGraphData = await res.json();
        setGraphData(data);
        setLastSynced(new Date().toLocaleTimeString());
      }
    } catch (err) {
      console.error('Failed to load activity graph:', err);
    } finally {
      setLoading(false);
    }
  }, [scopeId]);

  // Trigger Backend Graph Rebuild
  const handleRebuildGraph = async () => {
    setSyncing(true);
    try {
      const res = await fetch('/api/graph/build', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scopeId,
          temporalWindowSeconds: temporalWindow,
        }),
      });
      if (res.ok) {
        const result = await res.json();
        setGraphData(result.graph);
        setLastSynced(new Date().toLocaleTimeString());
      }
    } catch (err) {
      console.error('Failed to build graph:', err);
    } finally {
      setSyncing(false);
    }
  };

  // Fetch Context on Node Selection
  const fetchNodeContext = useCallback(
    async (node: ActivityGraphNode) => {
      setLoadingContext(true);
      try {
        const res = await fetch(
          `/api/graph/context/${node.source_type}/${encodeURIComponent(node.source_id)}?temporalWindow=${temporalWindow}`
        );
        if (res.ok) {
          const data: InvestigationContextResponse = await res.json();
          setContextData(data);
        }
      } catch (err) {
        console.error('Failed to load investigation context:', err);
      } finally {
        setLoadingContext(false);
      }
    },
    [temporalWindow]
  );

  useEffect(() => {
    fetchGraph();
    fetchHypotheses();
  }, [fetchGraph, fetchHypotheses]);

  // Initial Selected Entity handling
  useEffect(() => {
    if (initialSelectedEntity && graphData) {
      const target = graphData.nodes.find(
        (n) => n.source_type === initialSelectedEntity.type && n.source_id === initialSelectedEntity.id
      );
      if (target) {
        setSelectedNodeId(target.id);
        fetchNodeContext(target);
      }
    }
  }, [initialSelectedEntity, graphData, fetchNodeContext]);

  // Filtered Nodes & Edges
  const { filteredNodes, filteredEdges } = useMemo(() => {
    if (!graphData) return { filteredNodes: [], filteredEdges: [] };

    let nodes = graphData.nodes.filter((n) => activeNodeFilter.has(n.node_type));

    if (searchQuery.trim().length > 0) {
      const q = searchQuery.toLowerCase();
      nodes = nodes.filter(
        (n) =>
          n.node_label.toLowerCase().includes(q) ||
          n.source_id.toLowerCase().includes(q) ||
          n.source_type.toLowerCase().includes(q)
      );
    }

    const nodeIds = new Set(nodes.map((n) => n.id));
    const edges = graphData.edges.filter(
      (e) =>
        nodeIds.has(e.source_node_id) &&
        nodeIds.has(e.target_node_id) &&
        activeRelationFilter.has(e.relation_label)
    );

    return { filteredNodes: nodes, filteredEdges: edges };
  }, [graphData, activeNodeFilter, activeRelationFilter, searchQuery]);

  // Computed layout positions for nodes:
  // Strictly separates Network/Investigation Activity from Audit/Analyst Actors.
  // Network Hierarchy: HOST/DOMAIN -> EVENT -> DETECTION -> EVIDENCE -> HYPOTHESIS -> ALERT -> THREAT_INTEL
  // Audit Lane: ANALYST nodes placed in dedicated audit traceability track (x >= 950).
  const nodePositions = useMemo(() => {
    const positions = new Map<string, { x: number; y: number; layer: number }>();
    const networkLayerMap: Partial<Record<GraphNodeType, number>> = {
      HOST: 0,
      DOMAIN: 0,
      EVENT: 1,
      DETECTION: 2,
      EVIDENCE: 3,
      HYPOTHESIS: 4,
      ALERT: 5,
      THREAT_INTEL: 6,
    };

    const networkNodesByLayer: Map<number, ActivityGraphNode[]> = new Map();
    for (let i = 0; i <= 6; i++) networkNodesByLayer.set(i, []);
    const analystNodes: ActivityGraphNode[] = [];

    for (const node of filteredNodes) {
      if (node.node_type === 'ANALYST') {
        analystNodes.push(node);
      } else {
        const l = networkLayerMap[node.node_type] ?? 1;
        networkNodesByLayer.get(l)!.push(node);
      }
    }

    const layerHeight = 130;
    const networkCanvasWidth = 880;

    // Layout Network / Investigation Nodes
    for (const [layerIndex, layerNodes] of networkNodesByLayer.entries()) {
      const count = layerNodes.length;
      if (count === 0) continue;
      const spacing = Math.min(200, (networkCanvasWidth - 80) / (count + 1));
      const totalWidth = spacing * (count - 1);
      const startX = 60 + (networkCanvasWidth - totalWidth) / 2;

      layerNodes.forEach((node, idx) => {
        positions.set(node.id, {
          x: startX + idx * spacing,
          y: 70 + layerIndex * layerHeight,
          layer: layerIndex,
        });
      });
    }

    // Layout Audit Actors (ANALYST) in a dedicated, clearly separated Audit Track
    const auditStartX = 1040;
    analystNodes.forEach((node, idx) => {
      positions.set(node.id, {
        x: auditStartX,
        y: 120 + idx * 110,
        layer: 99,
      });
    });

    return positions;
  }, [filteredNodes]);

  // SVG Mouse Drag handlers for pan
  const handleMouseDown = (e: React.MouseEvent) => {
    if (e.button === 0) {
      setIsDragging(true);
      setDragStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
    }
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (isDragging) {
      setPan({ x: e.clientX - dragStart.x, y: e.clientY - dragStart.y });
    }
  };

  const handleMouseUp = () => {
    setIsDragging(false);
  };

  const handleZoom = (delta: number) => {
    setZoom((prev) => Math.max(0.3, Math.min(2.5, prev + delta)));
  };

  const handleResetView = () => {
    setZoom(1);
    setPan({ x: 0, y: 0 });
  };

  // Toggle Node Filter
  const toggleNodeType = (type: GraphNodeType) => {
    setActiveNodeFilter((prev) => {
      const next = new Set(prev);
      if (next.has(type)) {
        if (next.size > 1) next.delete(type);
      } else {
        next.add(type);
      }
      return next;
    });
  };

  // Select Node
  const handleSelectNode = (node: ActivityGraphNode) => {
    setSelectedNodeId(node.id);
    fetchNodeContext(node);
  };

  // Promote Evidence Submission
  const handlePromoteEvidence = async () => {
    if (!promoteCandidate) return;
    setPromoting(true);
    try {
      const res = await fetch('/api/graph/correlate-evidence', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          candidateType: promoteCandidate.candidate_type,
          candidateId: promoteCandidate.candidate_id,
          hypothesisId: promoteHypothesisId || undefined,
          evidenceRole: promoteRole,
          analystRationale: promoteRationale || promoteCandidate.correlation_reason,
          relevance: 'HIGH',
        }),
      });

      if (res.ok) {
        setPromoteCandidate(null);
        setPromoteRationale('');
        // Refresh graph & context to display new evidence edge
        await handleRebuildGraph();
        if (selectedNodeId && graphData) {
          const curr = graphData.nodes.find((n) => n.id === selectedNodeId);
          if (curr) fetchNodeContext(curr);
        }
      }
    } catch (err) {
      console.error('Failed to promote evidence:', err);
    } finally {
      setPromoting(false);
    }
  };

  const getNodeIcon = (type: GraphNodeType) => {
    switch (type) {
      case 'ALERT':
        return <ShieldAlert className="h-4 w-4" />;
      case 'HYPOTHESIS':
        return <HelpCircle className="h-4 w-4" />;
      case 'EVIDENCE':
        return <FileCheck2 className="h-4 w-4" />;
      case 'DETECTION':
        return <AlertTriangle className="h-4 w-4" />;
      case 'EVENT':
        return <Network className="h-4 w-4" />;
      case 'HOST':
        return <Server className="h-4 w-4" />;
      case 'DOMAIN':
        return <Globe className="h-4 w-4" />;
      case 'THREAT_INTEL':
        return <Database className="h-4 w-4" />;
      case 'ANALYST':
        return <UserIcon className="h-4 w-4" />;
    }
  };

  const selectedNode = useMemo(() => {
    if (!selectedNodeId || !graphData) return null;
    return graphData.nodes.find((n) => n.id === selectedNodeId) || null;
  }, [selectedNodeId, graphData]);

  // Edges linked to selected node
  const selectedNodeEdges = useMemo(() => {
    if (!selectedNodeId || !graphData) return [];
    return graphData.edges.filter(
      (e) => e.source_node_id === selectedNodeId || e.target_node_id === selectedNodeId
    );
  }, [selectedNodeId, graphData]);

  return (
    <div className="flex flex-col h-[calc(100vh-140px)] min-h-[700px] bg-slate-950 text-slate-100 rounded-xl border border-slate-800 overflow-hidden font-sans">
      {/* Top Header & Toolbar */}
      <div className="border-b border-slate-800 bg-slate-900/90 p-4 flex flex-wrap items-center justify-between gap-3 shrink-0">
        <div className="flex items-center space-x-3">
          <div className="h-10 w-10 rounded-lg bg-cyan-950 border border-cyan-800/60 flex items-center justify-center text-cyan-400">
            <Share2 className="h-5 w-5" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h2 className="text-base font-bold text-white">Activity Graph & Correlation Workbench</h2>
              <span className="text-[10px] font-semibold uppercase px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800/50">
                Phase 7 Active
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Deterministic, explainable evidence correlation & backward provenance across all investigation entities
            </p>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex items-center space-x-2">
          {/* Temporal Window Selector */}
          <div className="flex items-center space-x-1.5 bg-slate-950 border border-slate-800 px-2.5 py-1.5 rounded-lg text-xs">
            <Clock className="h-3.5 w-3.5 text-cyan-400" />
            <span className="text-slate-400 text-[11px]">Window:</span>
            <select
              value={temporalWindow}
              onChange={(e) => setTemporalWindow(Number(e.target.value))}
              className="bg-transparent text-slate-200 text-xs font-semibold focus:outline-none cursor-pointer"
            >
              <option value={30}>±30 seconds</option>
              <option value={60}>±60 seconds</option>
              <option value={300}>±5 minutes</option>
            </select>
          </div>

          {/* Sync / Rebuild Graph Button */}
          <button
            onClick={handleRebuildGraph}
            disabled={syncing || loading}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold text-xs transition disabled:opacity-50"
            title="Rebuild & Synchronize Activity Graph"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${syncing ? 'animate-spin' : ''}`} />
            <span>{syncing ? 'Syncing...' : 'Sync Graph'}</span>
          </button>

          {lastSynced && (
            <span className="hidden sm:inline text-[11px] text-slate-500">Synced: {lastSynced}</span>
          )}
        </div>
      </div>

      {/* Filter Bar */}
      <div className="border-b border-slate-800 bg-slate-900/50 px-4 py-2 flex flex-wrap items-center justify-between gap-2 text-xs shrink-0">
        {/* Node Type Toggles */}
        <div className="flex items-center flex-wrap gap-1.5">
          <span className="text-[11px] text-slate-500 font-semibold uppercase tracking-wider mr-1">Nodes:</span>
          {(
            [
              'ALERT',
              'HYPOTHESIS',
              'EVIDENCE',
              'DETECTION',
              'EVENT',
              'HOST',
              'DOMAIN',
              'THREAT_INTEL',
              'ANALYST',
            ] as GraphNodeType[]
          ).map((type) => {
            const active = activeNodeFilter.has(type);
            const count = graphData?.summary.node_types[type] ?? 0;
            const style = NODE_COLORS[type];
            return (
              <button
                key={type}
                onClick={() => toggleNodeType(type)}
                className={`flex items-center space-x-1 px-2 py-1 rounded text-[11px] font-semibold transition border ${
                  active
                    ? `${style.bg} ${style.text} ${style.border}`
                    : 'bg-slate-950 text-slate-500 border-slate-800 opacity-60'
                }`}
              >
                {getNodeIcon(type)}
                <span>{type}</span>
                <span className="ml-1 text-[10px] opacity-80">({count})</span>
              </button>
            );
          })}
        </div>

        {/* Search Input */}
        <div className="relative">
          <Search className="h-3.5 w-3.5 text-slate-400 absolute left-2.5 top-2" />
          <input
            type="text"
            placeholder="Filter by IP, domain, rule, ID..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-8 pr-3 py-1 bg-slate-950 border border-slate-800 rounded-md text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 w-52"
          />
        </div>
      </div>

      {/* Main Canvas + Inspector Split View */}
      <div className="flex-1 flex overflow-hidden relative">
        {/* Interactive SVG Canvas */}
        <div
          className="flex-1 relative bg-slate-950 overflow-hidden cursor-grab active:cursor-grabbing select-none"
          onMouseDown={handleMouseDown}
          onMouseMove={handleMouseMove}
          onMouseUp={handleMouseUp}
        >
          {/* Zoom & Canvas Controls Overlay */}
          <div className="absolute bottom-4 left-4 z-20 flex items-center space-x-1.5 bg-slate-900/90 border border-slate-800 rounded-lg p-1.5 shadow-lg backdrop-blur">
            <button
              onClick={() => handleZoom(0.2)}
              className="p-1.5 rounded hover:bg-slate-800 text-slate-300 hover:text-white"
              title="Zoom In"
            >
              <ZoomIn className="h-4 w-4" />
            </button>
            <button
              onClick={() => handleZoom(-0.2)}
              className="p-1.5 rounded hover:bg-slate-800 text-slate-300 hover:text-white"
              title="Zoom Out"
            >
              <ZoomOut className="h-4 w-4" />
            </button>
            <button
              onClick={handleResetView}
              className="p-1.5 rounded hover:bg-slate-800 text-slate-300 hover:text-white"
              title="Reset View"
            >
              <RotateCcw className="h-4 w-4" />
            </button>
            <div className="h-4 w-px bg-slate-800 mx-1" />
            <span className="text-[11px] font-mono text-slate-400 px-1">{Math.round(zoom * 100)}%</span>
          </div>

          {/* Graph Summary Badge Overlay */}
          <div className="absolute top-4 left-4 z-20 bg-slate-900/90 border border-slate-800 rounded-lg px-3 py-2 text-xs backdrop-blur space-y-1 max-w-xs shadow-md">
            <div className="flex items-center justify-between text-slate-300 font-semibold">
              <span className="flex items-center space-x-1.5">
                <Layers className="h-3.5 w-3.5 text-cyan-400" />
                <span>Deterministic Graph</span>
              </span>
              <span className="text-cyan-400 font-mono">
                {filteredNodes.length} nodes / {filteredEdges.length} edges
              </span>
            </div>
            <p className="text-[11px] text-slate-400 leading-snug">
              Semantic hierarchy: Click any node to inspect explainable correlation reasons and backward provenance.
            </p>
          </div>

          {/* SVG Canvas */}
          <svg
            ref={svgRef}
            className="w-full h-full"
            style={{ width: '100%', height: '100%' }}
          >
            <defs>
              {/* Arrowhead Markers for Edge Relations */}
              {Object.entries(EDGE_COLORS).map(([rel, color]) => (
                <marker
                  key={rel}
                  id={`arrow-${rel}`}
                  viewBox="0 0 10 10"
                  refX="18"
                  refY="5"
                  markerWidth="6"
                  markerHeight="6"
                  orient="auto-start-reverse"
                >
                  <path d="M 0 1 L 10 5 L 0 9 z" fill={color} />
                </marker>
              ))}
            </defs>

            <g transform={`translate(${pan.x}, ${pan.y}) scale(${zoom})`}>
              {/* Audit Actors Lane Partition */}
              <g className="pointer-events-none select-none">
                <line x1="970" y1="30" x2="970" y2="900" stroke="#334155" strokeDasharray="6 4" strokeWidth="1.5" />
                <rect x="980" y="30" width="220" height="28" rx="6" fill="#064e3b" fillOpacity="0.5" stroke="#059669" strokeWidth="1" />
                <text x="990" y="48" fill="#34d399" fontSize="11" fontWeight="bold">
                  AUDIT & ANALYST ACTORS
                </text>
                <text x="985" y="74" fill="#94a3b8" fontSize="10">
                  Authorship provenance (Non-network entities)
                </text>
              </g>

              {/* Render Edges */}
              {filteredEdges.map((edge) => {
                const sourcePos = nodePositions.get(edge.source_node_id);
                const targetPos = nodePositions.get(edge.target_node_id);
                if (!sourcePos || !targetPos) return null;

                const isConnectedToSelected =
                  selectedNodeId &&
                  (edge.source_node_id === selectedNodeId || edge.target_node_id === selectedNodeId);

                const color = EDGE_COLORS[edge.relation_label] || '#64748b';
                const isTemporal = edge.correlation_rule === 'TEMPORAL_PROXIMITY';

                // Curved bezier path
                const dx = targetPos.x - sourcePos.x;
                const dy = targetPos.y - sourcePos.y;
                const cx1 = sourcePos.x + dx * 0.2;
                const cy1 = sourcePos.y + dy * 0.8;
                const d = `M ${sourcePos.x} ${sourcePos.y} C ${cx1} ${cy1}, ${sourcePos.x} ${targetPos.y}, ${targetPos.x} ${targetPos.y}`;

                return (
                  <g key={edge.id} className="cursor-pointer group">
                    <path
                      d={d}
                      fill="none"
                      stroke={isConnectedToSelected ? '#ffffff' : color}
                      strokeWidth={isConnectedToSelected ? 2.5 : 1.5}
                      strokeOpacity={isConnectedToSelected ? 1 : 0.6}
                      strokeDasharray={isTemporal ? '4 3' : undefined}
                      markerEnd={`url(#arrow-${edge.relation_label})`}
                      className="transition-all duration-200"
                    />
                    {/* Edge Label on Midpoint */}
                    <text
                      x={(sourcePos.x + targetPos.x) / 2}
                      y={(sourcePos.y + targetPos.y) / 2}
                      fill={color}
                      fontSize="9"
                      fontWeight="bold"
                      textAnchor="middle"
                      className="opacity-0 group-hover:opacity-100 transition-opacity bg-slate-950 font-mono"
                    >
                      {edge.relation_label}
                    </text>
                  </g>
                );
              })}

              {/* Render Nodes */}
              {filteredNodes.map((node) => {
                const pos = nodePositions.get(node.id);
                if (!pos) return null;

                const isSelected = selectedNodeId === node.id;
                const colors = NODE_COLORS[node.node_type] || NODE_COLORS.EVENT;
                const isAnalyst = node.node_type === 'ANALYST';

                return (
                  <g
                    key={node.id}
                    transform={`translate(${pos.x}, ${pos.y})`}
                    onClick={(e) => {
                      e.stopPropagation();
                      handleSelectNode(node);
                    }}
                    className="cursor-pointer"
                  >
                    {/* Glowing Selection Ring */}
                    {isSelected && (
                      isAnalyst ? (
                        <rect
                          x="-58"
                          y="-24"
                          width="116"
                          height="48"
                          rx="10"
                          fill="none"
                          stroke="#34d399"
                          strokeWidth="2.5"
                          className="animate-pulse"
                        />
                      ) : (
                        <circle
                          r="24"
                          fill="none"
                          stroke="#38bdf8"
                          strokeWidth="3"
                          className="animate-pulse"
                        />
                      )
                    )}

                    {/* Node Visual Shape: Rounded badge for Audit Actors, Circle for Network/Investigation Entities */}
                    {isAnalyst ? (
                      <g>
                        <rect
                          x="-54"
                          y="-20"
                          width="108"
                          height="40"
                          rx="8"
                          className="fill-emerald-950/90 stroke-emerald-500 border-2 shadow-lg hover:scale-105 transition-transform"
                          strokeWidth="2"
                          strokeDasharray="4 2"
                        />
                        <foreignObject x="-48" y="-12" width="24" height="24" className="pointer-events-none">
                          <div className="w-full h-full flex items-center justify-center text-emerald-400">
                            <UserIcon className="h-4 w-4" />
                          </div>
                        </foreignObject>
                        <text
                          x="-20"
                          y="-2"
                          fill="#34d399"
                          fontSize="9"
                          fontWeight="bold"
                          className="pointer-events-none select-none uppercase tracking-wider"
                        >
                          AUDIT ACTOR
                        </text>
                        <text
                          x="-20"
                          y="11"
                          fill="#e2e8f0"
                          fontSize="9"
                          fontWeight="600"
                          className="pointer-events-none select-none truncate font-mono"
                        >
                          {node.source_id.slice(0, 10)}
                        </text>
                      </g>
                    ) : (
                      <circle
                        r="16"
                        className={`${colors.bg} ${colors.border} border-2 shadow-lg transition-transform hover:scale-110`}
                        fill="currentColor"
                        stroke={colors.border.replace('border-', '')}
                        strokeWidth="2"
                      />
                    )}

                    {/* Node Type Icon in SVG (for non-analyst) */}
                    {!isAnalyst && (
                      <foreignObject x="-10" y="-10" width="20" height="20" className="pointer-events-none">
                        <div className={`w-full h-full flex items-center justify-center ${colors.text}`}>
                          {getNodeIcon(node.node_type)}
                        </div>
                      </foreignObject>
                    )}

                    {/* Node Label Below */}
                    {!isAnalyst && (
                      <text
                        y="26"
                        textAnchor="middle"
                        fill="#e2e8f0"
                        fontSize="10"
                        fontWeight="600"
                        className="pointer-events-none select-none drop-shadow"
                      >
                        {node.node_label.length > 24 ? `${node.node_label.slice(0, 22)}...` : node.node_label}
                      </text>
                    )}
                  </g>
                );
              })}
            </g>
          </svg>
        </div>

        {/* Right Drawer: Investigation Context & Provenance Inspector */}
        <div className="w-96 border-l border-slate-800 bg-slate-900/95 flex flex-col overflow-y-auto shrink-0 z-10">
          {selectedNode ? (
            <div className="p-4 space-y-5">
              {/* Header with Type Badge */}
              <div className="pb-3 border-b border-slate-800">
                <div className="flex items-center justify-between">
                  <span
                    className={`inline-flex items-center space-x-1 px-2.5 py-0.5 rounded text-xs font-bold border ${
                      NODE_COLORS[selectedNode.node_type].bg
                    } ${NODE_COLORS[selectedNode.node_type].border} ${NODE_COLORS[selectedNode.node_type].text}`}
                  >
                    {getNodeIcon(selectedNode.node_type)}
                    <span className="uppercase">{selectedNode.node_type}</span>
                  </span>
                  <span className="text-[11px] text-slate-500 font-mono">{selectedNode.source_type}</span>
                </div>
                <h3 className="text-sm font-bold text-white mt-2 break-words">{selectedNode.node_label}</h3>
                <p className="text-[11px] text-slate-400 font-mono mt-0.5">ID: {selectedNode.source_id}</p>
              </div>

              {/* Architectural Entity Role & Boundary Notice */}
              {selectedNode.node_type === 'ANALYST' && (
                <div className="p-3 rounded-lg bg-emerald-950/60 border border-emerald-800/60 text-xs space-y-1">
                  <div className="flex items-center space-x-1.5 font-bold text-emerald-300">
                    <UserIcon className="h-4 w-4" />
                    <span>Audit Traceability & Authorship Actor</span>
                  </div>
                  <p className="text-[11px] text-emerald-200/80 leading-relaxed">
                    NetHunterSOC Boundary: This entity records audit attribution (authorship of evidence, hypotheses, and alert decisions). It is NOT a network asset or part of an attack path.
                  </p>
                </div>
              )}

              {selectedNode.node_type === 'HOST' && (
                <div className="p-3 rounded-lg bg-violet-950/60 border border-violet-800/60 text-xs space-y-1">
                  <div className="flex items-center space-x-1.5 font-bold text-violet-300">
                    <Server className="h-4 w-4" />
                    <span>Observed IP (Wire Telemetry)</span>
                  </div>
                  <p className="text-[11px] text-violet-200/80 leading-relaxed">
                    NetHunterSOC Principle: Represents strictly observed IP address from canonical packets. Zero speculative host attributes (OS, asset owner, criticality) are invented.
                  </p>
                </div>
              )}

              {selectedNode.node_type === 'THREAT_INTEL' && (
                <div className="p-3 rounded-lg bg-purple-950/60 border border-purple-800/60 text-xs space-y-1">
                  <div className="flex items-center space-x-1.5 font-bold text-purple-300">
                    <Database className="h-4 w-4" />
                    <span>Threat Intelligence Context (Enrichment Only)</span>
                  </div>
                  <p className="text-[11px] text-purple-200/80 leading-relaxed">
                    NetHunterSOC Principle: Threat intelligence provides external context only. It never autonomously creates detections, declares compromise, or generates evidence without analyst promotion.
                  </p>
                </div>
              )}

              {/* Connected Relationships with Explainable Reasons */}
              <div className="space-y-2">
                <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center space-x-1.5">
                  <Link2 className="h-3.5 w-3.5 text-cyan-400" />
                  <span>Explainable Correlations ({selectedNodeEdges.length})</span>
                </h4>

                {selectedNodeEdges.length === 0 ? (
                  <p className="text-xs text-slate-500 italic">No direct edges linked in this view</p>
                ) : (
                  <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
                    {selectedNodeEdges.map((edge) => {
                      const isOutgoing = edge.source_node_id === selectedNode.id;
                      const otherNodeId = isOutgoing ? edge.target_node_id : edge.source_node_id;
                      const otherNode = graphData?.nodes.find((n) => n.id === otherNodeId);

                      return (
                        <div
                          key={edge.id}
                          className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 space-y-1 text-xs"
                        >
                          <div className="flex items-center justify-between text-[11px]">
                            <span
                              className="font-bold font-mono px-1.5 py-0.5 rounded"
                              style={{
                                color: EDGE_COLORS[edge.relation_label],
                                backgroundColor: 'rgba(15, 23, 42, 0.8)',
                              }}
                            >
                              {edge.relation_label}
                            </span>
                            <span className="text-[10px] text-slate-400 uppercase">{edge.correlation_rule}</span>
                          </div>
                          <p className="text-slate-300 text-[11px] font-medium leading-relaxed">
                            {edge.correlation_reason}
                          </p>
                          {otherNode && (
                            <div className="text-[10px] text-slate-400 flex items-center space-x-1 pt-1 border-t border-slate-900">
                              <span className="text-slate-500">{isOutgoing ? 'Target:' : 'Source:'}</span>
                              <span className="text-cyan-400 font-mono truncate">{otherNode.node_label}</span>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>

              {/* Backward Provenance Chain */}
              {contextData && contextData.provenance_chain.length > 0 && (
                <div className="space-y-2">
                  <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center space-x-1.5">
                    <ShieldAlert className="h-3.5 w-3.5 text-rose-400" />
                    <span>Backward Provenance Chain</span>
                  </h4>
                  <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-2">
                    {contextData.provenance_chain.map((step, idx) => (
                      <div key={idx} className="flex items-start space-x-2 text-xs">
                        <span className="px-1.5 py-0.5 rounded bg-slate-800 text-[10px] font-bold text-slate-300 shrink-0">
                          {step.stage}
                        </span>
                        <div className="min-w-0">
                          <p className="text-slate-200 font-medium truncate">{step.label}</p>
                          <p className="text-[11px] text-slate-400 truncate">{step.summary}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Discovered Correlated Candidates (Evidence Boundary Guardrail) */}
              {contextData && contextData.correlated_candidates.length > 0 && (
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <h4 className="text-xs font-bold text-amber-400 uppercase tracking-wider flex items-center space-x-1.5">
                      <Sparkles className="h-3.5 w-3.5" />
                      <span>Candidate Correlations ({contextData.correlated_candidates.length})</span>
                    </h4>
                  </div>
                  <p className="text-[11px] text-slate-400">
                    Discovered through deterministic matching. Requires explicit analyst decision to become evidence.
                  </p>

                  <div className="space-y-2 max-h-56 overflow-y-auto pr-1">
                    {contextData.correlated_candidates.map((cand) => (
                      <div
                        key={cand.candidate_id}
                        className="p-2.5 rounded-lg bg-slate-950 border border-amber-900/40 space-y-1.5 text-xs"
                      >
                        <div className="flex items-center justify-between">
                          <span className="px-1.5 py-0.5 rounded bg-amber-950/70 text-amber-300 border border-amber-800/40 text-[10px] font-bold uppercase">
                            {cand.candidate_type}
                          </span>
                          <span className="text-[10px] text-slate-400">{cand.correlation_rule}</span>
                        </div>
                        <p className="text-slate-200 text-xs font-medium">{cand.summary}</p>
                        <p className="text-[11px] text-slate-400 leading-snug">{cand.correlation_reason}</p>

                        <div className="pt-1 flex items-center justify-between">
                          {cand.already_promoted_as_evidence ? (
                            <span className="text-[11px] text-cyan-400 flex items-center space-x-1">
                              <CheckCircle2 className="h-3 w-3" />
                              <span>Linked Evidence ({cand.existing_evidence_id?.slice(0, 8)})</span>
                            </span>
                          ) : (
                            <button
                              onClick={() => {
                                setPromoteCandidate(cand);
                                setPromoteRationale(cand.correlation_reason);
                              }}
                              className="flex items-center space-x-1 px-2 py-1 rounded bg-cyan-900/60 hover:bg-cyan-800 text-cyan-200 border border-cyan-700/60 text-[11px] font-semibold transition"
                            >
                              <PlusCircle className="h-3 w-3" />
                              <span>Promote to Evidence</span>
                            </button>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Node Properties JSON Viewer */}
              {selectedNode.parsed_properties && Object.keys(selectedNode.parsed_properties).length > 0 && (
                <div className="space-y-1.5">
                  <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider">Properties & Attributes</h4>
                  <pre className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-[11px] font-mono text-slate-300 overflow-x-auto max-h-36">
                    {JSON.stringify(selectedNode.parsed_properties, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          ) : (
            <div className="p-8 text-center text-slate-500 space-y-3 my-auto">
              <Share2 className="h-10 w-10 mx-auto text-slate-700" />
              <h4 className="text-sm font-semibold text-slate-400">No Entity Selected</h4>
              <p className="text-xs text-slate-500 leading-relaxed">
                Click any node in the Activity Graph canvas to inspect deterministic correlations, backward provenance,
                and discover candidate evidence items.
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Explicit Evidence Promotion Modal (Adheres to Evidence Boundary) */}
      {promoteCandidate && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-lg w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center space-x-2">
                <FileCheck2 className="h-5 w-5 text-cyan-400" />
                <h3 className="text-base font-bold text-white">Promote Correlated Item to Evidence</h3>
              </div>
              <button
                onClick={() => setPromoteCandidate(null)}
                className="text-slate-400 hover:text-white p-1 rounded"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <p className="text-xs text-slate-400 leading-relaxed">
              In accordance with NetHunterSOC architectural principles, correlation does not automatically become
              evidence. Provide your analyst reasoning and designation.
            </p>

            <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-xs space-y-1">
              <div className="flex items-center justify-between font-mono text-[11px] text-slate-400">
                <span>Candidate ID: {promoteCandidate.candidate_id}</span>
                <span className="uppercase text-amber-400">{promoteCandidate.candidate_type}</span>
              </div>
              <p className="text-white font-medium">{promoteCandidate.summary}</p>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-300 font-semibold mb-1">Evidence Role:</label>
                <select
                  value={promoteRole}
                  onChange={(e) => setPromoteRole(e.target.value as EvidenceRole)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-cyan-500"
                >
                  <option value="PRIMARY">PRIMARY (Direct causal telemetry or core detection)</option>
                  <option value="SUPPORTING">SUPPORTING (Corroborating activity in temporal window)</option>
                  <option value="CONTRADICTING">CONTRADICTING (Inconsistent observation or suppression match)</option>
                  <option value="CONTEXT">CONTEXT (Environmental telemetry or threat intel match)</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-300 font-semibold mb-1">Attach to Hypothesis (Optional):</label>
                <select
                  value={promoteHypothesisId}
                  onChange={(e) => setPromoteHypothesisId(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-cyan-500"
                >
                  <option value="">-- No Hypothesis Attachment (Standalone Evidence) --</option>
                  {hypothesesList.map((h) => (
                    <option key={h.id} value={h.id}>
                      {h.title || h.id}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-slate-300 font-semibold mb-1">Analyst Rationale / Deliberation:</label>
                <textarea
                  rows={3}
                  value={promoteRationale}
                  onChange={(e) => setPromoteRationale(e.target.value)}
                  placeholder="State the analytical justification for promoting this record to evidence..."
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-sans"
                />
              </div>
            </div>

            <div className="flex items-center justify-end space-x-3 pt-3 border-t border-slate-800">
              <button
                onClick={() => setPromoteCandidate(null)}
                className="px-4 py-2 rounded-lg text-slate-400 hover:text-white text-xs font-semibold"
              >
                Cancel
              </button>
              <button
                onClick={handlePromoteEvidence}
                disabled={promoting}
                className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold text-xs transition disabled:opacity-50 flex items-center space-x-1.5"
              >
                {promoting ? 'Promoting...' : 'Create Evidence Record'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
