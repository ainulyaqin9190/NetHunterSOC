import React, { useState, useEffect, useCallback, useId } from 'react';
import {
  Upload,
  RefreshCw,
  Search,
  Filter,
  Network,
  FileText,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Copy,
  ChevronLeft,
  ChevronRight,
  Eye,
  ShieldAlert,
  ArrowUpDown,
  DownloadCloud,
  Layers,
  X,
} from 'lucide-react';
import {
  CanonicalNetworkEvent,
  TelemetryFilters,
  TelemetryImportResult,
  TelemetrySummaryStats,
} from '../types/index.ts';

interface NetworkTelemetryViewProps {
  onEventCountUpdate?: (count: number) => void;
}

export const NetworkTelemetryView: React.FC<NetworkTelemetryViewProps> = ({ onEventCountUpdate }) => {
  const [events, setEvents] = useState<CanonicalNetworkEvent[]>([]);
  const [stats, setStats] = useState<TelemetrySummaryStats | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Pagination & Filter state
  const [page, setPage] = useState<number>(1);
  const [limit, setLimit] = useState<number>(25);
  const [totalPages, setTotalPages] = useState<number>(1);
  const [totalCount, setTotalCount] = useState<number>(0);

  const [searchTerm, setSearchTerm] = useState<string>('');
  const [selectedProto, setSelectedProto] = useState<string>('');
  const [selectedEventType, setSelectedEventType] = useState<string>('');
  const [selectedFormat, setSelectedFormat] = useState<string>('');
  const [sortBy, setSortBy] = useState<'timestamp' | 'bytes' | 'packets'>('timestamp');
  const [sortOrder, setSortOrder] = useState<'desc' | 'asc'>('desc');

  // Selected event for detail inspection
  const [selectedEvent, setSelectedEvent] = useState<CanonicalNetworkEvent | null>(null);
  const [copiedRaw, setCopiedRaw] = useState<boolean>(false);

  // Ingestion Modal state
  const [showImportModal, setShowImportModal] = useState<boolean>(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [formatHint, setFormatHint] = useState<'auto' | 'csv' | 'suricata_eve'>('auto');
  const [importing, setImporting] = useState<boolean>(false);
  const [importResult, setImportResult] = useState<TelemetryImportResult | null>(null);
  const [dragActive, setDragActive] = useState<boolean>(false);

  const fileInputId = useId();

  // Load telemetry stats
  const fetchStats = useCallback(async () => {
    try {
      const res = await fetch('/api/telemetry/stats');
      if (res.ok) {
        const data = await res.json();
        setStats(data);
        if (onEventCountUpdate) {
          onEventCountUpdate(data.total_events);
        }
      }
    } catch {
      // Non-critical stats error
    }
  }, [onEventCountUpdate]);

  // Fetch telemetry events with active filters
  const fetchEvents = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const query = new URLSearchParams();
      query.set('page', String(page));
      query.set('limit', String(limit));
      query.set('sort_by', sortBy);
      query.set('sort_order', sortOrder);

      if (searchTerm.trim()) query.set('search', searchTerm.trim());
      if (selectedProto) query.set('protocol', selectedProto);
      if (selectedEventType) query.set('event_type', selectedEventType);
      if (selectedFormat) query.set('source_format', selectedFormat);

      const res = await fetch(`/api/telemetry/events?${query.toString()}`);
      if (!res.ok) {
        throw new Error(`Failed to fetch events: HTTP ${res.status}`);
      }

      const data = await res.json();
      setEvents(data.events || []);
      setTotalPages(data.pagination?.total_pages || 1);
      setTotalCount(data.pagination?.total || 0);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Error fetching telemetry events');
    } finally {
      setLoading(false);
    }
  }, [page, limit, sortBy, sortOrder, searchTerm, selectedProto, selectedEventType, selectedFormat]);

  useEffect(() => {
    fetchEvents();
    fetchStats();
  }, [fetchEvents, fetchStats]);

  // Handle file drop
  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setSelectedFile(e.dataTransfer.files[0]);
    }
  };

  // Submit file upload
  const handleUpload = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!selectedFile) return;

    setImporting(true);
    setImportResult(null);

    const formData = new FormData();
    formData.append('file', selectedFile);
    formData.append('formatHint', formatHint);

    try {
      const res = await fetch('/api/telemetry/import', {
        method: 'POST',
        body: formData,
      });

      const result: TelemetryImportResult = await res.json();
      setImportResult(result);
      if (res.ok) {
        fetchEvents();
        fetchStats();
      }
    } catch (err) {
      setImportResult({
        status: 'failed',
        source_format: 'csv',
        filename: selectedFile.name,
        batch_id: 'err',
        total_records: 0,
        accepted: 0,
        normalized: 0,
        duplicates: 0,
        rejected: 1,
        warnings: 0,
        duration_ms: 0,
        errors: [{ line: 0, reason: err instanceof Error ? err.message : 'Network failure during upload' }],
      });
    } finally {
      setImporting(false);
    }
  };

  // Load sample test fixture
  const handleLoadSample = async (sampleType: 'csv' | 'suricata_eve') => {
    setImporting(true);
    setImportResult(null);

    try {
      const res = await fetch('/api/telemetry/import-sample', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sampleType }),
      });

      const result: TelemetryImportResult = await res.json();
      setImportResult(result);
      if (res.ok) {
        fetchEvents();
        fetchStats();
      }
    } catch (err) {
      setImportResult({
        status: 'failed',
        source_format: sampleType,
        filename: `sample_${sampleType}`,
        batch_id: 'err',
        total_records: 0,
        accepted: 0,
        normalized: 0,
        duplicates: 0,
        rejected: 1,
        warnings: 0,
        duration_ms: 0,
        errors: [{ line: 0, reason: err instanceof Error ? err.message : 'Failed to import sample' }],
      });
    } finally {
      setImporting(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedRaw(true);
    setTimeout(() => setCopiedRaw(false), 2000);
  };

  const resetFilters = () => {
    setSearchTerm('');
    setSelectedProto('');
    setSelectedEventType('');
    setSelectedFormat('');
    setPage(1);
  };

  const formatBytes = (bytes: number | null | undefined): string => {
    if (bytes === null || bytes === undefined) return '0 B';
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };

  return (
    <div className="space-y-6">
      {/* Top Banner & Action Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900 border border-slate-800 p-6 rounded-xl shadow-lg">
        <div>
          <div className="flex items-center gap-2">
            <Network className="w-5 h-5 text-emerald-400" />
            <h1 className="text-xl font-bold text-white tracking-wide">Canonical Network Telemetry</h1>
            <span className="text-xs bg-emerald-950 text-emerald-300 border border-emerald-800/80 px-2 py-0.5 rounded font-mono font-medium">
              Phase 2 Active
            </span>
          </div>
          <p className="text-slate-400 text-sm mt-1">
            Deterministic stream parser, normalization engine, and evidence provenance viewer.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            id="refresh-telemetry-btn"
            onClick={() => {
              fetchEvents();
              fetchStats();
            }}
            disabled={loading}
            className="flex items-center gap-2 px-3 py-2 text-sm bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg border border-slate-700 transition"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-emerald-400' : ''}`} />
            Refresh
          </button>

          <button
            id="open-import-modal-btn"
            onClick={() => {
              setShowImportModal(true);
              setImportResult(null);
            }}
            className="flex items-center gap-2 px-4 py-2 text-sm font-medium bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg shadow-sm shadow-emerald-950 transition"
          >
            <Upload className="w-4 h-4" />
            Import Telemetry
          </button>
        </div>
      </div>

      {/* Telemetry Stats Strip */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-slate-900/90 border border-slate-800 p-4 rounded-lg">
          <div className="text-xs font-medium text-slate-400 uppercase tracking-wider">Total Normalized Events</div>
          <div className="text-2xl font-bold text-white font-mono mt-1">
            {stats ? stats.total_events.toLocaleString() : '0'}
          </div>
          <div className="text-xs text-slate-500 mt-1 flex items-center gap-1.5">
            <Layers className="w-3.5 h-3.5 text-emerald-400" />
            <span>SQLite WAL Ingestion</span>
          </div>
        </div>

        <div className="bg-slate-900/90 border border-slate-800 p-4 rounded-lg">
          <div className="text-xs font-medium text-slate-400 uppercase tracking-wider">Distinct Endpoints</div>
          <div className="text-2xl font-bold text-white font-mono mt-1">
            {stats ? `${stats.distinct_src_ips} src / ${stats.distinct_dst_ips} dst` : '0 / 0'}
          </div>
          <div className="text-xs text-slate-500 mt-1">RFC 1918 & Public Scope Classified</div>
        </div>

        <div className="bg-slate-900/90 border border-slate-800 p-4 rounded-lg">
          <div className="text-xs font-medium text-slate-400 uppercase tracking-wider">Total Volume Logged</div>
          <div className="text-2xl font-bold text-white font-mono mt-1">
            {stats ? formatBytes(stats.total_bytes) : '0 B'}
          </div>
          <div className="text-xs text-slate-500 mt-1">
            {stats ? `${stats.total_packets.toLocaleString()} packets` : '0 packets'}
          </div>
        </div>

        <div className="bg-slate-900/90 border border-slate-800 p-4 rounded-lg">
          <div className="text-xs font-medium text-slate-400 uppercase tracking-wider">Source Formats</div>
          <div className="text-sm font-mono text-emerald-400 font-semibold mt-2 flex items-center gap-3">
            <span>CSV: {stats?.by_source_format?.csv ?? 0}</span>
            <span className="text-slate-600">|</span>
            <span>EVE: {stats?.by_source_format?.suricata_eve ?? 0}</span>
          </div>
          <div className="text-xs text-slate-500 mt-1">Full Provenance Retained</div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl space-y-3">
        <div className="flex flex-col md:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="w-4 h-4 absolute left-3 top-3 text-slate-400" />
            <input
              id="telemetry-search-input"
              type="text"
              value={searchTerm}
              onChange={(e) => {
                setSearchTerm(e.target.value);
                setPage(1);
              }}
              placeholder="Search IP address, domain query, alert signature, source file..."
              className="w-full pl-9 pr-4 py-2 bg-slate-950 text-slate-200 placeholder-slate-500 border border-slate-800 rounded-lg text-sm focus:outline-none focus:border-emerald-500 font-mono"
            />
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {/* Protocol Filter */}
            <select
              id="filter-protocol-select"
              value={selectedProto}
              onChange={(e) => {
                setSelectedProto(e.target.value);
                setPage(1);
              }}
              className="bg-slate-950 text-slate-300 border border-slate-800 text-sm rounded-lg px-3 py-2 focus:outline-none focus:border-emerald-500 font-mono"
            >
              <option value="">All Protocols</option>
              <option value="TCP">TCP</option>
              <option value="UDP">UDP</option>
              <option value="ICMP">ICMP</option>
              <option value="ICMPV6">ICMPv6</option>
              <option value="SCTP">SCTP</option>
            </select>

            {/* Event Type Filter */}
            <select
              id="filter-event-type-select"
              value={selectedEventType}
              onChange={(e) => {
                setSelectedEventType(e.target.value);
                setPage(1);
              }}
              className="bg-slate-950 text-slate-300 border border-slate-800 text-sm rounded-lg px-3 py-2 focus:outline-none focus:border-emerald-500 font-mono"
            >
              <option value="">All Event Types</option>
              <option value="flow">Flow</option>
              <option value="alert">Alert</option>
              <option value="dns">DNS</option>
              <option value="tls">TLS</option>
              <option value="http">HTTP</option>
              <option value="ssh">SSH</option>
            </select>

            {/* Source Format Filter */}
            <select
              id="filter-format-select"
              value={selectedFormat}
              onChange={(e) => {
                setSelectedFormat(e.target.value);
                setPage(1);
              }}
              className="bg-slate-950 text-slate-300 border border-slate-800 text-sm rounded-lg px-3 py-2 focus:outline-none focus:border-emerald-500 font-mono"
            >
              <option value="">All Formats</option>
              <option value="csv">CSV Flow</option>
              <option value="suricata_eve">Suricata EVE-JSON</option>
            </select>

            {/* Sort Order */}
            <button
              id="toggle-sort-order-btn"
              onClick={() => setSortOrder(sortOrder === 'desc' ? 'asc' : 'desc')}
              className="flex items-center gap-1.5 px-3 py-2 bg-slate-950 text-slate-300 border border-slate-800 text-sm rounded-lg hover:border-slate-700"
              title={`Sorting ${sortOrder.toUpperCase()}`}
            >
              <ArrowUpDown className="w-3.5 h-3.5 text-slate-400" />
              <span className="font-mono text-xs uppercase">{sortOrder}</span>
            </button>

            {(searchTerm || selectedProto || selectedEventType || selectedFormat) && (
              <button
                id="reset-filters-btn"
                onClick={resetFilters}
                className="px-3 py-2 text-xs text-slate-400 hover:text-white bg-slate-800/60 rounded-lg hover:bg-slate-800 transition"
              >
                Clear Filters
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Error notification */}
      {error && (
        <div className="bg-rose-950/60 border border-rose-800 text-rose-300 p-4 rounded-lg flex items-center gap-3">
          <XCircle className="w-5 h-5 flex-shrink-0 text-rose-400" />
          <div className="text-sm font-mono">{error}</div>
        </div>
      )}

      {/* Telemetry Events Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm text-slate-300">
            <thead className="bg-slate-950 text-slate-400 font-mono text-xs uppercase tracking-wider border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">Timestamp (UTC)</th>
                <th className="py-3 px-4">Type</th>
                <th className="py-3 px-4">Source Endpoint</th>
                <th className="py-3 px-4">Destination Endpoint</th>
                <th className="py-3 px-4">Proto</th>
                <th className="py-3 px-4">Volume</th>
                <th className="py-3 px-4">Context / Evidence</th>
                <th className="py-3 px-4">Provenance</th>
                <th className="py-3 px-3 text-right">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80 font-mono text-xs">
              {loading ? (
                <tr>
                  <td colSpan={9} className="py-12 text-center text-slate-500">
                    <div className="flex flex-col items-center justify-center gap-3">
                      <RefreshCw className="w-6 h-6 animate-spin text-emerald-400" />
                      <span>Reading normalized telemetry stream from SQLite...</span>
                    </div>
                  </td>
                </tr>
              ) : events.length === 0 ? (
                <tr>
                  <td colSpan={9} className="py-12 text-center text-slate-500">
                    <div className="max-w-md mx-auto space-y-3">
                      <Network className="w-10 h-10 text-slate-600 mx-auto" />
                      <div className="text-slate-300 text-base font-semibold">No Telemetry Events Ingested</div>
                      <p className="text-slate-400 text-xs">
                        Import network flow CSVs or Suricata EVE-JSON files, or quickly test with bundled sample fixtures.
                      </p>
                      <div className="flex items-center justify-center gap-3 pt-2">
                        <button
                          id="empty-load-csv-btn"
                          onClick={() => handleLoadSample('csv')}
                          className="px-3 py-1.5 text-xs bg-slate-800 hover:bg-slate-700 text-slate-200 rounded border border-slate-700"
                        >
                          Load Sample CSV
                        </button>
                        <button
                          id="empty-load-eve-btn"
                          onClick={() => handleLoadSample('suricata_eve')}
                          className="px-3 py-1.5 text-xs bg-slate-800 hover:bg-slate-700 text-slate-200 rounded border border-slate-700"
                        >
                          Load Sample Suricata EVE
                        </button>
                      </div>
                    </div>
                  </td>
                </tr>
              ) : (
                events.map((evt) => (
                  <tr
                    key={evt.id}
                    onClick={() => setSelectedEvent(evt)}
                    className="hover:bg-slate-800/50 cursor-pointer transition"
                  >
                    <td className="py-3 px-4 whitespace-nowrap text-slate-300">
                      {evt.timestamp.replace('T', ' ').replace('Z', '')}
                    </td>

                    {/* Event Type Badge */}
                    <td className="py-3 px-4 whitespace-nowrap">
                      {evt.event_type === 'alert' ? (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold bg-amber-950 text-amber-300 border border-amber-800">
                          <ShieldAlert className="w-3 h-3" />
                          alert
                        </span>
                      ) : evt.event_type === 'dns' ? (
                        <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-cyan-950 text-cyan-300 border border-cyan-800">
                          dns
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 rounded text-[11px] font-medium bg-slate-800 text-slate-300 border border-slate-700">
                          {evt.event_type || 'flow'}
                        </span>
                      )}
                    </td>

                    {/* Source */}
                    <td className="py-3 px-4 whitespace-nowrap">
                      <div className="flex items-center gap-1.5">
                        <span className="text-slate-200 font-semibold">{evt.src_ip}</span>
                        {evt.src_port !== null && (
                          <span className="text-slate-400">:{evt.src_port}</span>
                        )}
                        <span
                          title="Topological context only; not a security verdict"
                          className={`text-[9px] px-1 py-0.2 rounded uppercase border ${
                            evt.src_ip_scope === 'private'
                              ? 'bg-slate-800 text-slate-400 border-slate-700'
                              : evt.src_ip_scope === 'public'
                              ? 'bg-sky-950 text-sky-300 border-sky-800'
                              : evt.src_ip_scope === 'unspecified'
                              ? 'bg-amber-950/50 text-amber-300 border-amber-800'
                              : 'bg-slate-900 text-slate-500 border-slate-800'
                          }`}
                        >
                          {evt.src_ip_scope || 'scope'}
                        </span>
                      </div>
                    </td>

                    {/* Destination */}
                    <td className="py-3 px-4 whitespace-nowrap">
                      <div className="flex items-center gap-1.5">
                        <span className="text-slate-200 font-semibold">{evt.dst_ip}</span>
                        {evt.dst_port !== null && (
                          <span className="text-slate-400">:{evt.dst_port}</span>
                        )}
                        <span
                          title="Topological context only; not a security verdict"
                          className={`text-[9px] px-1 py-0.2 rounded uppercase border ${
                            evt.dst_ip_scope === 'private'
                              ? 'bg-slate-800 text-slate-400 border-slate-700'
                              : evt.dst_ip_scope === 'public'
                              ? 'bg-sky-950 text-sky-300 border-sky-800'
                              : evt.dst_ip_scope === 'unspecified'
                              ? 'bg-amber-950/50 text-amber-300 border-amber-800'
                              : 'bg-slate-900 text-slate-500 border-slate-800'
                          }`}
                        >
                          {evt.dst_ip_scope || 'scope'}
                        </span>
                      </div>
                    </td>

                    {/* Protocol */}
                    <td className="py-3 px-4 whitespace-nowrap">
                      <span className="font-semibold text-emerald-400">{evt.protocol}</span>
                    </td>

                    {/* Volume */}
                    <td className="py-3 px-4 whitespace-nowrap text-slate-400 font-mono text-xs">
                      {evt.packets !== null && evt.packets !== undefined ? `${evt.packets} pkts` : '—'} / {formatBytes(evt.bytes)}
                    </td>

                    {/* Details / Evidence Context */}
                    <td className="py-3 px-4 max-w-xs truncate">
                      {evt.alert_signature ? (
                        <span className="text-amber-300 font-medium truncate block" title={evt.alert_signature}>
                          {evt.alert_signature}
                        </span>
                      ) : evt.dns_query ? (
                        <span className="text-cyan-300 truncate block" title={evt.dns_query}>
                          query: {evt.dns_query}
                        </span>
                      ) : evt.application_protocol ? (
                        <span className="text-indigo-300">app: {evt.application_protocol}</span>
                      ) : evt.connection_state ? (
                        <span className="text-slate-400">state: {evt.connection_state}</span>
                      ) : (
                        <span className="text-slate-600">—</span>
                      )}
                    </td>

                    {/* Provenance */}
                    <td className="py-3 px-4 whitespace-nowrap text-slate-400">
                      <span className="text-[11px] bg-slate-950 px-2 py-0.5 rounded border border-slate-800 text-slate-400">
                        {evt.source_format}
                      </span>
                    </td>

                    {/* Action */}
                    <td className="py-3 px-3 text-right whitespace-nowrap">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedEvent(evt);
                        }}
                        className="p-1.5 text-slate-400 hover:text-emerald-400 hover:bg-slate-800 rounded transition"
                        title="Inspect Evidence & Provenance"
                      >
                        <Eye className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Footer */}
        <div className="bg-slate-950 px-4 py-3 border-t border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-slate-400">
          <div className="flex items-center gap-2">
            <span>Showing</span>
            <span className="text-slate-200 font-semibold">{events.length}</span>
            <span>of</span>
            <span className="text-slate-200 font-semibold">{totalCount.toLocaleString()}</span>
            <span>normalized records</span>
          </div>

          <div className="flex items-center gap-3">
            <div className="flex items-center gap-1.5">
              <span>Rows per page:</span>
              <select
                id="pagination-limit-select"
                value={limit}
                onChange={(e) => {
                  setLimit(Number(e.target.value));
                  setPage(1);
                }}
                className="bg-slate-900 border border-slate-800 text-slate-200 rounded px-2 py-1 focus:outline-none focus:border-emerald-500 font-mono"
              >
                <option value="15">15</option>
                <option value="25">25</option>
                <option value="50">50</option>
                <option value="100">100</option>
              </select>
            </div>

            <div className="flex items-center gap-1">
              <button
                id="prev-page-btn"
                onClick={() => setPage(Math.max(1, page - 1))}
                disabled={page <= 1}
                className="p-1.5 bg-slate-900 text-slate-300 border border-slate-800 rounded disabled:opacity-40 disabled:cursor-not-allowed hover:bg-slate-800"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
              <span className="px-2 font-mono text-slate-300">
                Page {page} of {totalPages}
              </span>
              <button
                id="next-page-btn"
                onClick={() => setPage(Math.min(totalPages, page + 1))}
                disabled={page >= totalPages}
                className="p-1.5 bg-slate-900 text-slate-300 border border-slate-800 rounded disabled:opacity-40 disabled:cursor-not-allowed hover:bg-slate-800"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Raw Event Detail Modal / Evidence Drawer */}
      {selectedEvent && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in duration-150">
          <div className="bg-slate-900 border border-slate-700 w-full max-w-3xl rounded-xl shadow-2xl overflow-hidden max-h-[90vh] flex flex-col">
            <div className="p-4 bg-slate-950 border-b border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <FileText className="w-5 h-5 text-emerald-400" />
                <h3 className="font-bold text-white text-base">Canonical Network Event Details</h3>
                <span className="text-xs font-mono bg-slate-800 text-slate-300 px-2 py-0.5 rounded">
                  {selectedEvent.id}
                </span>
              </div>
              <button
                id="close-event-detail-btn"
                onClick={() => setSelectedEvent(null)}
                className="text-slate-400 hover:text-white p-1 rounded hover:bg-slate-800"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-6 overflow-y-auto space-y-6 text-sm text-slate-300">
              {/* Core Attributes Grid */}
              <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                <div className="bg-slate-950/60 p-3 rounded border border-slate-800">
                  <div className="text-xs text-slate-500 uppercase font-mono">Timestamp (ISO UTC)</div>
                  <div className="font-mono text-slate-200 mt-1">{selectedEvent.timestamp}</div>
                </div>

                <div className="bg-slate-950/60 p-3 rounded border border-slate-800">
                  <div className="text-xs text-slate-500 uppercase font-mono">Protocol</div>
                  <div className="font-mono font-semibold text-emerald-400 mt-1">{selectedEvent.protocol}</div>
                </div>

                <div className="bg-slate-950/60 p-3 rounded border border-slate-800">
                  <div className="text-xs text-slate-500 uppercase font-mono">Event Type</div>
                  <div className="font-mono text-slate-200 mt-1 uppercase">{selectedEvent.event_type || 'flow'}</div>
                </div>

                <div className="bg-slate-950/60 p-3 rounded border border-slate-800">
                  <div className="text-xs text-slate-500 uppercase font-mono">Source Endpoint</div>
                  <div className="font-mono text-slate-200 mt-1">
                    {selectedEvent.src_ip}
                    {selectedEvent.src_port !== null && `:${selectedEvent.src_port}`}
                  </div>
                  <div className="text-[10px] text-slate-400 mt-0.5 font-mono">
                    Scope: {selectedEvent.src_ip_scope}
                  </div>
                </div>

                <div className="bg-slate-950/60 p-3 rounded border border-slate-800">
                  <div className="text-xs text-slate-500 uppercase font-mono">Destination Endpoint</div>
                  <div className="font-mono text-slate-200 mt-1">
                    {selectedEvent.dst_ip}
                    {selectedEvent.dst_port !== null && `:${selectedEvent.dst_port}`}
                  </div>
                  <div className="text-[10px] text-slate-400 mt-0.5 font-mono">
                    Scope: {selectedEvent.dst_ip_scope}
                  </div>
                </div>

                <div className="bg-slate-950/60 p-3 rounded border border-slate-800">
                  <div className="text-xs text-slate-500 uppercase font-mono">Volume</div>
                  <div className="font-mono text-slate-200 mt-1">
                    {selectedEvent.packets !== null && selectedEvent.packets !== undefined ? `${selectedEvent.packets} pkts` : '—'} / {formatBytes(selectedEvent.bytes)}
                  </div>
                  {(selectedEvent.bytes_in !== null && selectedEvent.bytes_in !== undefined || selectedEvent.bytes_out !== null && selectedEvent.bytes_out !== undefined) && (
                    <div className="text-[10px] text-slate-400 mt-0.5 font-mono">
                      In: {formatBytes(selectedEvent.bytes_in)} | Out: {formatBytes(selectedEvent.bytes_out)}
                    </div>
                  )}
                </div>
              </div>

              {/* Security / Telemetry Evidence Context */}
              {(selectedEvent.alert_signature || selectedEvent.dns_query || selectedEvent.connection_state) && (
                <div className="bg-slate-950/90 p-4 rounded-lg border border-slate-800 space-y-2">
                  <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider font-mono flex items-center justify-between">
                    <span>Telemetry Observation Evidence</span>
                    <span className="text-amber-400 text-[10px] lowercase border border-amber-800/60 px-1.5 py-0.5 rounded bg-amber-950/30">
                      neutral evidence • not detection verdict
                    </span>
                  </div>
                  {selectedEvent.alert_signature && (
                    <div className="text-sm">
                      <span className="text-amber-400 font-semibold font-mono">Suricata Sensor Alert: </span>
                      <span className="text-slate-200">{selectedEvent.alert_signature}</span>
                      {selectedEvent.alert_category && (
                        <span className="text-xs text-slate-400 ml-2 font-mono">
                          (Category: {selectedEvent.alert_category}, Severity: {selectedEvent.alert_severity})
                        </span>
                      )}
                      <p className="text-[11px] text-slate-400 mt-1 italic">
                        Architectural note: Ingested purely as raw sensor observational evidence. NetHunterSOC detection rules evaluate qualified alerts and hypotheses in Phase 3.
                      </p>
                    </div>
                  )}
                  {selectedEvent.dns_query && (
                    <div className="text-sm font-mono">
                      <span className="text-cyan-400 font-semibold">DNS Query: </span>
                      <span className="text-slate-200">{selectedEvent.dns_query}</span>
                      {selectedEvent.dns_qtype && (
                        <span className="text-xs text-slate-400 ml-2">Type: {selectedEvent.dns_qtype}</span>
                      )}
                      {selectedEvent.dns_rcode && (
                        <span className="text-xs text-slate-400 ml-2">RCode: {selectedEvent.dns_rcode}</span>
                      )}
                    </div>
                  )}
                  {selectedEvent.connection_state && (
                    <div className="text-sm font-mono text-slate-400">
                      <span>Connection State: </span>
                      <span className="text-slate-200">{selectedEvent.connection_state}</span>
                      {selectedEvent.tcp_flags && (
                        <span className="ml-3">Flags: {selectedEvent.tcp_flags}</span>
                      )}
                    </div>
                  )}
                </div>
              )}

              {/* Provenance Details */}
              <div className="bg-slate-950 p-4 rounded-lg border border-slate-800 space-y-2">
                <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider font-mono flex items-center justify-between">
                  <span>Data Provenance (Source Audit Trail)</span>
                  <span className="text-emerald-400 text-[11px] lowercase">verified immutable</span>
                </div>
                <div className="grid grid-cols-2 md:grid-cols-3 gap-2 font-mono text-xs text-slate-400">
                  <div>Source Format: <span className="text-slate-200">{selectedEvent.source_format}</span></div>
                  <div>Source File: <span className="text-slate-200">{selectedEvent.source_file}</span></div>
                  <div>Batch ID: <span className="text-slate-200">{selectedEvent.ingest_batch_id}</span></div>
                </div>
              </div>

              {/* Raw Record Metadata Viewer */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-slate-400 uppercase font-mono tracking-wider">
                    Raw Unmodified Record (Preserved Provenance)
                  </span>
                  <button
                    id="copy-raw-metadata-btn"
                    onClick={() => copyToClipboard(selectedEvent.raw_metadata || '')}
                    className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-emerald-400 bg-slate-800 px-2.5 py-1 rounded transition"
                  >
                    <Copy className="w-3 h-3" />
                    {copiedRaw ? 'Copied!' : 'Copy Raw'}
                  </button>
                </div>
                <pre className="p-3 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-emerald-300 overflow-x-auto max-h-48 whitespace-pre-wrap">
                  {(() => {
                    try {
                      return JSON.stringify(JSON.parse(selectedEvent.raw_metadata || '{}'), null, 2);
                    } catch {
                      return selectedEvent.raw_metadata;
                    }
                  })()}
                </pre>
              </div>
            </div>

            <div className="p-4 bg-slate-950 border-t border-slate-800 flex justify-end">
              <button
                onClick={() => setSelectedEvent(null)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-sm transition"
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Ingestion Modal */}
      {showImportModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/85 backdrop-blur-sm animate-in fade-in duration-150">
          <div className="bg-slate-900 border border-slate-700 w-full max-w-2xl rounded-xl shadow-2xl overflow-hidden flex flex-col">
            <div className="p-4 bg-slate-950 border-b border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Upload className="w-5 h-5 text-emerald-400" />
                <h3 className="font-bold text-white text-base">Import Telemetry Stream</h3>
              </div>
              <button
                id="close-import-modal-btn"
                onClick={() => setShowImportModal(false)}
                className="text-slate-400 hover:text-white p-1 rounded hover:bg-slate-800"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-6 space-y-5">
              {/* Format selection */}
              <div className="space-y-1.5">
                <label className="text-xs font-medium text-slate-400 uppercase tracking-wider font-mono">
                  Input Format
                </label>
                <div className="grid grid-cols-3 gap-2">
                  {(['auto', 'csv', 'suricata_eve'] as const).map((fmt) => (
                    <button
                      key={fmt}
                      type="button"
                      onClick={() => setFormatHint(fmt)}
                      className={`py-2 px-3 text-xs font-mono rounded-lg border transition text-center ${
                        formatHint === fmt
                          ? 'bg-emerald-950 text-emerald-300 border-emerald-600 font-semibold'
                          : 'bg-slate-950 text-slate-400 border-slate-800 hover:border-slate-700'
                      }`}
                    >
                      {fmt === 'auto' ? 'Auto-Detect' : fmt === 'csv' ? 'CSV Flow Log' : 'Suricata EVE-JSON'}
                    </button>
                  ))}
                </div>
              </div>

              {/* Drag & Drop Zone */}
              <div
                onDragEnter={handleDrag}
                onDragLeave={handleDrag}
                onDragOver={handleDrag}
                onDrop={handleDrop}
                className={`border-2 border-dashed rounded-xl p-8 text-center transition flex flex-col items-center justify-center gap-3 ${
                  dragActive
                    ? 'border-emerald-500 bg-emerald-950/20'
                    : selectedFile
                    ? 'border-slate-700 bg-slate-950/50'
                    : 'border-slate-800 hover:border-slate-700 bg-slate-950/30'
                }`}
              >
                <input
                  id={fileInputId}
                  type="file"
                  accept=".csv,.json,.log,.txt"
                  onChange={(e) => {
                    if (e.target.files && e.target.files[0]) {
                      setSelectedFile(e.target.files[0]);
                    }
                  }}
                  className="hidden"
                />

                <Upload className="w-8 h-8 text-slate-400" />

                {selectedFile ? (
                  <div className="space-y-1">
                    <div className="text-sm font-semibold text-slate-200 font-mono">{selectedFile.name}</div>
                    <div className="text-xs text-slate-400 font-mono">
                      {(selectedFile.size / 1024).toFixed(1)} KB — ready to normalize
                    </div>
                  </div>
                ) : (
                  <div className="space-y-1">
                    <div className="text-sm text-slate-300">
                      Drag & drop network log file here, or{' '}
                      <label htmlFor={fileInputId} className="text-emerald-400 hover:underline cursor-pointer">
                        browse files
                      </label>
                    </div>
                    <p className="text-xs text-slate-500">
                      Supports CSV flow records and Suricata EVE-JSON lines (up to 50MB)
                    </p>
                  </div>
                )}
              </div>

              {/* Quick Load Test Fixtures */}
              <div className="p-4 bg-slate-950/70 border border-slate-800 rounded-lg space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-slate-400 uppercase font-mono">
                    Instant Test Fixtures (Pre-packaged)
                  </span>
                  <span className="text-[11px] text-slate-500">No file required</span>
                </div>
                <div className="flex flex-wrap items-center gap-3 pt-1">
                  <button
                    id="modal-load-sample-csv-btn"
                    type="button"
                    onClick={() => handleLoadSample('csv')}
                    disabled={importing}
                    className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-slate-800 hover:bg-slate-700 text-slate-200 rounded border border-slate-700 transition"
                  >
                    <DownloadCloud className="w-3.5 h-3.5 text-emerald-400" />
                    Load Sample CSV Flows (12 records)
                  </button>

                  <button
                    id="modal-load-sample-eve-btn"
                    type="button"
                    onClick={() => handleLoadSample('suricata_eve')}
                    disabled={importing}
                    className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-slate-800 hover:bg-slate-700 text-slate-200 rounded border border-slate-700 transition"
                  >
                    <DownloadCloud className="w-3.5 h-3.5 text-cyan-400" />
                    Load Sample Suricata EVE (8 records + test malformed line)
                  </button>
                </div>
              </div>

              {/* Import Result Notification */}
              {importResult && (
                <div
                  className={`p-4 rounded-lg border text-sm space-y-2 font-mono ${
                    importResult.status === 'completed'
                      ? 'bg-emerald-950/40 border-emerald-800 text-emerald-300'
                      : importResult.status === 'completed_with_warnings'
                      ? 'bg-amber-950/40 border-amber-800 text-amber-300'
                      : 'bg-rose-950/40 border-rose-800 text-rose-300'
                  }`}
                >
                  <div className="flex items-center justify-between font-semibold">
                    <span className="flex items-center gap-2">
                      {importResult.status === 'completed' ? (
                        <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                      ) : importResult.status === 'completed_with_warnings' ? (
                        <AlertTriangle className="w-4 h-4 text-amber-400" />
                      ) : (
                        <XCircle className="w-4 h-4 text-rose-400" />
                      )}
                      Ingestion {importResult.status.replace(/_/g, ' ')}
                    </span>
                    <span className="text-xs font-normal">in {importResult.duration_ms}ms</span>
                  </div>

                  <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 text-xs pt-1 border-t border-slate-800/60">
                    <div>Format: <span className="font-semibold text-white">{importResult.source_format}</span></div>
                    <div>Parsed: <span className="font-semibold text-slate-200">{importResult.accepted}</span></div>
                    <div>Normalized: <span className="font-semibold text-emerald-400">{importResult.normalized ?? importResult.accepted}</span></div>
                    <div>Duplicates: <span className="font-semibold text-amber-400">{importResult.duplicates ?? 0}</span></div>
                    <div>Rejected: <span className="font-semibold text-rose-400">{importResult.rejected}</span></div>
                  </div>

                  {importResult.errors.length > 0 && (
                    <div className="mt-2 text-xs space-y-1 pt-1 border-t border-slate-800/60">
                      <div className="font-semibold text-slate-300">Parser Diagnostics / Rejected Lines:</div>
                      <div className="max-h-24 overflow-y-auto space-y-0.5 text-[11px] text-slate-400">
                        {importResult.errors.slice(0, 10).map((err, idx) => (
                          <div key={idx} className="truncate">
                            <span className="text-amber-400">Line {err.line}{err.field ? ` [${err.field}]` : ''}:</span> {err.reason}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>

            <div className="p-4 bg-slate-950 border-t border-slate-800 flex items-center justify-between">
              <div className="text-xs text-slate-500 font-mono">
                Streamed directly to SQLite WAL in batches of 250
              </div>

              <div className="flex items-center gap-3">
                <button
                  type="button"
                  onClick={() => setShowImportModal(false)}
                  className="px-4 py-2 text-sm bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition"
                >
                  Close
                </button>
                <button
                  id="submit-telemetry-import-btn"
                  type="button"
                  onClick={() => handleUpload()}
                  disabled={!selectedFile || importing}
                  className="flex items-center gap-2 px-5 py-2 text-sm font-medium bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg transition disabled:opacity-50 disabled:cursor-not-allowed shadow-sm"
                >
                  {importing ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin" />
                      Parsing & Ingesting...
                    </>
                  ) : (
                    <>
                      <Upload className="w-4 h-4" />
                      Parse & Ingest
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
