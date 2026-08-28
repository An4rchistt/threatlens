import {
  FormEvent,
  ReactNode,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import axios, { AxiosInstance } from 'axios';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  Activity,
  AlertCircle,
  AlertTriangle,
  Camera,
  Check,
  ChevronDown,
  Clock,
  Copy,
  Cpu,
  Database,
  ExternalLink,
  EyeOff,
  FileWarning,
  Fingerprint,
  Globe,
  History,
  ImageOff,
  Info,
  KeyRound,
  Link2,
  ListChecks,
  Loader2,
  Lock,
  Megaphone,
  Radar,
  RefreshCw,
  ScanLine,
  Search,
  Server,
  ShieldAlert,
  ShieldBan,
  ShieldCheck,
  Sparkles,
  Unlock,
  Zap,
} from 'lucide-react';

/* ==========================================================================
 * API CONTRACT (mirrors backend/models.py)
 * ========================================================================== */

type RiskLevel = 'safe' | 'low' | 'medium' | 'high' | 'critical' | 'unknown';
type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
type FactorSource = 'ai' | 'heuristic' | 'threat_intel' | 'reputation' | 'network';

interface RiskFactor {
  id: string;
  title: string;
  description: string;
  category: string;
  severity: Severity;
  source: FactorSource;
  confidence: number;
  weight: number;
  evidence?: string | null;
}

interface FormSummary {
  action: string;
  resolved_action: string;
  method: string;
  input_count: number;
  input_names: string[];
  input_types: string[];
  has_password_field: boolean;
  has_email_field: boolean;
  has_hidden_fields: boolean;
  hidden_field_count: number;
  is_cross_origin: boolean;
  action_scheme: string;
  action_is_insecure: boolean;
  action_is_empty: boolean;
}

interface LinkSummary {
  href: string;
  text: string;
  is_external: boolean;
  host: string;
}

interface PageMetadata {
  title: string;
  description: string;
  language: string;
  generator: string;
  favicon: string;
  meta_refresh: string;
  canonical_url: string;
  text_length: number;
  dom_length: number;
  link_count: number;
  external_link_count: number;
  unique_link_hosts: string[];
  form_count: number;
  password_field_count: number;
  hidden_input_count: number;
  iframe_count: number;
  iframe_sources: string[];
  script_count: number;
  external_script_hosts: string[];
  image_count: number;
  redirect_chain: string[];
  obfuscation_markers: string[];
  brand_keywords: string[];
}

interface VirusTotalStats {
  harmless: number;
  malicious: number;
  suspicious: number;
  undetected: number;
  timeout: number;
}

interface VirusTotalReport {
  available: boolean;
  queried_domain: string;
  status: string;
  detail?: string | null;
  domain_stats: VirusTotalStats;
  url_stats?: VirusTotalStats | null;
  malicious_engines: string[];
  reputation?: number | null;
  categories: Record<string, string>;
  registrar?: string | null;
  creation_date?: string | null;
  domain_age_days?: number | null;
  last_analysis_date?: string | null;
  permalink?: string | null;
}

interface AIAnalysis {
  available: boolean;
  status: string;
  detail?: string | null;
  provider: string;
  ai_model: string;
  threat_score: number;
  confidence: number;
  verdict: string;
  summary: string;
  brand_impersonated?: string | null;
  credential_harvesting: boolean;
  social_engineering_tactics: string[];
  recommended_action: string;
  indicators: RiskFactor[];
  latency_ms: number;
  tokens_used?: number | null;
}

interface EngineStatusPayload {
  reputation: string;
  scraper: string;
  heuristics: string;
  ai: string;
  threat_intel: string;
}

interface ReputationReport {
  available: boolean;
  status: string;
  detail?: string | null;
  classification: string;
  matched_value: string;
  match_type: string;
  category: string;
  source: string;
  checked_domain: string;
}

interface ScoreBreakdown {
  reputation_score: number;
  heuristic_score: number;
  ai_score: number;
  threat_intel_score: number;
  weights: Record<string, number>;
  escalations: string[];
}

interface ScanReport {
  scan_id: string;
  url: string;
  final_url: string;
  domain: string;
  registrable_domain: string;
  resolved_ips: string[];
  threat_score: number;
  risk_level: RiskLevel;
  verdict: string;
  summary: string;
  recommended_action: string;
  risk_factors: RiskFactor[];
  score_breakdown: ScoreBreakdown;
  ai_analysis: AIAnalysis;
  virustotal: VirusTotalReport;
  reputation: ReputationReport;
  screenshot_base64?: string | null;
  screenshot_mime: string;
  screenshot_bytes: number;
  headers: Record<string, string>;
  security_headers: Record<string, boolean>;
  http_status?: number | null;
  tls_enabled: boolean;
  page_metadata: PageMetadata;
  forms: FormSummary[];
  links: LinkSummary[];
  dom_excerpt: string;
  engines: EngineStatusPayload;
  duration_ms: number;
  scanned_at: string;
}

interface ScanHistoryItem {
  scan_id: string;
  url: string;
  domain: string;
  threat_score: number;
  risk_level: RiskLevel;
  verdict: string;
  page_title?: string | null;
  http_status?: number | null;
  indicator_count: number;
  duration_ms: number;
  created_at: string;
}

interface ScanHistoryPage {
  items: ScanHistoryItem[];
  total: number;
  limit: number;
  offset: number;
}

interface EngineCapabilities {
  ai_enabled: boolean;
  ai_provider: string;
  ai_provider_label: string;
  ai_model: string;
  ai_setup_url: string;
  ai_key_env: string;
  threat_intel_enabled: boolean;
  reputation_enabled: boolean;
  reputation_blocklist_size: number;
  reputation_allowlist_size: number;
  auth_required: boolean;
  max_concurrent_scans: number;
  nav_timeout_ms: number;
  rate_limit: string;
  version: string;
}

interface ApiErrorBody {
  error?: string;
  detail?: string;
  code?: string;
  request_id?: string;
}

/* ==========================================================================
 * HTTP CLIENT
 * ========================================================================== */

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
const API_KEY = process.env.NEXT_PUBLIC_API_KEY || '';

const api: AxiosInstance = axios.create({
  baseURL: API_BASE_URL,
  // A cold scan can legitimately take ~45s (navigation + screenshot + LLM).
  timeout: 120_000,
  headers: {
    'Content-Type': 'application/json',
    ...(API_KEY ? { 'X-API-Key': API_KEY } : {}),
  },
});

function describeApiError(error: unknown): string {
  if (axios.isAxiosError<ApiErrorBody>(error)) {
    if (error.code === 'ECONNABORTED' || error.code === 'ETIMEDOUT') {
      return 'The analysis timed out before the engine responded. The target may be deliberately slow.';
    }
    if (!error.response) {
      return `Could not reach the analysis engine at ${API_BASE_URL}. Confirm the backend container is running.`;
    }
    const body = error.response.data;
    const detail = body?.detail?.trim();
    const headline = body?.error?.trim();
    if (detail && headline) return `${headline}: ${detail}`;
    if (detail) return detail;
    if (headline) return headline;
    return `Request failed with HTTP ${error.response.status}.`;
  }
  if (error instanceof Error && error.message) return error.message;
  return 'An unexpected error occurred while contacting the analysis engine.';
}

async function postScan(url: string): Promise<ScanReport> {
  const { data } = await api.post<ScanReport>('/api/scan', {
    url,
    include_screenshot: true,
    deep_analysis: true,
    check_threat_intel: true,
  });
  return data;
}

async function fetchHistory(): Promise<ScanHistoryPage> {
  const { data } = await api.get<ScanHistoryPage>('/api/scans', { params: { limit: 8, offset: 0 } });
  return data;
}

async function fetchCapabilities(): Promise<EngineCapabilities> {
  const { data } = await api.get<EngineCapabilities>('/api/config');
  return data;
}

async function fetchReport(scanId: string): Promise<ScanReport> {
  const { data } = await api.get<ScanReport>(`/api/scans/${scanId}`);
  return data;
}

/* ==========================================================================
 * PRESENTATION HELPERS
 * ========================================================================== */

function cx(...values: Array<string | false | null | undefined>): string {
  return values.filter(Boolean).join(' ');
}

interface LevelTheme {
  label: string;
  text: string;
  border: string;
  bg: string;
  stroke: string;
  glow: string;
  dot: string;
}

const LEVEL_THEME: Record<RiskLevel, LevelTheme> = {
  critical: {
    label: 'Critical',
    text: 'text-rose-400',
    border: 'border-rose-500/40',
    bg: 'bg-rose-500/10',
    stroke: '#f43f5e',
    glow: 'shadow-neon-red',
    dot: 'bg-rose-500',
  },
  high: {
    label: 'High',
    text: 'text-rose-300',
    border: 'border-rose-400/35',
    bg: 'bg-rose-400/10',
    stroke: '#fb7185',
    glow: 'shadow-neon-red',
    dot: 'bg-rose-400',
  },
  medium: {
    label: 'Medium',
    text: 'text-amber-300',
    border: 'border-amber-400/35',
    bg: 'bg-amber-400/10',
    stroke: '#f59e0b',
    glow: 'shadow-neon-amber',
    dot: 'bg-amber-400',
  },
  low: {
    label: 'Low',
    text: 'text-sky-300',
    border: 'border-sky-400/30',
    bg: 'bg-sky-400/10',
    stroke: '#38bdf8',
    glow: 'shadow-neon-cyan',
    dot: 'bg-sky-400',
  },
  safe: {
    label: 'Clean',
    text: 'text-cyan-300',
    border: 'border-cyan-400/30',
    bg: 'bg-cyan-400/10',
    stroke: '#22d3ee',
    glow: 'shadow-neon-cyan',
    dot: 'bg-cyan-400',
  },
  unknown: {
    label: 'Unknown',
    text: 'text-slate-300',
    border: 'border-slate-500/30',
    bg: 'bg-slate-500/10',
    stroke: '#94a3b8',
    glow: '',
    dot: 'bg-slate-400',
  },
};

function themeFor(level: RiskLevel | undefined): LevelTheme {
  return LEVEL_THEME[level ?? 'unknown'] ?? LEVEL_THEME.unknown;
}

const SEVERITY_STYLE: Record<Severity, { text: string; bg: string; border: string; label: string }> = {
  critical: { text: 'text-rose-300', bg: 'bg-rose-500/15', border: 'border-rose-500/40', label: 'Critical' },
  high: { text: 'text-rose-200', bg: 'bg-rose-400/10', border: 'border-rose-400/30', label: 'High' },
  medium: { text: 'text-amber-200', bg: 'bg-amber-400/10', border: 'border-amber-400/30', label: 'Medium' },
  low: { text: 'text-sky-200', bg: 'bg-sky-400/10', border: 'border-sky-400/25', label: 'Low' },
  info: { text: 'text-slate-300', bg: 'bg-slate-500/10', border: 'border-slate-500/25', label: 'Info' },
};

function SeverityIcon({ severity, className }: { severity: Severity; className?: string }) {
  switch (severity) {
    case 'critical':
      return <ShieldAlert className={className} aria-hidden="true" />;
    case 'high':
      return <AlertTriangle className={className} aria-hidden="true" />;
    case 'medium':
      return <AlertCircle className={className} aria-hidden="true" />;
    default:
      return <Info className={className} aria-hidden="true" />;
  }
}

function CategoryIcon({ category, className }: { category: string; className?: string }) {
  switch (category) {
    case 'impersonation':
      return <Fingerprint className={className} aria-hidden="true" />;
    case 'credential_harvesting':
      return <KeyRound className={className} aria-hidden="true" />;
    case 'evasion':
      return <EyeOff className={className} aria-hidden="true" />;
    case 'social_engineering':
      return <Megaphone className={className} aria-hidden="true" />;
    case 'threat_intel':
      return <Radar className={className} aria-hidden="true" />;
    case 'reputation':
      return <ShieldBan className={className} aria-hidden="true" />;
    case 'infrastructure':
      return <Server className={className} aria-hidden="true" />;
    case 'transport':
      return <Unlock className={className} aria-hidden="true" />;
    case 'url':
      return <Link2 className={className} aria-hidden="true" />;
    default:
      return <FileWarning className={className} aria-hidden="true" />;
  }
}

const SOURCE_LABEL: Record<FactorSource, string> = {
  ai: 'AI analyst',
  heuristic: 'Rule engine',
  threat_intel: 'Threat intel',
  reputation: 'Reputation',
  network: 'Network',
};

function prettify(value: string): string {
  return value
    .replace(/[_-]+/g, ' ')
    .replace(/\b\w/g, (char) => char.toUpperCase())
    .trim();
}

function formatDuration(ms: number): string {
  if (!Number.isFinite(ms) || ms <= 0) return '0ms';
  if (ms < 1000) return `${Math.round(ms)}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB'];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return `${(bytes / 1024 ** index).toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
}

function formatTimestamp(value: string): string {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return parsed.toLocaleString(undefined, {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function truncate(value: string, max: number): string {
  if (value.length <= max) return value;
  return `${value.slice(0, max - 1)}\u2026`;
}

/* ==========================================================================
 * SMALL SHARED COMPONENTS
 * ========================================================================== */

function Panel({
  title,
  icon,
  action,
  className,
  children,
}: {
  title: string;
  icon: ReactNode;
  action?: ReactNode;
  className?: string;
  children: ReactNode;
}) {
  return (
    <section className={cx('glass p-5 sm:p-6', className)}>
      <div className="mb-4 flex items-center justify-between gap-3">
        <h2 className="panel-heading">
          {icon}
          {title}
        </h2>
        {action}
      </div>
      {children}
    </section>
  );
}

function StatChip({
  icon,
  label,
  tone = 'neutral',
}: {
  icon: ReactNode;
  label: string;
  tone?: 'neutral' | 'good' | 'warn' | 'bad';
}) {
  const tones = {
    neutral: 'text-slate-300 border-white/10',
    good: 'text-cyan-300 border-cyan-400/30',
    warn: 'text-amber-300 border-amber-400/30',
    bad: 'text-rose-300 border-rose-400/30',
  } as const;
  return (
    <span className={cx('chip', tones[tone])}>
      {icon}
      {label}
    </span>
  );
}

function CopyButton({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false);

  const copy = useCallback(async () => {
    try {
      if (navigator?.clipboard?.writeText) {
        await navigator.clipboard.writeText(value);
        setCopied(true);
        window.setTimeout(() => setCopied(false), 1600);
      }
    } catch {
      setCopied(false);
    }
  }, [value]);

  return (
    <button
      type="button"
      onClick={copy}
      aria-label={copied ? `${label} copied` : `Copy ${label}`}
      className="inline-flex items-center gap-1.5 rounded-lg border border-white/10 bg-slate-900/60 px-2.5 py-1 text-xs font-medium text-slate-300 transition hover:border-cyan-400/40 hover:text-cyan-300"
    >
      {copied ? (
        <Check className="h-3.5 w-3.5" aria-hidden="true" />
      ) : (
        <Copy className="h-3.5 w-3.5" aria-hidden="true" />
      )}
      {copied ? 'Copied' : 'Copy'}
    </button>
  );
}

/* ==========================================================================
 * HEADER
 * ========================================================================== */

function EngineBadge({
  enabled,
  label,
  icon,
  offLabel,
  setupUrl,
}: {
  enabled: boolean;
  label: string;
  icon: ReactNode;
  offLabel: string;
  setupUrl?: string;
}) {
  const content = (
    <>
      {icon}
      {label}
      <span className={cx('h-1.5 w-1.5 rounded-full', enabled ? 'bg-cyan-400' : 'bg-slate-600')} />
    </>
  );
  const className = cx(
    'inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] font-medium transition',
    enabled
      ? 'border-cyan-400/30 bg-cyan-400/10 text-cyan-300'
      : 'border-white/10 bg-slate-800/60 text-slate-500'
  );

  // When an engine is off and we know where the free key lives, make the badge
  // the shortest path to switching it on.
  if (!enabled && setupUrl) {
    return (
      <a
        href={setupUrl}
        target="_blank"
        rel="noopener noreferrer"
        title={`${offLabel} Click to get a free key.`}
        className={cx(className, 'hover:border-cyan-400/40 hover:text-cyan-300')}
      >
        {content}
      </a>
    );
  }

  return (
    <span className={className} title={enabled ? `${label} is active` : offLabel}>
      {content}
    </span>
  );
}

function SiteHeader({ capabilities }: { capabilities?: EngineCapabilities }) {
  return (
    <header className="mx-auto flex w-full max-w-7xl flex-col gap-4 px-4 pt-6 sm:flex-row sm:items-center sm:justify-between sm:px-6">
      <div className="flex items-center gap-3">
        <span className="relative flex h-10 w-10 items-center justify-center rounded-xl border border-cyan-400/30 bg-cyan-400/10">
          <ShieldCheck className="h-5 w-5 text-cyan-300" aria-hidden="true" />
          <span className="absolute inset-0 rounded-xl bg-cyan-400/10 blur-md" aria-hidden="true" />
        </span>
        <div>
          <p className="text-base font-semibold tracking-tight text-white">ThreatLens</p>
          <p className="text-xs text-slate-500">Phishing analysis &amp; web threat engine</p>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <EngineBadge
          enabled={Boolean(capabilities?.ai_enabled)}
          label={
            capabilities?.ai_enabled
              ? `${capabilities.ai_provider_label || 'AI'}: ${capabilities.ai_model}`
              : `AI analyst${capabilities?.ai_provider_label ? ` (${capabilities.ai_provider_label})` : ''}`
          }
          offLabel={
            capabilities?.ai_key_env
              ? `${capabilities.ai_key_env} is not set, so scans use the rule engine and threat intel.`
              : 'The AI analyst pass is not configured.'
          }
          setupUrl={capabilities?.ai_setup_url || undefined}
          icon={<Sparkles className="h-3.5 w-3.5" aria-hidden="true" />}
        />
        <EngineBadge
          enabled={Boolean(capabilities?.reputation_enabled)}
          label={
            capabilities?.reputation_enabled
              ? `Reputation: ${capabilities.reputation_blocklist_size} feeds`
              : 'Reputation'
          }
          offLabel="Local reputation feed is not loaded"
          icon={<ShieldBan className="h-3.5 w-3.5" aria-hidden="true" />}
        />
        <EngineBadge
          enabled={Boolean(capabilities?.threat_intel_enabled)}
          label="Threat intel"
          offLabel="VIRUSTOTAL_API_KEY is not set - reputation lookups are skipped"
          icon={<Radar className="h-3.5 w-3.5" aria-hidden="true" />}
        />
        <EngineBadge
          enabled
          label="Sandbox"
          offLabel="Browser sandbox unavailable"
          icon={<Cpu className="h-3.5 w-3.5" aria-hidden="true" />}
        />
      </div>
    </header>
  );
}

/* ==========================================================================
 * HERO / SEARCH
 * ========================================================================== */

const SAMPLE_TARGETS = ['https://example.com', 'https://github.com', 'http://neverssl.com'];

function SearchHero({
  value,
  onChange,
  onSubmit,
  isScanning,
  navTimeoutMs,
}: {
  value: string;
  onChange: (next: string) => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
  isScanning: boolean;
  navTimeoutMs?: number;
}) {
  return (
    <section className="relative mx-auto w-full max-w-5xl px-4 pt-14 text-center sm:px-6 sm:pt-20">
      <span className="chip mx-auto mb-6 border-cyan-400/20 bg-cyan-400/5 text-cyan-300">
        <Zap className="h-3.5 w-3.5" aria-hidden="true" />
        Sandboxed capture &middot; JavaScript disabled &middot; AI-scored
      </span>

      <h1 className="text-balance text-4xl font-semibold tracking-tight text-white sm:text-5xl lg:text-6xl">
        See the threat
        <span className="bg-gradient-to-r from-cyan-300 via-sky-400 to-cyan-200 bg-clip-text text-transparent">
          {' '}
          before your users do
        </span>
      </h1>
      <p className="mx-auto mt-5 max-w-2xl text-balance text-base leading-relaxed text-slate-400 sm:text-lg">
        Submit any URL. ThreatLens renders it in an isolated headless browser, hunts the DOM for
        credential harvesting and brand impersonation, cross-checks reputation feeds, and returns a
        scored, evidence-backed verdict.
      </p>

      <form onSubmit={onSubmit} className="mt-10" role="search" aria-label="Analyse a URL">
        <div
          className={cx(
            'group relative rounded-2xl border border-white/10 bg-slate-800/40 p-2 shadow-glass backdrop-blur-xl transition',
            'focus-within:border-cyan-400/40 focus-within:shadow-neon-cyan',
            isScanning && 'animate-pulse-glow'
          )}
        >
          <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
            <div className="flex flex-1 items-center gap-3 px-4 py-3">
              <Search className="h-5 w-5 shrink-0 text-slate-500" aria-hidden="true" />
              <label htmlFor="target-url" className="sr-only">
                URL to analyse
              </label>
              <input
                id="target-url"
                name="url"
                type="text"
                inputMode="url"
                autoComplete="off"
                autoCapitalize="none"
                spellCheck={false}
                enterKeyHint="search"
                disabled={isScanning}
                value={value}
                onChange={(event) => onChange(event.target.value)}
                placeholder="https://suspicious-login-portal.example"
                aria-describedby="url-help"
                className="w-full min-w-0 bg-transparent font-mono text-base text-white placeholder:text-slate-600 focus:outline-none disabled:opacity-60 sm:text-lg"
              />
            </div>
            <button
              type="submit"
              disabled={isScanning || value.trim().length === 0}
              className={cx(
                'inline-flex items-center justify-center gap-2 rounded-xl px-6 py-3.5 text-sm font-semibold transition',
                'bg-cyan-400 text-slate-900 hover:bg-cyan-300',
                'disabled:cursor-not-allowed disabled:bg-slate-700 disabled:text-slate-400'
              )}
            >
              {isScanning ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
                  Analyzing
                </>
              ) : (
                <>
                  <ScanLine className="h-4 w-4" aria-hidden="true" />
                  Analyze URL
                </>
              )}
            </button>
          </div>
        </div>
      </form>

      <p id="url-help" className="mt-4 text-xs text-slate-500">
        Loopback, private, link-local and cloud-metadata targets are rejected before any request is
        made. Navigation budget:{' '}
        {navTimeoutMs ? `${Math.round(navTimeoutMs / 1000)}s` : '10s'}.
      </p>

      <div className="mt-5 flex flex-wrap items-center justify-center gap-2">
        <span className="text-xs text-slate-600">Try:</span>
        {SAMPLE_TARGETS.map((sample) => (
          <button
            key={sample}
            type="button"
            disabled={isScanning}
            onClick={() => onChange(sample)}
            className="rounded-full border border-white/10 bg-slate-800/40 px-3 py-1 font-mono text-xs text-slate-400 transition hover:border-cyan-400/30 hover:text-cyan-300 disabled:opacity-50"
          >
            {sample}
          </button>
        ))}
      </div>
    </section>
  );
}

/* ==========================================================================
 * LOADING STATE
 * ========================================================================== */

const SCAN_STAGES = [
  'Validating target and resolving DNS',
  'Launching isolated browser context',
  'Rendering page with JavaScript disabled',
  'Extracting DOM, links and form actions',
  'Capturing full-page screenshot',
  'Querying reputation feeds',
  'Running AI phishing analysis',
  'Fusing threat score',
];

function ScanningPanel({ target }: { target: string }) {
  const [stage, setStage] = useState(0);

  useEffect(() => {
    const timer = window.setInterval(() => {
      setStage((current) => Math.min(current + 1, SCAN_STAGES.length - 1));
    }, 2200);
    return () => window.clearInterval(timer);
  }, []);

  return (
    <div
      className="mx-auto mt-14 w-full max-w-7xl px-4 sm:px-6"
      role="status"
      aria-live="polite"
      aria-busy="true"
    >
      <div className="glass relative overflow-hidden p-6 sm:p-8">
        <div
          className="pointer-events-none absolute inset-x-0 top-0 h-24 animate-scanline bg-gradient-to-b from-cyan-400/15 to-transparent"
          aria-hidden="true"
        />

        <div className="flex flex-col gap-6 lg:flex-row lg:items-center lg:justify-between">
          <div className="flex items-center gap-4">
            <span className="relative flex h-14 w-14 items-center justify-center rounded-2xl border border-cyan-400/30 bg-cyan-400/10">
              <Radar className="h-7 w-7 animate-spin-slow text-cyan-300" aria-hidden="true" />
            </span>
            <div className="min-w-0">
              <p className="text-lg font-semibold text-white">Analysis in progress</p>
              <p className="truncate font-mono text-sm text-slate-400">{target}</p>
            </div>
          </div>

          <ol className="grid gap-2 text-sm sm:grid-cols-2 lg:max-w-xl">
            {SCAN_STAGES.map((label, index) => {
              const done = index < stage;
              const active = index === stage;
              return (
                <li
                  key={label}
                  className={cx(
                    'flex items-center gap-2 transition-colors',
                    done && 'text-slate-500',
                    active && 'text-cyan-300',
                    !done && !active && 'text-slate-600'
                  )}
                >
                  {done ? (
                    <Check className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                  ) : active ? (
                    <Loader2 className="h-3.5 w-3.5 shrink-0 animate-spin" aria-hidden="true" />
                  ) : (
                    <span
                      className="h-1.5 w-1.5 shrink-0 rounded-full bg-slate-700"
                      aria-hidden="true"
                    />
                  )}
                  <span className="truncate">{label}</span>
                </li>
              );
            })}
          </ol>
        </div>

        <div className="mt-8 grid gap-4 lg:grid-cols-12">
          <div className="glass-subtle h-52 animate-pulse lg:col-span-4" aria-hidden="true" />
          <div className="glass-subtle h-52 animate-pulse lg:col-span-8" aria-hidden="true" />
          <div className="glass-subtle h-40 animate-pulse lg:col-span-7" aria-hidden="true" />
          <div className="glass-subtle h-40 animate-pulse lg:col-span-5" aria-hidden="true" />
        </div>
      </div>
    </div>
  );
}

/* ==========================================================================
 * THREAT SCORE GAUGE
 * ========================================================================== */

function ThreatGauge({ score, level }: { score: number; level: RiskLevel }) {
  const theme = themeFor(level);
  const size = 240;
  const strokeWidth = 16;
  const radius = (size - strokeWidth) / 2 - 6;
  const circumference = 2 * Math.PI * radius;
  const clamped = Math.max(0, Math.min(score, 100));

  // Animate from empty to the real value on mount so the gauge reads as a
  // measurement rather than a static number.
  const [progress, setProgress] = useState(0);
  useEffect(() => {
    const frame = window.requestAnimationFrame(() => setProgress(clamped));
    return () => window.cancelAnimationFrame(frame);
  }, [clamped]);

  const offset = circumference * (1 - progress / 100);

  return (
    <div className={cx('glass flex flex-col items-center p-6 sm:p-8', theme.glow)}>
      <h2 className="panel-heading mb-6 self-start">
        <Activity className="h-4 w-4" aria-hidden="true" />
        Threat score
      </h2>

      <div className="relative" style={{ width: size, height: size }}>
        <svg
          width={size}
          height={size}
          viewBox={`0 0 ${size} ${size}`}
          role="img"
          aria-label={`Threat score ${clamped} out of 100, rated ${theme.label}`}
          className="-rotate-90"
        >
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke="rgba(148, 163, 184, 0.13)"
            strokeWidth={strokeWidth}
          />
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke={theme.stroke}
            strokeWidth={strokeWidth}
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            style={{
              transition: 'stroke-dashoffset 1.2s cubic-bezier(0.22, 1, 0.36, 1)',
              filter: `drop-shadow(0 0 12px ${theme.stroke}aa)`,
            }}
          />
        </svg>

        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={cx('text-6xl font-bold tabular-nums tracking-tight', theme.text)}>
            {clamped}
          </span>
          <span className="mt-1 text-xs uppercase tracking-[0.2em] text-slate-500">out of 100</span>
        </div>
      </div>

      <div
        className={cx(
          'mt-6 inline-flex items-center gap-2 rounded-full border px-4 py-1.5 text-sm font-semibold',
          theme.border,
          theme.bg,
          theme.text
        )}
      >
        <span className={cx('h-2 w-2 rounded-full', theme.dot)} aria-hidden="true" />
        {theme.label} risk
      </div>
    </div>
  );
}

/* ==========================================================================
 * VERDICT + BREAKDOWN
 * ========================================================================== */

function BreakdownBar({
  label,
  score,
  weight,
  active,
}: {
  label: string;
  score: number;
  weight?: number;
  active: boolean;
}) {
  const theme = themeFor(
    score >= 85 ? 'critical' : score >= 65 ? 'high' : score >= 40 ? 'medium' : score >= 20 ? 'low' : 'safe'
  );
  return (
    <div className={cx('space-y-1.5', !active && 'opacity-40')}>
      <div className="flex items-baseline justify-between gap-2 text-xs">
        <span className="font-medium text-slate-300">{label}</span>
        <span className="font-mono text-slate-400">
          {active ? score : '--'}
          {weight !== undefined && active ? (
            <span className="ml-1 text-slate-600">&times;{weight.toFixed(2)}</span>
          ) : null}
        </span>
      </div>
      <div className="h-1.5 overflow-hidden rounded-full bg-slate-700/60">
        <div
          className="h-full rounded-full transition-all duration-1200"
          style={{
            width: `${active ? Math.max(2, Math.min(score, 100)) : 0}%`,
            backgroundColor: theme.stroke,
          }}
        />
      </div>
    </div>
  );
}

function VerdictPanel({ report }: { report: ScanReport }) {
  const theme = themeFor(report.risk_level);
  const breakdown = report.score_breakdown;

  return (
    <section className="glass flex flex-col gap-5 p-6 sm:p-8">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0 space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityIcon
              severity={
                report.risk_level === 'critical'
                  ? 'critical'
                  : report.risk_level === 'high'
                    ? 'high'
                    : report.risk_level === 'medium'
                      ? 'medium'
                      : 'info'
              }
              className={cx('h-5 w-5', theme.text)}
            />
            <h2 className={cx('text-xl font-semibold tracking-tight sm:text-2xl', theme.text)}>
              {report.verdict || `${theme.label} risk`}
            </h2>
          </div>
          <div className="flex min-w-0 items-center gap-2">
            <Globe className="h-4 w-4 shrink-0 text-slate-500" aria-hidden="true" />
            <a
              href={report.final_url || report.url}
              target="_blank"
              rel="noopener noreferrer nofollow"
              className="truncate font-mono text-sm text-slate-300 underline decoration-slate-600 decoration-dotted underline-offset-4 hover:text-cyan-300"
              title={report.final_url || report.url}
            >
              {truncate(report.final_url || report.url, 78)}
            </a>
            <ExternalLink className="h-3.5 w-3.5 shrink-0 text-slate-600" aria-hidden="true" />
          </div>
        </div>
        <CopyButton value={report.final_url || report.url} label="URL" />
      </div>

      <div className="flex flex-wrap gap-2">
        <StatChip
          icon={<Server className="h-3.5 w-3.5" aria-hidden="true" />}
          label={`HTTP ${report.http_status ?? '--'}`}
          tone={
            report.http_status && report.http_status >= 400
              ? 'warn'
              : report.http_status
                ? 'good'
                : 'neutral'
          }
        />
        <StatChip
          icon={
            report.tls_enabled ? (
              <Lock className="h-3.5 w-3.5" aria-hidden="true" />
            ) : (
              <Unlock className="h-3.5 w-3.5" aria-hidden="true" />
            )
          }
          label={report.tls_enabled ? 'HTTPS' : 'No TLS'}
          tone={report.tls_enabled ? 'good' : 'bad'}
        />
        <StatChip
          icon={<Clock className="h-3.5 w-3.5" aria-hidden="true" />}
          label={formatDuration(report.duration_ms)}
        />
        <StatChip
          icon={<ListChecks className="h-3.5 w-3.5" aria-hidden="true" />}
          label={`${report.risk_factors.length} indicator${report.risk_factors.length === 1 ? '' : 's'}`}
          tone={report.risk_factors.length > 0 ? 'warn' : 'good'}
        />
        {report.resolved_ips.slice(0, 1).map((ip) => (
          <StatChip
            key={ip}
            icon={<Radar className="h-3.5 w-3.5" aria-hidden="true" />}
            label={ip}
          />
        ))}
        {report.ai_analysis.brand_impersonated ? (
          <StatChip
            icon={<Fingerprint className="h-3.5 w-3.5" aria-hidden="true" />}
            label={`Impersonates ${prettify(report.ai_analysis.brand_impersonated)}`}
            tone="bad"
          />
        ) : null}
      </div>

      <div className="space-y-3">
        <h3 className="kv-label">Analyst summary</h3>
        <p className="text-sm leading-relaxed text-slate-300">{report.summary}</p>
      </div>

      {report.recommended_action ? (
        <div className={cx('rounded-xl border p-4', theme.border, theme.bg)}>
          <h3 className="kv-label mb-1.5">Recommended action</h3>
          <p className={cx('text-sm leading-relaxed', theme.text)}>{report.recommended_action}</p>
        </div>
      ) : null}

      <div className="grid gap-4 border-t border-white/5 pt-5 sm:grid-cols-3">
        <BreakdownBar
          label="Rule engine"
          score={breakdown.heuristic_score}
          weight={breakdown.weights.heuristic}
          active
        />
        <BreakdownBar
          label="AI analyst"
          score={breakdown.ai_score}
          weight={breakdown.weights.ai}
          active={report.ai_analysis.available && report.ai_analysis.status === 'ok'}
        />
        <BreakdownBar
          label="Threat intel"
          score={breakdown.threat_intel_score}
          weight={breakdown.weights.threat_intel}
          active={report.virustotal.available}
        />
      </div>

      {breakdown.escalations.length > 0 ? (
        <ul className="space-y-1.5 border-t border-white/5 pt-4">
          {breakdown.escalations.map((escalation) => (
            <li key={escalation} className="flex items-start gap-2 text-xs text-slate-400">
              <Zap className="mt-0.5 h-3.5 w-3.5 shrink-0 text-amber-400" aria-hidden="true" />
              <span>
                <span className="font-medium text-slate-300">Score floor applied: </span>
                {escalation}
              </span>
            </li>
          ))}
        </ul>
      ) : null}
    </section>
  );
}

/* ==========================================================================
 * SCREENSHOT
 * ========================================================================== */

function ScreenshotPanel({ report }: { report: ScanReport }) {
  const [expanded, setExpanded] = useState(false);
  const source = report.screenshot_base64
    ? `data:${report.screenshot_mime};base64,${report.screenshot_base64}`
    : null;

  return (
    <Panel
      title="Sandbox capture"
      icon={<Camera className="h-4 w-4" aria-hidden="true" />}
      action={
        source ? (
          <div className="flex items-center gap-2">
            <span className="text-[11px] text-slate-500">{formatBytes(report.screenshot_bytes)}</span>
            <button
              type="button"
              onClick={() => setExpanded((current) => !current)}
              aria-expanded={expanded}
              className="inline-flex items-center gap-1.5 rounded-lg border border-white/10 bg-slate-900/60 px-2.5 py-1 text-xs font-medium text-slate-300 transition hover:border-cyan-400/40 hover:text-cyan-300"
            >
              {expanded ? 'Collapse' : 'Full page'}
              <ChevronDown
                className={cx('h-3.5 w-3.5 transition-transform', expanded && 'rotate-180')}
                aria-hidden="true"
              />
            </button>
          </div>
        ) : null
      }
    >
      {source ? (
        <figure className="space-y-3">
          <div
            className={cx(
              'relative overflow-hidden rounded-xl border border-white/10 bg-slate-950',
              expanded ? 'max-h-[42rem] overflow-y-auto' : 'max-h-80 mask-fade-b'
            )}
          >
            {/* Rendered with JavaScript disabled, so this is a passive image of
                a hostile page - never an interactive frame. */}
            <img
              src={source}
              alt={`Rendered screenshot of ${report.domain} captured in the sandbox`}
              className="w-full"
              loading="lazy"
              decoding="async"
            />
          </div>
          <figcaption className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-slate-500">
            <span>Captured with JavaScript disabled</span>
            <span aria-hidden="true">&middot;</span>
            <span className="font-mono">{report.page_metadata.title || 'Untitled document'}</span>
          </figcaption>
        </figure>
      ) : (
        <div className="flex flex-col items-center justify-center gap-2 rounded-xl border border-dashed border-white/10 py-14 text-center">
          <ImageOff className="h-6 w-6 text-slate-600" aria-hidden="true" />
          <p className="text-sm text-slate-400">No screenshot captured</p>
          <p className="max-w-xs text-xs text-slate-600">
            The target blocked rendering or the capture exceeded its time budget. DOM analysis below
            is unaffected.
          </p>
        </div>
      )}
    </Panel>
  );
}

/* ==========================================================================
 * INDICATORS
 * ========================================================================== */

function IndicatorCard({ factor }: { factor: RiskFactor }) {
  const style = SEVERITY_STYLE[factor.severity] ?? SEVERITY_STYLE.info;

  return (
    <li
      className={cx(
        'animate-fade-up rounded-xl border bg-slate-900/40 p-4 transition hover:bg-slate-900/70',
        style.border
      )}
    >
      <div className="flex items-start gap-3">
        <span
          className={cx(
            'mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border',
            style.border,
            style.bg
          )}
        >
          <SeverityIcon severity={factor.severity} className={cx('h-4 w-4', style.text)} />
        </span>

        <div className="min-w-0 flex-1 space-y-2">
          <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
            <h3 className="text-sm font-semibold text-slate-100">{factor.title}</h3>
            <span
              className={cx(
                'rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider',
                style.border,
                style.bg,
                style.text
              )}
            >
              {style.label}
            </span>
          </div>

          <p className="text-sm leading-relaxed text-slate-400">{factor.description}</p>

          {factor.evidence ? (
            <p className="overflow-x-auto rounded-lg border border-white/5 bg-slate-950/70 px-3 py-2 font-mono text-[11px] leading-relaxed text-slate-400">
              {factor.evidence}
            </p>
          ) : null}

          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-slate-500">
            <span className="inline-flex items-center gap-1">
              <CategoryIcon category={factor.category} className="h-3 w-3" />
              {prettify(factor.category)}
            </span>
            <span aria-hidden="true">&middot;</span>
            <span>{SOURCE_LABEL[factor.source] ?? prettify(factor.source)}</span>
            <span aria-hidden="true">&middot;</span>
            <span>{Math.round(factor.confidence * 100)}% confidence</span>
          </div>
        </div>
      </div>
    </li>
  );
}

function IndicatorList({ factors }: { factors: RiskFactor[] }) {
  const [showAll, setShowAll] = useState(false);
  const visible = showAll ? factors : factors.slice(0, 6);

  return (
    <Panel
      title={`AI threat indicators (${factors.length})`}
      icon={<ShieldAlert className="h-4 w-4" aria-hidden="true" />}
      action={
        factors.length > 6 ? (
          <button
            type="button"
            onClick={() => setShowAll((current) => !current)}
            aria-expanded={showAll}
            className="inline-flex items-center gap-1.5 rounded-lg border border-white/10 bg-slate-900/60 px-2.5 py-1 text-xs font-medium text-slate-300 transition hover:border-cyan-400/40 hover:text-cyan-300"
          >
            {showAll ? 'Show top 6' : `Show all ${factors.length}`}
            <ChevronDown
              className={cx('h-3.5 w-3.5 transition-transform', showAll && 'rotate-180')}
              aria-hidden="true"
            />
          </button>
        ) : null
      }
    >
      {factors.length === 0 ? (
        <div className="flex flex-col items-center gap-2 rounded-xl border border-dashed border-cyan-400/20 bg-cyan-400/5 py-12 text-center">
          <ShieldCheck className="h-7 w-7 text-cyan-300" aria-hidden="true" />
          <p className="text-sm font-medium text-cyan-200">No phishing indicators found</p>
          <p className="max-w-sm text-xs text-slate-400">
            The rule engine, the AI analyst and the reputation feeds all came back clean for this
            capture.
          </p>
        </div>
      ) : (
        <ul className="space-y-3">
          {visible.map((factor, index) => (
            <IndicatorCard key={`${factor.id}-${index}`} factor={factor} />
          ))}
        </ul>
      )}
    </Panel>
  );
}

/* ==========================================================================
 * THREAT INTEL + ENGINES
 * ========================================================================== */

function IntelStat({ label, value, tone }: { label: string; value: number; tone: 'bad' | 'warn' | 'good' | 'neutral' }) {
  const tones = {
    bad: 'text-rose-300 border-rose-400/30 bg-rose-500/10',
    warn: 'text-amber-300 border-amber-400/30 bg-amber-400/10',
    good: 'text-cyan-300 border-cyan-400/30 bg-cyan-400/10',
    neutral: 'text-slate-300 border-white/10 bg-slate-900/50',
  } as const;
  return (
    <div className={cx('rounded-xl border p-3 text-center', tones[tone])}>
      <p className="text-2xl font-semibold tabular-nums">{value}</p>
      <p className="mt-0.5 text-[10px] font-medium uppercase tracking-wider opacity-80">{label}</p>
    </div>
  );
}

function ThreatIntelPanel({ report }: { report: ScanReport }) {
  const vt = report.virustotal;
  const engines = report.engines;

  return (
    <Panel
      title="Threat intelligence"
      icon={<Radar className="h-4 w-4" aria-hidden="true" />}
      action={
        vt.permalink && vt.available ? (
          <a
            href={vt.permalink}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-400 transition hover:text-cyan-300"
          >
            VirusTotal
            <ExternalLink className="h-3.5 w-3.5" aria-hidden="true" />
          </a>
        ) : null
      }
    >
      {vt.available ? (
        <div className="space-y-4">
          <div className="grid grid-cols-3 gap-2">
            <IntelStat
              label="Malicious"
              value={vt.domain_stats.malicious}
              tone={vt.domain_stats.malicious > 0 ? 'bad' : 'neutral'}
            />
            <IntelStat
              label="Suspicious"
              value={vt.domain_stats.suspicious}
              tone={vt.domain_stats.suspicious > 0 ? 'warn' : 'neutral'}
            />
            <IntelStat label="Harmless" value={vt.domain_stats.harmless} tone="good" />
          </div>

          <dl className="space-y-2 text-sm">
            <div className="flex items-baseline justify-between gap-3">
              <dt className="kv-label">Domain age</dt>
              <dd className="kv-value">
                {vt.domain_age_days !== null && vt.domain_age_days !== undefined
                  ? `${vt.domain_age_days} days`
                  : 'unknown'}
              </dd>
            </div>
            <div className="flex items-baseline justify-between gap-3">
              <dt className="kv-label">Registrar</dt>
              <dd className="kv-value">{vt.registrar || 'unknown'}</dd>
            </div>
            <div className="flex items-baseline justify-between gap-3">
              <dt className="kv-label">Community score</dt>
              <dd className="kv-value">{vt.reputation ?? 'n/a'}</dd>
            </div>
          </dl>

          {vt.malicious_engines.length > 0 ? (
            <div className="space-y-1.5">
              <p className="kv-label">Flagged by</p>
              <ul className="space-y-1">
                {vt.malicious_engines.slice(0, 5).map((engine) => (
                  <li
                    key={engine}
                    className="flex items-center gap-2 rounded-lg border border-rose-400/20 bg-rose-500/5 px-2.5 py-1.5 font-mono text-[11px] text-rose-200"
                  >
                    <AlertTriangle className="h-3 w-3 shrink-0" aria-hidden="true" />
                    {engine}
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
        </div>
      ) : (
        <div className="rounded-xl border border-dashed border-white/10 p-4">
          <p className="text-sm font-medium text-slate-300">Reputation data unavailable</p>
          <p className="mt-1 text-xs text-slate-500">
            {vt.detail || `Lookup status: ${prettify(vt.status)}.`}
          </p>
        </div>
      )}

      <div className="mt-5 space-y-2 border-t border-white/5 pt-4">
        <p className="kv-label">Engine status</p>
        <ul className="grid grid-cols-2 gap-2 text-xs">
          {(
            [
              ['Reputation', engines.reputation, <ShieldBan key="r" className="h-3.5 w-3.5" aria-hidden="true" />],
              ['Sandbox', engines.scraper, <Cpu key="s" className="h-3.5 w-3.5" aria-hidden="true" />],
              ['Rule engine', engines.heuristics, <ListChecks key="h" className="h-3.5 w-3.5" aria-hidden="true" />],
              ['AI analyst', engines.ai, <Sparkles key="a" className="h-3.5 w-3.5" aria-hidden="true" />],
              ['Threat intel', engines.threat_intel, <Radar key="t" className="h-3.5 w-3.5" aria-hidden="true" />],
            ] as Array<[string, string, ReactNode]>
          ).map(([label, state, icon]) => {
            const ok = state === 'ok';
            const skipped = state.startsWith('skipped') || state === 'not_configured';
            return (
              <li
                key={label}
                className={cx(
                  'flex items-center justify-between gap-2 rounded-lg border px-2.5 py-2',
                  ok
                    ? 'border-cyan-400/20 bg-cyan-400/5 text-cyan-200'
                    : skipped
                      ? 'border-white/10 bg-slate-900/50 text-slate-500'
                      : 'border-amber-400/20 bg-amber-400/5 text-amber-200'
                )}
              >
                <span className="inline-flex items-center gap-1.5">
                  {icon}
                  {label}
                </span>
                <span className="font-mono text-[10px] uppercase tracking-wide">
                  {state.replace(/_/g, ' ')}
                </span>
              </li>
            );
          })}
        </ul>
        {report.reputation && report.reputation.classification === 'malicious' ? (
          <p className="pt-1 text-[11px] text-rose-300">
            Reputation: matched the known-bad {report.reputation.category || 'threat'} feed
            {report.reputation.matched_value ? ` (${report.reputation.matched_value})` : ''}.
          </p>
        ) : report.reputation && report.reputation.classification === 'trusted' ? (
          <p className="pt-1 text-[11px] text-cyan-300">
            Reputation: {report.reputation.checked_domain || 'domain'} is on the trusted allowlist.
          </p>
        ) : null}
        {report.ai_analysis.available && report.ai_analysis.status === 'ok' ? (
          <p className="pt-1 text-[11px] text-slate-500">
            {report.ai_analysis.provider ? `${prettify(report.ai_analysis.provider)} / ` : ''}
            {report.ai_analysis.ai_model} responded in {formatDuration(report.ai_analysis.latency_ms)} with{' '}
            {Math.round(report.ai_analysis.confidence * 100)}% confidence.
          </p>
        ) : report.ai_analysis.detail ? (
          <p className="pt-1 text-[11px] text-slate-500">{report.ai_analysis.detail}</p>
        ) : null}
      </div>
    </Panel>
  );
}

/* ==========================================================================
 * PAGE FACTS (forms, headers, metadata)
 * ========================================================================== */

function PageFactsPanel({ report }: { report: ScanReport }) {
  const meta = report.page_metadata;
  const headerEntries = Object.entries(report.headers).slice(0, 10);

  return (
    <Panel title="Capture details" icon={<Database className="h-4 w-4" aria-hidden="true" />}>
      <div className="space-y-5">
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
          {(
            [
              ['Forms', meta.form_count],
              ['Password fields', meta.password_field_count],
              ['Links', meta.link_count],
              ['External links', meta.external_link_count],
              ['Hidden inputs', meta.hidden_input_count],
              ['Iframes', meta.iframe_count],
              ['Scripts', meta.script_count],
              ['DOM size', meta.dom_length],
            ] as Array<[string, number]>
          ).map(([label, value]) => (
            <div key={label} className="glass-subtle p-3">
              <p className="text-lg font-semibold tabular-nums text-slate-200">
                {value.toLocaleString()}
              </p>
              <p className="kv-label mt-0.5">{label}</p>
            </div>
          ))}
        </div>

        {report.forms.length > 0 ? (
          <div className="space-y-2">
            <p className="kv-label">Form targets (where submitted data goes)</p>
            <ul className="space-y-2">
              {report.forms.slice(0, 4).map((form, index) => (
                <li
                  key={`${form.resolved_action}-${index}`}
                  className={cx(
                    'rounded-lg border px-3 py-2 text-xs',
                    form.is_cross_origin || form.action_is_insecure
                      ? 'border-rose-400/30 bg-rose-500/5'
                      : 'border-white/10 bg-slate-900/50'
                  )}
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="rounded bg-slate-800 px-1.5 py-0.5 font-mono text-[10px] uppercase text-slate-300">
                      {form.method}
                    </span>
                    <span className="min-w-0 flex-1 truncate font-mono text-slate-300">
                      {form.resolved_action || '(same page)'}
                    </span>
                  </div>
                  <div className="mt-1.5 flex flex-wrap gap-1.5 text-[10px]">
                    {form.has_password_field ? (
                      <span className="rounded-full border border-rose-400/30 bg-rose-500/10 px-2 py-0.5 text-rose-200">
                        password field
                      </span>
                    ) : null}
                    {form.is_cross_origin ? (
                      <span className="rounded-full border border-rose-400/30 bg-rose-500/10 px-2 py-0.5 text-rose-200">
                        cross-origin
                      </span>
                    ) : null}
                    {form.action_is_insecure ? (
                      <span className="rounded-full border border-amber-400/30 bg-amber-400/10 px-2 py-0.5 text-amber-200">
                        http action
                      </span>
                    ) : null}
                    <span className="rounded-full border border-white/10 bg-slate-800/60 px-2 py-0.5 text-slate-400">
                      {form.input_count} inputs
                    </span>
                  </div>
                </li>
              ))}
            </ul>
          </div>
        ) : null}

        {meta.brand_keywords.length > 0 ? (
          <div className="space-y-2">
            <p className="kv-label">Brand references in page content</p>
            <div className="flex flex-wrap gap-1.5">
              {meta.brand_keywords.map((brand) => (
                <span
                  key={brand}
                  className="rounded-full border border-amber-400/25 bg-amber-400/5 px-2.5 py-0.5 text-xs text-amber-200"
                >
                  {prettify(brand)}
                </span>
              ))}
            </div>
          </div>
        ) : null}

        {headerEntries.length > 0 ? (
          <div className="space-y-2">
            <p className="kv-label">Response headers</p>
            <div className="max-h-52 overflow-y-auto rounded-lg border border-white/5 bg-slate-950/60">
              <table className="w-full text-left text-[11px]">
                <caption className="sr-only">HTTP response headers returned by the target</caption>
                <tbody>
                  {headerEntries.map(([name, value]) => (
                    <tr key={name} className="border-b border-white/5 last:border-0">
                      <th scope="row" className="whitespace-nowrap px-3 py-1.5 font-mono font-normal text-slate-500">
                        {name}
                      </th>
                      <td className="px-3 py-1.5 font-mono text-slate-300">{truncate(value, 90)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        ) : null}
      </div>
    </Panel>
  );
}

/* ==========================================================================
 * HISTORY
 * ========================================================================== */

function HistoryPanel({
  items,
  isLoading,
  onSelect,
  onRefresh,
  activeScanId,
}: {
  items: ScanHistoryItem[];
  isLoading: boolean;
  onSelect: (scanId: string) => void;
  onRefresh: () => void;
  activeScanId?: string;
}) {
  return (
    <Panel
      title="Recent scans"
      icon={<History className="h-4 w-4" aria-hidden="true" />}
      action={
        <button
          type="button"
          onClick={onRefresh}
          className="inline-flex items-center gap-1.5 rounded-lg border border-white/10 bg-slate-900/60 px-2.5 py-1 text-xs font-medium text-slate-300 transition hover:border-cyan-400/40 hover:text-cyan-300"
        >
          <RefreshCw className={cx('h-3.5 w-3.5', isLoading && 'animate-spin')} aria-hidden="true" />
          Refresh
        </button>
      }
    >
      {items.length === 0 ? (
        <p className="py-6 text-center text-sm text-slate-500">
          {isLoading ? 'Loading history\u2026' : 'No scans recorded yet.'}
        </p>
      ) : (
        <ul className="divide-y divide-white/5">
          {items.map((item) => {
            const theme = themeFor(item.risk_level);
            const active = item.scan_id === activeScanId;
            return (
              <li key={item.scan_id}>
                <button
                  type="button"
                  onClick={() => onSelect(item.scan_id)}
                  aria-current={active ? 'true' : undefined}
                  className={cx(
                    'flex w-full items-center gap-3 py-2.5 text-left transition',
                    active ? 'opacity-100' : 'opacity-80 hover:opacity-100'
                  )}
                >
                  <span
                    className={cx(
                      'flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border text-xs font-semibold tabular-nums',
                      theme.border,
                      theme.bg,
                      theme.text
                    )}
                  >
                    {item.threat_score}
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-sm text-slate-200">{item.domain}</span>
                    <span className="block truncate text-[11px] text-slate-500">
                      {truncate(item.url, 62)}
                    </span>
                  </span>
                  <span className="shrink-0 text-right">
                    <span className={cx('block text-[11px] font-medium', theme.text)}>
                      {theme.label}
                    </span>
                    <span className="block text-[10px] text-slate-600">
                      {formatTimestamp(item.created_at)}
                    </span>
                  </span>
                </button>
              </li>
            );
          })}
        </ul>
      )}
    </Panel>
  );
}

/* ==========================================================================
 * ERROR BANNER
 * ========================================================================== */

function ErrorBanner({ message, onDismiss }: { message: string; onDismiss: () => void }) {
  return (
    <div
      role="alert"
      className="mx-auto mt-10 w-full max-w-3xl px-4 sm:px-6"
    >
      <div className="flex items-start gap-3 rounded-xl border border-rose-500/30 bg-rose-500/10 p-4 backdrop-blur-xl">
        <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-rose-400" aria-hidden="true" />
        <div className="min-w-0 flex-1">
          <p className="text-sm font-semibold text-rose-200">Analysis could not complete</p>
          <p className="mt-1 break-words text-sm text-rose-100/80">{message}</p>
        </div>
        <button
          type="button"
          onClick={onDismiss}
          className="rounded-lg px-2 py-1 text-xs font-medium text-rose-200/70 transition hover:text-rose-100"
          aria-label="Dismiss error"
        >
          Dismiss
        </button>
      </div>
    </div>
  );
}

/* ==========================================================================
 * PAGE
 * ========================================================================== */

export default function Home() {
  const [inputValue, setInputValue] = useState('');
  const [submittedUrl, setSubmittedUrl] = useState('');
  const [report, setReport] = useState<ScanReport | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const resultsRef = useRef<HTMLDivElement | null>(null);
  const queryClient = useQueryClient();

  const capabilitiesQuery = useQuery({
    queryKey: ['capabilities'],
    queryFn: fetchCapabilities,
    staleTime: 5 * 60_000,
    retry: 1,
  });

  const historyQuery = useQuery({
    queryKey: ['scans'],
    queryFn: fetchHistory,
    staleTime: 15_000,
    retry: 1,
  });

  const scanMutation = useMutation<ScanReport, unknown, string>({
    mutationFn: postScan,
    onMutate: () => {
      setErrorMessage(null);
      setReport(null);
    },
    onSuccess: (data) => {
      setReport(data);
      setErrorMessage(null);
      void queryClient.invalidateQueries({ queryKey: ['scans'] });
    },
    onError: (error) => {
      setErrorMessage(describeApiError(error));
    },
  });

  const loadStoredReport = useMutation<ScanReport, unknown, string>({
    mutationFn: fetchReport,
    onSuccess: (data) => {
      setReport(data);
      setInputValue(data.url);
      setSubmittedUrl(data.url);
      setErrorMessage(null);
    },
    onError: (error) => {
      setErrorMessage(describeApiError(error));
    },
  });

  const isScanning = scanMutation.isPending || loadStoredReport.isPending;

  const handleSubmit = useCallback(
    (event: FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      const target = inputValue.trim();
      if (!target || isScanning) return;
      setSubmittedUrl(target);
      scanMutation.mutate(target);
    },
    [inputValue, isScanning, scanMutation]
  );

  // Bring the verdict into view as soon as a report lands.
  useEffect(() => {
    if (report && resultsRef.current) {
      resultsRef.current.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }, [report]);

  const historyItems = useMemo(() => historyQuery.data?.items ?? [], [historyQuery.data]);

  return (
    <div className="relative min-h-screen bg-slate-900">
      {/* Ambient background: blueprint grid plus a cyan aurora behind the hero. */}
      <div
        className="pointer-events-none fixed inset-0 bg-blueprint opacity-70"
        aria-hidden="true"
      />
      <div
        className="pointer-events-none fixed inset-x-0 top-0 h-[38rem] bg-[radial-gradient(ellipse_80%_50%_at_50%_-10%,rgba(34,211,238,0.14),transparent_70%)]"
        aria-hidden="true"
      />

      <div className="relative z-10 flex min-h-screen flex-col pb-20">
        <SiteHeader capabilities={capabilitiesQuery.data} />

        <main className="flex flex-1 flex-col">
          <SearchHero
            value={inputValue}
            onChange={setInputValue}
            onSubmit={handleSubmit}
            isScanning={isScanning}
            navTimeoutMs={capabilitiesQuery.data?.nav_timeout_ms}
          />

          {errorMessage ? (
            <ErrorBanner message={errorMessage} onDismiss={() => setErrorMessage(null)} />
          ) : null}

          {isScanning ? <ScanningPanel target={submittedUrl || inputValue} /> : null}

          <div ref={resultsRef} className="scroll-mt-6">
            {report && !isScanning ? (
              <section className="mx-auto mt-14 w-full max-w-7xl animate-fade-up px-4 sm:px-6">
                <h2 className="sr-only">Analysis results for {report.domain}</h2>

                <div className="grid gap-4 lg:grid-cols-12">
                  <div className="lg:col-span-4">
                    <ThreatGauge score={report.threat_score} level={report.risk_level} />
                  </div>
                  <div className="lg:col-span-8">
                    <VerdictPanel report={report} />
                  </div>

                  <div className="lg:col-span-7">
                    <ScreenshotPanel report={report} />
                  </div>
                  <div className="lg:col-span-5">
                    <ThreatIntelPanel report={report} />
                  </div>

                  <div className="lg:col-span-7">
                    <IndicatorList factors={report.risk_factors} />
                  </div>
                  <div className="lg:col-span-5">
                    <PageFactsPanel report={report} />
                  </div>
                </div>

                <p className="mt-4 text-center text-[11px] text-slate-600">
                  Scan {report.scan_id} &middot; {formatTimestamp(report.scanned_at)} &middot; completed
                  in {formatDuration(report.duration_ms)}
                </p>
              </section>
            ) : null}
          </div>

          {!isScanning ? (
            <section className="mx-auto mt-14 w-full max-w-7xl px-4 sm:px-6">
              <h2 className="sr-only">Scan history and scoring methodology</h2>
              <div className="grid gap-4 lg:grid-cols-12">
                <div className="lg:col-span-5">
                  <HistoryPanel
                    items={historyItems}
                    isLoading={historyQuery.isFetching}
                    onSelect={(scanId) => loadStoredReport.mutate(scanId)}
                    onRefresh={() => historyQuery.refetch()}
                    activeScanId={report?.scan_id}
                  />
                </div>
                <div className="lg:col-span-7">
                  <Panel title="How scoring works" icon={<Info className="h-4 w-4" aria-hidden="true" />}>
                    <ul className="space-y-3 text-sm text-slate-400">
                      <li className="flex gap-3">
                        <ListChecks
                          className="mt-0.5 h-4 w-4 shrink-0 text-cyan-300"
                          aria-hidden="true"
                        />
                        <span>
                          <span className="font-medium text-slate-200">Rule engine.</span>{' '}
                          Deterministic checks for typosquatting, brand impersonation, credential forms
                          posting off-origin, punycode hosts, free hosting and high-abuse TLDs.
                        </span>
                      </li>
                      <li className="flex gap-3">
                        <Sparkles className="mt-0.5 h-4 w-4 shrink-0 text-cyan-300" aria-hidden="true" />
                        <span>
                          <span className="font-medium text-slate-200">AI analyst.</span> An LLM reads
                          the distilled evidence and reasons about intent, brand claims and social
                          engineering, returning cited indicators.
                        </span>
                      </li>
                      <li className="flex gap-3">
                        <Radar className="mt-0.5 h-4 w-4 shrink-0 text-cyan-300" aria-hidden="true" />
                        <span>
                          <span className="font-medium text-slate-200">Threat intel.</span> VirusTotal
                          domain and URL reputation, vendor detections and domain age.
                        </span>
                      </li>
                      <li className="flex gap-3">
                        <Activity className="mt-0.5 h-4 w-4 shrink-0 text-cyan-300" aria-hidden="true" />
                        <span>
                          <span className="font-medium text-slate-200">Fusion.</span> Scores are blended
                          by confidence, then hard floors are applied so a confirmed vendor detection or
                          a cross-origin credential post can never be averaged away.
                        </span>
                      </li>
                    </ul>
                  </Panel>
                </div>
              </div>
            </section>
          ) : null}
        </main>

        <footer className="mx-auto w-full max-w-7xl px-4 pt-16 sm:px-6">
          <div className="flex flex-col items-center justify-between gap-3 border-t border-white/5 pt-6 text-[11px] text-slate-600 sm:flex-row">
            <p>
              ThreatLens {capabilitiesQuery.data?.version ?? ''} &middot; targets are rendered in an
              isolated sandbox with JavaScript disabled
            </p>
            <p className="font-mono">
              API {API_BASE_URL}
              {capabilitiesQuery.data?.auth_required ? ' \u00b7 authenticated' : ''}
              {capabilitiesQuery.data?.rate_limit ? ` \u00b7 ${capabilitiesQuery.data.rate_limit}` : ''}
            </p>
          </div>
        </footer>
      </div>
    </div>
  );
}
