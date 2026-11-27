export type Severity = 'critical' | 'high' | 'medium' | 'low'
export type Triage = 'open' | 'fixed' | 'accepted' | 'false_positive'

export interface User { id: number; name: string; email: string }

export interface Scan {
  id: number; project_id: number; project_name: string; base_url: string
  status: 'queued' | 'running' | 'completed' | 'failed' | 'cancelled'
  stage: string; progress: number; message: string; warnings: string[]
  stats: Record<string, number>; created_at: string; finished_at: string | null
}

export interface Project {
  id: number; name: string; base_url: string; is_demo: boolean
  has_spec: boolean; has_har: boolean; scan_count: number; created_at: string
  last_scan: Scan | null; scans?: Scan[]
  identities: { name: string; role: 'user' | 'admin'; header_names: string[] }[]
  options: { enable_crawl: boolean; enable_wordlist: boolean; rate: number; max_requests: number }
}

export interface Endpoint {
  id: number; method: string; path: string; classification: string
  sources: string[]; in_spec: boolean; live: boolean; statuses: number[]
  sensitive: Record<string, string[]>; skip_reason: string
}

export interface Evidence { note: string; identity: string; request: string; status: number; response: unknown }

export interface Finding {
  id: number; type: string; endpoint: string; title: string; description: string
  remediation: string; owasp: string; confidence: 'confirmed' | 'review'; attacker: string
  evidence: Evidence[]; data_categories: string[]; score: number; severity: Severity
  score_breakdown: Record<string, number>; triage: Triage
}

export interface Link {
  id: number; producer: string; consumer: string; entity: string; producer_field: string
  consumer_param: string; confidence: number; evidence: string[]
}

export interface PathStep {
  number: number; endpoint: string; request: string; status: number; classification: string
  uses: { entity: string; field: string; from_step: number }[]
  gains: { entity: string; field: string }[]
  weaknesses: string[]; data: string[]
}

export interface AttackPath {
  id: number; title: string; attacker: string; victim: string; steps: PathStep[]
  data_categories: string[]; score: number; severity: Severity; narrative: string
}

export interface Results {
  scan: Scan; endpoints: Endpoint[]; findings: Finding[]; links: Link[]; paths: AttackPath[]
}

export interface DashboardData {
  totals: { projects: number; live: number; shadow: number; zombie: number; paths: number }
  severity: Record<Severity, number>
  top_findings: { id: number; scan_id: number; project: string; title: string; endpoint: string; severity: Severity; score: number }[]
  recent_scans: Scan[]
}
