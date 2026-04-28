/// <reference path="../env.d.ts" />
import { tool } from "@opencode-ai/plugin"
import DESCRIPTION from "./vuln-db.txt"
import { Database } from "bun:sqlite"
import { writeFile, mkdir } from "node:fs/promises"
import { dirname } from "node:path"

const SCHEMA = `
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id TEXT PRIMARY KEY,
    phase TEXT NOT NULL DEFAULT 'candidate'
        CHECK(phase IN ('candidate', 'verified')),
    source_agent TEXT NOT NULL,
    source_module TEXT,
    language TEXT,
    framework TEXT,
    analysis_kind TEXT,
    type TEXT,
    cwe TEXT,
    severity TEXT,
    description TEXT,
    file TEXT,
    line_start INTEGER,
    line_end INTEGER,
    function_name TEXT,
    code_snippet TEXT,
    data_flow TEXT,
    source_kind TEXT,
    sink_kind TEXT,
    sanitizer_checked TEXT,
    evidence_json TEXT,
    rule_id TEXT,
    analysis_backend TEXT,
    pre_validated INTEGER DEFAULT 0,
    cross_module INTEGER DEFAULT 0,
    modules_involved TEXT,
    confidence INTEGER,
    status TEXT CHECK(status IN ('CONFIRMED','LIKELY','POSSIBLE','FALSE_POSITIVE') OR status IS NULL),
    original_severity TEXT,
    verified_severity TEXT,
    scoring_details TEXT,
    veto_applied INTEGER DEFAULT 0,
    veto_reason TEXT,
    verification_reason TEXT,
    control_flow TEXT,
    mitigations_found TEXT,
    source_agents TEXT,
    dedup_kept INTEGER DEFAULT 1,
    merged_into TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS scan_metadata (
    key TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS agent_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_name TEXT NOT NULL,
    module_name TEXT,
    phase TEXT,
    status TEXT,
    message TEXT,
    item_count INTEGER,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS scan_work_items (
    id TEXT PRIMARY KEY,
    scan_id TEXT,
    agent_name TEXT NOT NULL,
    shard_type TEXT NOT NULL
        CHECK(shard_type IN ('entrypoint_slice','sink_slice','module_sweep','expansion_slice','cross_module_slice')),
    language TEXT,
    framework TEXT,
    source_module TEXT,
    focus TEXT,
    entrypoint TEXT,
    sink TEXT,
    files_json TEXT,
    context_json TEXT,
    priority INTEGER DEFAULT 50,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK(status IN ('pending','running','success','failed','skipped')),
    attempts INTEGER DEFAULT 0,
    finding_count INTEGER DEFAULT 0,
    error TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    started_at TEXT,
    finished_at TEXT,
    updated_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_vuln_phase ON vulnerabilities(phase);
CREATE INDEX IF NOT EXISTS idx_vuln_status ON vulnerabilities(status);
CREATE INDEX IF NOT EXISTS idx_vuln_module ON vulnerabilities(source_module);
CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vuln_file ON vulnerabilities(file);
CREATE INDEX IF NOT EXISTS idx_vuln_dedup ON vulnerabilities(file, line_start, function_name, type);
CREATE INDEX IF NOT EXISTS idx_vuln_kept ON vulnerabilities(dedup_kept);
CREATE INDEX IF NOT EXISTS idx_work_status ON scan_work_items(status);
CREATE INDEX IF NOT EXISTS idx_work_agent ON scan_work_items(agent_name);
CREATE INDEX IF NOT EXISTS idx_work_module ON scan_work_items(source_module);
CREATE INDEX IF NOT EXISTS idx_work_language ON scan_work_items(language);
CREATE INDEX IF NOT EXISTS idx_work_priority ON scan_work_items(priority);
`

function openDb(dbPath: string): Database {
  const db = new Database(dbPath)
  db.exec("PRAGMA journal_mode=WAL")
  db.exec("PRAGMA busy_timeout=5000")
  return db
}

const EXTRA_COLUMNS = [
  ["language", "TEXT"],
  ["framework", "TEXT"],
  ["analysis_kind", "TEXT"],
  ["source_kind", "TEXT"],
  ["sink_kind", "TEXT"],
  ["sanitizer_checked", "TEXT"],
  ["evidence_json", "TEXT"],
  ["rule_id", "TEXT"],
  ["analysis_backend", "TEXT"],
] as const

function migrate(db: Database) {
  const table = db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'vulnerabilities'").get()
  if (!table) return

  const rows = db.prepare("PRAGMA table_info(vulnerabilities)").all() as Array<{ name: string }>
  const existing = new Set(rows.map((row) => row.name))

  for (const [name, ddl] of EXTRA_COLUMNS) {
    if (existing.has(name)) continue
    db.exec(`ALTER TABLE vulnerabilities ADD COLUMN ${name} ${ddl}`)
  }
}

const SEVERITY_ORDER: Record<string, number> = {
  Critical: 4,
  High: 3,
  Medium: 2,
  Low: 1,
}

const VULN_ID_RE = /^VULN-(DF|SEC)-(CPP|PY|GO|LUA|JAVA|MIX)-[A-Z0-9]{2,12}-[A-Z0-9]{2,16}-\d{3}$/

function severityRank(s: string | null): number {
  return SEVERITY_ORDER[s ?? ""] ?? 0
}

function expectedChannel(sourceAgent: unknown): string | null {
  if (sourceAgent === "dataflow-scanner") return "DF"
  if (sourceAgent === "security-auditor") return "SEC"
  return null
}

function expectedLang(language: unknown): string | null {
  if (language === "c_cpp") return "CPP"
  if (language === "python") return "PY"
  if (language === "go") return "GO"
  if (language === "lua") return "LUA"
  if (language === "java") return "JAVA"
  if (language === "mixed") return "MIX"
  return null
}

function validateVulnIds(vulns: Record<string, unknown>[]): string | null {
  const errors: string[] = []
  for (const v of vulns) {
    const id = String(v.id ?? "")
    if (!VULN_ID_RE.test(id)) {
      errors.push(`${id || "(missing)"}: expected VULN-{DF|SEC}-{CPP|PY|GO|LUA|JAVA|MIX}-{KIND}-{MODULE}-{NNN}`)
      continue
    }
    const parts = id.split("-")
    const channel = expectedChannel(v.source_agent)
    const lang = expectedLang(v.language)
    if (channel && parts[1] !== channel) errors.push(`${id}: source_agent requires channel ${channel}`)
    if (lang && parts[2] !== lang) errors.push(`${id}: language requires code ${lang}`)
  }
  if (errors.length === 0) return null
  return `Error: invalid vulnerability id(s)\n${errors.map((error) => `  - ${error}`).join("\n")}`
}

interface VulnRow {
  id: string
  source_agent: string
  source_module: string | null
  language: string | null
  framework: string | null
  analysis_kind: string | null
  file: string | null
  line_start: number | null
  function_name: string | null
  type: string | null
  severity: string | null
  [key: string]: unknown
}

interface WorkItem {
  id?: string
  scan_id?: string
  agent_name?: string
  shard_type?: string
  language?: string | null
  framework?: string | string[] | null
  source_module?: string | null
  focus?: string | string[] | null
  entrypoint?: string | null
  sink?: string | null
  files?: string[] | null
  files_json?: string | null
  context?: Record<string, unknown> | null
  context_json?: string | null
  priority?: number | null
}

function stringifyMaybeJson(value: unknown): string | null {
  if (value == null) return null
  if (typeof value === "string") return value
  return JSON.stringify(value)
}

function parseWorkRow(row: Record<string, unknown>) {
  for (const key of ["files_json", "context_json", "focus"]) {
    if (typeof row[key] !== "string") continue
    try {
      row[key] = JSON.parse(row[key] as string)
    } catch {}
  }
  return row
}

function handleInit(dbPath: string): string {
  const dir = dirname(dbPath)
  const fs = require("node:fs")
  fs.mkdirSync(dir, { recursive: true })
  const db = openDb(dbPath)
  try {
    db.exec(SCHEMA)
    migrate(db)
    db.exec(`
CREATE INDEX IF NOT EXISTS idx_vuln_language ON vulnerabilities(language);
CREATE INDEX IF NOT EXISTS idx_vuln_analysis_kind ON vulnerabilities(analysis_kind);
`)
    return `Database initialized: ${dbPath}\nTables: vulnerabilities, scan_work_items, scan_metadata, agent_log`
  } finally {
    db.close()
  }
}

function handleInsert(dbPath: string, vulnsJson: string): string {
  const vulns = JSON.parse(vulnsJson) as Record<string, unknown>[]
  if (vulns.length === 0) return "No vulnerabilities to insert"
  const idError = validateVulnIds(vulns)
  if (idError) return idError

  const db = openDb(dbPath)
  try {
    const stmt = db.prepare(`
      INSERT OR REPLACE INTO vulnerabilities (
        id, source_agent, source_module, language, framework, analysis_kind, type, cwe, severity, description,
        file, line_start, line_end, function_name, code_snippet, data_flow,
        source_kind, sink_kind, sanitizer_checked, evidence_json, rule_id, analysis_backend,
        pre_validated, cross_module, modules_involved, source_agents
      ) VALUES (
        $id, $source_agent, $source_module, $language, $framework, $analysis_kind, $type, $cwe, $severity, $description,
        $file, $line_start, $line_end, $function_name, $code_snippet, $data_flow,
        $source_kind, $sink_kind, $sanitizer_checked, $evidence_json, $rule_id, $analysis_backend,
        $pre_validated, $cross_module, $modules_involved, $source_agents
      )
    `)

    const tx = db.transaction(() => {
      for (const v of vulns) {
        stmt.run({
          $id: v.id,
          $source_agent: v.source_agent,
          $source_module: v.source_module ?? null,
          $language: v.language ?? null,
          $framework: Array.isArray(v.framework) ? v.framework.join(",") : v.framework ?? null,
          $analysis_kind: v.analysis_kind ?? (v.source_agent === "dataflow-scanner" ? "dataflow" : null),
          $type: v.type ?? null,
          $cwe: v.cwe ?? null,
          $severity: v.severity ?? null,
          $description: v.description ?? null,
          $file: v.file ?? null,
          $line_start: v.line_start ?? null,
          $line_end: v.line_end ?? null,
          $function_name: v.function ?? v.function_name ?? null,
          $code_snippet: v.code_snippet ?? null,
          $data_flow: v.data_flow ?? null,
          $source_kind: v.source_kind ?? null,
          $sink_kind: v.sink_kind ?? null,
          $sanitizer_checked: v.sanitizer_checked ?? null,
          $evidence_json: typeof v.evidence_json === "object" && v.evidence_json !== null ? JSON.stringify(v.evidence_json) : v.evidence_json ?? null,
          $rule_id: v.rule_id ?? null,
          $analysis_backend: v.analysis_backend ?? null,
          $pre_validated: v.pre_validated ? 1 : 0,
          $cross_module: v.cross_module ? 1 : 0,
          $modules_involved: Array.isArray(v.modules_involved) ? JSON.stringify(v.modules_involved) : v.modules_involved ?? null,
          $source_agents: v.source_agent ? JSON.stringify([v.source_agent]) : null,
        })
      }
    })
    tx()

    return `Inserted ${vulns.length} vulnerabilities into database`
  } finally {
    db.close()
  }
}

function handleQuery(db: Database, args: Record<string, unknown>): string {
  const conditions: string[] = ["dedup_kept = 1"]
  const params: Record<string, unknown> = {}

  if (args.phase) {
    conditions.push("phase = $phase")
    params.$phase = args.phase
  }
  if (args.status) {
    conditions.push("status = $status")
    params.$status = args.status
  }
  if (args.source_module) {
    conditions.push("source_module = $source_module")
    params.$source_module = args.source_module
  }
  if (args.source_agent) {
    conditions.push("source_agent = $source_agent")
    params.$source_agent = args.source_agent
  }
  if (args.language) {
    conditions.push("language = $language")
    params.$language = args.language
  }
  if (args.analysis_kind) {
    conditions.push("analysis_kind = $analysis_kind")
    params.$analysis_kind = args.analysis_kind
  }
  if (args.min_confidence != null) {
    conditions.push("confidence >= $min_confidence")
    params.$min_confidence = args.min_confidence
  }
  if (args.exclude_status) {
    conditions.push("status != $exclude_status")
    params.$exclude_status = args.exclude_status
  }
  if (args.ids) {
    const idList = (args.ids as string).split(",").map((s) => s.trim())
    const placeholders = idList.map((_, i) => `$id_${i}`).join(",")
    conditions.push(`id IN (${placeholders})`)
    idList.forEach((id, i) => {
      params[`$id_${i}`] = id
    })
  }

  const where = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : ""
  let sql = `SELECT * FROM vulnerabilities ${where} ORDER BY
    CASE severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END,
    confidence DESC`

  if (args.limit) {
    sql += ` LIMIT ${Number(args.limit)}`
    if (args.offset) sql += ` OFFSET ${Number(args.offset)}`
  }

  const rows = db.prepare(sql).all(params)

  for (const row of rows as Record<string, unknown>[]) {
    for (const key of ["modules_involved", "scoring_details", "source_agents", "mitigations_found", "evidence_json"]) {
      if (typeof row[key] === "string") {
        try {
          row[key] = JSON.parse(row[key] as string)
        } catch {}
      }
    }
    row.pre_validated = row.pre_validated === 1
    row.cross_module = row.cross_module === 1
    row.veto_applied = row.veto_applied === 1
    row.dedup_kept = row.dedup_kept === 1
  }

  return JSON.stringify(rows, null, 2)
}

function handleUpdate(db: Database, id: string, fieldsJson: string): string {
  const fields = JSON.parse(fieldsJson) as Record<string, unknown>
  fields.phase = "verified"
  fields.updated_at = new Date().toISOString()

  const setClauses: string[] = []
  const params: Record<string, unknown> = { $id: id }

  for (const [key, value] of Object.entries(fields)) {
    const paramName = `$${key}`
    setClauses.push(`${key} = ${paramName}`)
    if (typeof value === "object" && value !== null) {
      params[paramName] = JSON.stringify(value)
    } else if (typeof value === "boolean") {
      params[paramName] = value ? 1 : 0
    } else {
      params[paramName] = value
    }
  }

  const sql = `UPDATE vulnerabilities SET ${setClauses.join(", ")} WHERE id = $id`
  const result = db.prepare(sql).run(params)
  return `Updated vulnerability ${id} (${result.changes} row affected)`
}

function handleBatchUpdate(db: Database, updatesJson: string): string {
  const updates = JSON.parse(updatesJson) as Array<{ id: string; fields: Record<string, unknown> }>
  let totalChanged = 0

  const tx = db.transaction(() => {
    for (const { id, fields } of updates) {
      fields.phase = "verified"
      fields.updated_at = new Date().toISOString()

      const setClauses: string[] = []
      const params: Record<string, unknown> = { $id: id }

      for (const [key, value] of Object.entries(fields)) {
        const paramName = `$${key}`
        setClauses.push(`${key} = ${paramName}`)
        if (typeof value === "object" && value !== null) {
          params[paramName] = JSON.stringify(value)
        } else if (typeof value === "boolean") {
          params[paramName] = value ? 1 : 0
        } else {
          params[paramName] = value
        }
      }

      const sql = `UPDATE vulnerabilities SET ${setClauses.join(", ")} WHERE id = $id`
      const result = db.prepare(sql).run(params)
      totalChanged += result.changes
    }
  })
  tx()

  return `Batch updated ${updates.length} vulnerabilities (${totalChanged} rows affected)`
}

function handleDedup(db: Database): string {
  const dupes = db
    .prepare(
      `SELECT file, line_start, function_name, type, GROUP_CONCAT(id) as ids, COUNT(*) as cnt
     FROM vulnerabilities
     WHERE phase = 'candidate' AND dedup_kept = 1
     GROUP BY file, line_start, function_name, type
     HAVING cnt > 1`,
    )
    .all() as Array<{ file: string; line_start: number; function_name: string; type: string; ids: string; cnt: number }>

  let mergedCount = 0
  let groupCount = 0

  const tx = db.transaction(() => {
    for (const group of dupes) {
      groupCount++
      const ids = group.ids.split(",")
      const rows = db
        .prepare(`SELECT id, severity, source_agent, source_agents FROM vulnerabilities WHERE id IN (${ids.map(() => "?").join(",")})`)
        .all(...ids) as Array<{ id: string; severity: string; source_agent: string; source_agents: string | null }>

      rows.sort((a, b) => severityRank(b.severity) - severityRank(a.severity))
      const primary = rows[0]
      const others = rows.slice(1)

      const allAgents = new Set<string>()
      for (const r of rows) {
        if (r.source_agents) {
          try {
            for (const a of JSON.parse(r.source_agents)) allAgents.add(a)
          } catch {}
        }
        if (r.source_agent) allAgents.add(r.source_agent)
      }

      db.prepare(`UPDATE vulnerabilities SET source_agents = ?, updated_at = datetime('now') WHERE id = ?`).run(
        JSON.stringify([...allAgents]),
        primary.id,
      )

      for (const other of others) {
        db.prepare(`UPDATE vulnerabilities SET dedup_kept = 0, merged_into = ?, updated_at = datetime('now') WHERE id = ?`).run(
          primary.id,
          other.id,
        )
        mergedCount++
      }
    }
  })
  tx()

  const total = (db.prepare("SELECT COUNT(*) as cnt FROM vulnerabilities WHERE phase = 'candidate'").get() as { cnt: number }).cnt
  const kept = (
    db.prepare("SELECT COUNT(*) as cnt FROM vulnerabilities WHERE phase = 'candidate' AND dedup_kept = 1").get() as { cnt: number }
  ).cnt

  return [
    `Deduplication complete`,
    `  Duplicate groups found: ${groupCount}`,
    `  Entries merged: ${mergedCount}`,
    `  Total candidates: ${total}`,
    `  After dedup: ${kept}`,
  ].join("\n")
}

function handleStats(db: Database, phase?: string): string {
  const wherePhase = phase ? "WHERE phase = $phase AND dedup_kept = 1" : "WHERE dedup_kept = 1"
  const params = phase ? { $phase: phase } : {}

  const total = (db.prepare(`SELECT COUNT(*) as cnt FROM vulnerabilities ${wherePhase}`).get(params) as { cnt: number }).cnt

  const byStatus = db
    .prepare(`SELECT status, COUNT(*) as cnt FROM vulnerabilities ${wherePhase} GROUP BY status ORDER BY cnt DESC`)
    .all(params) as Array<{ status: string | null; cnt: number }>

  const bySeverity = db
    .prepare(
      `SELECT COALESCE(verified_severity, severity) as sev, COUNT(*) as cnt FROM vulnerabilities ${wherePhase} GROUP BY sev ORDER BY
      CASE sev WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END`,
    )
    .all(params) as Array<{ sev: string; cnt: number }>

  const byModule = db
    .prepare(`SELECT source_module, COUNT(*) as cnt FROM vulnerabilities ${wherePhase} GROUP BY source_module ORDER BY cnt DESC`)
    .all(params) as Array<{ source_module: string; cnt: number }>

  const byLanguage = db
    .prepare(`SELECT language, COUNT(*) as cnt FROM vulnerabilities ${wherePhase} GROUP BY language ORDER BY cnt DESC`)
    .all(params) as Array<{ language: string | null; cnt: number }>
  const byKind = db
    .prepare(`SELECT analysis_kind, COUNT(*) as cnt FROM vulnerabilities ${wherePhase} GROUP BY analysis_kind ORDER BY cnt DESC`)
    .all(params) as Array<{ analysis_kind: string | null; cnt: number }>

  const lines = [`Total: ${total}`, "", "By status:"]
  for (const r of byStatus) lines.push(`  ${r.status ?? "(none)"}: ${r.cnt}`)
  lines.push("", "By severity:")
  for (const r of bySeverity) lines.push(`  ${r.sev ?? "(none)"}: ${r.cnt}`)
  lines.push("", "By module:")
  for (const r of byModule) lines.push(`  ${r.source_module ?? "(none)"}: ${r.cnt}`)
  lines.push("", "By language:")
  for (const r of byLanguage) lines.push(`  ${r.language ?? "(none)"}: ${r.cnt}`)
  lines.push("", "By analysis kind:")
  for (const r of byKind) lines.push(`  ${r.analysis_kind ?? "(none)"}: ${r.cnt}`)

  return lines.join("\n")
}

function handleLog(db: Database, args: Record<string, unknown>): string {
  db.prepare(
    `INSERT INTO agent_log (agent_name, module_name, phase, status, message, item_count)
     VALUES ($agent_name, $module_name, $phase, $status, $message, $item_count)`,
  ).run({
    $agent_name: args.agent_name,
    $module_name: args.module_name ?? null,
    $phase: args.phase ?? null,
    $status: args.status ?? null,
    $message: args.message ?? null,
    $item_count: args.item_count ?? null,
  })
  return `Logged event for ${args.agent_name}`
}

async function handleExportJson(db: Database, args: Record<string, unknown>): Promise<string> {
  const json = handleQuery(db, args)
  const rows = JSON.parse(json)
  const output = args.output as string
  await mkdir(dirname(output), { recursive: true })
  await writeFile(output, JSON.stringify({ vulnerabilities: rows }, null, 2), "utf-8")
  return `Exported ${rows.length} vulnerabilities to ${output}`
}

function handleWorkAdd(db: Database, itemsJson: string): string {
  const items = JSON.parse(itemsJson) as WorkItem[]
  if (items.length === 0) return "No work items to add"

  const stmt = db.prepare(`
    INSERT OR IGNORE INTO scan_work_items (
      id, scan_id, agent_name, shard_type, language, framework, source_module,
      focus, entrypoint, sink, files_json, context_json, priority
    ) VALUES (
      $id, $scan_id, $agent_name, $shard_type, $language, $framework, $source_module,
      $focus, $entrypoint, $sink, $files_json, $context_json, $priority
    )
  `)

  let inserted = 0
  const tx = db.transaction(() => {
    for (let i = 0; i < items.length; i++) {
      const item = items[i]
      const id = item.id ?? `${item.agent_name ?? "scanner"}-${Date.now()}-${i}`
      const result = stmt.run({
        $id: id,
        $scan_id: item.scan_id ?? null,
        $agent_name: item.agent_name ?? "scanner",
        $shard_type: item.shard_type ?? "module_sweep",
        $language: item.language ?? null,
        $framework: Array.isArray(item.framework) ? item.framework.join(",") : item.framework ?? null,
        $source_module: item.source_module ?? null,
        $focus: stringifyMaybeJson(item.focus),
        $entrypoint: item.entrypoint ?? null,
        $sink: item.sink ?? null,
        $files_json: item.files_json ?? stringifyMaybeJson(item.files),
        $context_json: item.context_json ?? stringifyMaybeJson(item.context),
        $priority: item.priority ?? 50,
      })
      inserted += result.changes
    }
  })
  tx()

  return `Work items added: ${inserted}/${items.length} (duplicates skipped: ${items.length - inserted})`
}

function handleWorkQuery(db: Database, args: Record<string, unknown>): string {
  const conditions: string[] = ["1=1"]
  const params: Record<string, unknown> = {}

  if (args.status) {
    conditions.push("status = $status")
    params.$status = args.status
  }
  if (args.agent_name) {
    conditions.push("agent_name = $agent_name")
    params.$agent_name = args.agent_name
  }
  if (args.source_module) {
    conditions.push("source_module = $source_module")
    params.$source_module = args.source_module
  }
  if (args.language) {
    conditions.push("language = $language")
    params.$language = args.language
  }
  if (args.shard_type) {
    conditions.push("shard_type = $shard_type")
    params.$shard_type = args.shard_type
  }

  let sql = `SELECT * FROM scan_work_items WHERE ${conditions.join(" AND ")} ORDER BY priority DESC, created_at ASC`
  if (args.limit) sql += ` LIMIT ${Number(args.limit)}`

  const rows = db.prepare(sql).all(params) as Record<string, unknown>[]
  return JSON.stringify(rows.map(parseWorkRow), null, 2)
}

function handleWorkClaim(db: Database, args: Record<string, unknown>): string {
  const limit = Number(args.limit ?? 1)
  const conditions: string[] = ["status = 'pending'"]
  const params: Record<string, unknown> = {}

  if (args.agent_name) {
    conditions.push("agent_name = $agent_name")
    params.$agent_name = args.agent_name
  }
  if (args.language) {
    conditions.push("language = $language")
    params.$language = args.language
  }

  const rows = db
    .prepare(`SELECT * FROM scan_work_items WHERE ${conditions.join(" AND ")} ORDER BY priority DESC, created_at ASC LIMIT ${limit}`)
    .all(params) as Record<string, unknown>[]

  if (rows.length === 0) return "[]"

  const tx = db.transaction(() => {
    for (const row of rows) {
      const id = row.id as string
      db.prepare(
        `UPDATE scan_work_items
         SET status = 'running', attempts = attempts + 1, started_at = datetime('now'), updated_at = datetime('now')
         WHERE id = ? AND status = 'pending'`,
      ).run(id)
    }
  })
  tx()

  const ids = rows.map((row) => row.id as string)
  const placeholders = ids.map(() => "?").join(",")
  const claimed = db.prepare(`SELECT * FROM scan_work_items WHERE id IN (${placeholders})`).all(...ids) as Record<string, unknown>[]
  return JSON.stringify(claimed.map(parseWorkRow), null, 2)
}

function handleWorkComplete(db: Database, id: string, args: Record<string, unknown>): string {
  const count = Number(args.item_count ?? args.finding_count ?? 0)
  const result = db
    .prepare(
      `UPDATE scan_work_items
       SET status = 'success', finding_count = $finding_count, finished_at = datetime('now'), updated_at = datetime('now'), error = NULL
       WHERE id = $id`,
    )
    .run({ $id: id, $finding_count: count })
  return `Work item completed: ${id} (${result.changes} row affected)`
}

function handleWorkFail(db: Database, id: string, args: Record<string, unknown>): string {
  const message = String(args.message ?? "failed")
  const result = db
    .prepare(
      `UPDATE scan_work_items
       SET status = 'failed', error = $error, finished_at = datetime('now'), updated_at = datetime('now')
       WHERE id = $id`,
    )
    .run({ $id: id, $error: message })
  return `Work item failed: ${id} (${result.changes} row affected)`
}

function handleWorkStats(db: Database, args: Record<string, unknown>): string {
  const where = args.agent_name ? "WHERE agent_name = $agent_name" : ""
  const params = args.agent_name ? { $agent_name: args.agent_name } : {}
  const rows = db
    .prepare(`SELECT status, COUNT(*) as cnt FROM scan_work_items ${where} GROUP BY status ORDER BY status`)
    .all(params) as Array<{ status: string; cnt: number }>
  const byLanguage = db
    .prepare(`SELECT language, status, COUNT(*) as cnt FROM scan_work_items ${where} GROUP BY language, status ORDER BY language, status`)
    .all(params) as Array<{ language: string | null; status: string; cnt: number }>

  const lines = ["Work items by status:"]
  for (const row of rows) lines.push(`  ${row.status}: ${row.cnt}`)
  lines.push("", "Work items by language/status:")
  for (const row of byLanguage) lines.push(`  ${row.language ?? "(none)"} / ${row.status}: ${row.cnt}`)
  return lines.join("\n")
}

function handleWorkRequeue(db: Database, args: Record<string, unknown>): string {
  if (args.id) {
    const result = db
      .prepare(
        `UPDATE scan_work_items
         SET status = 'pending', error = NULL, started_at = NULL, finished_at = NULL, updated_at = datetime('now')
         WHERE id = $id AND status IN ('running','failed')`,
      )
      .run({ $id: args.id })
    return `Work item requeued: ${args.id} (${result.changes} row affected)`
  }

  const conditions = ["status IN ('running','failed')"]
  const params: Record<string, unknown> = {}
  if (args.agent_name) {
    conditions.push("agent_name = $agent_name")
    params.$agent_name = args.agent_name
  }
  const result = db
    .prepare(
      `UPDATE scan_work_items
       SET status = 'pending', error = NULL, started_at = NULL, finished_at = NULL, updated_at = datetime('now')
       WHERE ${conditions.join(" AND ")}`,
    )
    .run(params)
  return `Work items requeued: ${result.changes}`
}

export default tool({
  description: DESCRIPTION,
  args: {
    command: tool.schema
      .enum([
        "init",
        "insert",
        "query",
        "update",
        "batch-update",
        "dedup",
        "stats",
        "log",
        "export-json",
        "work-add",
        "work-query",
        "work-claim",
        "work-complete",
        "work-fail",
        "work-stats",
        "work-requeue",
      ])
      .describe("The operation to perform"),
    db_path: tool.schema.string().describe("Absolute path to the SQLite database file"),
    vulnerabilities: tool.schema.string().optional().describe("JSON array of vulnerability objects (for insert)"),
    id: tool.schema.string().optional().describe("Vulnerability ID (for update) or work item ID (for work-complete/work-fail/work-requeue)"),
    fields: tool.schema.string().optional().describe("JSON object of fields to update (for update)"),
    updates: tool.schema.string().optional().describe("JSON array of {id, fields} objects (for batch-update)"),
    phase: tool.schema.string().optional().describe("Filter by phase: candidate or verified"),
    status: tool.schema.string().optional().describe("Filter by vulnerability status or work item status"),
    source_module: tool.schema.string().optional().describe("Filter by module name"),
    source_agent: tool.schema.string().optional().describe("Filter by source agent name"),
    language: tool.schema.string().optional().describe("Filter by language: c_cpp, python, go, lua, java"),
    analysis_kind: tool.schema.string().optional().describe("Filter by analysis kind: dataflow, authn, authz, crypto, config, secret, framework_misuse"),
    min_confidence: tool.schema.number().optional().describe("Minimum confidence score"),
    exclude_status: tool.schema.string().optional().describe("Exclude vulnerabilities with this status"),
    limit: tool.schema.number().optional().describe("Max results to return"),
    offset: tool.schema.number().optional().describe("Pagination offset"),
    ids: tool.schema.string().optional().describe("Comma-separated vulnerability IDs to query"),
    agent_name: tool.schema.string().optional().describe("Agent name (for log)"),
    module_name: tool.schema.string().optional().describe("Module name (for log)"),
    message: tool.schema.string().optional().describe("Log message"),
    item_count: tool.schema.number().optional().describe("Item count (for log)"),
    output: tool.schema.string().optional().describe("Output file path (for export-json)"),
    work_items: tool.schema.string().optional().describe("JSON array of scan work items (for work-add)"),
    shard_type: tool.schema.string().optional().describe("Filter by work item shard type"),
    finding_count: tool.schema.number().optional().describe("Finding count for a completed work item"),
  },
  async execute(args) {
    const { command, db_path } = args

    if (command === "init") {
      return handleInit(db_path)
    }

    if (command === "insert") {
      if (!args.vulnerabilities) return "Error: vulnerabilities parameter required for insert"
      return handleInsert(db_path, args.vulnerabilities)
    }

    const db = openDb(db_path)
    try {
      switch (command) {
        case "query":
          return handleQuery(db, args)
        case "update":
          if (!args.id || !args.fields) return "Error: id and fields parameters required for update"
          return handleUpdate(db, args.id, args.fields)
        case "batch-update":
          if (!args.updates) return "Error: updates parameter required for batch-update"
          return handleBatchUpdate(db, args.updates)
        case "dedup":
          return handleDedup(db)
        case "stats":
          return handleStats(db, args.phase as string | undefined)
        case "log":
          if (!args.agent_name) return "Error: agent_name required for log"
          return handleLog(db, args)
        case "export-json":
          if (!args.output) return "Error: output parameter required for export-json"
          return await handleExportJson(db, args)
        case "work-add":
          if (!args.work_items) return "Error: work_items parameter required for work-add"
          return handleWorkAdd(db, args.work_items)
        case "work-query":
          return handleWorkQuery(db, args)
        case "work-claim":
          return handleWorkClaim(db, args)
        case "work-complete":
          if (!args.id) return "Error: id parameter required for work-complete"
          return handleWorkComplete(db, args.id, args)
        case "work-fail":
          if (!args.id) return "Error: id parameter required for work-fail"
          return handleWorkFail(db, args.id, args)
        case "work-stats":
          return handleWorkStats(db, args)
        case "work-requeue":
          return handleWorkRequeue(db, args)
        default:
          return `Unknown command: ${command}`
      }
    } finally {
      db.close()
    }
  },
})
