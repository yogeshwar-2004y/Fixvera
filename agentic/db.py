import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path

DB_PATH = Path(os.getenv("AGENTIC_DB_PATH", "./data/agentic.sqlite3"))

SCHEMA = """
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS workspaces (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS memberships (
  workspace_id TEXT NOT NULL REFERENCES workspaces(id),
  user_id TEXT NOT NULL REFERENCES users(id), role TEXT NOT NULL,
  PRIMARY KEY (workspace_id,user_id)
);
CREATE TABLE IF NOT EXISTS sessions (
  id_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
  csrf_hash TEXT NOT NULL, expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS login_attempts (
  id TEXT PRIMARY KEY, email_hash TEXT NOT NULL, attempted_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_login_attempts ON login_attempts(email_hash,attempted_at);
CREATE TABLE IF NOT EXISTS sites (
  id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES workspaces(id),
  origin TEXT NOT NULL, hostname TEXT NOT NULL, label TEXT NOT NULL,
  verify_token TEXT NOT NULL, verified_at TEXT,
  wp_user TEXT, wp_secret TEXT, automation_mode TEXT NOT NULL DEFAULT 'observe',
  created_at TEXT NOT NULL, UNIQUE(workspace_id,hostname)
);
CREATE TABLE IF NOT EXISTS crawls (
  id TEXT PRIMARY KEY, site_id TEXT NOT NULL REFERENCES sites(id),
  started_at TEXT NOT NULL, finished_at TEXT, status TEXT NOT NULL,
  page_count INTEGER NOT NULL DEFAULT 0, error TEXT
);
CREATE TABLE IF NOT EXISTS pages (
  id TEXT PRIMARY KEY, crawl_id TEXT NOT NULL REFERENCES crawls(id),
  site_id TEXT NOT NULL REFERENCES sites(id), url TEXT NOT NULL,
  status_code INTEGER, title TEXT, description TEXT, canonical TEXT,
  h1_count INTEGER, wp_post_id INTEGER, body_hash TEXT,
  UNIQUE(crawl_id,url)
);
CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY, site_id TEXT NOT NULL REFERENCES sites(id),
  crawl_id TEXT NOT NULL REFERENCES crawls(id), page_id TEXT NOT NULL REFERENCES pages(id),
  rule TEXT NOT NULL, severity TEXT NOT NULL, evidence TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open', created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS changes (
  id TEXT PRIMARY KEY, site_id TEXT NOT NULL REFERENCES sites(id),
  finding_id TEXT REFERENCES findings(id), page_url TEXT NOT NULL,
  wp_post_id INTEGER NOT NULL, field TEXT NOT NULL,
  before_value TEXT NOT NULL, after_value TEXT NOT NULL,
  status TEXT NOT NULL, risk TEXT NOT NULL DEFAULT 'low',
  proposed_by TEXT NOT NULL REFERENCES users(id), approved_by TEXT REFERENCES users(id),
  applied_at TEXT, verified_at TEXT, error TEXT,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS change_provenance (
  change_id TEXT PRIMARY KEY REFERENCES changes(id),
  source TEXT NOT NULL, plan_id TEXT
);
CREATE TABLE IF NOT EXISTS events (
  id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES workspaces(id),
  site_id TEXT REFERENCES sites(id), actor_id TEXT REFERENCES users(id),
  action TEXT NOT NULL, object_type TEXT NOT NULL, object_id TEXT NOT NULL,
  detail TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sites_workspace ON sites(workspace_id);
CREATE INDEX IF NOT EXISTS idx_findings_site ON findings(site_id,created_at);
CREATE INDEX IF NOT EXISTS idx_changes_site ON changes(site_id,created_at);
CREATE INDEX IF NOT EXISTS idx_events_workspace ON events(workspace_id,created_at);
CREATE TABLE IF NOT EXISTS invitations (
  id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES workspaces(id),
  email TEXT NOT NULL, role TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE,
  invited_by TEXT NOT NULL REFERENCES users(id), expires_at TEXT NOT NULL,
  accepted_at TEXT, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS integrations (
  id TEXT PRIMARY KEY, site_id TEXT NOT NULL REFERENCES sites(id),
  platform TEXT NOT NULL, config_json TEXT NOT NULL, secret_ciphertext TEXT NOT NULL,
  status TEXT NOT NULL, checked_at TEXT, created_at TEXT NOT NULL,
  UNIQUE(site_id,platform)
);
CREATE TABLE IF NOT EXISTS page_snapshots (
  page_id TEXT PRIMARY KEY REFERENCES pages(id), signals_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS crawl_jobs (
  id TEXT PRIMARY KEY, site_id TEXT NOT NULL REFERENCES sites(id),
  requested_by TEXT REFERENCES users(id), status TEXT NOT NULL,
  attempt INTEGER NOT NULL DEFAULT 0, error TEXT,
  created_at TEXT NOT NULL, started_at TEXT, finished_at TEXT
);
CREATE TABLE IF NOT EXISTS automation_policies (
  site_id TEXT PRIMARY KEY REFERENCES sites(id), interval_hours INTEGER NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 0, next_run_at TEXT, last_run_at TEXT,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS write_policies (
  site_id TEXT PRIMARY KEY REFERENCES sites(id), enabled INTEGER NOT NULL,
  allowed_fields_json TEXT NOT NULL, max_daily_writes INTEGER NOT NULL,
  updated_by TEXT NOT NULL REFERENCES users(id), updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS policy_approvals (
  id TEXT PRIMARY KEY, site_id TEXT NOT NULL REFERENCES sites(id),
  change_kind TEXT NOT NULL, change_id TEXT NOT NULL,
  policy_updated_at TEXT NOT NULL, approved_at TEXT NOT NULL,
  UNIQUE(change_kind,change_id)
);
CREATE TABLE IF NOT EXISTS agent_runs (
  id TEXT PRIMARY KEY, site_id TEXT NOT NULL REFERENCES sites(id),
  agent TEXT NOT NULL, status TEXT NOT NULL, input_json TEXT NOT NULL,
  output_json TEXT, error TEXT, created_at TEXT NOT NULL, finished_at TEXT
);
CREATE TABLE IF NOT EXISTS action_plans (
  id TEXT PRIMARY KEY, site_id TEXT NOT NULL REFERENCES sites(id),
  finding_id TEXT REFERENCES findings(id), title TEXT NOT NULL,
  rationale TEXT NOT NULL, proposed_value TEXT, source TEXT NOT NULL,
  priority INTEGER NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS change_sets (
  id TEXT PRIMARY KEY, site_id TEXT NOT NULL REFERENCES sites(id),
  integration_id TEXT NOT NULL REFERENCES integrations(id),
  platform TEXT NOT NULL, resource_id TEXT NOT NULL, resource_url TEXT NOT NULL,
  field TEXT NOT NULL, before_value TEXT NOT NULL, after_value TEXT NOT NULL,
  status TEXT NOT NULL, risk TEXT NOT NULL,
  proposed_by TEXT NOT NULL REFERENCES users(id), approved_by TEXT REFERENCES users(id),
  output_json TEXT, error TEXT, created_at TEXT NOT NULL, applied_at TEXT, verified_at TEXT
);
CREATE TABLE IF NOT EXISTS content_drafts (
  id TEXT PRIMARY KEY, site_id TEXT NOT NULL REFERENCES sites(id),
  title TEXT NOT NULL, brief TEXT NOT NULL, body TEXT NOT NULL,
  source TEXT NOT NULL, status TEXT NOT NULL, created_by TEXT NOT NULL REFERENCES users(id),
  approved_by TEXT REFERENCES users(id), created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS search_metrics (
  id TEXT PRIMARY KEY, site_id TEXT NOT NULL REFERENCES sites(id),
  day TEXT NOT NULL, query TEXT NOT NULL, page TEXT NOT NULL,
  clicks INTEGER NOT NULL, impressions INTEGER NOT NULL,
  ctr REAL NOT NULL, position REAL NOT NULL, source TEXT NOT NULL,
  UNIQUE(site_id,day,query,page,source)
);
CREATE TABLE IF NOT EXISTS usage_ledger (
  id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES workspaces(id),
  site_id TEXT REFERENCES sites(id), kind TEXT NOT NULL,
  units INTEGER NOT NULL, detail TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS reports (
  id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES workspaces(id),
  site_id TEXT NOT NULL REFERENCES sites(id), title TEXT NOT NULL,
  report_json TEXT NOT NULL, created_by TEXT NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS oauth_states (
  state_hash TEXT PRIMARY KEY, site_id TEXT NOT NULL REFERENCES sites(id),
  user_id TEXT NOT NULL REFERENCES users(id), property_url TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS deletion_receipts (
  id TEXT PRIMARY KEY, workspace_name TEXT NOT NULL,
  actor_hash TEXT NOT NULL, deleted_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS site_webhooks (
  site_id TEXT PRIMARY KEY REFERENCES sites(id), secret_ciphertext TEXT NOT NULL,
  enabled INTEGER NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS webhook_events (
  id TEXT PRIMARY KEY, site_id TEXT NOT NULL REFERENCES sites(id),
  event_key TEXT NOT NULL, received_at TEXT NOT NULL,
  UNIQUE(site_id,event_key)
);
CREATE INDEX IF NOT EXISTS idx_crawl_jobs_status ON crawl_jobs(status,created_at);
CREATE INDEX IF NOT EXISTS idx_change_sets_site ON change_sets(site_id,created_at);
CREATE INDEX IF NOT EXISTS idx_metrics_site_day ON search_metrics(site_id,day);
"""


class ClosingConnection(sqlite3.Connection):
    def __exit__(self, exc_type, exc_value, traceback):
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()


def connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB_PATH, timeout=15, factory=ClosingConnection)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    db.execute("PRAGMA busy_timeout=15000")
    return db


def init():
    with connect() as db:
        db.executescript(SCHEMA)


@contextmanager
def transaction():
    db = connect()
    try:
        db.execute("BEGIN IMMEDIATE")
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def one(db, sql, params=()):
    row = db.execute(sql, params).fetchone()
    return dict(row) if row else None


def many(db, sql, params=()):
    return [dict(row) for row in db.execute(sql, params).fetchall()]
