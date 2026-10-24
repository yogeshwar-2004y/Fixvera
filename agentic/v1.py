"""Versioned product API beyond the first WordPress vertical slice."""
import json
import os
import hmac
import hashlib
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field

from . import connectors, gsc, llm, wordpress as wp
from .crawler import bounded_get, extract, safe_client
from .db import connect, many, one, transaction
from .main import log_event, membership, site_for_user
from .security import decrypt, digest, encrypt, new_id, now, safe_page_url, session_user

router = APIRouter(prefix="/api/v1")


def integration_for_user(db, integration_id, user_id, write=False):
    integration = one(db, "SELECT * FROM integrations WHERE id=?", (integration_id,))
    if not integration:
        raise HTTPException(404, "Integration not found")
    site = site_for_user(db, integration["site_id"], user_id, write)
    return integration, site


async def integration_token(integration):
    config = json.loads(integration["config_json"])
    if integration["platform"] == "github" and config.get("auth_mode") == "github_app":
        return await connectors.github_app_token(config["installation_id"])
    return decrypt(integration["secret_ciphertext"])


def change_for_user(db, change_id, user_id, write=False):
    change = one(db, "SELECT * FROM change_sets WHERE id=?", (change_id,))
    if not change:
        raise HTTPException(404, "Change set not found")
    site = site_for_user(db, change["site_id"], user_id, write)
    integration = one(db, "SELECT * FROM integrations WHERE id=? AND site_id=?", (change["integration_id"], site["id"]))
    return change, site, integration


class InviteInput(BaseModel):
    email: str
    role: str = "editor"


@router.post("/workspaces/{workspace_id}/invitations")
async def invite(workspace_id: str, data: InviteInput, user=Depends(session_user)):
    email = data.email.strip().lower()
    if "@" not in email or data.role not in ("editor", "viewer"):
        raise HTTPException(422, "Valid email and editor/viewer role required")
    token, ident = new_id(), new_id()
    expires = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
    with transaction() as db:
        member = membership(db, workspace_id, user["id"], True)
        if member["role"] != "owner":
            raise HTTPException(403, "Only workspace owners can invite members")
        db.execute("INSERT INTO invitations VALUES (?,?,?,?,?,?,?,?,?)",
                   (ident, workspace_id, email, data.role, digest(token), user["id"], expires, None, now()))
        log_event(db, workspace_id, None, user["id"], "member.invited", "invitation", ident, {"email": email, "role": data.role})
    return {"id": ident, "invite_token": token, "expires_at": expires,
            "delivery": "Share this token securely; email delivery is not configured"}


class AcceptInvite(BaseModel):
    token: str


@router.post("/invitations/accept")
async def accept_invite(data: AcceptInvite, user=Depends(session_user)):
    with transaction() as db:
        invite = one(db, "SELECT * FROM invitations WHERE token_hash=?", (digest(data.token),))
        if not invite or invite["accepted_at"] or invite["expires_at"] < now():
            raise HTTPException(404, "Invitation expired or unavailable")
        if invite["email"] != user["email"]:
            raise HTTPException(403, "Invitation belongs to another email")
        db.execute("INSERT OR IGNORE INTO memberships VALUES (?,?,?)",
                   (invite["workspace_id"], user["id"], invite["role"]))
        db.execute("UPDATE invitations SET accepted_at=? WHERE id=?", (now(), invite["id"]))
        log_event(db, invite["workspace_id"], None, user["id"], "member.joined", "invitation", invite["id"])
    return {"workspace_id": invite["workspace_id"], "role": invite["role"]}


@router.get("/workspaces/{workspace_id}/members")
async def members(workspace_id: str, user=Depends(session_user)):
    with connect() as db:
        membership(db, workspace_id, user["id"])
        return many(db, "SELECT u.id,u.email,m.role FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.workspace_id=? ORDER BY u.email", (workspace_id,))


@router.get("/workspaces/{workspace_id}/export")
async def export_workspace(workspace_id: str, user=Depends(session_user)):
    with connect() as db:
        member = membership(db, workspace_id, user["id"])
        if member["role"] != "owner":
            raise HTTPException(403, "Only workspace owners can export all workspace data")
        workspace = one(db, "SELECT * FROM workspaces WHERE id=?", (workspace_id,))
        site_rows = many(db, "SELECT id,origin,hostname,label,verified_at,automation_mode,created_at FROM sites WHERE workspace_id=?", (workspace_id,))
        export = {"workspace": workspace, "sites": site_rows, "exported_at": now(),
                  "members": many(db, "SELECT u.email,m.role FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.workspace_id=?", (workspace_id,)),
                  "events": many(db, "SELECT action,object_type,object_id,detail,created_at FROM events WHERE workspace_id=?", (workspace_id,)),
                  "usage": many(db, "SELECT kind,units,detail,created_at FROM usage_ledger WHERE workspace_id=?", (workspace_id,)),
                  "reports": many(db, "SELECT title,report_json,created_at FROM reports WHERE workspace_id=?", (workspace_id,)),
                  "site_data": {}}
        for site in site_rows:
            sid = site["id"]
            export["site_data"][sid] = {
                "crawls": many(db, "SELECT * FROM crawls WHERE site_id=?", (sid,)),
                "pages": many(db, "SELECT p.* FROM pages p WHERE p.site_id=?", (sid,)),
                "findings": many(db, "SELECT * FROM findings WHERE site_id=?", (sid,)),
                "changes": many(db, "SELECT * FROM changes WHERE site_id=?", (sid,)),
                "change_sets": many(db, "SELECT * FROM change_sets WHERE site_id=?", (sid,)),
                "action_plans": many(db, "SELECT * FROM action_plans WHERE site_id=?", (sid,)),
                "content_drafts": many(db, "SELECT * FROM content_drafts WHERE site_id=?", (sid,)),
                "search_metrics": many(db, "SELECT * FROM search_metrics WHERE site_id=?", (sid,)),
                "integrations": many(db, "SELECT platform,config_json,status,checked_at FROM integrations WHERE site_id=?", (sid,)),
            }
        return export


class DeleteWorkspace(BaseModel):
    confirm_name: str


@router.delete("/workspaces/{workspace_id}")
async def delete_workspace(workspace_id: str, data: DeleteWorkspace, user=Depends(session_user)):
    with transaction() as db:
        member = membership(db, workspace_id, user["id"])
        if member["role"] != "owner":
            raise HTTPException(403, "Only workspace owners can delete a workspace")
        workspace = one(db, "SELECT * FROM workspaces WHERE id=?", (workspace_id,))
        if data.confirm_name != workspace["name"]:
            raise HTTPException(422, "Workspace name confirmation does not match")
        site_ids = [item["id"] for item in many(db, "SELECT id FROM sites WHERE workspace_id=?", (workspace_id,))]
        if site_ids:
            marks = ",".join("?" for _ in site_ids)
            for table in ("oauth_states", "webhook_events", "site_webhooks", "reports", "usage_ledger", "policy_approvals", "write_policies",
                          "automation_policies", "agent_runs", "action_plans", "content_drafts", "search_metrics",
                          "change_sets", "change_provenance", "changes", "findings", "page_snapshots", "pages", "crawl_jobs",
                          "crawls", "integrations", "events"):
                if table == "page_snapshots":
                    db.execute(f"DELETE FROM page_snapshots WHERE page_id IN (SELECT id FROM pages WHERE site_id IN ({marks}))", site_ids)
                elif table == "change_provenance":
                    db.execute(f"DELETE FROM change_provenance WHERE change_id IN (SELECT id FROM changes WHERE site_id IN ({marks}))", site_ids)
                elif table in ("reports", "usage_ledger", "events"):
                    db.execute(f"DELETE FROM {table} WHERE site_id IN ({marks})", site_ids)
                else:
                    db.execute(f"DELETE FROM {table} WHERE site_id IN ({marks})", site_ids)
            db.execute(f"DELETE FROM sites WHERE id IN ({marks})", site_ids)
        for table in ("reports", "usage_ledger", "events", "invitations", "memberships"):
            db.execute(f"DELETE FROM {table} WHERE workspace_id=?", (workspace_id,))
        db.execute("DELETE FROM workspaces WHERE id=?", (workspace_id,))
        receipt = new_id()
        db.execute("INSERT INTO deletion_receipts VALUES (?,?,?,?)",
                   (receipt, workspace["name"], digest(user["email"]), now()))
    return {"deleted": True, "receipt_id": receipt,
            "note": "Live database records removed; backup retention is controlled by the operator"}


@router.get("/sites/{site_id}/pages")
async def pages(site_id: str, user=Depends(session_user)):
    with connect() as db:
        site_for_user(db, site_id, user["id"])
        latest = one(db, "SELECT id FROM crawls WHERE site_id=? AND status='completed' ORDER BY finished_at DESC LIMIT 1", (site_id,))
        if not latest:
            return []
        return many(db, "SELECT p.*,s.signals_json FROM pages p LEFT JOIN page_snapshots s ON s.page_id=p.id WHERE p.crawl_id=? ORDER BY p.url", (latest["id"],))


@router.get("/sites/{site_id}/audit")
async def audit(site_id: str, user=Depends(session_user)):
    with connect() as db:
        site_for_user(db, site_id, user["id"])
        latest = one(db, "SELECT * FROM crawls WHERE site_id=? AND status='completed' ORDER BY finished_at DESC LIMIT 1", (site_id,))
        if not latest:
            return {"score": None, "crawl": None, "issues": [], "by_severity": {}}
        issues = many(db, "SELECT f.rule,f.severity,f.evidence,p.url FROM findings f JOIN pages p ON p.id=f.page_id WHERE f.crawl_id=?", (latest["id"],))
    weights = {"high": 8, "medium": 4, "low": 2}
    score = max(0, round(100 - sum(weights.get(i["severity"], 2) for i in issues) / max(1, latest["page_count"])))
    return {"score": score, "method": "pilot rule-based health score, not a Google metric",
            "crawl": latest, "issues": issues,
            "by_severity": {key: sum(1 for i in issues if i["severity"] == key) for key in ("high", "medium", "low")}}


class IntegrationInput(BaseModel):
    site_id: str
    platform: str
    credential: str | None = None
    shop_domain: str | None = None
    repository: str | None = None
    installation_id: str | None = None


@router.post("/integrations")
async def connect_integration(data: IntegrationInput, user=Depends(session_user)):
    with connect() as db:
        site = site_for_user(db, data.site_id, user["id"], True)
    if not site["verified_at"]:
        raise HTTPException(409, "Verify the website before granting connector access")
    try:
        if data.platform == "shopify":
            if not data.shop_domain or not data.credential or len(data.credential) < 8:
                raise HTTPException(422, "Shopify shop domain and Admin token required")
            health = await connectors.shopify_health(data.shop_domain, data.credential, site["hostname"])
            config = {"shop_domain": data.shop_domain, **health}
            stored_secret = data.credential
        elif data.platform == "github":
            if not data.repository:
                raise HTTPException(422, "GitHub repository required")
            if data.installation_id:
                token = await connectors.github_app_token(data.installation_id)
                config = {**await connectors.github_health(data.repository, token),
                          "auth_mode": "github_app", "installation_id": data.installation_id}
                stored_secret = "github_app_installation:" + data.installation_id
            elif data.credential and len(data.credential) >= 8:
                config = {**await connectors.github_health(data.repository, data.credential), "auth_mode": "scoped_token"}
                stored_secret = data.credential
            else:
                raise HTTPException(422, "GitHub App installation ID or scoped token required")
        else:
            raise HTTPException(422, "Supported platforms: Shopify, GitHub")
    except connectors.ConnectorError as exc:
        raise HTTPException(422, str(exc))
    ident = new_id()
    with transaction() as db:
        db.execute("INSERT INTO integrations VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(site_id,platform) DO UPDATE SET config_json=excluded.config_json,secret_ciphertext=excluded.secret_ciphertext,status='connected',checked_at=excluded.checked_at",
                   (ident, site["id"], data.platform, json.dumps(config), encrypt(stored_secret), "connected", now(), now()))
        actual_id = one(db, "SELECT id FROM integrations WHERE site_id=? AND platform=?", (site["id"], data.platform))["id"]
        log_event(db, site["workspace_id"], site["id"], user["id"], "integration.connected", "integration", actual_id,
                  {"platform": data.platform})
    return {"id": actual_id, "platform": data.platform, "status": "connected", "config": config}


@router.get("/sites/{site_id}/integrations")
async def integrations(site_id: str, user=Depends(session_user)):
    with connect() as db:
        site_for_user(db, site_id, user["id"])
        rows = many(db, "SELECT id,platform,config_json,status,checked_at FROM integrations WHERE site_id=?", (site_id,))
    return [{**row, "config": json.loads(row.pop("config_json"))} for row in rows]


@router.post("/integrations/{integration_id}/health")
async def check_health(integration_id: str, user=Depends(session_user)):
    with connect() as db:
        integration, site = integration_for_user(db, integration_id, user["id"], True)
    config, token = json.loads(integration["config_json"]), await integration_token(integration)
    try:
        if integration["platform"] == "shopify":
            result = await connectors.shopify_health(config["shop_domain"], token, site["hostname"])
        else:
            result = await connectors.github_health(config["repository"], token)
        status = "connected"
    except connectors.ConnectorError as exc:
        result, status = {"error": str(exc)}, "unhealthy"
    with transaction() as db:
        db.execute("UPDATE integrations SET status=?,checked_at=? WHERE id=?", (status, now(), integration_id))
    return {"status": status, "detail": result}


def llm_budget(db, workspace_id):
    spent = one(db, "SELECT COALESCE(SUM(units),0) AS units FROM usage_ledger WHERE workspace_id=? AND kind='llm_tokens' AND julianday(created_at)>=julianday('now','-1 day')", (workspace_id,))["units"]
    if spent >= 50000:
        raise HTTPException(429, "Daily AI token budget reached")


def record_ai(db, site, user_id, run_id, output, tokens, model):
    db.execute("UPDATE agent_runs SET status='completed',output_json=?,finished_at=? WHERE id=?",
               (json.dumps(output), now(), run_id))
    db.execute("INSERT INTO usage_ledger VALUES (?,?,?,?,?,?,?)",
               (new_id(), site["workspace_id"], site["id"], "llm_tokens", tokens, model, now()))
    log_event(db, site["workspace_id"], site["id"], user_id, "agent.completed", "agent_run", run_id,
              {"model": model, "tokens": tokens})


class PlanInput(BaseModel):
    finding_id: str


@router.post("/sites/{site_id}/plans/generate")
async def generate_plan(site_id: str, data: PlanInput, user=Depends(session_user)):
    with connect() as db:
        site = site_for_user(db, site_id, user["id"], True)
        llm_budget(db, site["workspace_id"])
        finding = one(db, "SELECT f.*,p.url,p.title,p.description FROM findings f JOIN pages p ON p.id=f.page_id WHERE f.id=? AND f.site_id=?", (data.finding_id, site_id))
        if not finding:
            raise HTTPException(404, "Finding not found")
    run_id = new_id()
    with transaction() as db:
        db.execute("INSERT INTO agent_runs VALUES (?,?,?,?,?,?,?,?,?)",
                   (run_id, site_id, "strategy", "running", json.dumps({"finding_id": data.finding_id}), None, None, now(), None))
    try:
        advice, tokens, model = await llm.metadata_advice(finding, finding)
    except llm.LLMUnavailable as exc:
        with transaction() as db:
            db.execute("UPDATE agent_runs SET status='failed',error=?,finished_at=? WHERE id=?", (str(exc), now(), run_id))
        raise HTTPException(503, str(exc))
    value = advice.title if finding["rule"] in ("missing_title", "long_title") else advice.description
    plan_id = new_id()
    with transaction() as db:
        db.execute("INSERT INTO action_plans VALUES (?,?,?,?,?,?,?,?,?,?)",
                   (plan_id, site_id, data.finding_id, "Improve page metadata", advice.rationale,
                    value, "ai_draft", advice.priority, "proposed", now()))
        record_ai(db, site, user["id"], run_id, advice.model_dump(), tokens, model)
    return {"id": plan_id, "advice": advice.model_dump(), "status": "proposed", "source": "ai_draft"}


@router.get("/sites/{site_id}/plans")
async def plans(site_id: str, user=Depends(session_user)):
    with connect() as db:
        site_for_user(db, site_id, user["id"])
        return many(db, "SELECT * FROM action_plans WHERE site_id=? ORDER BY priority,created_at DESC", (site_id,))


class CopilotInput(BaseModel):
    site_id: str
    question: str = Field(min_length=3, max_length=1000)


@router.post("/copilot")
async def copilot(data: CopilotInput, user=Depends(session_user)):
    with connect() as db:
        site = site_for_user(db, data.site_id, user["id"])
        llm_budget(db, site["workspace_id"])
        context = many(db, "SELECT f.rule,f.severity,f.evidence,p.url FROM findings f JOIN pages p ON p.id=f.page_id WHERE f.site_id=? ORDER BY f.created_at DESC LIMIT 15", (site["id"],))
    run_id = new_id()
    with transaction() as db:
        db.execute("INSERT INTO agent_runs VALUES (?,?,?,?,?,?,?,?,?)",
                   (run_id, site["id"], "copilot", "running", json.dumps({"question": data.question}), None, None, now(), None))
    try:
        answer, tokens, model = await llm.copilot_answer(data.question, context)
    except llm.LLMUnavailable as exc:
        with transaction() as db:
            db.execute("UPDATE agent_runs SET status='failed',error=?,finished_at=? WHERE id=?", (str(exc), now(), run_id))
        raise HTTPException(503, str(exc))
    with transaction() as db:
        record_ai(db, site, user["id"], run_id, answer.model_dump(), tokens, model)
    return {"run_id": run_id, **answer.model_dump(), "source": "ai_assistant"}


class CrawlRequest(BaseModel):
    site_id: str


@router.post("/crawls")
async def queue_crawl(data: CrawlRequest, user=Depends(session_user)):
    with transaction() as db:
        site = site_for_user(db, data.site_id, user["id"], True)
        count = one(db, "SELECT COUNT(*) AS count FROM crawl_jobs WHERE site_id=? AND julianday(created_at)>=julianday('now','-1 day')", (site["id"],))["count"]
        if count >= 10:
            raise HTTPException(429, "Daily crawl limit reached")
        existing = one(db, "SELECT id FROM crawl_jobs WHERE site_id=? AND status IN ('queued','running')", (site["id"],))
        if existing:
            return {"id": existing["id"], "status": "queued_or_running"}
        ident = new_id()
        db.execute("INSERT INTO crawl_jobs (id,site_id,requested_by,status,created_at) VALUES (?,?,?,?,?)",
                   (ident, site["id"], user["id"], "queued", now()))
        log_event(db, site["workspace_id"], site["id"], user["id"], "crawl.queued", "crawl_job", ident)
    return {"id": ident, "status": "queued"}


@router.get("/crawls/{job_id}")
async def crawl_job(job_id: str, user=Depends(session_user)):
    with connect() as db:
        job = one(db, "SELECT * FROM crawl_jobs WHERE id=?", (job_id,))
        if not job:
            raise HTTPException(404, "Crawl job not found")
        site_for_user(db, job["site_id"], user["id"])
        return job


@router.get("/sites/{site_id}/crawl-jobs")
async def crawl_jobs(site_id: str, user=Depends(session_user)):
    with connect() as db:
        site_for_user(db, site_id, user["id"])
        return many(db, "SELECT * FROM crawl_jobs WHERE site_id=? ORDER BY created_at DESC LIMIT 20", (site_id,))


class ScheduleInput(BaseModel):
    interval_hours: int = Field(ge=24, le=168)
    enabled: bool


@router.put("/sites/{site_id}/automations")
async def set_schedule(site_id: str, data: ScheduleInput, user=Depends(session_user)):
    next_run = (datetime.now(timezone.utc) + timedelta(hours=data.interval_hours)).isoformat() if data.enabled else None
    with transaction() as db:
        site = site_for_user(db, site_id, user["id"], True)
        db.execute("INSERT INTO automation_policies VALUES (?,?,?,?,?,?) ON CONFLICT(site_id) DO UPDATE SET interval_hours=excluded.interval_hours,enabled=excluded.enabled,next_run_at=excluded.next_run_at,updated_at=excluded.updated_at",
                   (site_id, data.interval_hours, int(data.enabled), next_run, None, now()))
        log_event(db, site["workspace_id"], site_id, user["id"], "automation.updated", "site", site_id,
                  {"interval_hours": data.interval_hours, "enabled": data.enabled})
    return {"enabled": data.enabled, "next_run_at": next_run}


@router.get("/sites/{site_id}/automations")
async def get_schedule(site_id: str, user=Depends(session_user)):
    with connect() as db:
        site_for_user(db, site_id, user["id"])
        return one(db, "SELECT * FROM automation_policies WHERE site_id=?", (site_id,)) or {"enabled": False}


@router.post("/sites/{site_id}/webhook")
async def rotate_webhook(site_id: str, user=Depends(session_user)):
    secret = new_id() + new_id()
    with transaction() as db:
        site = site_for_user(db, site_id, user["id"], True)
        if membership(db, site["workspace_id"], user["id"])["role"] != "owner":
            raise HTTPException(403, "Only workspace owners can configure webhooks")
        if not site["verified_at"]:
            raise HTTPException(409, "Verify the website first")
        db.execute("INSERT INTO site_webhooks VALUES (?,?,?,?) ON CONFLICT(site_id) DO UPDATE SET secret_ciphertext=excluded.secret_ciphertext,enabled=1,created_at=excluded.created_at",
                   (site_id, encrypt(secret), 1, now()))
        log_event(db, site["workspace_id"], site_id, user["id"], "webhook.rotated", "site", site_id)
    return {"url_path": f"/api/v1/webhooks/{site_id}", "secret": secret,
            "signature_header": "X-Agentic-Signature: sha256=<hex HMAC-SHA256 of raw body>",
            "event_id_header": "X-Agentic-Event-Id"}


@router.get("/sites/{site_id}/webhook")
async def webhook_config(site_id: str, user=Depends(session_user)):
    with connect() as db:
        site_for_user(db, site_id, user["id"])
        row = one(db, "SELECT enabled,created_at FROM site_webhooks WHERE site_id=?", (site_id,))
    return {"enabled": bool(row["enabled"]), "created_at": row["created_at"],
            "url_path": f"/api/v1/webhooks/{site_id}"} if row else {"enabled": False}


@router.post("/webhooks/{site_id}")
async def receive_webhook(site_id: str, request: Request):
    body = await request.body()
    if len(body) > 10000:
        raise HTTPException(413, "Webhook payload too large")
    event_key = request.headers.get("X-Agentic-Event-Id", "")
    signature = request.headers.get("X-Agentic-Signature", "")
    if not event_key or len(event_key) > 128:
        raise HTTPException(422, "Event ID required")
    with connect() as db:
        hook = one(db, "SELECT * FROM site_webhooks WHERE site_id=? AND enabled=1", (site_id,))
        site = one(db, "SELECT * FROM sites WHERE id=?", (site_id,))
    if not hook or not site:
        raise HTTPException(404, "Webhook unavailable")
    expected = "sha256=" + hmac.new(decrypt(hook["secret_ciphertext"]).encode(), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise HTTPException(403, "Invalid webhook signature")
    with transaction() as db:
        prior = one(db, "SELECT id FROM webhook_events WHERE site_id=? AND event_key=?", (site_id, event_key))
        if prior:
            return {"status": "duplicate"}
        count = one(db, "SELECT COUNT(*) AS total FROM crawl_jobs WHERE site_id=? AND julianday(created_at)>=julianday('now','-1 day')", (site_id,))["total"]
        if count >= 10:
            raise HTTPException(429, "Daily crawl limit reached")
        db.execute("INSERT INTO webhook_events VALUES (?,?,?,?)", (new_id(), site_id, event_key, now()))
        existing = one(db, "SELECT id FROM crawl_jobs WHERE site_id=? AND status IN ('queued','running')", (site_id,))
        if existing:
            return {"status": "already_queued", "job_id": existing["id"]}
        owner = one(db, "SELECT user_id FROM memberships WHERE workspace_id=? AND role='owner' LIMIT 1", (site["workspace_id"],))
        if not owner:
            raise HTTPException(409, "Workspace owner unavailable")
        ident = new_id()
        db.execute("INSERT INTO crawl_jobs (id,site_id,requested_by,status,created_at) VALUES (?,?,?,?,?)",
                   (ident, site_id, owner["user_id"], "queued", now()))
        log_event(db, site["workspace_id"], site_id, owner["user_id"], "crawl.webhook_queued", "crawl_job", ident,
                  {"event_id_hash": digest(event_key)})
    return {"status": "queued", "job_id": ident}


class WritePolicyInput(BaseModel):
    enabled: bool
    allowed_fields: list[str] = Field(max_length=2)
    max_daily_writes: int = Field(ge=1, le=10)
    authorize_low_risk_metadata: bool


@router.put("/sites/{site_id}/write-policy")
async def set_write_policy(site_id: str, data: WritePolicyInput, user=Depends(session_user)):
    if data.enabled and not data.authorize_low_risk_metadata:
        raise HTTPException(422, "Explicit metadata automation authorization is required")
    if (data.enabled and not data.allowed_fields) or any(field not in ("seo_title", "seo_description") for field in data.allowed_fields):
        raise HTTPException(422, "Only SEO title and description can be automated")
    with transaction() as db:
        site = site_for_user(db, site_id, user["id"], True)
        role = membership(db, site["workspace_id"], user["id"])["role"]
        if role != "owner":
            raise HTTPException(403, "Only workspace owners can configure automatic writes")
        if data.enabled and not site["verified_at"]:
            raise HTTPException(409, "Verify the website first")
        db.execute("INSERT INTO write_policies VALUES (?,?,?,?,?,?) ON CONFLICT(site_id) DO UPDATE SET enabled=excluded.enabled,allowed_fields_json=excluded.allowed_fields_json,max_daily_writes=excluded.max_daily_writes,updated_by=excluded.updated_by,updated_at=excluded.updated_at",
                   (site_id, int(data.enabled), json.dumps(sorted(set(data.allowed_fields))), data.max_daily_writes, user["id"], now()))
        if not data.enabled:
            db.execute("UPDATE sites SET automation_mode='observe' WHERE id=? AND automation_mode='autopilot'", (site_id,))
        log_event(db, site["workspace_id"], site_id, user["id"], "write_policy.updated", "site", site_id,
                  {"enabled": data.enabled, "fields": data.allowed_fields, "max_daily_writes": data.max_daily_writes})
    return {"enabled": data.enabled, "allowed_fields": data.allowed_fields,
            "max_daily_writes": data.max_daily_writes}


@router.get("/sites/{site_id}/write-policy")
async def get_write_policy(site_id: str, user=Depends(session_user)):
    with connect() as db:
        site_for_user(db, site_id, user["id"])
        policy = one(db, "SELECT enabled,allowed_fields_json,max_daily_writes,updated_at FROM write_policies WHERE site_id=?", (site_id,))
    return {"enabled": bool(policy["enabled"]), "allowed_fields": json.loads(policy["allowed_fields_json"]),
            "max_daily_writes": policy["max_daily_writes"], "updated_at": policy["updated_at"]} if policy else {"enabled": False}


def policy_allows(db, site, field):
    if site["automation_mode"] != "autopilot" or not site["verified_at"]:
        return None
    policy = one(db, "SELECT * FROM write_policies WHERE site_id=? AND enabled=1", (site["id"],))
    if not policy or field not in json.loads(policy["allowed_fields_json"]):
        return None
    count = one(db, "SELECT COUNT(*) AS total FROM policy_approvals WHERE site_id=? AND julianday(approved_at)>=julianday('now','-1 day')", (site["id"],))["total"]
    return policy if count < policy["max_daily_writes"] else None


class ChangeSetInput(BaseModel):
    integration_id: str
    resource_id: str = Field(min_length=1, max_length=300)
    resource_url: str
    field: str
    after_value: str = Field(min_length=1, max_length=170)


@router.post("/change-sets")
async def propose_change_set(data: ChangeSetInput, user=Depends(session_user)):
    if data.field not in ("seo_title", "seo_description"):
        raise HTTPException(422, "Only metadata fields are supported")
    value = data.after_value.strip()
    if (data.field == "seo_title" and len(value) > 70) or (data.field == "seo_description" and len(value) > 170):
        raise HTTPException(422, "Metadata exceeds field limit")
    with connect() as db:
        integration, site = integration_for_user(db, data.integration_id, user["id"], True)
    if not site["verified_at"] or integration["status"] != "connected":
        raise HTTPException(409, "A verified site and healthy integration are required")
    resource_url = safe_page_url(data.resource_url, site["hostname"])
    if not resource_url:
        raise HTTPException(422, "Live URL must belong to the verified website")
    config, token = json.loads(integration["config_json"]), await integration_token(integration)
    try:
        if integration["platform"] == "shopify":
            current = await connectors.shopify_metadata(config["shop_domain"], token, data.resource_id)
            if current.get("url") and current["url"].rstrip("/") != resource_url.rstrip("/"):
                raise connectors.ConnectorError("Shopify resource URL does not match the proposed page")
        else:
            current = await connectors.github_file_metadata(config["repository"], token, data.resource_id)
    except connectors.ConnectorError as exc:
        raise HTTPException(422, str(exc))
    before = current.get(data.field)
    if before is None:
        raise HTTPException(422, "Metadata field is not uniquely editable on this resource")
    if before == value:
        raise HTTPException(422, "Proposed value matches the current value")
    ident = new_id()
    with transaction() as db:
        db.execute("INSERT INTO change_sets (id,site_id,integration_id,platform,resource_id,resource_url,field,before_value,after_value,status,risk,proposed_by,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                   (ident, site["id"], integration["id"], integration["platform"], data.resource_id,
                    resource_url, data.field, before, value, "proposed", "low", user["id"], now()))
        log_event(db, site["workspace_id"], site["id"], user["id"], "change_set.proposed", "change_set", ident,
                  {"platform": integration["platform"], "field": data.field, "before": before, "after": value})
    return {"id": ident, "status": "proposed", "before_value": before, "after_value": value}


@router.get("/sites/{site_id}/change-sets")
async def list_change_sets(site_id: str, user=Depends(session_user)):
    with connect() as db:
        site_for_user(db, site_id, user["id"])
        return many(db, "SELECT * FROM change_sets WHERE site_id=? ORDER BY created_at DESC", (site_id,))


@router.post("/change-sets/{change_id}/approve")
async def approve_change_set(change_id: str, user=Depends(session_user)):
    with transaction() as db:
        change, site, _ = change_for_user(db, change_id, user["id"], True)
        if change["status"] != "proposed":
            raise HTTPException(409, "Only proposed changes can be approved")
        db.execute("UPDATE change_sets SET status='approved',approved_by=? WHERE id=?", (user["id"], change_id))
        log_event(db, site["workspace_id"], site["id"], user["id"], "change_set.approved", "change_set", change_id,
                  {"before": change["before_value"], "after": change["after_value"]})
    return {"status": "approved"}


@router.post("/change-sets/{change_id}/reject")
async def reject_change_set(change_id: str, user=Depends(session_user)):
    with transaction() as db:
        change, site, _ = change_for_user(db, change_id, user["id"], True)
        if change["status"] != "proposed":
            raise HTTPException(409, "Only proposed changes can be rejected")
        db.execute("UPDATE change_sets SET status='rejected' WHERE id=?", (change_id,))
        log_event(db, site["workspace_id"], site["id"], user["id"], "change_set.rejected", "change_set", change_id)
    return {"status": "rejected"}


@router.post("/change-sets/{change_id}/execute")
async def execute_change_set(change_id: str, user=Depends(session_user)):
    with transaction() as db:
        change, site, integration = change_for_user(db, change_id, user["id"], True)
        if change["status"] != "approved" or not change["approved_by"]:
            raise HTTPException(409, "Human approval of the exact change is required")
        if site["automation_mode"] not in ("assist", "autopilot") or not site["verified_at"]:
            raise HTTPException(409, "Verified site and enabled write mode required")
        db.execute("UPDATE change_sets SET status='applying' WHERE id=?", (change_id,))
    config, token = json.loads(integration["config_json"]), await integration_token(integration)
    try:
        if change["platform"] == "shopify":
            current = await connectors.shopify_metadata(config["shop_domain"], token, change["resource_id"])
            if current[change["field"]] != change["before_value"]:
                raise connectors.ConnectorError("Live Shopify value changed since approval")
            current[change["field"]] = change["after_value"]
            output = await connectors.shopify_set_metadata(config["shop_domain"], token, change["resource_id"],
                                                            current["seo_title"], current["seo_description"])
            status = "applied"
        else:
            output = await connectors.github_open_pr(config["repository"], token, change["resource_id"],
                                                     change["field"], change["before_value"], change["after_value"], change_id)
            status = "pr_open"
    except connectors.ConnectorError as exc:
        with transaction() as db:
            db.execute("UPDATE change_sets SET status='failed',error=? WHERE id=?", (str(exc)[:250], change_id))
            log_event(db, site["workspace_id"], site["id"], user["id"], "change_set.failed", "change_set", change_id,
                      {"error": str(exc)[:250]})
        raise HTTPException(409, str(exc))
    with transaction() as db:
        db.execute("UPDATE change_sets SET status=?,output_json=?,applied_at=?,error=NULL WHERE id=?",
                   (status, json.dumps(output), now(), change_id))
        log_event(db, site["workspace_id"], site["id"], user["id"], "change_set." + status, "change_set", change_id)
    return {"status": status, "output": output}


@router.post("/change-sets/{change_id}/verify")
async def verify_change_set(change_id: str, user=Depends(session_user)):
    with connect() as db:
        change, site, integration = change_for_user(db, change_id, user["id"], True)
    if change["status"] not in ("applied", "pr_open", "awaiting_deployment", "verified"):
        raise HTTPException(409, "Change has not been applied or submitted")
    if change["platform"] == "github":
        config, token = json.loads(integration["config_json"]), await integration_token(integration)
        output = json.loads(change["output_json"] or "{}")
        try:
            pr = await connectors.github_api(token, "GET", f"/repos/{config['repository']}/pulls/{output['pull_request_number']}")
        except (connectors.ConnectorError, KeyError) as exc:
            raise HTTPException(502, str(exc))
        if not pr.get("merged_at"):
            return {"verified": False, "status": "pr_open", "detail": "PR has not been merged; deployment not inferred"}
    try:
        async with safe_client() as session:
            http_status, _, body = await bounded_get(session, change["resource_url"], site["hostname"])
    except Exception as exc:
        raise HTTPException(502, "Live verification fetch failed: " + type(exc).__name__)
    page = extract(change["resource_url"], body)
    observed = page["title"] if change["field"] == "seo_title" else page["description"]
    verified = http_status == 200 and observed == change["after_value"]
    status = "verified" if verified else ("awaiting_deployment" if change["platform"] == "github" else "applied")
    with transaction() as db:
        db.execute("UPDATE change_sets SET status=?,verified_at=? WHERE id=?", (status, now() if verified else None, change_id))
        log_event(db, site["workspace_id"], site["id"], user["id"], "change_set.verification", "change_set", change_id,
                  {"verified": verified, "observed": observed[:300], "http_status": http_status})
    return {"verified": verified, "status": status, "observed": observed, "http_status": http_status}


@router.post("/change-sets/{change_id}/reconcile")
async def reconcile_change_set(change_id: str, user=Depends(session_user)):
    with connect() as db:
        change, site, integration = change_for_user(db, change_id, user["id"], True)
    if change["status"] not in ("applying", "failed"):
        raise HTTPException(409, "Only uncertain applications can be reconciled")
    config, token = json.loads(integration["config_json"]), await integration_token(integration)
    try:
        if change["platform"] == "shopify":
            current = await connectors.shopify_metadata(config["shop_domain"], token, change["resource_id"])
            observed = current[change["field"]]
            status = "applied" if observed == change["after_value"] else ("approved" if observed == change["before_value"] else "failed")
            output = change["output_json"]
        else:
            repo = config["repository"]
            name = "agentic-seo/" + change_id[:20]
            owner = repo.split("/")[0]
            from urllib.parse import quote
            prs = await connectors.github_api(token, "GET", f"/repos/{repo}/pulls?state=all&head={quote(owner + ':' + name, safe='')}")
            if prs:
                pr = prs[0]
                status = "pr_open"
                output = json.dumps({"pull_request_url": pr["html_url"], "pull_request_number": pr["number"], "branch": name})
            else:
                status, output = "approved", change["output_json"]
            observed = "pull_request_found" if prs else "no_pull_request"
    except (connectors.ConnectorError, KeyError) as exc:
        raise HTTPException(502, str(exc))
    with transaction() as db:
        db.execute("UPDATE change_sets SET status=?,output_json=?,error=? WHERE id=?",
                   (status, output, None if status != "failed" else "Live value differs from snapshot and proposal", change_id))
        log_event(db, site["workspace_id"], site["id"], user["id"], "change_set.reconciled", "change_set", change_id,
                  {"status": status, "observed": str(observed)[:300]})
    return {"status": status, "observed": observed}


@router.post("/change-sets/{change_id}/rollback")
async def rollback_change_set(change_id: str, user=Depends(session_user)):
    with connect() as db:
        change, site, integration = change_for_user(db, change_id, user["id"], True)
    if change["platform"] != "shopify":
        raise HTTPException(409, "GitHub changes require a reviewed revert PR after merge")
    if change["status"] not in ("applied", "verified"):
        raise HTTPException(409, "Only applied Shopify changes can be restored")
    config, token = json.loads(integration["config_json"]), await integration_token(integration)
    try:
        current = await connectors.shopify_metadata(config["shop_domain"], token, change["resource_id"])
        if current[change["field"]] != change["after_value"]:
            raise connectors.ConnectorError("Live value changed; manual review required")
        current[change["field"]] = change["before_value"]
        await connectors.shopify_set_metadata(config["shop_domain"], token, change["resource_id"],
                                               current["seo_title"], current["seo_description"])
    except connectors.ConnectorError as exc:
        raise HTTPException(409, str(exc))
    with transaction() as db:
        db.execute("UPDATE change_sets SET status='rolled_back' WHERE id=?", (change_id,))
        log_event(db, site["workspace_id"], site["id"], user["id"], "change_set.rolled_back", "change_set", change_id)
    return {"status": "rolled_back"}


class DraftInput(BaseModel):
    site_id: str
    topic: str = Field(min_length=5, max_length=200)
    audience: str = Field(min_length=2, max_length=200)


@router.post("/content/drafts")
async def create_draft(data: DraftInput, user=Depends(session_user)):
    with connect() as db:
        site = site_for_user(db, data.site_id, user["id"], True)
        llm_budget(db, site["workspace_id"])
    run_id = new_id()
    with transaction() as db:
        db.execute("INSERT INTO agent_runs VALUES (?,?,?,?,?,?,?,?,?)",
                   (run_id, site["id"], "content", "running", json.dumps(data.model_dump()), None, None, now(), None))
    try:
        draft, tokens, model = await llm.editorial_draft(data.topic, data.audience, site["label"])
    except llm.LLMUnavailable as exc:
        with transaction() as db:
            db.execute("UPDATE agent_runs SET status='failed',error=?,finished_at=? WHERE id=?", (str(exc), now(), run_id))
        raise HTTPException(503, str(exc))
    ident = new_id()
    with transaction() as db:
        db.execute("INSERT INTO content_drafts VALUES (?,?,?,?,?,?,?,?,?,?)",
                   (ident, site["id"], draft.title, draft.brief, draft.body, "ai_draft", "draft", user["id"], None, now()))
        record_ai(db, site, user["id"], run_id, draft.model_dump(), tokens, model)
    return {"id": ident, "status": "draft", **draft.model_dump()}


@router.get("/sites/{site_id}/content/drafts")
async def list_drafts(site_id: str, user=Depends(session_user)):
    with connect() as db:
        site_for_user(db, site_id, user["id"])
        return many(db, "SELECT * FROM content_drafts WHERE site_id=? ORDER BY created_at DESC", (site_id,))


@router.post("/content/drafts/{draft_id}/approve")
async def approve_draft(draft_id: str, user=Depends(session_user)):
    with transaction() as db:
        draft = one(db, "SELECT * FROM content_drafts WHERE id=?", (draft_id,))
        if not draft:
            raise HTTPException(404, "Draft not found")
        site = site_for_user(db, draft["site_id"], user["id"], True)
        if draft["status"] != "draft":
            raise HTTPException(409, "Draft has already been reviewed")
        db.execute("UPDATE content_drafts SET status='editor_approved',approved_by=? WHERE id=?", (user["id"], draft_id))
        log_event(db, site["workspace_id"], site["id"], user["id"], "content.approved", "content_draft", draft_id)
    return {"status": "editor_approved", "published": False}


@router.get("/sites/{site_id}/keywords")
async def keywords(site_id: str, user=Depends(session_user)):
    with connect() as db:
        site_for_user(db, site_id, user["id"])
        rows = many(db, "SELECT query,SUM(clicks) AS clicks,SUM(impressions) AS impressions,ROUND(SUM(clicks)*1.0/NULLIF(SUM(impressions),0),4) AS ctr,ROUND(AVG(position),1) AS position FROM search_metrics WHERE site_id=? AND query<>'' GROUP BY query ORDER BY impressions DESC LIMIT 100", (site_id,))
    for row in rows:
        row["opportunity"] = "high_impressions_low_ctr" if row["impressions"] >= 100 and (row["ctr"] or 0) < 0.03 else "review"
        query = row["query"].lower()
        row["intent"] = ("transactional" if any(term in query for term in ("buy", "price", "pricing", "cost"))
                         else "informational" if any(query.startswith(term) for term in ("how ", "what ", "why ", "guide "))
                         else "navigational" if "login" in query or "website" in query
                         else "unclassified")
    return rows


@router.get("/sites/{site_id}/ai-search-readiness")
async def ai_search_readiness(site_id: str, user=Depends(session_user)):
    with connect() as db:
        site_for_user(db, site_id, user["id"])
        latest = one(db, "SELECT id FROM crawls WHERE site_id=? AND status='completed' ORDER BY finished_at DESC LIMIT 1", (site_id,))
        if not latest:
            return {"score": None, "checks": [], "claim": "No AI-search visibility was measured"}
        pages = many(db, "SELECT p.*,s.signals_json FROM pages p LEFT JOIN page_snapshots s ON s.page_id=p.id WHERE p.crawl_id=?", (latest["id"],))
    checks = []
    for page in pages[:20]:
        signals = json.loads(page["signals_json"] or "{}")
        checks.append({"url": page["url"], "readable_title": bool(page["title"]),
                       "description": bool(page["description"]), "crawl_allowed": page["status_code"] == 200,
                       "indexable_signal": not signals.get("noindex", False),
                       "substantive_text_signal": signals.get("word_count", 0) >= 150,
                       "structured_data_parses": signals.get("jsonld_errors", 0) == 0})
    passed = sum(sum(bool(v) for k,v in item.items() if k != "url") for item in checks)
    score = round(passed / max(1, len(checks) * 6) * 100)
    return {"score": score, "checks": checks,
            "claim": "Technical readiness heuristic only; no AI-search inclusion or visibility was measured"}


@router.get("/sites/{site_id}/analytics")
async def analytics(site_id: str, user=Depends(session_user)):
    with connect() as db:
        site_for_user(db, site_id, user["id"])
        daily = many(db, "SELECT day,SUM(clicks) AS clicks,SUM(impressions) AS impressions FROM search_metrics WHERE site_id=? GROUP BY day ORDER BY day DESC LIMIT 90", (site_id,))
        history = many(db, "SELECT id,started_at,finished_at,page_count FROM crawls WHERE site_id=? AND status='completed' ORDER BY started_at DESC LIMIT 20", (site_id,))
        changes = many(db, "SELECT 'wordpress' AS platform,status,applied_at,verified_at FROM changes WHERE site_id=? UNION ALL SELECT platform,status,applied_at,verified_at FROM change_sets WHERE site_id=?", (site_id, site_id))
    return {"daily_search_metrics": daily, "crawl_history": history, "change_history": changes,
            "interpretation": "Search traffic is directional and cannot be attributed to a single SEO change without further analysis"}


@router.post("/sites/{site_id}/reports")
async def generate_report(site_id: str, user=Depends(session_user)):
    with transaction() as db:
        site = site_for_user(db, site_id, user["id"], True)
        workspace = one(db, "SELECT name FROM workspaces WHERE id=?", (site["workspace_id"],))
        crawls = many(db, "SELECT started_at,page_count,status FROM crawls WHERE site_id=? ORDER BY started_at DESC LIMIT 5", (site_id,))
        findings = many(db, "SELECT rule,severity,COUNT(*) AS count FROM findings WHERE site_id=? GROUP BY rule,severity ORDER BY count DESC", (site_id,))
        changes = many(db, "SELECT status,COUNT(*) AS count FROM changes WHERE site_id=? GROUP BY status", (site_id,))
        metrics = many(db, "SELECT day,SUM(clicks) AS clicks,SUM(impressions) AS impressions FROM search_metrics WHERE site_id=? GROUP BY day ORDER BY day DESC LIMIT 28", (site_id,))
        report = {"brand": workspace["name"], "site": site["origin"], "generated_at": now(),
                  "crawls": crawls, "findings": findings, "wordpress_changes": changes,
                  "search_metrics": metrics, "caveat": "Search metrics are directional, not proof of causation"}
        ident = new_id()
        db.execute("INSERT INTO reports VALUES (?,?,?,?,?,?,?)",
                   (ident, site["workspace_id"], site_id, f"SEO report: {site['label']}", json.dumps(report), user["id"], now()))
        log_event(db, site["workspace_id"], site_id, user["id"], "report.generated", "report", ident)
    return {"id": ident, "report": report}


@router.get("/workspaces/{workspace_id}/reports")
async def reports(workspace_id: str, user=Depends(session_user)):
    with connect() as db:
        membership(db, workspace_id, user["id"])
        rows = many(db, "SELECT * FROM reports WHERE workspace_id=? ORDER BY created_at DESC LIMIT 50", (workspace_id,))
    return [{**row, "report": json.loads(row.pop("report_json"))} for row in rows]


@router.get("/workspaces/{workspace_id}/billing")
async def billing(workspace_id: str, user=Depends(session_user)):
    with connect() as db:
        membership(db, workspace_id, user["id"])
        usage = many(db, "SELECT kind,SUM(units) AS units FROM usage_ledger WHERE workspace_id=? GROUP BY kind", (workspace_id,))
        site_count = one(db, "SELECT COUNT(*) AS count FROM sites WHERE workspace_id=?", (workspace_id,))["count"]
    return {"plan": "controlled_pilot", "billing_active": False,
            "site_count": site_count, "usage": usage, "daily_ai_token_cap": 50000,
            "note": "No paid subscription or payment method is configured"}


@router.post("/sites/{site_id}/gsc/authorize")
async def gsc_authorize(site_id: str, property_url: str | None = None, user=Depends(session_user)):
    with connect() as db:
        site = site_for_user(db, site_id, user["id"], True)
    if not site["verified_at"]:
        raise HTTPException(409, "Verify the website before connecting Search Console")
    property_url = property_url or site["origin"] + "/"
    if property_url not in (site["origin"] + "/", "sc-domain:" + site["hostname"]):
        raise HTTPException(422, "Property must match the verified website")
    state = new_id()
    try:
        url = gsc.authorization_url(state)
    except gsc.GSCError as exc:
        raise HTTPException(503, str(exc))
    with transaction() as db:
        db.execute("INSERT INTO oauth_states VALUES (?,?,?,?,?)",
                   (digest(state), site_id, user["id"], property_url, now()))
    return {"authorization_url": url}


@router.get("/gsc/callback")
async def gsc_callback(code: str, state: str):
    with transaction() as db:
        record = one(db, "SELECT * FROM oauth_states WHERE state_hash=? AND julianday(created_at)>=julianday('now','-10 minutes')", (digest(state),))
        if not record:
            raise HTTPException(400, "OAuth state expired or invalid")
        db.execute("DELETE FROM oauth_states WHERE state_hash=?", (digest(state),))
    try:
        tokens = await gsc.exchange_code(code)
    except gsc.GSCError as exc:
        raise HTTPException(502, str(exc))
    refresh = tokens.get("refresh_token")
    if not refresh:
        raise HTTPException(502, "Google did not provide an offline refresh token")
    config = json.dumps({"property_url": record["property_url"]})
    ident = new_id()
    with transaction() as db:
        site = one(db, "SELECT * FROM sites WHERE id=?", (record["site_id"],))
        db.execute("INSERT INTO integrations VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(site_id,platform) DO UPDATE SET config_json=excluded.config_json,secret_ciphertext=excluded.secret_ciphertext,status='connected',checked_at=excluded.checked_at",
                   (ident, site["id"], "gsc", config, encrypt(refresh), "connected", now(), now()))
        actual_id = one(db, "SELECT id FROM integrations WHERE site_id=? AND platform='gsc'", (site["id"],))["id"]
        log_event(db, site["workspace_id"], site["id"], record["user_id"], "gsc.connected", "integration", actual_id)
    return RedirectResponse(url="/?gsc=connected", status_code=303)


@router.post("/sites/{site_id}/gsc/sync")
async def gsc_sync(site_id: str, user=Depends(session_user)):
    with connect() as db:
        site = site_for_user(db, site_id, user["id"], True)
        integration = one(db, "SELECT * FROM integrations WHERE site_id=? AND platform='gsc'", (site_id,))
    if not integration:
        raise HTTPException(409, "Connect Search Console first")
    property_url = json.loads(integration["config_json"])["property_url"]
    end = datetime.now(timezone.utc).date() - timedelta(days=3)
    start = end - timedelta(days=27)
    try:
        token = await gsc.refresh_access(decrypt(integration["secret_ciphertext"]))
        rows = await gsc.query_metrics(token, property_url, start.isoformat(), end.isoformat())
    except (gsc.GSCError, KeyError) as exc:
        raise HTTPException(502, str(exc))
    accepted = 0
    with transaction() as db:
        for row in rows[:1000]:
            keys = row.get("keys") or []
            if len(keys) != 3:
                continue
            day, query, page = keys
            if not safe_page_url(page, site["hostname"]):
                continue
            db.execute("INSERT INTO search_metrics VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT(site_id,day,query,page,source) DO UPDATE SET clicks=excluded.clicks,impressions=excluded.impressions,ctr=excluded.ctr,position=excluded.position",
                       (new_id(), site_id, day, query[:500], page[:2000], int(row.get("clicks", 0)),
                        int(row.get("impressions", 0)), float(row.get("ctr", 0)), float(row.get("position", 0)), "gsc"))
            accepted += 1
        log_event(db, site["workspace_id"], site_id, user["id"], "gsc.synced", "integration", integration["id"],
                  {"rows": accepted, "start": start.isoformat(), "end": end.isoformat()})
    return {"rows": accepted, "start": start.isoformat(), "end": end.isoformat()}
