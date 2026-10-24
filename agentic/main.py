import json
import os
import sqlite3
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, Field

from . import wordpress as wp
from .crawler import bounded_get, crawl, findings_for_page, safe_client
from .db import connect, init, many, one, transaction
from .security import (digest, encrypt, new_id, normalized_site, now,
                       password_hash, password_valid, safe_page_url,
                       session_expiry, session_user)

app = FastAPI(title="Agentic SEO pilot", version="0.1.0")
WEB = Path(__file__).parent / "web"


@app.on_event("startup")
async def startup():
    init()


@app.get("/api/health")
async def health():
    with connect() as db:
        db.execute("SELECT 1").fetchone()
    return {"status": "ok"}


class Credentials(BaseModel):
    email: str
    password: str


class WorkspaceInput(BaseModel):
    name: str = Field(min_length=2, max_length=80)


class SiteInput(BaseModel):
    workspace_id: str
    origin: str
    label: str = Field(min_length=2, max_length=100)


class WordPressInput(BaseModel):
    username: str = Field(min_length=1)
    application_password: str = Field(min_length=8)


class ModeInput(BaseModel):
    mode: str


class ChangeInput(BaseModel):
    finding_id: str | None = None
    page_url: str
    field: str
    after_value: str = Field(min_length=1, max_length=300)


def log_event(db, workspace_id, site_id, actor_id, action, object_type, object_id, detail=None):
    db.execute("INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?)",
               (new_id(), workspace_id, site_id, actor_id, action, object_type,
                object_id, json.dumps(detail or {}, separators=(",", ":")), now()))


def queue_initial_audit(db, site, actor_id):
    scanned = one(db, "SELECT id FROM crawls WHERE site_id=? LIMIT 1", (site["id"],))
    pending = one(db, "SELECT id FROM crawl_jobs WHERE site_id=? AND status IN ('queued','running') LIMIT 1", (site["id"],))
    if not scanned and not pending:
        ident = new_id()
        db.execute("INSERT INTO crawl_jobs (id,site_id,requested_by,status,created_at) VALUES (?,?,?,?,?)",
                   (ident, site["id"], actor_id, "queued", now()))
        log_event(db, site["workspace_id"], site["id"], actor_id, "crawl.initial_queued", "crawl_job", ident)


def membership(db, workspace_id, user_id, write=False):
    row = one(db, "SELECT role FROM memberships WHERE workspace_id=? AND user_id=?", (workspace_id, user_id))
    if not row or (write and row["role"] not in ("owner", "editor")):
        raise HTTPException(404, "Workspace unavailable")
    return row


def site_for_user(db, site_id, user_id, write=False):
    site = one(db, "SELECT * FROM sites WHERE id=?", (site_id,))
    if not site:
        raise HTTPException(404, "Site not found")
    membership(db, site["workspace_id"], user_id, write)
    return site


def change_for_user(db, change_id, user_id, write=False):
    change = one(db, "SELECT * FROM changes WHERE id=?", (change_id,))
    if not change:
        raise HTTPException(404, "Change not found")
    site = site_for_user(db, change["site_id"], user_id, write)
    return change, site


def exposed_site(site):
    return {**{key: value for key, value in site.items() if key not in ("wp_secret", "verify_token", "wp_user")},
            "wordpress_connected": bool(site["wp_secret"])}


def set_session(response, user_id):
    token, csrf = new_id(), new_id()
    with transaction() as db:
        db.execute("INSERT INTO sessions VALUES (?,?,?,?)", (digest(token), user_id, digest(csrf), session_expiry()))
    secure = os.getenv("AGENTIC_COOKIE_SECURE", "false").lower() == "true"
    response.set_cookie("agentic_session", token, httponly=True, secure=secure, samesite="strict", max_age=604800)
    response.set_cookie("agentic_csrf", csrf, httponly=False, secure=secure, samesite="strict", max_age=604800)


@app.post("/api/register")
async def register(data: Credentials, response: Response):
    email = data.email.strip().lower()
    if "@" not in email or len(email) > 254:
        raise HTTPException(422, "Valid email required")
    hashed = password_hash(data.password)
    user_id, workspace_id = new_id(), new_id()
    try:
        with transaction() as db:
            db.execute("INSERT INTO users VALUES (?,?,?,?)", (user_id, email, hashed, now()))
            db.execute("INSERT INTO workspaces VALUES (?,?,?)", (workspace_id, "My workspace", now()))
            db.execute("INSERT INTO memberships VALUES (?,?,?)", (workspace_id, user_id, "owner"))
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Account already exists")
    set_session(response, user_id)
    return {"user_id": user_id, "workspace_id": workspace_id}


@app.post("/api/login")
async def login(data: Credentials, response: Response):
    email = data.email.strip().lower()
    key = digest(email)
    with connect() as db:
        attempts = one(db, "SELECT COUNT(*) AS total FROM login_attempts WHERE email_hash=? AND julianday(attempted_at)>=julianday('now','-15 minutes')", (key,))["total"]
        if attempts >= 10:
            raise HTTPException(429, "Too many sign-in attempts; try again later")
        user = one(db, "SELECT * FROM users WHERE email=?", (email,))
    if not user or not password_valid(data.password, user["password_hash"]):
        with transaction() as db:
            db.execute("INSERT INTO login_attempts VALUES (?,?,?)", (new_id(), key, now()))
        raise HTTPException(401, "Invalid email or password")
    with transaction() as db:
        db.execute("DELETE FROM login_attempts WHERE email_hash=?", (key,))
    set_session(response, user["id"])
    return {"user_id": user["id"]}


@app.post("/api/logout")
async def logout(request: Request, response: Response, user=Depends(session_user)):
    with transaction() as db:
        db.execute("DELETE FROM sessions WHERE id_hash=?", (digest(request.cookies.get("agentic_session", "")),))
    response.delete_cookie("agentic_session")
    response.delete_cookie("agentic_csrf")
    return {"ok": True}


@app.get("/api/me")
async def me(user=Depends(session_user)):
    with connect() as db:
        workspaces = many(db, "SELECT w.*,m.role FROM workspaces w JOIN memberships m ON m.workspace_id=w.id WHERE m.user_id=? ORDER BY w.created_at", (user["id"],))
    return {"id": user["id"], "email": user["email"], "workspaces": workspaces}


@app.post("/api/workspaces")
async def create_workspace(data: WorkspaceInput, user=Depends(session_user)):
    ident = new_id()
    with transaction() as db:
        db.execute("INSERT INTO workspaces VALUES (?,?,?)", (ident, data.name.strip(), now()))
        db.execute("INSERT INTO memberships VALUES (?,?,?)", (ident, user["id"], "owner"))
    return {"id": ident, "name": data.name.strip()}


@app.get("/api/sites")
async def sites(workspace_id: str, user=Depends(session_user)):
    with connect() as db:
        membership(db, workspace_id, user["id"])
        rows = many(db, "SELECT s.*, (SELECT COUNT(*) FROM findings f WHERE f.site_id=s.id AND f.status='open' AND f.crawl_id=(SELECT c.id FROM crawls c WHERE c.site_id=s.id AND c.status='completed' ORDER BY c.finished_at DESC LIMIT 1)) AS open_findings FROM sites s WHERE s.workspace_id=? ORDER BY s.created_at DESC", (workspace_id,))
        return [exposed_site(s) for s in rows]


@app.post("/api/sites")
async def create_site(data: SiteInput, user=Depends(session_user)):
    origin, hostname = normalized_site(data.origin)
    ident, token = new_id(), "agentic-seo-verification=" + new_id()
    try:
        with transaction() as db:
            membership(db, data.workspace_id, user["id"], True)
            db.execute("INSERT INTO sites (id,workspace_id,origin,hostname,label,verify_token,created_at) VALUES (?,?,?,?,?,?,?)",
                       (ident, data.workspace_id, origin, hostname, data.label.strip(), token, now()))
            log_event(db, data.workspace_id, ident, user["id"], "site.created", "site", ident)
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Site already exists in this workspace")
    return {"id": ident, "origin": origin, "verification_path": "/.well-known/agentic-seo-verification.txt", "verification_token": token}


@app.get("/api/sites/{site_id}")
async def site_detail(site_id: str, user=Depends(session_user)):
    with connect() as db:
        site = site_for_user(db, site_id, user["id"])
        crawls = many(db, "SELECT * FROM crawls WHERE site_id=? ORDER BY started_at DESC LIMIT 10", (site_id,))
        counts = one(db, "SELECT COUNT(*) AS open_findings FROM findings WHERE site_id=? AND status='open' AND crawl_id=(SELECT id FROM crawls WHERE site_id=? AND status='completed' ORDER BY finished_at DESC LIMIT 1)", (site_id, site_id))
        return {**exposed_site(site), "verification_token": site["verify_token"] if not site["verified_at"] else None,
                "crawls": crawls, **counts}


@app.post("/api/sites/{site_id}/verify")
async def verify_site(site_id: str, user=Depends(session_user)):
    with connect() as db:
        site = site_for_user(db, site_id, user["id"], True)
    async with safe_client() as client:
        status, _, body = await bounded_get(client, site["origin"] + "/.well-known/agentic-seo-verification.txt", site["hostname"])
    if status != 200 or site["verify_token"].encode() not in body:
        raise HTTPException(422, "Verification token was not found at the expected URL")
    with transaction() as db:
        db.execute("UPDATE sites SET verified_at=? WHERE id=?", (now(), site_id))
        log_event(db, site["workspace_id"], site_id, user["id"], "site.verified", "site", site_id)
        queue_initial_audit(db, site, user["id"])
    return {"verified": True}


@app.post("/api/sites/{site_id}/wordpress")
async def connect_wordpress(site_id: str, data: WordPressInput, user=Depends(session_user)):
    with connect() as db:
        site = site_for_user(db, site_id, user["id"], True)
    probe = {**site, "wp_user": data.username}
    try:
        capabilities = await wp.capabilities(probe, password=data.application_password)
    except wp.WordPressError as exc:
        raise HTTPException(422, str(exc))
    if capabilities.get("can_edit_posts") is not True or capabilities.get("plugin") != "agentic-seo-companion":
        raise HTTPException(422, "WordPress user lacks companion plugin edit permission")
    with transaction() as db:
        db.execute("UPDATE sites SET wp_user=?,wp_secret=?,verified_at=COALESCE(verified_at,?) WHERE id=?",
                   (data.username, encrypt(data.application_password), now(), site_id))
        log_event(db, site["workspace_id"], site_id, user["id"], "wordpress.connected", "site", site_id)
        queue_initial_audit(db, site, user["id"])
    return {"connected": True, "verified": True}


@app.post("/api/sites/{site_id}/mode")
async def set_mode(site_id: str, data: ModeInput, user=Depends(session_user)):
    if data.mode not in ("observe", "assist", "autopilot"):
        raise HTTPException(422, "Supported modes: Observe, Assist, Autopilot")
    with transaction() as db:
        site = site_for_user(db, site_id, user["id"], True)
        if data.mode == "autopilot":
            policy = one(db, "SELECT * FROM write_policies WHERE site_id=? AND enabled=1", (site_id,))
            if not site["verified_at"] or not policy:
                raise HTTPException(409, "Verify the site and configure an explicit write policy first")
        db.execute("UPDATE sites SET automation_mode=? WHERE id=?", (data.mode, site_id))
        log_event(db, site["workspace_id"], site_id, user["id"], "policy.changed", "site", site_id, {"mode": data.mode})
    return {"mode": data.mode}


@app.post("/api/sites/{site_id}/crawl")
async def run_crawl(site_id: str, user=Depends(session_user)):
    with connect() as db:
        site = site_for_user(db, site_id, user["id"], True)
    crawl_id = new_id()
    with transaction() as db:
        recent = one(db, "SELECT COUNT(*) AS total FROM crawls WHERE site_id=? AND julianday(started_at)>=julianday('now','-1 day')", (site_id,))
        if recent["total"] >= 10:
            raise HTTPException(429, "Daily pilot crawl limit reached")
        active = one(db, "SELECT id FROM crawls WHERE site_id=? AND status='running' AND julianday(started_at)>=julianday('now','-15 minutes')", (site_id,))
        if active:
            raise HTTPException(409, "A crawl is already running")
        db.execute("INSERT INTO crawls (id,site_id,started_at,status) VALUES (?,?,?,?)", (crawl_id, site_id, now(), "running"))
    try:
        pages = await crawl(site["origin"], site["hostname"])
        if not pages:
            raise ValueError("No crawlable pages found")
        with transaction() as db:
            page_ids = {}
            for page in pages:
                page_id = new_id()
                page_ids[page["url"]] = page_id
                db.execute("INSERT INTO pages VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                           (page_id, crawl_id, site_id, page["url"], page["status_code"],
                            page["title"], page["description"], page["canonical"],
                            page["h1_count"], page["wp_post_id"], page["body_hash"]))
                signals = {key: page.get(key) for key in ("noindex", "word_count", "images_without_alt", "jsonld_errors",
                                                          "jsonld_missing_fields", "duplicate_h1", "missing_viewport",
                                                          "oversized_image_dimensions", "sitemap_orphan_candidate",
                                                          "sitemap_status", "depth", "discovery_source", "fetch_error") if key in page}
                db.execute("INSERT INTO page_snapshots VALUES (?,?)", (page_id, json.dumps(signals)))
                for rule, severity, evidence in findings_for_page(page):
                    db.execute("INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,?)",
                               (new_id(), site_id, crawl_id, page_id, rule, severity, evidence, "open", now()))
            for field, rule in (("title", "duplicate_title"), ("description", "duplicate_description")):
                groups = {}
                for page in pages:
                    if page.get(field):
                        groups.setdefault(page[field].strip().lower(), []).append(page)
                for grouped in groups.values():
                    if len(grouped) > 1:
                        for page in grouped:
                            db.execute("INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,?)",
                                       (new_id(), site_id, crawl_id, page_ids[page["url"]], rule, "medium",
                                        f"Same {field} appears on {len(grouped)} crawled pages", "open", now()))
            db.execute("UPDATE crawls SET finished_at=?,status='completed',page_count=? WHERE id=?", (now(), len(pages), crawl_id))
            log_event(db, site["workspace_id"], site_id, user["id"], "crawl.completed", "crawl", crawl_id, {"pages": len(pages)})
        return {"crawl_id": crawl_id, "page_count": len(pages)}
    except Exception as exc:
        with transaction() as db:
            db.execute("UPDATE crawls SET finished_at=?,status='failed',error=? WHERE id=?", (now(), str(exc)[:200], crawl_id))
        raise HTTPException(502, "Crawl failed: " + str(exc)[:160])


@app.get("/api/sites/{site_id}/findings")
async def list_findings(site_id: str, user=Depends(session_user)):
    with connect() as db:
        site_for_user(db, site_id, user["id"])
        latest = one(db, "SELECT id FROM crawls WHERE site_id=? AND status='completed' ORDER BY finished_at DESC LIMIT 1", (site_id,))
        if not latest:
            return []
        return many(db, "SELECT f.*,p.url,p.title,p.description,p.wp_post_id FROM findings f JOIN pages p ON p.id=f.page_id WHERE f.crawl_id=? ORDER BY CASE f.severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END,p.url", (latest["id"],))


@app.get("/api/sites/{site_id}/changes")
async def list_changes(site_id: str, user=Depends(session_user)):
    with connect() as db:
        site_for_user(db, site_id, user["id"])
        return many(db, "SELECT c.*,COALESCE(p.source,'manual') AS source FROM changes c LEFT JOIN change_provenance p ON p.change_id=c.id WHERE c.site_id=? ORDER BY c.created_at DESC", (site_id,))


@app.post("/api/sites/{site_id}/changes")
async def propose_change(site_id: str, data: ChangeInput, user=Depends(session_user)):
    if data.field not in ("seo_title", "seo_description"):
        raise HTTPException(422, "Only title and description are supported in the pilot")
    with connect() as db:
        site = site_for_user(db, site_id, user["id"], True)
        if not site["verified_at"] or not site["wp_secret"]:
            raise HTTPException(409, "Verify and connect WordPress first")
        if data.finding_id:
            finding = one(db, "SELECT f.*,p.url FROM findings f JOIN pages p ON p.id=f.page_id WHERE f.id=? AND f.site_id=?", (data.finding_id, site_id))
            if not finding or finding["url"] != data.page_url:
                raise HTTPException(422, "Finding does not match the page")
    if not safe_page_url(data.page_url, site["hostname"]):
        raise HTTPException(422, "Page must be on the connected website")
    try:
        resolved = await wp.resolve(site, data.page_url)
        post_id = int(resolved["post_id"])
        current = await wp.get_metadata(site, post_id)
    except (wp.WordPressError, KeyError, ValueError) as exc:
        raise HTTPException(422, "Could not resolve WordPress page: " + str(exc))
    before = str(current.get(data.field, ""))
    after = data.after_value.strip()
    if before == after:
        raise HTTPException(422, "Proposed value matches the current value")
    if data.field == "seo_title" and len(after) > 70:
        raise HTTPException(422, "SEO title must be 70 characters or fewer")
    if data.field == "seo_description" and len(after) > 170:
        raise HTTPException(422, "SEO description must be 170 characters or fewer")
    ident = new_id()
    with transaction() as db:
        db.execute("INSERT INTO changes (id,site_id,finding_id,page_url,wp_post_id,field,before_value,after_value,status,proposed_by,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                   (ident, site_id, data.finding_id, data.page_url, post_id, data.field, before, after, "proposed", user["id"], now()))
        log_event(db, site["workspace_id"], site_id, user["id"], "change.proposed", "change", ident, {"field": data.field, "before": before, "after": after})
    return {"id": ident, "status": "proposed", "before_value": before, "after_value": after}


@app.post("/api/changes/{change_id}/approve")
async def approve_change(change_id: str, user=Depends(session_user)):
    with transaction() as db:
        change, site = change_for_user(db, change_id, user["id"], True)
        if change["status"] != "proposed":
            raise HTTPException(409, "Only proposed changes can be approved")
        db.execute("UPDATE changes SET status='approved',approved_by=? WHERE id=?", (user["id"], change_id))
        log_event(db, site["workspace_id"], site["id"], user["id"], "change.approved", "change", change_id,
                  {"field": change["field"], "before": change["before_value"], "after": change["after_value"]})
    return {"status": "approved"}


@app.post("/api/changes/{change_id}/apply")
async def apply_change(change_id: str, user=Depends(session_user)):
    with transaction() as db:
        change, site = change_for_user(db, change_id, user["id"], True)
        policy_approval = one(db, "SELECT id FROM policy_approvals WHERE change_kind='wordpress' AND change_id=?", (change_id,))
        if change["status"] != "approved" or not (change["approved_by"] or (site["automation_mode"] == "autopilot" and policy_approval)):
            raise HTTPException(409, "Exact change approval is required")
        if site["automation_mode"] not in ("assist", "autopilot") or not site["verified_at"] or not site["wp_secret"]:
            raise HTTPException(409, "Enabled write mode and verified WordPress access are required")
        db.execute("UPDATE changes SET status='applying' WHERE id=?", (change_id,))
    try:
        current = await wp.get_metadata(site, change["wp_post_id"])
        if str(current.get(change["field"], "")) != change["before_value"]:
            raise wp.WordPressError("Live value changed since proposal; create a new change")
        payload = {"seo_title": str(current.get("seo_title", "")),
                   "seo_description": str(current.get("seo_description", ""))}
        payload[change["field"]] = change["after_value"]
        await wp.set_metadata(site, change["wp_post_id"], payload["seo_title"], payload["seo_description"], current["revision"])
    except (wp.WordPressError, KeyError) as exc:
        with transaction() as db:
            db.execute("UPDATE changes SET status='failed',error=? WHERE id=?", (str(exc)[:200], change_id))
            log_event(db, site["workspace_id"], site["id"], user["id"], "change.failed", "change", change_id, {"error": str(exc)[:200]})
        raise HTTPException(409, str(exc))
    with transaction() as db:
        db.execute("UPDATE changes SET status='applied',applied_at=?,error=NULL WHERE id=?", (now(), change_id))
        log_event(db, site["workspace_id"], site["id"], user["id"], "change.applied", "change", change_id)
    return {"status": "applied"}


@app.post("/api/changes/{change_id}/verify")
async def verify_change(change_id: str, user=Depends(session_user)):
    with connect() as db:
        change, site = change_for_user(db, change_id, user["id"], True)
    if change["status"] not in ("applied", "verified"):
        raise HTTPException(409, "Apply the change first")
    async with safe_client() as client:
        status, _, body = await bounded_get(client, change["page_url"], site["hostname"])
    from .crawler import extract
    parsed = extract(change["page_url"], body)
    observed = parsed["title"] if change["field"] == "seo_title" else parsed["description"]
    verified = status == 200 and observed == change["after_value"]
    with transaction() as db:
        if verified:
            db.execute("UPDATE changes SET status='verified',verified_at=? WHERE id=?", (now(), change_id))
        log_event(db, site["workspace_id"], site["id"], user["id"], "change.verification", "change", change_id,
                  {"verified": verified, "observed": observed[:300], "http_status": status})
    return {"verified": verified, "observed": observed, "http_status": status}


@app.post("/api/changes/{change_id}/reconcile")
async def reconcile_change(change_id: str, user=Depends(session_user)):
    with connect() as db:
        change, site = change_for_user(db, change_id, user["id"], True)
    if change["status"] not in ("applying", "failed"):
        raise HTTPException(409, "Only uncertain applications can be reconciled")
    try:
        current = await wp.get_metadata(site, change["wp_post_id"])
    except wp.WordPressError as exc:
        raise HTTPException(502, str(exc))
    observed = str(current.get(change["field"], ""))
    if observed == change["after_value"]:
        status = "applied"
    elif observed == change["before_value"]:
        status = "approved"
    else:
        status = "failed"
    with transaction() as db:
        db.execute("UPDATE changes SET status=?,error=? WHERE id=?", (status, None if status != "failed" else "Live value differs from both snapshot and proposal", change_id))
        log_event(db, site["workspace_id"], site["id"], user["id"], "change.reconciled", "change", change_id,
                  {"status": status, "observed": observed[:300]})
    return {"status": status, "observed": observed}


@app.post("/api/changes/{change_id}/rollback")
async def rollback_change(change_id: str, user=Depends(session_user)):
    with transaction() as db:
        change, site = change_for_user(db, change_id, user["id"], True)
        if change["status"] not in ("applied", "verified"):
            raise HTTPException(409, "Only applied changes can be rolled back")
        db.execute("UPDATE changes SET status='rolling_back' WHERE id=?", (change_id,))
    try:
        current = await wp.get_metadata(site, change["wp_post_id"])
        if str(current.get(change["field"], "")) != change["after_value"]:
            raise wp.WordPressError("Live value changed since apply; manual review required")
        payload = {"seo_title": str(current.get("seo_title", "")), "seo_description": str(current.get("seo_description", ""))}
        payload[change["field"]] = change["before_value"]
        await wp.set_metadata(site, change["wp_post_id"], payload["seo_title"], payload["seo_description"], current["revision"])
    except (wp.WordPressError, KeyError) as exc:
        with transaction() as db:
            db.execute("UPDATE changes SET status='rollback_failed',error=? WHERE id=?", (str(exc)[:200], change_id))
            log_event(db, site["workspace_id"], site["id"], user["id"], "change.rollback_failed", "change", change_id,
                      {"error": str(exc)[:200]})
        raise HTTPException(409, str(exc))
    with transaction() as db:
        db.execute("UPDATE changes SET status='rolled_back',error=NULL WHERE id=?", (change_id,))
        log_event(db, site["workspace_id"], site["id"], user["id"], "change.rolled_back", "change", change_id)
    return {"status": "rolled_back"}


@app.get("/api/events")
async def events(workspace_id: str, user=Depends(session_user)):
    with connect() as db:
        membership(db, workspace_id, user["id"])
        return many(db, "SELECT id,site_id,actor_id,action,object_type,object_id,detail,created_at FROM events WHERE workspace_id=? ORDER BY created_at DESC LIMIT 100", (workspace_id,))


@app.get("/")
async def index():
    return Response((WEB / "index.html").read_bytes(), media_type="text/html")


@app.get("/app.css")
async def css():
    return Response((WEB / "app.css").read_bytes(), media_type="text/css")


@app.get("/app.js")
async def js():
    return Response((WEB / "app.js").read_bytes(), media_type="text/javascript")


from .v1 import router as v1_router  # Import after shared authorization helpers are defined.
app.include_router(v1_router)
