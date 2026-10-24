"""Small pilot worker. Run as a separate process; replace with a managed queue at scale."""
import asyncio
import os
from datetime import datetime, timedelta, timezone

from .db import connect, init, many, one, transaction
from .main import ChangeInput, apply_change, log_event, propose_change, run_crawl
from .v1 import PlanInput, generate_plan, policy_allows
from .security import new_id, now


def enqueue_due_schedules():
    with transaction() as db:
        due = many(db, "SELECT p.*,s.workspace_id FROM automation_policies p JOIN sites s ON s.id=p.site_id WHERE p.enabled=1 AND p.next_run_at<=?", (now(),))
        for policy in due:
            already = one(db, "SELECT id FROM crawl_jobs WHERE site_id=? AND status IN ('queued','running')", (policy["site_id"],))
            owner = one(db, "SELECT user_id FROM memberships WHERE workspace_id=? AND role='owner' LIMIT 1", (policy["workspace_id"],))
            if not already and owner:
                ident = new_id()
                db.execute("INSERT INTO crawl_jobs (id,site_id,requested_by,status,created_at) VALUES (?,?,?,?,?)",
                           (ident, policy["site_id"], owner["user_id"], "queued", now()))
                log_event(db, policy["workspace_id"], policy["site_id"], owner["user_id"], "crawl.scheduled", "crawl_job", ident)
            next_run = (datetime.now(timezone.utc) + timedelta(hours=policy["interval_hours"])).isoformat()
            db.execute("UPDATE automation_policies SET last_run_at=?,next_run_at=? WHERE site_id=?", (now(), next_run, policy["site_id"]))


async def process_one():
    with transaction() as db:
        job = one(db, "SELECT * FROM crawl_jobs WHERE status='queued' ORDER BY created_at LIMIT 1")
        if not job:
            return False
        db.execute("UPDATE crawl_jobs SET status='running',attempt=attempt+1,started_at=? WHERE id=?",
                   (now(), job["id"]))
    try:
        result = await run_crawl(job["site_id"], user={"id": job["requested_by"]})
    except Exception as exc:
        status = "queued" if job["attempt"] < 2 else "failed"
        with transaction() as db:
            db.execute("UPDATE crawl_jobs SET status=?,error=?,finished_at=? WHERE id=?",
                       (status, str(exc)[:200], now(), job["id"]))
        return True
    with transaction() as db:
        db.execute("UPDATE crawl_jobs SET status='completed',finished_at=?,error=NULL WHERE id=?", (now(), job["id"]))
    if os.getenv("OPENAI_API_KEY"):
        with connect() as db:
            candidates = many(db, "SELECT f.id,f.rule,p.url FROM findings f JOIN pages p ON p.id=f.page_id WHERE f.crawl_id=? AND f.rule IN ('missing_title','long_title','missing_description') ORDER BY CASE f.severity WHEN 'high' THEN 0 ELSE 1 END LIMIT 3", (result["crawl_id"],))
        for finding in candidates:
            try:
                plan = await generate_plan(job["site_id"], PlanInput(finding_id=finding["id"]), user={"id": job["requested_by"]})
                with connect() as db:
                    site = one(db, "SELECT * FROM sites WHERE id=?", (job["site_id"],))
                    existing = one(db, "SELECT id FROM changes WHERE finding_id=? LIMIT 1", (finding["id"],))
                if site["wp_secret"] and not existing:
                    field = "seo_title" if finding["rule"] in ("missing_title", "long_title") else "seo_description"
                    value = plan["advice"]["title"] if field == "seo_title" else plan["advice"]["description"]
                    change = await propose_change(job["site_id"], ChangeInput(
                        finding_id=finding["id"], page_url=finding["url"], field=field,
                        after_value=value), user={"id": job["requested_by"]})
                    with transaction() as db:
                        db.execute("INSERT INTO change_provenance VALUES (?,?,?)", (change["id"], "ai_draft", plan["id"]))
                        log_event(db, site["workspace_id"], site["id"], job["requested_by"],
                                  "change.ai_prepared", "change", change["id"], {"plan_id": plan["id"]})
            except Exception:
                # The agent run records provider failure; an audit remains valid without an AI draft.
                pass
    return True


async def process_automatic_change():
    selected = None
    with transaction() as db:
        for change in many(db, "SELECT c.* FROM changes c JOIN sites s ON s.id=c.site_id WHERE c.status='proposed' AND s.automation_mode='autopilot' ORDER BY c.created_at LIMIT 20"):
            site = one(db, "SELECT * FROM sites WHERE id=?", (change["site_id"],))
            policy = policy_allows(db, site, change["field"])
            if policy and site["wp_secret"]:
                db.execute("UPDATE changes SET status='approved' WHERE id=?", (change["id"],))
                db.execute("INSERT INTO policy_approvals VALUES (?,?,?,?,?,?)",
                           (new_id(), site["id"], "wordpress", change["id"], policy["updated_at"], now()))
                log_event(db, site["workspace_id"], site["id"], policy["updated_by"], "change.policy_approved", "change", change["id"],
                          {"field": change["field"], "before": change["before_value"], "after": change["after_value"]})
                selected = ("wordpress", change["id"], policy["updated_by"])
                break
    if not selected:
        return False
    try:
        await apply_change(selected[1], user={"id": selected[2]})
    except Exception:
        # The write route records a failed state. Reconciliation or a new proposal is required.
        pass
    return True


async def main():
    init()
    while True:
        enqueue_due_schedules()
        processed = await process_one()
        processed = await process_automatic_change() or processed
        await asyncio.sleep(2 if processed else 30)


if __name__ == "__main__":
    asyncio.run(main())
