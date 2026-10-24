# Agentic SEO V1 controlled pilot

A runnable SEO automation product codebase based on the supplied V1 PRD. Read `ARCHITECTURE.md` for the precise coverage and release gate.

## Start the API and worker

Python 3.12+ is required. From this directory:

```sh
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
```

Put the generated Fernet key in `.env` as `AGENTIC_ENCRYPTION_KEY`. Keep it stable; changing it makes stored connector credentials unreadable. Load `.env` into the process environment, then run in two terminals:

```sh
set -a
. ./.env
set +a
uvicorn agentic.main:app --host 127.0.0.1 --port 8000
python -m agentic.worker
```

Open `http://127.0.0.1:8000`. Alternatively, run `docker compose up --build` after filling `.env`. The compose file binds the API to local loopback; put a TLS reverse proxy in front before any staging access. Set `AGENTIC_COOKIE_SECURE=true` on HTTPS.

## Platform access

- **WordPress:** Install `wordpress-companion/agentic-seo-companion.php` as a plugin and create an Application Password for a user with permission to edit the selected posts/pages. The companion owns its `_agentic_seo_title` and `_agentic_seo_description` metadata. Test theme and SEO-plugin interactions on staging.
- **Shopify:** Use a development store, its `*.myshopify.com` domain, and a custom app Admin API token with product/page read and write scopes. The store primary domain must match the site origin added in the dashboard. The GraphQL mutation contract needs live verification against that store's API version.
- **GitHub:** Use a disposable repository containing a static HTML page. Prefer a GitHub App installation with repository content-write and pull-request permissions; configure `GITHUB_APP_ID` and `GITHUB_APP_PRIVATE_KEY` as secrets, then enter its installation ID. A scoped token is available as a pilot fallback. The pilot connector edits one explicit `.html` file and opens a PR. It does not infer production deployment from PR creation or merge.
- **AI:** Configure `OPENAI_API_KEY` through a secret store or local ignored `.env`. The model name is `AGENTIC_LLM_MODEL`; no key means generation routes return a clear 503.
- **Search Console:** Configure `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, and an exact `GOOGLE_REDIRECT_URI` ending in `/api/v1/gsc/callback`. The OAuth scope is read-only. Authorize a URL or domain property matching the verified site.

Do not paste production secrets into source code or commit `.env`. The app encrypts connector tokens in its database. For a shared deployment, use a managed secrets service.

## Tests

```sh
python -m unittest discover -s tests -v
node --check agentic/web/app.js
python -m compileall -q agentic
```

The test suite covers tenant isolation, private-DNS blocking, WordPress approval/verification/restore, Shopify approval/restore, GitHub PR versus deployment, AI plan persistence and policy-bounded automatic writes. These are simulated connector tests. Live integration and PHP lint have not run here.

For an operator-run SQLite backup, use `python -m agentic.backup data/agentic.sqlite3 backups/pilot-YYYYMMDD.sqlite3`. To verify a restore, copy that backup to a new database path with the same command and run the application against the restored path. The command refuses to overwrite an existing file and checks SQLite integrity. Store backups off-host with controlled retention.

## Important limits

This is a controlled single-instance pilot implementation. SQLite, in-request WordPress/Shopify writes, a small polling worker, and a basic password login are not the intended commercial V1 infrastructure. Billing is usage display only; no payment is charged. AI-search visibility measurement, PageSpeed, selective browser rendering, approved link/schema edits, OIDC, off-host backup operations, and production monitoring remain open. Workspace export and live-data deletion are implemented; backup retention remains an operator responsibility. See `ARCHITECTURE.md` before treating this as release-ready.
