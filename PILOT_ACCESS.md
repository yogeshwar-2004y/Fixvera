# Live pilot validation setup

Provide nonsecret staging identifiers to the development session: the WordPress HTTPS URL, Shopify `*.myshopify.com` domain and public primary domain, GitHub `owner/repository`, and Search Console property URL. Do not paste application passwords, Admin API tokens, OAuth client secrets, or private keys in chat.

## Runtime secrets

Configure these in the target runtime's secret store or an ignored local `.env`:

| Name | Purpose |
| --- | --- |
| `AGENTIC_ENCRYPTION_KEY` | Stable Fernet key for stored connector credentials |
| `AGENTIC_PUBLIC_ORIGIN` | Exact HTTPS origin used by the dashboard and CSRF check |
| `AGENTIC_COOKIE_SECURE=true` | HTTPS-only session cookies |
| `OPENAI_API_KEY` | Managed LLM for metadata plans, copilot and content drafts |
| `AGENTIC_LLM_MODEL` | Approved model ID; defaults to `gpt-4o-mini` |
| `GITHUB_APP_ID`, `GITHUB_APP_PRIVATE_KEY` | GitHub App installation authentication; the key can be PEM text with escaped newlines |
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_REDIRECT_URI` | Read-only Search Console OAuth |

The WordPress Application Password and Shopify Admin token are entered through the signed-in dashboard and stored encrypted. The GitHub App installation ID is entered there after installing the App on a disposable test repository. A scoped repository token can be used as a pilot fallback.

## Network access

The current managed development environment's outbound policy is enforced and allows package sources, not these vendor or staging destinations. Live tests need outbound HTTPS access to the exact WordPress and Shopify staging hosts, their public site domains, `api.github.com`, `api.openai.com`, `accounts.google.com`, `oauth2.googleapis.com`, and `www.googleapis.com`. The future application host also needs those destinations. Keep TLS verification enabled.

## Live acceptance sequence

1. Install the WordPress companion plugin on staging; connect a user with post edit permission; find a metadata issue; apply and verify a title/description; restore it. Check for conflicts with the active SEO plugin and page cache.
2. Install the Shopify App or create a development-store Admin token with product/page read-write scopes; confirm the GraphQL mutation contract; edit a disposable product/page; verify the public page and restore it.
3. Install the GitHub App with Contents read/write and Pull requests read/write on a disposable static HTML repository. Create a PR, confirm it is unverified before merge, deploy the merge, then confirm live verification.
4. Exercise a prompt-injection fixture, cross-workspace access checks, Observe/Assist/Autopilot boundaries, webhook signature rejection, and interrupted-write reconciliation.
5. Invite a second user into a client workspace, verify viewer/editor permissions, generate a report, and review export/deletion behavior.

A controlled production pilot remains gated on those real tests, a backup and restore drill, monitoring, and security review. Simulation tests establish code behavior only.
