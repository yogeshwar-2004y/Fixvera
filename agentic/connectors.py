"""Narrow, credential-scoped connector operations. No arbitrary customer commands."""
import base64
import json
import os
import re
import time
from urllib.parse import quote, urlsplit

import aiohttp
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from .security import PublicResolver


class ConnectorError(Exception):
    pass


def client():
    return aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(resolver=PublicResolver(), use_dns_cache=False, limit=3),
        timeout=aiohttp.ClientTimeout(total=20), trust_env=False)


async def shopify_graphql(shop_domain, token, query, variables=None):
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,60}\.myshopify\.com", shop_domain):
        raise ConnectorError("Invalid Shopify shop domain")
    url = f"https://{shop_domain}/admin/api/2026-07/graphql.json"
    async with client() as session:
        try:
            async with session.post(url, headers={"X-Shopify-Access-Token": token},
                                    json={"query": query, "variables": variables or {}}, allow_redirects=False) as response:
                if response.status != 200:
                    raise ConnectorError(f"Shopify returned HTTP {response.status}")
                data = await response.json()
        except (aiohttp.ClientError, OSError, ValueError) as exc:
            raise ConnectorError("Shopify connection failed") from exc
    if data.get("errors"):
        raise ConnectorError("Shopify GraphQL error: " + str(data["errors"])[:250])
    return data.get("data") or {}


async def shopify_health(shop_domain, token, expected_hostname):
    data = await shopify_graphql(shop_domain, token, "query { shop { id name primaryDomain { url } } }")
    shop = data.get("shop") or {}
    host = urlsplit((shop.get("primaryDomain") or {}).get("url", "")).hostname
    if host != expected_hostname:
        raise ConnectorError("Shopify primary domain does not match the connected website")
    return {"shop_id": shop.get("id"), "shop_name": shop.get("name"), "primary_domain": host}


async def shopify_metadata(shop_domain, token, resource_id):
    if not re.fullmatch(r"gid://shopify/(Product|Page)/\d+", resource_id):
        raise ConnectorError("Only Shopify products and pages are supported")
    query = "query($id: ID!) { node(id: $id) { ... on Product { id seo { title description } onlineStoreUrl } ... on Page { id seo { title description } onlineStoreUrl } } }"
    data = await shopify_graphql(shop_domain, token, query, {"id": resource_id})
    item = data.get("node")
    if not item or item.get("id") != resource_id:
        raise ConnectorError("Shopify resource not found or inaccessible")
    return {"seo_title": (item.get("seo") or {}).get("title") or "",
            "seo_description": (item.get("seo") or {}).get("description") or "",
            "url": item.get("onlineStoreUrl")}


async def shopify_set_metadata(shop_domain, token, resource_id, title, description):
    if resource_id.startswith("gid://shopify/Product/"):
        query = "mutation($product: ProductUpdateInput!) { productUpdate(product: $product) { product { id seo { title description } } userErrors { field message } } }"
        key, var = "productUpdate", "product"
    elif resource_id.startswith("gid://shopify/Page/"):
        query = "mutation($id: ID!, $page: PageUpdateInput!) { pageUpdate(id: $id, page: $page) { page { id seo { title description } } userErrors { field message } } }"
        key, var = "pageUpdate", "page"
    else:
        raise ConnectorError("Unsupported Shopify resource")
    payload = {"id": resource_id, "seo": {"title": title, "description": description}}
    variables = {var: payload} if var == "product" else {"id": resource_id, "page": {"seo": payload["seo"]}}
    data = await shopify_graphql(shop_domain, token, query, variables)
    result = data.get(key) or {}
    if result.get("userErrors"):
        raise ConnectorError("Shopify rejected update: " + str(result["userErrors"])[:250])
    if not result.get("product") and not result.get("page"):
        raise ConnectorError("Shopify returned no updated resource")
    return result


async def github_api(token, method, path, payload=None):
    if not path.startswith("/") or ".." in path:
        raise ConnectorError("Invalid GitHub API path")
    async with client() as session:
        try:
            async with session.request(method, "https://api.github.com" + path,
                                       headers={"Authorization": "Bearer " + token,
                                                "Accept": "application/vnd.github+json",
                                                "X-GitHub-Api-Version": "2022-11-28",
                                                "User-Agent": "AgenticSEO-Pilot"},
                                       json=payload, allow_redirects=False) as response:
                body = await response.text()
                if response.status >= 300:
                    raise ConnectorError(f"GitHub returned HTTP {response.status}: {body[:120]}")
                return json.loads(body)
        except (aiohttp.ClientError, OSError, ValueError) as exc:
            raise ConnectorError("GitHub connection failed") from exc


async def github_app_token(installation_id):
    app_id = os.getenv("GITHUB_APP_ID")
    pem = os.getenv("GITHUB_APP_PRIVATE_KEY", "").replace("\\n", "\n")
    if not app_id or not pem or not str(installation_id).isdigit():
        raise ConnectorError("GitHub App ID, private key, and installation ID are required")
    def encoded(value):
        return base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode()).decode().rstrip("=")
    issued = int(time.time())
    signing_input = encoded({"alg": "RS256", "typ": "JWT"}) + "." + encoded({"iat": issued - 60, "exp": issued + 540, "iss": str(app_id)})
    try:
        key = serialization.load_pem_private_key(pem.encode(), password=None)
        signature = key.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
    except (ValueError, TypeError) as exc:
        raise ConnectorError("Invalid GitHub App private key") from exc
    jwt = signing_input + "." + base64.urlsafe_b64encode(signature).decode().rstrip("=")
    data = await github_api(jwt, "POST", f"/app/installations/{installation_id}/access_tokens", {})
    if not data.get("token"):
        raise ConnectorError("GitHub App installation did not provide an access token")
    return data["token"]


def validate_repo(repo):
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}", repo) or ".." in repo:
        raise ConnectorError("Invalid GitHub repository")
    return repo


async def github_health(repo, token):
    record = await github_api(token, "GET", "/repos/" + validate_repo(repo))
    if record.get("full_name", "").lower() != repo.lower():
        raise ConnectorError("GitHub repository mismatch")
    permissions = record.get("permissions") or {}
    if permissions.get("push") is not True:
        raise ConnectorError("GitHub token needs repository write access")
    return {"repository": record["full_name"], "default_branch": record["default_branch"]}


def patch_html_metadata(source, field, before, after):
    if field == "seo_title":
        pattern = re.compile(r"(<title\b[^>]*>)(.*?)(</title>)", re.I | re.S)
        matches = list(pattern.finditer(source))
        if len(matches) != 1 or matches[0].group(2).strip() != before:
            raise ConnectorError("HTML title no longer matches the approved snapshot")
        return source[:matches[0].start(2)] + after + source[matches[0].end(2):]
    if field == "seo_description":
        pattern = re.compile(r"<meta\b[^>]*name=['\"]description['\"][^>]*>", re.I)
        matches = list(pattern.finditer(source))
        if len(matches) != 1:
            raise ConnectorError("Expected exactly one description tag")
        tag = matches[0].group(0)
        attr = re.search(r"content=(['\"])(.*?)\1", tag, re.I | re.S)
        if not attr or attr.group(2) != before:
            raise ConnectorError("Description no longer matches the approved snapshot")
        updated = tag[:attr.start(2)] + after.replace('"', '&quot;').replace("'", '&#39;') + tag[attr.end(2):]
        return source[:matches[0].start()] + updated + source[matches[0].end():]
    raise ConnectorError("Unsupported HTML metadata field")


async def github_file_metadata(repo, token, file_path, ref=None):
    validate_repo(repo)
    if not re.fullmatch(r"[A-Za-z0-9_./-]+\.html", file_path) or file_path.startswith("/") or ".." in file_path:
        raise ConnectorError("Only a specific tracked HTML file is supported")
    suffix = "?ref=" + quote(ref, safe="") if ref else ""
    item = await github_api(token, "GET", f"/repos/{repo}/contents/{quote(file_path, safe='/')}{suffix}")
    if item.get("type") != "file" or item.get("size", 0) > 500_000:
        raise ConnectorError("HTML source file is unavailable or too large")
    source = base64.b64decode(item["content"]).decode("utf-8")
    title_matches = list(re.finditer(r"<title\b[^>]*>(.*?)</title>", source, re.I | re.S))
    desc_matches = list(re.finditer(r"<meta\b[^>]*name=['\"]description['\"][^>]*>", source, re.I))
    title = title_matches[0].group(1).strip() if len(title_matches) == 1 else None
    desc = None
    if len(desc_matches) == 1:
        attr = re.search(r"content=(['\"])(.*?)\1", desc_matches[0].group(0), re.I | re.S)
        desc = attr.group(2) if attr else None
    return {"seo_title": title, "seo_description": desc, "sha": item["sha"]}


async def github_open_pr(repo, token, file_path, field, before, after, change_id):
    validate_repo(repo)
    if not re.fullmatch(r"[A-Za-z0-9_./-]+\.html", file_path) or file_path.startswith("/") or ".." in file_path:
        raise ConnectorError("Only a specific tracked HTML file is supported")
    info = await github_health(repo, token)
    branch = info["default_branch"]
    name = "agentic-seo/" + change_id[:20]
    owner = repo.split("/")[0]
    existing = await github_api(token, "GET", f"/repos/{repo}/pulls?state=all&head={quote(owner + ':' + name, safe='')}")
    if existing:
        pr = existing[0]
        return {"pull_request_url": pr["html_url"], "pull_request_number": pr["number"], "branch": name}
    path = quote(file_path, safe="/")
    item = await github_api(token, "GET", f"/repos/{repo}/contents/{path}?ref={quote(branch, safe='')}")
    if item.get("type") != "file" or item.get("size", 0) > 500_000:
        raise ConnectorError("HTML source file is unavailable or too large")
    original = base64.b64decode(item["content"]).decode("utf-8")
    updated = patch_html_metadata(original, field, before, after)
    try:
        await github_api(token, "GET", f"/repos/{repo}/git/ref/heads/{quote(name, safe='')}")
        branch_item = await github_api(token, "GET", f"/repos/{repo}/contents/{path}?ref={quote(name, safe='')}")
        branch_source = base64.b64decode(branch_item["content"]).decode("utf-8")
        if branch_source == updated:
            needs_write = False
        elif branch_source == original:
            needs_write = True
            item = branch_item
        else:
            raise ConnectorError("Existing SEO branch differs from the approved patch")
    except ConnectorError as exc:
        if "HTTP 404" not in str(exc):
            raise
        ref = await github_api(token, "GET", f"/repos/{repo}/git/ref/heads/{quote(branch, safe='')}")
        await github_api(token, "POST", f"/repos/{repo}/git/refs", {"ref": "refs/heads/" + name, "sha": ref["object"]["sha"]})
        needs_write = True
    if needs_write:
        await github_api(token, "PUT", f"/repos/{repo}/contents/{path}", {
            "message": f"SEO: update {field} for approved change {change_id}",
            "content": base64.b64encode(updated.encode()).decode(),
            "sha": item["sha"], "branch": name})
    pr = await github_api(token, "POST", f"/repos/{repo}/pulls", {
        "title": f"SEO: update {field}",
        "head": name, "base": branch,
        "body": f"Approved Agentic SEO change `{change_id}`. Review and merge through your normal release process."})
    return {"pull_request_url": pr["html_url"], "pull_request_number": pr["number"], "branch": name}
