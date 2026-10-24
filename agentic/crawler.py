import hashlib
import json
import re
from collections import deque
from urllib.parse import urljoin
from urllib.robotparser import RobotFileParser

import aiohttp
from lxml import html
from lxml import etree

from .security import PublicResolver, safe_page_url

USER_AGENT = "AgenticSEO-Pilot/0.1 (+site-owner-initiated audit)"
MAX_PAGES = 20
MAX_BYTES = 1_000_000


class CrawlError(Exception):
    pass


async def bounded_get(client, url, hostname):
    async with client.get(url, headers={"User-Agent": USER_AGENT, "Accept": "text/html, text/plain;q=0.5"}, allow_redirects=False) as response:
        if 300 <= response.status < 400:
            raise CrawlError("Redirects are not followed during the pilot crawl")
        chunks, size = [], 0
        async for chunk in response.content.iter_chunked(65536):
            size += len(chunk)
            if size > MAX_BYTES:
                raise CrawlError("Page exceeds the 1 MB crawl limit")
            chunks.append(chunk)
        return response.status, response.headers.get("content-type", ""), b"".join(chunks)


def safe_client():
    return aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(resolver=PublicResolver(), use_dns_cache=False, limit=2),
        timeout=aiohttp.ClientTimeout(total=12), trust_env=False)


def extract(page_url, raw):
    try:
        root = html.fromstring(raw, base_url=page_url)
    except (ValueError, TypeError):
        return {"title": "", "description": "", "canonical": "", "h1_count": 0, "links": [], "wp_post_id": None,
                "noindex": False, "word_count": 0, "images_without_alt": 0, "jsonld_errors": 0, "duplicate_h1": False,
                "missing_viewport": False, "oversized_image_dimensions": 0, "jsonld_missing_fields": 0}
    def first(xpath):
        values = root.xpath(xpath)
        return str(values[0]).strip() if values else ""
    title = first("//title/text()")
    description = first("//meta[translate(@name,'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz')='description']/@content")
    canonical = first("//link[translate(@rel,'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz')='canonical']/@href")
    links = [urljoin(page_url, value) for value in root.xpath("//a[@href]/@href")[:250]]
    classes = " ".join(root.xpath("//body/@class"))
    post_match = re.search(r"(?:postid|page-id|post-id)-(\d+)", classes)
    robots = " ".join(root.xpath("//meta[translate(@name,'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz')='robots']/@content")).lower()
    headings = [" ".join(value.split()).lower() for value in root.xpath("//h1/text()")]
    visible = " ".join(root.xpath("//body//text()[not(ancestor::script) and not(ancestor::style)]"))
    jsonld_errors = 0
    jsonld_missing_fields = 0
    for script in root.xpath("//script[@type='application/ld+json']/text()")[:20]:
        try:
            payload = json.loads(script)
            objects = payload if isinstance(payload, list) else [payload]
            for item in objects:
                if isinstance(item, dict) and not item.get("@graph") and (not item.get("@context") or not item.get("@type")):
                    jsonld_missing_fields += 1
        except ValueError:
            jsonld_errors += 1
    oversized = 0
    for image in root.xpath("//img[@width or @height]")[:200]:
        try:
            if max(int(image.get("width", 0)), int(image.get("height", 0))) > 2000:
                oversized += 1
        except ValueError:
            pass
    return {"title": title[:500], "description": description[:1000],
            "canonical": canonical[:2000], "h1_count": len(root.xpath("//h1")),
            "links": links, "wp_post_id": int(post_match.group(1)) if post_match else None,
            "noindex": "noindex" in robots, "word_count": len(visible.split()),
            "images_without_alt": len(root.xpath("//img[not(@alt) or normalize-space(@alt)='']")),
            "jsonld_errors": jsonld_errors,
            "jsonld_missing_fields": jsonld_missing_fields,
            "missing_viewport": not bool(root.xpath("//meta[translate(@name,'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz')='viewport']")),
            "oversized_image_dimensions": oversized,
            "duplicate_h1": len(headings) > len(set(headings))}


def findings_for_page(page):
    if page["status_code"] == -2:
        return [("robots_blocked", "low", "robots.txt disallows this URL for the pilot crawler")]
    if page["status_code"] == 0:
        return [("fetch_failed", "high", page.get("fetch_error", "Fetch failed"))]
    if page["status_code"] >= 400:
        return [("http_error", "high", f"HTTP {page['status_code']}")]
    found = []
    if not page["title"]:
        found.append(("missing_title", "high", "HTML title element is empty or absent"))
    elif len(page["title"]) > 65:
        found.append(("long_title", "low", f"Title has {len(page['title'])} characters"))
    if not page["description"]:
        found.append(("missing_description", "medium", "Meta description is empty or absent"))
    if not page["canonical"]:
        found.append(("missing_canonical", "medium", "Canonical link is absent"))
    elif page["canonical"].rstrip("/") != page["url"].rstrip("/"):
        found.append(("canonical_elsewhere", "low", "Canonical points to " + page["canonical"][:150]))
    if page.get("noindex"):
        found.append(("noindex", "medium", "Page declares noindex; confirm this is intentional"))
    if page["h1_count"] == 0:
        found.append(("missing_h1", "low", "No H1 heading found"))
    elif page["h1_count"] > 1:
        found.append(("multiple_h1", "low", f"Found {page['h1_count']} H1 headings"))
    if page.get("duplicate_h1"):
        found.append(("duplicate_h1", "low", "Repeated H1 text on the same page"))
    if page.get("images_without_alt", 0):
        found.append(("images_missing_alt", "low", f"{page['images_without_alt']} image(s) have empty or missing alt text"))
    if page.get("jsonld_errors", 0):
        found.append(("invalid_jsonld", "medium", f"{page['jsonld_errors']} JSON-LD block(s) do not parse"))
    if page.get("jsonld_missing_fields", 0):
        found.append(("jsonld_missing_fields", "low", f"{page['jsonld_missing_fields']} JSON-LD object(s) lack @context or @type"))
    if page.get("missing_viewport"):
        found.append(("missing_viewport", "low", "Viewport meta tag is absent; mobile rendering needs manual review"))
    if page.get("oversized_image_dimensions", 0):
        found.append(("large_image_dimensions", "low", f"{page['oversized_image_dimensions']} image(s) declare dimensions over 2000px; file size was not measured"))
    if page.get("sitemap_orphan_candidate"):
        found.append(("orphan_candidate", "low", "Sitemap URL has no incoming links among crawled pages; inventory is incomplete"))
    if page.get("sitemap_status") == "missing":
        found.append(("sitemap_missing", "low", "sitemap.xml was not available at the expected path"))
    if page.get("sitemap_status") == "invalid":
        found.append(("sitemap_invalid", "medium", "sitemap.xml could not be parsed as a URL sitemap"))
    if 0 < page.get("word_count", 0) < 150:
        found.append(("thin_content_signal", "low", f"Only {page['word_count']} visible words; manual review needed"))
    if page.get("depth", 0) > 3:
        found.append(("deep_navigation", "low", f"Reached at link depth {page['depth']}"))
    return found


async def crawl(origin, hostname, max_pages=MAX_PAGES, client=None):
    owned_client = client is None
    if owned_client:
        client = safe_client()
    try:
        robots = RobotFileParser()
        robots.set_url(origin + "/robots.txt")
        try:
            status, _, body = await bounded_get(client, origin + "/robots.txt", hostname)
            robots.parse(body.decode("utf-8", "replace").splitlines() if status == 200 else (["User-agent: *", "Disallow: /"] if status in (401, 403) else []))
        except (aiohttp.ClientError, CrawlError, OSError):
            robots.parse(["User-agent: *", "Disallow: /"])
        queue = deque([(origin + "/", 0, "homepage")])
        sitemap_status = "missing"
        try:
            status, _, sitemap = await bounded_get(client, origin + "/sitemap.xml", hostname)
            if status == 200:
                parser = etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=False)
                tree = etree.fromstring(sitemap, parser)
                sitemap_status = "valid"
                for location in tree.xpath("//*[local-name()='url']/*[local-name()='loc']/text()")[:80]:
                    safe = safe_page_url(location.strip(), hostname)
                    if safe and safe != origin + "/":
                        queue.append((safe, 0, "sitemap"))
        except etree.XMLSyntaxError:
            sitemap_status = "invalid"
        except (aiohttp.ClientError, CrawlError, OSError):
            sitemap_status = "unavailable"
        seen, pages = set(), []
        while queue and len(pages) < max_pages:
            url, depth, source = queue.popleft()
            if url in seen:
                continue
            if not robots.can_fetch(USER_AGENT, url):
                seen.add(url)
                pages.append({"url": url, "status_code": -2, "body_hash": "", "title": "", "description": "",
                              "canonical": "", "h1_count": 0, "links": [], "wp_post_id": None,
                              "depth": depth, "discovery_source": source})
                continue
            seen.add(url)
            try:
                status, content_type, body = await bounded_get(client, url, hostname)
                if "text/html" not in content_type and status < 400:
                    continue
                parsed = extract(url, body) if status < 400 else extract(url, b"")
                page = {"url": url, "status_code": status, "body_hash": hashlib.sha256(body).hexdigest(),
                        "depth": depth, "discovery_source": source, **parsed}
                pages.append(page)
                for link in parsed["links"]:
                    safe = safe_page_url(link, hostname)
                    if safe and safe not in seen and all(item[0] != safe for item in queue) and len(queue) < 100:
                        queue.append((safe, depth + 1, "link"))
            except (aiohttp.ClientError, CrawlError, OSError) as exc:
                pages.append({"url": url, "status_code": 0, "body_hash": "", "title": "", "description": "",
                              "canonical": "", "h1_count": 0, "links": [], "wp_post_id": None,
                              "depth": depth, "discovery_source": source, "fetch_error": str(exc)[:200]})
        incoming = {link for page in pages for link in page.get("links", [])}
        for page in pages:
            page["sitemap_orphan_candidate"] = page.get("discovery_source") == "sitemap" and page["url"] not in incoming
        if pages:
            pages[0]["sitemap_status"] = sitemap_status
        return pages
    finally:
        if owned_client:
            await client.aclose()
