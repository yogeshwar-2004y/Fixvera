import aiohttp

from .security import PublicResolver, decrypt


class WordPressError(Exception):
    pass


async def request(site, method, path, payload=None, password=None):
    credential = password if password is not None else decrypt(site["wp_secret"])
    connector = aiohttp.TCPConnector(resolver=PublicResolver(), use_dns_cache=False, limit=2)
    async with aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=15), trust_env=False,
                                     auth=aiohttp.BasicAuth(site["wp_user"], credential)) as client:
        try:
            async with client.request(method, site["origin"] + "/wp-json/agentic-seo/v1" + path,
                                      json=payload, allow_redirects=False) as response:
                status = response.status
                body = await response.text()
        except (aiohttp.ClientError, OSError) as exc:
            raise WordPressError(f"WordPress connection failed: {type(exc).__name__}") from exc
    if status >= 300:
        raise WordPressError(f"WordPress companion returned HTTP {status}: {body[:150]}")
    try:
        import json
        return json.loads(body)
    except ValueError as exc:
        raise WordPressError("WordPress companion returned invalid JSON") from exc


async def capabilities(site, password=None):
    return await request(site, "GET", "/capabilities", password=password)


async def resolve(site, url):
    from urllib.parse import quote
    return await request(site, "GET", "/resolve?url=" + quote(url, safe=""))


async def get_metadata(site, post_id):
    return await request(site, "GET", f"/posts/{post_id}/metadata")


async def set_metadata(site, post_id, title, description, expected_revision):
    return await request(site, "PUT", f"/posts/{post_id}/metadata",
                         {"seo_title": title, "seo_description": description,
                          "expected_revision": expected_revision})
