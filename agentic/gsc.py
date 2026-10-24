"""Google Search Console OAuth and bounded Search Analytics reads."""
import os
from urllib.parse import quote, urlencode

import aiohttp

from .connectors import client


class GSCError(Exception):
    pass


def config():
    client_id = os.getenv("GOOGLE_CLIENT_ID")
    client_secret = os.getenv("GOOGLE_CLIENT_SECRET")
    redirect_uri = os.getenv("GOOGLE_REDIRECT_URI")
    if not all((client_id, client_secret, redirect_uri)):
        raise GSCError("Google OAuth credentials and redirect URI are not configured")
    return client_id, client_secret, redirect_uri


def authorization_url(state):
    client_id, _, redirect_uri = config()
    params = {"client_id": client_id, "redirect_uri": redirect_uri,
              "response_type": "code", "scope": "https://www.googleapis.com/auth/webmasters.readonly",
              "access_type": "offline", "prompt": "consent", "state": state}
    return "https://accounts.google.com/o/oauth2/v2/auth?" + urlencode(params)


async def token_request(payload):
    async with client() as session:
        try:
            async with session.post("https://oauth2.googleapis.com/token", data=payload, allow_redirects=False) as response:
                data = await response.json()
                if response.status != 200:
                    raise GSCError("Google OAuth token exchange failed")
                return data
        except (aiohttp.ClientError, OSError, ValueError) as exc:
            raise GSCError("Google OAuth request failed") from exc


async def exchange_code(code):
    client_id, secret, redirect_uri = config()
    return await token_request({"client_id": client_id, "client_secret": secret,
                                "redirect_uri": redirect_uri, "grant_type": "authorization_code", "code": code})


async def refresh_access(refresh_token):
    client_id, secret, _ = config()
    data = await token_request({"client_id": client_id, "client_secret": secret,
                                "grant_type": "refresh_token", "refresh_token": refresh_token})
    return data["access_token"]


async def query_metrics(access_token, property_url, start_date, end_date):
    url = "https://www.googleapis.com/webmasters/v3/sites/" + quote(property_url, safe="") + "/searchAnalytics/query"
    payload = {"startDate": start_date, "endDate": end_date,
               "dimensions": ["date", "query", "page"], "rowLimit": 1000}
    async with client() as session:
        try:
            async with session.post(url, headers={"Authorization": "Bearer " + access_token},
                                    json=payload, allow_redirects=False) as response:
                data = await response.json()
                if response.status != 200:
                    raise GSCError("Search Console query was rejected; check property access")
                return data.get("rows", [])
        except (aiohttp.ClientError, OSError, ValueError) as exc:
            raise GSCError("Search Console request failed") from exc
