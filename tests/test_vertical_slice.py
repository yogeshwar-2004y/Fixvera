import hashlib
import os
import socket
import tempfile
import unittest
from unittest.mock import patch

import httpx
from cryptography.fernet import Fernet

from agentic import db, main
from agentic.crawler import extract, findings_for_page
from agentic.security import PublicResolver, safe_page_url


class VerticalSliceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        db.DB_PATH = __import__('pathlib').Path(self.tmp.name) / 'test.sqlite3'
        os.environ['AGENTIC_ENCRYPTION_KEY'] = Fernet.generate_key().decode()
        db.init()
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=main.app), base_url='http://testserver')
        self.meta = {'seo_title': '', 'seo_description': ''}

    async def asyncTearDown(self):
        await self.client.aclose()
        self.tmp.cleanup()

    def headers(self):
        return {'x-csrf-token': self.client.cookies.get('agentic_csrf', '')}

    async def post(self, path, data=None):
        return await self.client.post('/api'+path, json=data or {}, headers=self.headers())

    def revision(self):
        return hashlib.sha256((self.meta['seo_title']+'\0'+self.meta['seo_description']).encode()).hexdigest()

    async def test_approved_wordpress_change_verifies_and_rolls_back(self):
        registered = await self.post('/register', {'email':'owner@example.com','password':'very-long-password-123'})
        self.assertEqual(registered.status_code, 200)
        workspace = registered.json()['workspace_id']
        site = (await self.post('/sites', {'workspace_id':workspace,'origin':'https://example.com','label':'Example'})).json()['id']

        async def capabilities(*args, **kwargs):
            return {'plugin':'agentic-seo-companion','can_edit_posts':True}
        async def fake_crawl(*args, **kwargs):
            return [{'url':'https://example.com/','status_code':200,'body_hash':'hash','title':'Example',
                     'description':'','canonical':'https://example.com/','h1_count':1,'links':[],'wp_post_id':42}]
        async def resolve(*args): return {'post_id':42}
        async def get_meta(*args): return {**self.meta,'revision':self.revision()}
        async def set_meta(site, post_id, title, description, expected_revision):
            self.assertEqual(expected_revision,self.revision())
            self.meta.update(seo_title=title,seo_description=description)
            return {**self.meta,'revision':self.revision()}
        async def live_page(*args):
            body=f'<html><head><title>Example</title><meta name="description" content="{self.meta["seo_description"]}"></head></html>'
            return 200,'text/html',body.encode()
        with patch.object(main.wp,'capabilities',capabilities),patch.object(main,'crawl',fake_crawl),\
             patch.object(main.wp,'resolve',resolve),patch.object(main.wp,'get_metadata',get_meta),\
             patch.object(main.wp,'set_metadata',set_meta),patch.object(main,'bounded_get',live_page):
            self.assertEqual((await self.post(f'/sites/{site}/wordpress',{'username':'editor','application_password':'app-password-123'})).status_code,200)
            self.assertEqual((await self.post(f'/sites/{site}/mode',{'mode':'assist'})).status_code,200)
            self.assertEqual((await self.post(f'/sites/{site}/crawl')).json()['page_count'],1)
            findings=(await self.client.get(f'/api/sites/{site}/findings')).json()
            finding=next(f for f in findings if f['rule']=='missing_description')
            proposed=await self.post(f'/sites/{site}/changes',{'finding_id':finding['id'],'page_url':'https://example.com/',
                                                               'field':'seo_description','after_value':'A clear page description.'})
            self.assertEqual(proposed.status_code,200,proposed.text)
            change=proposed.json()['id']
            self.assertEqual((await self.post(f'/changes/{change}/apply')).status_code,409)
            self.assertEqual((await self.post(f'/changes/{change}/approve')).status_code,200)
            self.assertEqual((await self.post(f'/changes/{change}/apply')).status_code,200)
            self.assertEqual(self.meta['seo_description'],'A clear page description.')
            with db.transaction() as connection:
                connection.execute("UPDATE changes SET status='failed' WHERE id=?",(change,))
            self.assertEqual((await self.post(f'/changes/{change}/reconcile')).json()['status'],'applied')
            self.assertTrue((await self.post(f'/changes/{change}/verify')).json()['verified'])
            self.assertEqual((await self.post(f'/changes/{change}/rollback')).status_code,200)
            self.assertEqual(self.meta['seo_description'],'')
            actions=(await self.client.get('/api/events?workspace_id='+workspace)).json()
            self.assertIn('change.rolled_back',[item['action'] for item in actions])

    async def test_workspace_isolation(self):
        first=await self.post('/register',{'email':'one@example.com','password':'very-long-password-123'})
        wid=first.json()['workspace_id']
        site=(await self.post('/sites',{'workspace_id':wid,'origin':'https://example.com','label':'Example'})).json()['id']
        await self.client.aclose()
        self.client=httpx.AsyncClient(transport=httpx.ASGITransport(app=main.app),base_url='http://testserver')
        await self.post('/register',{'email':'two@example.com','password':'very-long-password-456'})
        self.assertEqual((await self.client.get(f'/api/sites/{site}')).status_code,404)
        self.assertEqual((await self.client.get(f'/api/sites?workspace_id={wid}')).status_code,404)

    async def test_crawler_blocks_private_dns_and_cross_site_links(self):
        class Loop:
            async def getaddrinfo(self, *args, **kwargs):
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 443))]
        with patch('agentic.security.asyncio.get_running_loop', return_value=Loop()):
            with self.assertRaises(OSError):
                await PublicResolver().resolve('example.com',443)
        self.assertIsNone(safe_page_url('https://other.example/private','example.com'))

    async def test_audit_records_indexability_schema_and_mobile_signals(self):
        body=b'''<html><head><title>Example</title><meta name="robots" content="noindex">
        <script type="application/ld+json">{bad json}</script></head><body><h1>Hello</h1><img src="x.jpg"></body></html>'''
        page={'url':'https://example.com/','status_code':200,**extract('https://example.com/',body)}
        rules={item[0] for item in findings_for_page(page)}
        self.assertTrue({'noindex','invalid_jsonld','images_missing_alt','missing_viewport'}.issubset(rules))


if __name__=='__main__':
    unittest.main()
