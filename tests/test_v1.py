import os
import hashlib
import hmac
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx
from cryptography.fernet import Fernet

from agentic import db, main, llm, worker
from agentic.backup import copy_verified
from agentic.security import encrypt


class V1Tests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        db.DB_PATH = Path(self.tmp.name) / 'test.sqlite3'
        os.environ['AGENTIC_ENCRYPTION_KEY'] = Fernet.generate_key().decode()
        db.init()
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=main.app), base_url='http://testserver')
        reg = await self.post('/register',{'email':'owner@example.com','password':'a-good-long-password-123'})
        self.workspace = reg.json()['workspace_id']
        self.site = (await self.post('/sites',{'workspace_id':self.workspace,'origin':'https://example.com','label':'Example'})).json()['id']
        with db.transaction() as conn:
            conn.execute('UPDATE sites SET verified_at=? WHERE id=?',('2026-10-24T00:00:00+00:00',self.site))
        await self.post(f'/sites/{self.site}/mode',{'mode':'assist'})

    async def asyncTearDown(self):
        await self.client.aclose()
        self.tmp.cleanup()

    def headers(self):
        return {'x-csrf-token':self.client.cookies.get('agentic_csrf','')}

    async def post(self,path,data=None):
        return await self.client.post('/api'+path,json=data or {},headers=self.headers())

    async def test_shopify_change_requires_approval_and_can_restore(self):
        values={'seo_title':'Old title','seo_description':'Old description'}
        async def health(*args): return {'shop_id':'gid://shopify/Shop/1','primary_domain':'example.com'}
        async def metadata(*args): return {**values,'url':'https://example.com/products/widget'}
        async def update(shop,token,rid,title,description):
            values.update(seo_title=title,seo_description=description)
            return {'product':{'id':rid,'seo':values.copy()}}
        async def live(*args):
            return 200,'text/html',f'<html><head><title>{values["seo_title"]}</title></head></html>'.encode()
        with patch('agentic.connectors.shopify_health',health),\
             patch('agentic.connectors.shopify_metadata',metadata),\
             patch('agentic.connectors.shopify_set_metadata',update),\
             patch('agentic.v1.bounded_get',live):
            connected=await self.post('/v1/integrations',{'site_id':self.site,'platform':'shopify','credential':'shpat_test_123456','shop_domain':'store.myshopify.com'})
            self.assertEqual(connected.status_code,200,connected.text)
            integrations=(await self.client.get(f'/api/v1/sites/{self.site}/integrations')).json()
            iid=integrations[0]['id']
            proposed=await self.post('/v1/change-sets',{'integration_id':iid,'resource_id':'gid://shopify/Product/42',
                'resource_url':'https://example.com/products/widget','field':'seo_title','after_value':'New title'})
            self.assertEqual(proposed.status_code,200,proposed.text)
            cid=proposed.json()['id']
            self.assertEqual((await self.post(f'/v1/change-sets/{cid}/execute')).status_code,409)
            self.assertEqual((await self.post(f'/v1/change-sets/{cid}/approve')).status_code,200)
            self.assertEqual((await self.post(f'/v1/change-sets/{cid}/execute')).json()['status'],'applied')
            with db.transaction() as conn:
                conn.execute("UPDATE change_sets SET status='failed' WHERE id=?",(cid,))
            self.assertEqual((await self.post(f'/v1/change-sets/{cid}/reconcile')).json()['status'],'applied')
            self.assertTrue((await self.post(f'/v1/change-sets/{cid}/verify')).json()['verified'])
            self.assertEqual((await self.post(f'/v1/change-sets/{cid}/rollback')).status_code,200)
            self.assertEqual(values['seo_title'],'Old title')
            exported=(await self.client.get(f'/api/v1/workspaces/{self.workspace}/export')).json()
            self.assertIn(self.site,exported['site_data'])
            self.assertNotIn('shpat_test_123456',str(exported))
            removed=await self.client.request('DELETE',f'/api/v1/workspaces/{self.workspace}',
                                              headers=self.headers(),json={'confirm_name':'My workspace'})
            self.assertEqual(removed.status_code,200,removed.text)
            self.assertEqual((await self.client.get(f'/api/sites/{self.site}')).status_code,404)

    async def test_github_pr_is_not_treated_as_deployment(self):
        merged=False
        async def health(*args): return {'repository':'owner/site','default_branch':'main'}
        async def metadata(*args): return {'seo_title':'Old title','seo_description':'Old description'}
        async def open_pr(*args): return {'pull_request_url':'https://github.com/owner/site/pull/9','pull_request_number':9}
        async def github_api(*args):
            if '/pulls?' in args[2]:
                return [{'html_url':'https://github.com/owner/site/pull/9','number':9}]
            return {'merged_at':'2026-10-24T00:00:00Z' if merged else None}
        async def live(*args): return 200,'text/html',b'<html><head><title>New title</title></head></html>'
        with patch('agentic.connectors.github_health',health),patch('agentic.connectors.github_file_metadata',metadata),\
             patch('agentic.connectors.github_open_pr',open_pr),patch('agentic.connectors.github_api',github_api),\
             patch('agentic.v1.bounded_get',live):
            await self.post('/v1/integrations',{'site_id':self.site,'platform':'github','credential':'github_token_123','repository':'owner/site'})
            iid=(await self.client.get(f'/api/v1/sites/{self.site}/integrations')).json()[0]['id']
            change=(await self.post('/v1/change-sets',{'integration_id':iid,'resource_id':'index.html',
                'resource_url':'https://example.com/','field':'seo_title','after_value':'New title'})).json()['id']
            await self.post(f'/v1/change-sets/{change}/approve')
            self.assertEqual((await self.post(f'/v1/change-sets/{change}/execute')).json()['status'],'pr_open')
            with db.transaction() as conn:
                conn.execute("UPDATE change_sets SET status='failed' WHERE id=?",(change,))
            self.assertEqual((await self.post(f'/v1/change-sets/{change}/reconcile')).json()['status'],'pr_open')
            result=(await self.post(f'/v1/change-sets/{change}/verify')).json()
            self.assertFalse(result['verified'])
            self.assertEqual(result['status'],'pr_open')
            merged=True
            self.assertTrue((await self.post(f'/v1/change-sets/{change}/verify')).json()['verified'])

    async def test_github_app_installation_connection(self):
        async def app_token(*args):return 'short-lived-installation-token'
        async def health(*args):return {'repository':'owner/site','default_branch':'main'}
        with patch('agentic.connectors.github_app_token',app_token),patch('agentic.connectors.github_health',health):
            result=await self.post('/v1/integrations',{'site_id':self.site,'platform':'github',
                'repository':'owner/site','installation_id':'12345'})
        self.assertEqual(result.status_code,200,result.text)
        self.assertEqual(result.json()['config']['auth_mode'],'github_app')

    async def test_ai_plan_persists_and_is_only_a_draft(self):
        with db.transaction() as conn:
            crawl='crawl1';page='page1';finding='finding1'
            conn.execute("INSERT INTO crawls(id,site_id,started_at,status) VALUES (?,?,?,?)",(crawl,self.site,'2026-10-24','completed'))
            conn.execute("INSERT INTO pages(id,crawl_id,site_id,url,title,description) VALUES (?,?,?,?,?,?)",(page,crawl,self.site,'https://example.com/','',''))
            conn.execute("INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,?)",(finding,self.site,crawl,page,'missing_title','high','No title','open','2026-10-24'))
        async def advice(*args):return llm.MetadataAdvice(title='Example title',description='Example description',rationale='Page has no title',priority=1),42,'test-model'
        with patch('agentic.llm.metadata_advice',advice):
            result=await self.post(f'/v1/sites/{self.site}/plans/generate',{'finding_id':'finding1'})
        self.assertEqual(result.status_code,200,result.text)
        self.assertEqual(result.json()['source'],'ai_draft')
        plans=(await self.client.get(f'/api/v1/sites/{self.site}/plans')).json()
        self.assertEqual(plans[0]['status'],'proposed')
        self.assertEqual((await self.client.get(f'/api/v1/workspaces/{self.workspace}/billing')).json()['usage'][0]['units'],42)

    async def test_explicit_policy_automates_only_allowed_metadata(self):
        policy=await self.client.put(f'/api/v1/sites/{self.site}/write-policy',headers=self.headers(),json={
            'enabled':True,'allowed_fields':['seo_description'],'max_daily_writes':1,
            'authorize_low_risk_metadata':True})
        self.assertEqual(policy.status_code,200,policy.text)
        self.assertEqual((await self.post(f'/sites/{self.site}/mode',{'mode':'autopilot'})).status_code,200)
        with db.transaction() as conn:
            conn.execute('UPDATE sites SET wp_user=?,wp_secret=? WHERE id=?',('editor',encrypt('application-password-123'),self.site))
            uid=conn.execute('SELECT user_id FROM memberships WHERE workspace_id=?',(self.workspace,)).fetchone()[0]
            conn.execute("INSERT INTO changes(id,site_id,page_url,wp_post_id,field,before_value,after_value,status,proposed_by,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                         ('autochg',self.site,'https://example.com/',42,'seo_description','','A useful description','proposed',uid,'2026-10-24'))
        async def current(*args):return {'seo_title':'','seo_description':'','revision':'rev'}
        async def update(*args):return {'seo_description':'A useful description'}
        with patch('agentic.wordpress.get_metadata',current),patch('agentic.wordpress.set_metadata',update):
            self.assertTrue(await worker.process_automatic_change())
        with db.connect() as conn:
            self.assertEqual(conn.execute("SELECT status FROM changes WHERE id='autochg'").fetchone()[0],'applied')
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM policy_approvals").fetchone()[0],1)

    async def test_invited_viewer_cannot_edit_client_workspace(self):
        invited=await self.post(f'/v1/workspaces/{self.workspace}/invitations',{'email':'viewer@example.com','role':'viewer'})
        self.assertEqual(invited.status_code,200,invited.text)
        token=invited.json()['invite_token']
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=main.app),base_url='http://testserver') as second:
            await second.post('/api/register',json={'email':'viewer@example.com','password':'another-long-password-456'})
            headers={'x-csrf-token':second.cookies.get('agentic_csrf','')}
            joined=await second.post('/api/v1/invitations/accept',json={'token':token},headers=headers)
            self.assertEqual(joined.status_code,200,joined.text)
            can_read=await second.get(f'/api/sites?workspace_id={self.workspace}')
            self.assertEqual(can_read.status_code,200)
            cannot_write=await second.post('/api/sites',json={'workspace_id':self.workspace,'origin':'https://other.example','label':'Other'},headers=headers)
            self.assertEqual(cannot_write.status_code,404)

    async def test_signed_deployment_webhook_is_idempotent(self):
        created=await self.post(f'/v1/sites/{self.site}/webhook')
        self.assertEqual(created.status_code,200,created.text)
        secret=created.json()['secret'].encode()
        payload=b'{"event":"deployed"}'
        path=f'/api/v1/webhooks/{self.site}'
        invalid=await self.client.post(path,content=payload,headers={'X-Agentic-Event-Id':'release-1','X-Agentic-Signature':'sha256=wrong'})
        self.assertEqual(invalid.status_code,403)
        signature='sha256='+hmac.new(secret,payload,hashlib.sha256).hexdigest()
        headers={'X-Agentic-Event-Id':'release-1','X-Agentic-Signature':signature}
        accepted=await self.client.post(path,content=payload,headers=headers)
        self.assertEqual(accepted.json()['status'],'queued')
        duplicate=await self.client.post(path,content=payload,headers=headers)
        self.assertEqual(duplicate.json()['status'],'duplicate')
        with db.connect() as conn:
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM crawl_jobs').fetchone()[0],1)

    async def test_search_console_sync_and_directional_analytics(self):
        with db.transaction() as conn:
            conn.execute("INSERT INTO integrations VALUES (?,?,?,?,?,?,?,?)",
                         ('gsc1',self.site,'gsc','{"property_url":"https://example.com/"}',
                          encrypt('refresh-test-token'),'connected','2026-10-24','2026-10-24'))
        async def refresh(*args):return 'access-test-token'
        async def rows(*args):return [{'keys':['2026-10-20','how to use example','https://example.com/'],
                                      'clicks':3,'impressions':200,'ctr':0.015,'position':8.4}]
        with patch('agentic.gsc.refresh_access',refresh),patch('agentic.gsc.query_metrics',rows):
            result=await self.post(f'/v1/sites/{self.site}/gsc/sync')
        self.assertEqual(result.status_code,200,result.text)
        self.assertEqual(result.json()['rows'],1)
        keywords=(await self.client.get(f'/api/v1/sites/{self.site}/keywords')).json()
        self.assertEqual(keywords[0]['opportunity'],'high_impressions_low_ctr')
        self.assertEqual(keywords[0]['intent'],'informational')
        analytics=(await self.client.get(f'/api/v1/sites/{self.site}/analytics')).json()
        self.assertEqual(analytics['daily_search_metrics'][0]['impressions'],200)

    async def test_content_draft_requires_editorial_approval_without_publishing(self):
        async def draft(*args):
            return llm.EditorialDraft(title='Pilot guide',brief='Outline and fact-check.',body='Draft text for review.'),30,'test-model'
        with patch('agentic.llm.editorial_draft',draft):
            result=await self.post('/v1/content/drafts',{'site_id':self.site,'topic':'Pilot guide topic','audience':'Owners'})
        self.assertEqual(result.status_code,200,result.text)
        ident=result.json()['id']
        approved=await self.post(f'/v1/content/drafts/{ident}/approve')
        self.assertEqual(approved.json()['status'],'editor_approved')
        self.assertFalse(approved.json()['published'])

    async def test_pilot_database_backup_restores_integrity(self):
        backup=Path(self.tmp.name)/'backup.sqlite3'
        restored=Path(self.tmp.name)/'restored.sqlite3'
        copy_verified(db.DB_PATH,backup)
        copy_verified(backup,restored)
        import sqlite3
        with sqlite3.connect(restored) as conn:
            self.assertEqual(conn.execute('PRAGMA integrity_check').fetchone()[0],'ok')
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM sites').fetchone()[0],1)

    async def test_audit_worker_prepares_ai_wordpress_proposal_without_publishing(self):
        with db.transaction() as conn:
            uid=conn.execute('SELECT user_id FROM memberships WHERE workspace_id=?',(self.workspace,)).fetchone()[0]
            conn.execute('UPDATE sites SET wp_user=?,wp_secret=? WHERE id=?',
                         ('editor',encrypt('application-password-123'),self.site))
            conn.execute("INSERT INTO crawl_jobs (id,site_id,requested_by,status,created_at) VALUES (?,?,?,?,?)",
                         ('job-ai',self.site,uid,'queued','2026-10-24'))
        async def fake_crawl(site_id,user):
            with db.transaction() as conn:
                conn.execute("INSERT INTO crawls(id,site_id,started_at,status) VALUES (?,?,?,?)",
                             ('crawl-ai',site_id,'2026-10-24','completed'))
                conn.execute("INSERT INTO pages(id,crawl_id,site_id,url,title,description) VALUES (?,?,?,?,?,?)",
                             ('page-ai','crawl-ai',site_id,'https://example.com/','',''))
                conn.execute("INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,?)",
                             ('finding-ai',site_id,'crawl-ai','page-ai','missing_title','high','No title','open','2026-10-24'))
            return {'crawl_id':'crawl-ai'}
        async def fake_plan(*args,**kwargs):
            return {'id':'plan-ai','advice':{'title':'Example site title','description':'Example site description'}}
        async def resolve(*args):return {'post_id':42}
        async def metadata(*args):return {'seo_title':'','seo_description':'','revision':'rev'}
        with patch.dict(os.environ,{'OPENAI_API_KEY':'test-key'}),patch('agentic.worker.run_crawl',fake_crawl),\
             patch('agentic.worker.generate_plan',fake_plan),patch('agentic.wordpress.resolve',resolve),\
             patch('agentic.wordpress.get_metadata',metadata):
            self.assertTrue(await worker.process_one())
        with db.connect() as conn:
            row=conn.execute("SELECT c.status,p.source FROM changes c JOIN change_provenance p ON p.change_id=c.id WHERE c.finding_id='finding-ai'").fetchone()
            self.assertEqual(tuple(row),('proposed','ai_draft'))


if __name__=='__main__':unittest.main()
