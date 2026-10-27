import unittest
from unittest.mock import patch, Mock
import engine


class EngineTests(unittest.TestCase):
    def test_reject_bad_targets(self):
        for value in ('file:///etc/passwd','https://user:password@example.com/','https://example.com/?x=1','https://example.com:22/'):
            with self.assertRaises(ValueError):
                engine.target(value)

    def test_local_and_mixed_dns_blocked(self):
        for addresses in [('127.0.0.1',), ('8.8.8.8','192.168.1.1'), ('::1',)]:
            records=[(2,1,6,'',(address,443)) for address in addresses]
            with patch('engine.socket.getaddrinfo',return_value=records):
                with self.assertRaises(ValueError): engine.public_ip('example.com',443)

    def test_sql_is_unconfirmed(self):
        rows=engine.sql_review('cursor.execute("SELECT * FROM records WHERE id=" + user_input)')
        self.assertEqual(rows[0]['status'],'Suspected')
        self.assertNotIn('user_input',rows[0]['evidence'])

    def test_parameterized_not_flagged(self):
        rows=engine.sql_review('cursor.execute("SELECT * FROM records WHERE id=?", (value,))')
        self.assertEqual(rows[0]['status'],'Informational')

    def test_nmap_no_shell_and_bounded(self):
        result=Mock(returncode=0,stdout='<nmaprun><host><ports><port portid="443"><state state="open"/></port></ports></host></nmaprun>')
        with patch('engine.shutil.which',return_value='/usr/bin/nmap'),patch('engine.public_ip',return_value='8.8.8.8'),patch('engine.subprocess.run',return_value=result) as run:
            rows=engine.nmap_check('https://example.com/')
            args=run.call_args.args[0]
            self.assertNotIn('--script',args)
            self.assertEqual(args[args.index('-p')+1],'443')
            self.assertEqual(run.call_args.kwargs['timeout'],25)
            self.assertNotIn('shell',run.call_args.kwargs)
            self.assertEqual(rows[0]['status'],'Informational')

    def test_nmap_rejects_path_scope(self):
        with self.assertRaises(ValueError): engine.nmap_check('https://example.com/app')

    def test_headers_one_request_and_no_redirect(self):
        conn=Mock(); conn.getresponse.return_value=Mock(status=302,getheaders=lambda:[('Location','http://127.0.0.1/')])
        with patch('engine.public_ip',return_value='8.8.8.8'),patch('engine.socket.create_connection'),patch('engine.http.client.HTTPConnection',return_value=conn):
            rows=engine.header_check('http://example.com/')
            conn.request.assert_called_once()
            self.assertTrue(any(r['title']=='Redirect not followed' for r in rows))
            self.assertFalse(any(r['status']=='Confirmed' for r in rows))

    def test_report_manual_submission(self):
        report=engine.report(dict(created='2026-10-27',target='local',mode='sql-local',policy='local',rules='local scope'),[])
        self.assertIn('not submitted',report)

if __name__=='__main__': unittest.main()
