import unittest
from scanner import Scanner

class ScannerChecks(unittest.TestCase):
    def setUp(self): self.scanner=Scanner('http://127.0.0.1:5000',delay=0)
    def test_missing_security_headers(self):
        class R:
            url='http://127.0.0.1:5000/'; headers={'Content-Type':'text/html'}
            class Raw:
                headers=type('H',(),{'getlist':lambda self,k: []})()
            raw=Raw()
        self.scanner.check_response(R())
        ids={f.id for f in self.scanner.findings.values()}
        self.assertTrue({'HDR-CSP','HDR-XFO','HDR-NOSNIFF','TLS-001'} <= ids)
    def test_cookie_flags(self):
        class R:
            url='http://127.0.0.1:5000/'; headers={}
            class Raw:
                headers=type('H',(),{'getlist':lambda self,k:['sid=x; Path=/']})()
            raw=Raw()
        self.scanner.check_response(R())
        self.assertTrue({'COOKIE-HTTPONLY','COOKIE-SAMESITE'} <= {f.id for f in self.scanner.findings.values()})
    def test_error_signature_not_status_only(self):
        import re
        self.assertTrue(any(re.search(x,'sqlite3.OperationalError: near quote',re.I) for x in __import__('scanner').SQL_ERRORS))
        self.assertFalse(any(re.search(x,'Welcome to the store',re.I) for x in __import__('scanner').SQL_ERRORS))
    def test_loopback_boundary(self):
        self.assertTrue(Scanner.is_loopback('http://127.0.0.1:5000'))
        self.assertFalse(Scanner.is_loopback('https://example.com'))

if __name__=='__main__': unittest.main()
