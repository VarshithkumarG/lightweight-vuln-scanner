"""A small, read-only web scanner intended for explicitly authorised localhost labs."""
from __future__ import annotations
import argparse, json, re, sys, time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlparse, urlunparse, parse_qsl, urlencode
import ipaddress
from urllib.request import Request, build_opener, HTTPRedirectHandler
from urllib.error import HTTPError, URLError
from email.message import Message
from urllib.parse import quote

class Response:
    def __init__(self, code, url, headers, body):
        self.status_code=code; self.url=url; self.headers=headers; self.text=body
        self.raw=type('Raw',(),{'headers':type('H',(),{'getlist':lambda _,k: headers.get_all(k,[])})()})()

class Session:
    class NoRedirect(HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl): return None
    def __init__(self): self.headers={}; self.opener=build_opener(self.NoRedirect())
    def get(self,url,params=None,timeout=8,allow_redirects=False):
        if params:
            parts=urlparse(url); replaced=set(params)
            query=[(k,v) for k,v in parse_qsl(parts.query,keep_blank_values=True) if k not in replaced]
            query.extend(params.items()); url=urlunparse(parts._replace(query=urlencode(query)))
        req=Request(url,headers=self.headers,method='GET')
        try:
            with self.opener.open(req,timeout=timeout) as r: return Response(r.status,r.geturl(),r.headers,r.read(500000).decode('utf-8','replace'))
        except HTTPError as e: return Response(e.code,e.geturl(),e.headers,e.read(500000).decode('utf-8','replace'))
        except (URLError,TimeoutError,OSError): return None

UA = "LightweightLabScanner/1.0 (+read-only; authorised localhost testing)"
MARKER = "LVSXSS7f31a"
SQL_ERRORS = ("you have an error in your sql syntax", "sqlite3.operationalerror", "sql syntax", "unclosed quotation mark", "mysql_fetch", "ora-01756", "postgresql.*error")

@dataclass
class Finding:
    id: str; title: str; severity: str; owasp: str; url: str; evidence: str; recommendation: str

class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(); self.links=[]; self.forms=[]; self.scripts=[]; self.images=[]
        self.form=None
    def handle_starttag(self, tag, attrs):
        a=dict(attrs)
        if tag=='a' and a.get('href'): self.links.append(a['href'])
        if tag=='script' and a.get('src'): self.scripts.append(a)
        if tag in ('img','iframe','link') and a.get('src') or tag=='link' and a.get('href'):
            self.images.append(a.get('src') or a.get('href'))
        if tag=='form': self.form={'action':a.get('action',''),'method':a.get('method','get').lower(),'inputs':[]}
        elif tag in ('input','textarea','select') and self.form is not None: self.form['inputs'].append(a.get('name',''))
    def handle_endtag(self, tag):
        if tag=='form' and self.form is not None: self.forms.append(self.form); self.form=None

class Scanner:
    def __init__(self, target, delay=.25, max_pages=30, timeout=8, session=None):
        self.target=target.rstrip('/')+'/'; self.origin=urlparse(self.target); self.delay=delay; self.max_pages=max_pages; self.timeout=timeout
        self.s=session or Session(); self.s.headers.update({'User-Agent':UA,'Accept':'text/html,application/xhtml+xml,*/*;q=0.8','Origin':'https://scanner.invalid'})
        self.visited=set(); self.findings={}; self.forms=[]; self.parameters=[]; self.last=0; self.request_errors=[]
    @staticmethod
    def is_loopback(url):
        try:
            p=urlparse(url)
            return p.scheme in ('http','https') and bool(p.hostname) and ipaddress.ip_address(p.hostname).is_loopback
        except ValueError: return False
    def request(self,url, params=None):
        if not self.is_loopback(url): raise ValueError('Refusing non-loopback URL')
        elapsed=time.monotonic()-self.last
        if self.last and elapsed<self.delay: time.sleep(self.delay-elapsed)
        self.last=time.monotonic()
        return self.s.get(url,params=params,timeout=self.timeout,allow_redirects=False)
    def add(self, key, title, sev, owasp, url, evidence, fix):
        f=Finding(key,title,sev,owasp,url,str(evidence)[:300],fix)
        origin=f'{urlparse(url).scheme}://{urlparse(url).netloc}'
        global_checks={'TLS-001','HDR-HSTS','HDR-CSP','HDR-XFO','HDR-NOSNIFF','INFO-VERSION','CORS-001','COOKIE-HTTPONLY','COOKIE-SAMESITE','COOKIE-SECURE'}
        scope=origin if key in global_checks else url
        if key in global_checks: self.findings.setdefault((key,scope),f)
        else: self.findings[(key,scope)]=f
    def scan(self):
        queue=[self.target]; parsed_initial=urlparse(self.target); base=parsed_initial._replace(path='',params='',query='',fragment='').geturl().rstrip('/')
        root_resp=None
        while queue and len(self.visited)<self.max_pages:
            url=queue.pop(0); clean=urlunparse(urlparse(url)._replace(fragment=''))
            if clean in self.visited or not self.is_loopback(clean): continue
            self.visited.add(clean); response=self.request(clean)
            if not response:
                self.request_errors.append({'url':clean,'error':'connection failed, timed out, or request was blocked'}); continue
            if clean.rstrip('/')==self.target.rstrip('/'): root_resp=response
            self.check_response(response)
            if 'html' not in response.headers.get('Content-Type','').lower(): continue
            parser=PageParser()
            try: parser.feed(response.text[:500000])
            except Exception: continue
            self.forms += [{**f,'page':clean} for f in parser.forms]
            for name,value in parse_qsl(urlparse(clean).query,keep_blank_values=True): self.parameters.append({'url':clean,'name':name,'value':value})
            self.check_html(response,parser)
            for link in parser.links:
                nxt=urljoin(clean,link); pn=urlparse(nxt)
                if pn.scheme in ('http','https') and pn.hostname==parsed_initial.hostname and pn.port==parsed_initial.port:
                    if nxt not in self.visited and nxt not in queue: queue.append(nxt)
        if root_resp: self.root_probes(base)
        self.parameter_probes()
        return {'scanner':'LightweightLabScanner','version':'1.0','target':self.target,'scanned_at':datetime.now(timezone.utc).isoformat(),'status':'complete' if not self.request_errors else 'incomplete','pages_crawled':len(self.visited),'pages':sorted(self.visited),'request_errors':self.request_errors,'forms':self.forms,'parameters':self.parameters,'findings':[asdict(f) for f in sorted(self.findings.values(),key=lambda x:({'critical':0,'high':1,'medium':2,'low':3,'info':4}.get(x.severity,5),x.id,x.url))]}
    def check_response(self,r):
        h={k.lower():v for k,v in r.headers.items()}; u=r.url
        if urlparse(u).scheme=='http': self.add('TLS-001','Site served over unencrypted HTTP','medium','A02 Cryptographic Failures',u,'URL scheme is http','Serve the application over HTTPS and redirect HTTP to HTTPS.')
        for header,key,title,owasp in [('strict-transport-security','HDR-HSTS','Missing HSTS','A02 Cryptographic Failures'),('content-security-policy','HDR-CSP','Missing Content-Security-Policy','A05 Security Misconfiguration'),('x-frame-options','HDR-XFO','Missing X-Frame-Options','A05 Security Misconfiguration'),('x-content-type-options','HDR-NOSNIFF','Missing X-Content-Type-Options','A05 Security Misconfiguration')]:
            missing = header not in h and (header != 'strict-transport-security' or urlparse(u).scheme == 'https')
            if missing:
                self.add(key,title,'medium',owasp,u,f'{header} response header absent','Set a restrictive '+header+' response header.')
        server=h.get('server','')+' '+h.get('x-powered-by','')
        if re.search(r'\d+\.\d+',server): self.add('INFO-VERSION','Server technology version disclosed','low','A06 Vulnerable and Outdated Components',u,server.strip(),'Remove unnecessary version banners and maintain supported dependencies.')
        acao=h.get('access-control-allow-origin',''); vary=h.get('vary','').lower()
        if acao=='*' or (acao and acao==self.s.headers.get('Origin') and 'origin' not in vary): self.add('CORS-001','Permissive CORS policy','medium','A01 Broken Access Control',u,'Access-Control-Allow-Origin: '+acao,'Allow only trusted origins; avoid reflecting arbitrary Origin values.')
        for cookie in r.raw.headers.getlist('Set-Cookie') if hasattr(r.raw.headers,'getlist') else [r.headers.get('Set-Cookie','')]:
            low=cookie.lower()
            if not cookie: continue
            if 'httponly' not in low: self.add('COOKIE-HTTPONLY','Cookie missing HttpOnly','medium','A07 Identification and Authentication Failures',u,cookie.split(';')[0],'Set HttpOnly on session cookies.')
            if 'samesite' not in low: self.add('COOKIE-SAMESITE','Cookie missing SameSite','low','A07 Identification and Authentication Failures',u,cookie.split(';')[0],'Set SameSite=Lax or Strict as the application permits.')
            if urlparse(u).scheme=='https' and 'secure' not in low: self.add('COOKIE-SECURE','Cookie missing Secure','medium','A02 Cryptographic Failures',u,cookie.split(';')[0],'Set Secure on cookies served over HTTPS.')
    def check_html(self,r,p):
        u=r.url; body=r.text[:500000]
        if urlparse(u).scheme=='https' and re.search(r'(?:src|href)=[\"\']http://',body,re.I): self.add('MIXED-001','Potential mixed content','medium','A02 Cryptographic Failures',u,'HTML references an http:// resource','Load all page resources over HTTPS.')
        for s in p.scripts:
            src=s.get('src','')
            if src.startswith(('http://','https://')) and not s.get('integrity'): self.add('SRI-001','External script without Subresource Integrity','low','A08 Software and Data Integrity Failures',u,src,'Pin third-party script content with an integrity hash and crossorigin attribute.')
        for f in p.forms:
            if f['method']=='get': continue
            # Passive detection only; never submit a form.
            if not any(('csrf' in x.lower() or 'token' in x.lower()) for x in f['inputs']): self.add('CSRF-PASSIVE','State-changing form has no apparent CSRF token','low','A01 Broken Access Control',urljoin(u,f['action']),'Form fields contain no obvious CSRF/token name; form was not submitted','Use framework CSRF protection and validate tokens server-side.')
        if re.search(r'Index of /|Directory listing for /',body,re.I): self.add('DIRLIST-001','Directory listing exposed','medium','A05 Security Misconfiguration',u,'Recognised directory-index title','Disable directory indexing and restrict sensitive paths.')
    def root_probes(self,base):
        # Harmless GET-only common file checks; require file-specific signatures, not status alone.
        checks=[('/.env',re.compile(r'(?im)^(?:APP_KEY|DB_PASSWORD|SECRET_KEY|AWS_ACCESS_KEY_ID)=',re.I),'EXPOSED-ENV','Exposed environment file'),('/.git/HEAD',re.compile(r'\Aref: refs/(?:heads|remotes)/',re.I),'EXPOSED-GIT','Exposed Git metadata'),('/phpinfo.php',re.compile(r'<title>phpinfo\(\)</title>|PHP Version</td>',re.I),'PHPINFO','Exposed phpinfo page')]
        for path,signature,key,title in checks:
            r=self.request(base+path)
            if r and r.status_code==200 and signature.search(r.text[:50000]): self.add(key,title,'high','A05 Security Misconfiguration',r.url,'HTTP 200 with matching content signature','Remove the exposed file and block access at the web server.')
    def parameter_probes(self):
        # One unique harmless marker and one quote per discovered query parameter; GET only.
        for item in self.parameters[:20]:
            u=item['url']; name=item['name']
            r=self.request(u,params={name:MARKER})
            if r and MARKER in r.text: self.add('XSS-REFLECT','Reflected marker observed; review output encoding','low','A03 Injection',r.url,'Unique harmless marker returned in response; reflection alone does not prove script execution','Contextually encode untrusted output and use safe DOM APIs.')
            q=self.request(u,params={name:"'"})
            if q and any(re.search(sig,q.text,re.I) for sig in SQL_ERRORS): self.add('SQL-ERROR','Database error signature after quote probe','medium','A03 Injection',q.url,'Database-specific error signature found in response','Use parameterized queries and return generic error responses.')

def main(argv=None):
    ap=argparse.ArgumentParser(description='Read-only scanner for authorised localhost labs only.')
    ap.add_argument('url'); ap.add_argument('--i-have-permission',action='store_true',help='required consent acknowledgement')
    ap.add_argument('--delay',type=float,default=.25); ap.add_argument('--max-pages',type=int,default=30); ap.add_argument('--timeout',type=float,default=8); ap.add_argument('-o','--output',default='scan-report.json')
    a=ap.parse_args(argv)
    if not a.i_have_permission: ap.error('refusing to run without --i-have-permission')
    if not Scanner.is_loopback(a.url): ap.error('only loopback IP targets (127.0.0.1 or ::1) are allowed')
    if a.delay<0 or a.max_pages<1 or a.timeout<=0: ap.error('delay must be >=0, page limit >=1, timeout >0')
    data=Scanner(a.url,a.delay,a.max_pages,a.timeout).scan(); Path(a.output).write_text(json.dumps(data,indent=2),encoding='utf-8')
    counts={s:sum(f['severity']==s for f in data['findings']) for s in ('high','medium','low')}
    print(f"Scan status: {data['status']}; attempted pages: {data['pages_crawled']}; findings: {len(data['findings'])} (high {counts['high']}, medium {counts['medium']}, low {counts['low']})")
    for error in data['request_errors']: print(f"[INCOMPLETE] {error['url']}: {error['error']}")
    for f in data['findings']:
        print(f"[{f['severity'].upper()}] {f['title']} | {f['owasp']} | {f['url']} | Evidence: {f['evidence']} | Fix: {f['recommendation']}")
    print('JSON report:',Path(a.output).resolve())
if __name__=='__main__': main()
