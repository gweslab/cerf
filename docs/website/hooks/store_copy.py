import os
import posixpath
import re
import sys
from html.parser import HTMLParser
from urllib.parse import urlsplit, urlunsplit

HERE  = os.path.dirname(os.path.abspath(__file__))
SITE  = os.path.dirname(HERE)
ROOT  = os.path.dirname(os.path.dirname(SITE))
sys.path.insert(0, os.path.join(ROOT, 'tools'))
from header_defines import str_define

LINKS_HEADER = os.path.join(ROOT, 'cerf-qt', 'play_store_links_text.h')
REDIRECTS    = os.path.join(SITE, 'content', '_redirects')
HEADERS      = '/*\n  X-Robots-Tag: noindex, nofollow\n'
HREF         = re.compile(r'\bhref="[^"]*"')


def active(config):
    return bool(config.extra.get('play_store_copy'))


def store_url():
    return str_define(LINKS_HEADER, 'CERF_PLAY_STORE_WEBSITE_URL')


def _bare_host(parts):
    host = (parts.hostname or '').lower()
    return host[len('www.'):] if host.startswith('www.') else host


def _site_path(path):
    path = '/' + path.lstrip('/')
    if path.endswith('.md'):
        path = path[:-len('.md')]
    if path.endswith('/index'):
        path = path[:-len('/index')]
    return path.rstrip('/') or '/'


def _under(parts, prefix):
    prefix = urlsplit(prefix)
    if _bare_host(parts) != _bare_host(prefix):
        return False
    base = prefix.path.rstrip('/')
    return not base or parts.path == base or parts.path.startswith(base + '/')


def _on_domain(host, domain):
    return host == domain or host.endswith('.' + domain)


def _redirect_rules():
    with open(REDIRECTS, 'r', encoding='utf-8') as f:
        return f.read().splitlines()


def _header_words(name):
    return str_define(LINKS_HEADER, name).split()


class StoreLinks:
    def __init__(self):
        self.removed_urls    = _header_words('CERF_PLAY_STORE_REMOVED_URLS')
        self.removed_domains = _header_words('CERF_PLAY_STORE_SITE_REMOVED_DOMAINS')
        self.removed_paths   = set(_header_words('CERF_PLAY_STORE_REMOVED_PATHS'))
        self.main_host       = _bare_host(urlsplit(str_define(LINKS_HEADER, 'CERF_WEBSITE_URL')))
        self.store_netloc    = urlsplit(store_url()).netloc

    def _removed_url(self, parts):
        host = _bare_host(parts)
        return (any(_on_domain(host, domain) for domain in self.removed_domains)
                or any(_under(parts, prefix) for prefix in self.removed_urls))

    def _site_path_of(self, parts, base):
        if parts.netloc:
            return _site_path(parts.path) if _bare_host(parts) == self.main_host else None
        if not parts.path:
            return None
        return _site_path(parts.path if parts.path.startswith('/')
                          else posixpath.normpath(posixpath.join(base, parts.path)))

    def missing_page(self, url, base=''):
        parts = urlsplit(url)
        if parts.scheme and parts.scheme not in ('http', 'https'):
            return False
        return self._site_path_of(parts, base) in self.removed_paths

    def target(self, url, base=''):
        parts = urlsplit(url)
        if parts.scheme and parts.scheme not in ('http', 'https'):
            return url
        if parts.netloc and self._removed_url(parts):
            return None
        if self.missing_page(url, base):
            return None
        if parts.netloc and _bare_host(parts) == self.main_host:
            return urlunsplit((parts.scheme, self.store_netloc, parts.path, parts.query, parts.fragment))
        return url


class _LinkRewriter(HTMLParser):
    def __init__(self, links, base):
        super().__init__(convert_charrefs=False)
        self.links   = links
        self.base    = base
        self.out     = []
        self.anchors = []
        self.items   = []
        self.skip    = False

    def _child(self, removed_anchor=False):
        if self.items and not self.items[-1]['seen']:
            self.items[-1]['seen'] = True
            self.items[-1]['drop'] = removed_anchor

    def handle_starttag(self, tag, attrs):
        if self.skip:
            return
        text = self.get_starttag_text()
        if tag == 'li':
            self.items.append({'start': len(self.out), 'seen': False, 'drop': False})
            self.out.append(text)
            return
        values = dict(attrs)
        if tag != 'a' or values.get('href') is None:
            self._child()
            self.out.append(text)
            return
        target = self.links.target(values['href'], self.base)
        self._child(target is None and self.links.missing_page(values['href'], self.base))
        if target is None:
            if values.get('class'):
                self.skip = True
            else:
                self.anchors.append(False)
            return
        self.anchors.append(True)
        self.out.append(HREF.sub(lambda _m: f'href="{target}"', text, count=1))

    def handle_startendtag(self, tag, attrs):
        if not self.skip:
            self._child()
            self.out.append(self.get_starttag_text())

    def handle_endtag(self, tag):
        if self.skip:
            self.skip = tag != 'a'
            return
        if tag == 'a':
            if not self.anchors or self.anchors.pop():
                self.out.append('</a>')
            return
        self.out.append(f'</{tag}>')
        if tag == 'li' and self.items:
            item = self.items.pop()
            if item['drop']:
                del self.out[item['start']:]

    def handle_data(self, data):
        if not self.skip:
            if data.strip():
                self._child()
            self.out.append(data)

    def handle_entityref(self, name):
        if not self.skip:
            self._child()
            self.out.append(f'&{name};')

    def handle_charref(self, name):
        if not self.skip:
            self._child()
            self.out.append(f'&#{name};')

    def handle_comment(self, data):
        if not self.skip:
            self.out.append(f'<!--{data}-->')

    def handle_decl(self, decl):
        self.out.append(f'<!{decl}>')

    def handle_pi(self, data):
        self.out.append(f'<?{data}>')

    def unknown_decl(self, data):
        self.out.append(f'<![{data}]>')


def _page_base(page):
    url = page.url or ''
    return url if url.endswith('/') or not url else posixpath.dirname(url)


def _nav(items, links):
    kept = []
    for item in items:
        if isinstance(item, dict):
            (title, target), = item.items()
            if isinstance(target, list):
                kept.append({title: _nav(target, links)})
            elif links.target(target) is not None:
                kept.append(item)
        elif links.target(item) is not None:
            kept.append(item)
    return kept


def configure(config):
    config.site_url = store_url() + '/'
    config.repo_url = None
    config.edit_uri = None
    links = StoreLinks()
    config.extra['social'] = [entry for entry in config.extra.get('social', [])
                              if links.target(entry['link']) is not None]
    config.nav = _nav(config.nav, links)


def page_html(html, page, config):
    rewriter = _LinkRewriter(StoreLinks(), _page_base(page))
    rewriter.feed(html)
    rewriter.close()
    return ''.join(rewriter.out)


def post_build(config):
    links = StoreLinks()
    rules = []
    for line in _redirect_rules():
        fields = line.split()
        if len(fields) >= 2 and (_site_path(fields[0]) in links.removed_paths or links.target(fields[1]) is None):
            continue
        rules.append(line)
    with open(os.path.join(config.site_dir, '_redirects'), 'w', encoding='utf-8') as f:
        f.write('\n'.join(rules) + '\n')
    with open(os.path.join(config.site_dir, '_headers'), 'w', encoding='utf-8') as f:
        f.write(HEADERS)
