import hashlib,requests
from bs4 import BeautifulSoup
def fetch(url,timeout=30):
    s=requests.Session(); s.proxies.update({"http":"socks5h://127.0.0.1:9050","https":"socks5h://127.0.0.1:9050"})
    r=s.get(url,timeout=timeout,headers={"User-Agent":"TorWatch-Public-OSINT/0.3"}); r.raise_for_status()
    soup=BeautifulSoup(r.text,"html.parser")
    for x in soup(["script","style","noscript"]): x.decompose()
    title=soup.title.get_text(" ",strip=True) if soup.title else ""
    text=" ".join(soup.get_text(" ",strip=True).split())
    return title,text,hashlib.sha256(text.encode()).hexdigest()
