"""Verschlüsselt privat/app.html mit dem Passwort aus privat/passwort.txt
und schreibt das Ergebnis nach index.html (das ist die Datei, die veröffentlicht wird).

Verfahren: PBKDF2-SHA256 (600.000 Runden) -> AES-256-GCM. Entschlüsselt wird im Browser per WebCrypto.
Aufruf:  python build.py
"""
import base64, os, pathlib, secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ROOT = pathlib.Path(__file__).parent
SRC = ROOT / "privat" / "app.html"
PWFILE = ROOT / "privat" / "passwort.txt"
OUT = ROOT / "index.html"
ITER = 600_000

WORDS = ("apfel birne sonne mond stern wolke regen blume garten fenster tisch stuhl katze vogel fisch "
         "brot honig kaffee wasser wald berg fluss insel schiff zug buch lampe kerze herz brief").split()

if not PWFILE.exists():
    pw = "-".join(secrets.choice(WORDS) for _ in range(4)) + "-" + str(secrets.randbelow(90) + 10)
    PWFILE.write_text(pw, encoding="utf-8")
    print("Neues Passwort erzeugt in", PWFILE)
pw = PWFILE.read_text(encoding="utf-8").strip()

salt, iv = os.urandom(16), os.urandom(12)
key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITER).derive(pw.encode())
ct = AESGCM(key).encrypt(iv, SRC.read_bytes(), None)
b64 = lambda b: base64.b64encode(b).decode()

SHELL = r"""<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Antragshelfer</title>
<meta name="theme-color" content="#1f6f5c">
<style>
:root{--bg:#f6f4ef;--card:#fff;--text:#1f2328;--muted:#5b6470;--line:#d9d5cc;--accent:#1f6f5c;--danger:#b42318}
@media (prefers-color-scheme: dark){:root:not([data-theme="light"]){--bg:#16181c;--card:#1f2228;--text:#eceff3;--muted:#a3acb8;--line:#30343c;--accent:#5cc4a6;--danger:#ff8a80}}
:root[data-theme="dark"]{--bg:#16181c;--card:#1f2228;--text:#eceff3;--muted:#a3acb8;--line:#30343c;--accent:#5cc4a6;--danger:#ff8a80}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--text);font:18px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif;padding:16px}
form{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:24px 20px;width:100%;max-width:420px}
h1{font-size:1.3rem;margin:0 0 6px}
p{margin:0 0 16px;color:var(--muted)}
input[type=password]{width:100%;font:inherit;padding:12px;border:2px solid var(--line);border-radius:10px;background:var(--bg);color:var(--text)}
label.r{display:flex;gap:10px;align-items:center;margin:14px 0;font-size:.95rem}
label.r input{width:1.4em;height:1.4em;accent-color:var(--accent)}
button{width:100%;font:inherit;font-weight:700;padding:12px;border:0;border-radius:10px;background:var(--accent);color:#fff;cursor:pointer}
#err{color:var(--danger);min-height:1.5em;margin-top:10px;font-size:.95rem}
</style>
</head>
<body>
<form id="f">
  <h1>🔒 Antragshelfer</h1>
  <p>Diese Seite ist geschützt. Bitte gib das Passwort ein.</p>
  <input type="password" id="pw" autocomplete="current-password" placeholder="Passwort" required>
  <label class="r"><input type="checkbox" id="keep" checked> Auf diesem Handy merken</label>
  <button type="submit">Öffnen</button>
  <div id="err" role="alert"></div>
</form>
<script>
const D={salt:"__SALT__",iv:"__IV__",ct:"__CT__",it:__ITER__};
const ub=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
async function open_(pw){
  const base=await crypto.subtle.importKey('raw',new TextEncoder().encode(pw),'PBKDF2',false,['deriveKey']);
  const key=await crypto.subtle.deriveKey({name:'PBKDF2',salt:ub(D.salt),iterations:D.it,hash:'SHA-256'},base,{name:'AES-GCM',length:256},false,['decrypt']);
  const pt=await crypto.subtle.decrypt({name:'AES-GCM',iv:ub(D.iv)},key,ub(D.ct));
  return new TextDecoder().decode(pt);
}
function show(html){document.open();document.write(html);document.close()}
let saved=null;try{saved=localStorage.getItem('petra-pw')}catch(e){}
if(saved){open_(saved).then(show).catch(()=>{try{localStorage.removeItem('petra-pw')}catch(e){}})}
document.getElementById('f').onsubmit=async e=>{
  e.preventDefault();
  const pw=document.getElementById('pw').value.trim().toLowerCase();
  const err=document.getElementById('err');err.textContent='Einen Moment …';
  try{
    const html=await open_(pw);
    if(document.getElementById('keep').checked){try{localStorage.setItem('petra-pw',pw)}catch(e){}}
    show(html);
  }catch(x){err.textContent='Das Passwort stimmt nicht. Bitte noch einmal versuchen (auf Bindestriche achten).'}
};
</script>
</body>
</html>
"""
html = (SHELL.replace("__SALT__", b64(salt)).replace("__IV__", b64(iv))
        .replace("__CT__", b64(ct)).replace("__ITER__", str(ITER)))
OUT.write_text(html, encoding="utf-8")
print(f"index.html geschrieben ({len(html)//1024} KB, verschlüsselt)")
