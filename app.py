import os
import requests
from flask import Flask, request, jsonify, Response

ANALYZER_URL = os.environ.get("ANALYZER_URL", "http://presidio-analyzer:3000")
ANONYMIZER_URL = os.environ.get("ANONYMIZER_URL", "http://presidio-anonymizer:3000")

app = Flask(__name__)

INDEX_HTML = r"""<!DOCTYPE html>
<html lang="sk">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PII Anonymizer</title>
<style>
  :root{--card:#fff;--ink:#0f172a;--muted:#64748b;--line:#e2e8f0;--accent:#4f46e5;
    --accent-press:#4338ca;--soft:#eef2ff;--ok:#059669;--err:#dc2626}
  *{box-sizing:border-box}
  body{margin:0;min-height:100vh;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
    background:radial-gradient(1200px 600px at 50% -10%,#1e293b,#0f172a);color:var(--ink);
    display:flex;justify-content:center;padding:40px 16px}
  .wrap{width:100%;max-width:820px}
  .head{color:#e2e8f0;margin-bottom:22px}
  .head h1{margin:0;font-size:22px;letter-spacing:-.01em}
  .head p{margin:4px 0 0;color:#94a3b8;font-size:13px}
  .card{background:var(--card);border-radius:16px;padding:24px;box-shadow:0 20px 50px -20px rgba(0,0,0,.5)}
  label{display:block;font-size:13px;font-weight:600;margin:0 0 6px}
  .row{display:flex;gap:14px;align-items:flex-end;flex-wrap:wrap}
  textarea{width:100%;min-height:150px;resize:vertical;padding:12px 14px;border:1px solid var(--line);
    border-radius:10px;font-family:ui-monospace,Menlo,monospace;font-size:13.5px;line-height:1.5;outline:none;color:var(--ink)}
  textarea:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--soft)}
  select{width:100%;padding:10px 12px;border:1px solid var(--line);border-radius:10px;font-size:14px;background:#fff}
  .actions{display:flex;gap:10px;align-items:center;margin-top:14px}
  button{border:0;border-radius:10px;padding:11px 18px;font-size:14px;font-weight:600;cursor:pointer;
    background:var(--accent);color:#fff;transition:background .15s}
  button:hover{background:var(--accent-press)}
  button:disabled{opacity:.6;cursor:default}
  .ghost{background:#f1f5f9;color:var(--ink)}
  .ghost:hover{background:#e2e8f0}
  .hint{font-size:12px;color:var(--muted);margin-top:8px}
  .out{margin-top:22px;display:none}
  .out.show{display:block}
  .result{border:1px solid var(--line);border-radius:10px;padding:14px;background:#f8fafc;
    font-family:ui-monospace,Menlo,monospace;font-size:13.5px;line-height:1.6;white-space:pre-wrap;word-break:break-word}
  .tok{background:#fee2e2;color:#b91c1c;border-radius:5px;padding:0 4px;font-weight:600}
  .meta{display:flex;align-items:center;justify-content:space-between;margin:18px 0 8px}
  .meta h3{margin:0;font-size:13px}
  .badges{display:flex;flex-wrap:wrap;gap:6px}
  .badge{background:var(--soft);color:var(--accent);border-radius:999px;padding:4px 10px;font-size:12px;font-weight:600}
  .none{color:var(--muted);font-size:13px}
  .err{display:none;margin-top:14px;background:#fef2f2;color:var(--err);border:1px solid #fecaca;
    border-radius:10px;padding:10px 12px;font-size:13px}
  .err.show{display:block}
  .copied{color:var(--ok);font-size:12px;font-weight:600;opacity:0;transition:opacity .2s}
  .copied.show{opacity:1}
</style>
</head>
<body>
  <div class="wrap">
    <div class="head">
      <h1>PII Anonymizer</h1>
      <p>Detekcia a anonymizácia osobných údajov · Microsoft Presidio</p>
    </div>
    <div class="card">
      <label for="text">Vstupný text</label>
      <textarea id="text" placeholder="Vlož text, ktorý chceš anonymizovať…"></textarea>
      <div class="row" style="margin-top:14px">
        <div style="max-width:220px">
          <label for="lang">Jazyk</label>
          <select id="lang"><option value="en" selected>English (en)</option></select>
        </div>
      </div>
      <p class="hint">Default model vie po anglicky. Slovenčina / ďalšie jazyky potrebujú dokonfigurovať NLP engine analyzera.</p>
      <div class="actions">
        <button id="go">Anonymizovať</button>
        <button id="clear" class="ghost" type="button">Vyčistiť</button>
      </div>
      <div class="err" id="err"></div>
      <div class="out" id="out">
        <div class="meta">
          <h3>Výsledok</h3>
          <div style="display:flex;gap:10px;align-items:center">
            <span class="copied" id="copied">Skopírované</span>
            <button class="ghost" id="copy" type="button" style="padding:6px 12px;font-size:13px">Kopírovať</button>
          </div>
        </div>
        <div class="result" id="result"></div>
        <div class="meta"><h3>Nájdené entity (<span id="count">0</span>)</h3></div>
        <div class="badges" id="badges"></div>
      </div>
    </div>
  </div>
<script>
const $ = id => document.getElementById(id);
const esc = s => s.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
async function run(){
  const text=$("text").value, language=$("lang").value;
  $("err").classList.remove("show");
  if(!text.trim()){showErr("Zadaj nejaký text.");return;}
  $("go").disabled=true; $("go").textContent="Spracúvam…";
  try{
    const res=await fetch("/api/anonymize",{method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({text,language})});
    const data=await res.json();
    if(!res.ok){showErr(data.error||"Chyba servera.");return;}
    render(data);
  }catch(e){showErr("Nepodarilo sa spojiť so serverom.");}
  finally{$("go").disabled=false; $("go").textContent="Anonymizovať";}
}
function render(data){
  const html=esc(data.anonymized_text).replace(/&lt;[A-Z_]+&gt;/g,m=>'<span class="tok">'+m+'</span>');
  $("result").innerHTML=html||'<span class="none">—</span>';
  $("count").textContent=data.count;
  const c={}; (data.entities||[]).forEach(e=>c[e.entity_type]=(c[e.entity_type]||0)+1);
  const b=Object.keys(c).sort().map(k=>'<span class="badge">'+k+' ×'+c[k]+'</span>').join("");
  $("badges").innerHTML=b||'<span class="none">Žiadne osobné údaje neboli nájdené.</span>';
  $("out").classList.add("show");
}
function showErr(m){$("err").textContent=m; $("err").classList.add("show");}
$("go").addEventListener("click",run);
$("clear").addEventListener("click",()=>{$("text").value="";$("out").classList.remove("show");$("err").classList.remove("show");});
$("copy").addEventListener("click",async()=>{
  const t=$("result").innerText;
  try{await navigator.clipboard.writeText(t);}
  catch(e){const ta=document.createElement("textarea");ta.value=t;document.body.appendChild(ta);
    ta.select();document.execCommand("copy");document.body.removeChild(ta);}
  $("copied").classList.add("show"); setTimeout(()=>$("copied").classList.remove("show"),1400);
});
</script>
</body>
</html>"""

@app.route("/")
def index():
    return Response(INDEX_HTML, mimetype="text/html")

@app.route("/healthz")
def healthz():
    return "ui ok", 200

@app.route("/api/anonymize", methods=["POST"])
def api_anonymize():
    data = request.get_json(force=True, silent=True) or {}
    text = (data.get("text") or "").strip()
    language = data.get("language") or "en"
    if not text:
        return jsonify({"error": "Prázdny text."}), 400

    try:
        r = requests.post(f"{ANALYZER_URL}/analyze",
                          json={"text": text, "language": language}, timeout=60)
        r.raise_for_status()
        analyzer_results = r.json()
    except requests.HTTPError:
        return jsonify({"error": f"Analyzer vrátil {r.status_code}: {r.text[:200]}"}), 502
    except requests.RequestException as e:
        return jsonify({"error": f"Analyzer nedostupný: {e}"}), 502

    results = [{"entity_type": x["entity_type"], "start": x["start"],
                "end": x["end"], "score": x.get("score", 0.0)} for x in analyzer_results]

    if not results:
        return jsonify({"anonymized_text": text, "entities": [], "count": 0})

    try:
        r = requests.post(f"{ANONYMIZER_URL}/anonymize",
                          json={"text": text, "analyzer_results": results}, timeout=60)
        r.raise_for_status()
        anon = r.json()
    except requests.HTTPError:
        return jsonify({"error": f"Anonymizer vrátil {r.status_code}: {r.text[:200]}"}), 502
    except requests.RequestException as e:
        return jsonify({"error": f"Anonymizer nedostupný: {e}"}), 502

    return jsonify({"anonymized_text": anon.get("text", ""),
                    "entities": results, "count": len(results)})
