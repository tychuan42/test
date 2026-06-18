import os
import re
from flask import Flask, request, jsonify, Response
from presidio_analyzer import AnalyzerEngine, RecognizerRegistry, RecognizerResult
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig
from presidio_anonymizer.operators import Operator, OperatorType

SUPPORTED_LANGUAGES = ["en", "sk"]

NLP_CONFIG = {
    "nlp_engine_name": "spacy",
    "models": [
        {"lang_code": "en", "model_name": "en_core_web_lg"},
        {"lang_code": "sk", "model_name": "xx_ent_wiki_sm"},
    ],
    "ner_model_configuration": {
        "model_to_presidio_entity_mapping": {
            "PER": "PERSON", "PERSON": "PERSON",
            "LOC": "LOCATION", "LOCATION": "LOCATION", "GPE": "LOCATION",
            "ORG": "ORGANIZATION", "ORGANIZATION": "ORGANIZATION",
            "DATE": "DATE_TIME", "TIME": "DATE_TIME", "NORP": "NRP",
        },
        "low_confidence_score_multiplier": 0.4,
        "low_score_entity_names": ["ORGANIZATION", "ORG"],
    },
}

LABELS = {"PERSON": "Meno", "LOCATION": "Miesto", "EMAIL_ADDRESS": "Email", "PHONE_NUMBER": "Telefon",
          "CREDIT_CARD": "Karta", "IBAN_CODE": "IBAN", "IP_ADDRESS": "IP", "DATE_TIME": "Datum",
          "ORGANIZATION": "Organizacia", "CRYPTO": "Krypto", "URL": "URL", "NRP": "NRP", "US_SSN": "SSN"}


class InstanceCounterAnonymizer(Operator):
    """Každú unikátnu hodnotu nahradí číslovaným tagom, napr. <Meno1>. Rovnaká hodnota = rovnaký tag."""

    def operate(self, text=None, params=None):
        entity_type = params["entity_type"]
        mapping = params["entity_mapping"]
        per_type = mapping.setdefault(entity_type, {})
        if text in per_type:
            return per_type[text]
        placeholder = "<{}{}>".format(LABELS.get(entity_type, entity_type), len(per_type) + 1)
        per_type[text] = placeholder
        return placeholder

    def validate(self, params=None):
        pass

    def operator_name(self):
        return "entity_counter"

    def operator_type(self):
        return OperatorType.Anonymize


# --- engines sa postavia raz pri štarte ---
nlp_engine = NlpEngineProvider(nlp_configuration=NLP_CONFIG).create_engine()
registry = RecognizerRegistry(supported_languages=SUPPORTED_LANGUAGES)
registry.load_predefined_recognizers(nlp_engine=nlp_engine, languages=SUPPORTED_LANGUAGES)
analyzer = AnalyzerEngine(registry=registry, nlp_engine=nlp_engine,
                          supported_languages=SUPPORTED_LANGUAGES)
anonymizer = AnonymizerEngine()
anonymizer.add_anonymizer(InstanceCounterAnonymizer)


def operators(approach):
    if approach == "redact":
        cfg = OperatorConfig("redact", {})
    elif approach == "hash":
        cfg = OperatorConfig("hash", {"hash_type": "sha256"})
    elif approach == "mask":
        cfg = OperatorConfig("mask", {"masking_char": "*", "chars_to_mask": 100, "from_end": False})
    else:
        cfg = OperatorConfig("replace", {})
    return {"DEFAULT": cfg}


def custom_term_results(text, terms):
    """Pre každé vlastné meno/pravidlo nájde všetky výskyty (bez ohľadu na veľkosť písmen) ako PERSON."""
    out = []
    for term in terms:
        term = (term or "").strip()
        if len(term) < 2:
            continue
        for m in re.finditer(re.escape(term), text, flags=re.IGNORECASE):
            out.append(RecognizerResult(entity_type="PERSON", start=m.start(), end=m.end(), score=1.0))
    return out


INDEX_HTML = r"""<!DOCTYPE html>
<html lang="sk">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PII Anonymizer · Presidio</title>
<style>
  :root{--bg:#0b1220;--panel:#0f1729;--panel2:#131d33;--line:#243049;--ink:#e7ecf5;
    --muted:#8b9bb4;--accent:#6366f1;--accent2:#4f46e5;--tok-bg:#3b1d2a;--tok-ink:#fda4af}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--ink);
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
  .layout{display:flex;min-height:100vh}
  .side{width:300px;flex-shrink:0;background:var(--panel);border-right:1px solid var(--line);
    padding:26px 22px;display:flex;flex-direction:column;gap:20px}
  .brand h1{font-size:17px;margin:0 0 2px}
  .brand p{font-size:12px;color:var(--muted);margin:0}
  .ctl label{display:block;font-size:12px;font-weight:600;color:var(--muted);
    text-transform:uppercase;letter-spacing:.04em;margin-bottom:7px}
  select{width:100%;padding:10px 12px;background:var(--panel2);color:var(--ink);
    border:1px solid var(--line);border-radius:9px;font-size:14px;outline:none}
  select:focus{border-color:var(--accent)}
  .slider-row{display:flex;justify-content:space-between;align-items:baseline;margin-bottom:6px}
  .slider-row .val{color:var(--accent);font-weight:700;font-size:13px}
  input[type=range]{width:100%;accent-color:var(--accent)}
  .scale{display:flex;justify-content:space-between;font-size:11px;color:var(--muted);margin-top:2px}
  textarea.mini{width:100%;min-height:92px;resize:vertical;background:var(--panel2);color:var(--ink);
    border:1px solid var(--line);border-radius:9px;padding:10px 12px;font-size:13px;line-height:1.5;
    font-family:ui-monospace,Menlo,Consolas,monospace;outline:none}
  textarea.mini:focus{border-color:var(--accent)}
  .minihint{font-size:11px;color:var(--muted);margin:6px 0 0;line-height:1.45}
  button.run{margin-top:auto;background:var(--accent);color:#fff;border:0;border-radius:10px;
    padding:13px;font-size:14px;font-weight:700;cursor:pointer;transition:background .15s}
  button.run:hover{background:var(--accent2)}
  button.run:disabled{opacity:.6;cursor:default}
  .main{flex:1;padding:30px 34px;min-width:0}
  .cols{display:grid;grid-template-columns:1fr 1fr;gap:22px}
  .col h2{font-size:13px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);margin:0 0 10px}
  textarea{width:100%;min-height:280px;resize:vertical;background:var(--panel);color:var(--ink);
    border:1px solid var(--line);border-radius:12px;padding:16px;font-size:14px;line-height:1.6;
    font-family:ui-monospace,Menlo,Consolas,monospace;outline:none}
  textarea:focus{border-color:var(--accent)}
  .output{min-height:280px;background:var(--panel);border:1px solid var(--line);border-radius:12px;
    padding:16px;font-size:14px;line-height:1.7;font-family:ui-monospace,Menlo,Consolas,monospace;
    white-space:pre-wrap;word-break:break-word}
  .placeholder{color:var(--muted)}
  .tok{background:var(--tok-bg);color:var(--tok-ink);border-radius:5px;padding:1px 5px;font-weight:700}
  .err{display:none;margin-top:14px;background:#3b1116;color:#fca5a5;border:1px solid #7f1d1d;
    border-radius:9px;padding:11px 14px;font-size:13px}
  .err.show{display:block}
  .findings{margin-top:30px}
  .findings h2{font-size:13px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);margin:0 0 12px}
  table{width:100%;border-collapse:collapse;font-size:13.5px}
  th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--line)}
  th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.03em}
  td.type{font-weight:600;color:#a5b4fc}
  td.mono{font-family:ui-monospace,Menlo,monospace}
  .empty{color:var(--muted);font-size:13px;padding:12px 0}
  .bar{height:5px;border-radius:3px;background:linear-gradient(90deg,var(--accent),#22d3ee);
    display:inline-block;vertical-align:middle;margin-right:8px}
  .restore{margin-top:30px}
  .restore h2{font-size:13px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);margin:0 0 6px}
  .restore .hint{font-size:12.5px;color:var(--muted);margin:0 0 12px;line-height:1.5}
  .restore textarea{min-height:120px}
  .run2{margin-top:12px;background:var(--accent);color:#fff;border:0;border-radius:9px;
    padding:11px 16px;font-size:14px;font-weight:700;cursor:pointer}
  .run2:hover{background:var(--accent2)}
  #mapWrap{margin-top:18px}
  .maptag{font-family:ui-monospace,Menlo,monospace;color:#a5b4fc;font-weight:700}
  @media(max-width:880px){.layout{flex-direction:column}.side{width:auto}.cols{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class="layout">
  <aside class="side">
    <div class="brand"><h1>PII De-Identification</h1><p>Microsoft Presidio</p></div>
    <div class="ctl">
      <label for="lang">Jazyk</label>
      <select id="lang"><option value="en" selected>English</option><option value="sk">Slovenčina</option></select>
    </div>
    <div class="ctl">
      <label for="approach">Spôsob anonymizácie</label>
      <select id="approach">
        <option value="replace" selected>Nahradiť značkou (&lt;TYP&gt;)</option>
        <option value="redact">Odstrániť</option>
        <option value="mask">Maskovať (****)</option>
        <option value="hash">Hash (SHA-256)</option>
        <option value="pseudonymize">Pseudonymizovať (&lt;Meno1&gt;, zvratné)</option>
      </select>
    </div>
    <div class="ctl">
      <div class="slider-row"><label style="margin:0">Prah dôveryhodnosti</label><span class="val" id="thVal">0.35</span></div>
      <input type="range" id="threshold" min="0" max="1" step="0.05" value="0.35">
      <div class="scale"><span>0.00</span><span>1.00</span></div>
    </div>
    <div class="ctl">
      <label for="customTerms">Vlastné mená / pravidlá</label>
      <textarea id="customTerms" class="mini" placeholder="Jedno meno na riadok, napr.:&#10;Marek Novák&#10;Žofia"></textarea>
      <p class="minihint">Vždy sa označia (bez ohľadu na veľké/malé písmená) a dostanú tag ako ostatné mená.</p>
    </div>
    <button class="run" id="go">Anonymizovať</button>
  </aside>
  <main class="main">
    <div class="cols">
      <div class="col"><h2>Vstup</h2><textarea id="text" placeholder="Vlož text, ktorý chceš anonymizovať…"></textarea></div>
      <div class="col"><h2>Výstup</h2><div class="output" id="output"><span class="placeholder">Výsledok sa zobrazí tu.</span></div></div>
    </div>
    <div class="err" id="err"></div>
    <div class="findings">
      <h2>Nájdené entity (<span id="count">0</span>)</h2>
      <div id="tableWrap"><div class="empty">Zatiaľ nič — spusti anonymizáciu.</div></div>
    </div>
    <div class="restore" id="restore" style="display:none">
      <h2>De-anonymizácia — mapa žije len v tvojom prehliadači</h2>
      <p class="hint">Vlož text, ktorý ti prišiel späť (napr. odpoveď z LLM) s tagmi typu &lt;Meno1&gt;. Nahradia sa pôvodnými hodnotami z mapy nižšie. Na server sa neposiela nič.</p>
      <textarea id="restoreIn" placeholder="Sem vlož text s tagmi…"></textarea>
      <button class="run2" id="restoreBtn">Obnoviť pôvodné hodnoty</button>
      <div class="output" id="restoreOut" style="margin-top:14px;display:none"></div>
      <div id="mapWrap"></div>
    </div>
  </main>
</div>
<script>
const $=id=>document.getElementById(id);
const esc=s=>s.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
let pseudoMap=[];
$("threshold").addEventListener("input",e=>$("thVal").textContent=Number(e.target.value).toFixed(2));
async function run(){
  const text=$("text").value;
  $("err").classList.remove("show");
  if(!text.trim()){showErr("Zadaj nejaký text.");return;}
  const customTerms=$("customTerms").value.split("\n").map(s=>s.trim()).filter(Boolean);
  $("go").disabled=true;$("go").textContent="Spracúvam…";
  try{
    const res=await fetch("/api/anonymize",{method:"POST",headers:{"Content-Type":"application/json"},
      body:JSON.stringify({text,language:$("lang").value,approach:$("approach").value,
        threshold:parseFloat($("threshold").value),custom_terms:customTerms})});
    const data=await res.json();
    if(!res.ok){showErr(data.error||"Chyba servera.");return;}
    render(data);
  }catch(e){showErr("Nepodarilo sa spojiť so serverom.");}
  finally{$("go").disabled=false;$("go").textContent="Anonymizovať";}
}
function render(data){
  let html=esc(data.anonymized_text).replace(/&lt;[^&]+?&gt;/g,m=>'<span class="tok">'+m+'</span>');
  $("output").innerHTML=html||'<span class="placeholder">—</span>';
  $("count").textContent=data.count;
  pseudoMap=data.mapping||[];
  if(pseudoMap.length){
    $("restore").style.display="";
    $("restoreIn").value=data.anonymized_text;
    $("restoreOut").style.display="none";
    renderMap();
  }else{$("restore").style.display="none";}
  const f=data.findings||[];
  if(!f.length){$("tableWrap").innerHTML='<div class="empty">Žiadne osobné údaje neboli nájdené.</div>';return;}
  const rows=f.map((e,i)=>{const w=Math.max(6,Math.round(e.score*46));
    return '<tr><td>'+i+'</td><td class="type">'+esc(e.entity_type)+'</td><td class="mono">'+esc(e.text)+
      '</td><td>'+e.start+'</td><td>'+e.end+'</td><td><span class="bar" style="width:'+w+'px"></span>'+e.score.toFixed(2)+'</td></tr>';}).join("");
  $("tableWrap").innerHTML='<table><thead><tr><th>#</th><th>Typ entity</th><th>Text</th><th>Začiatok</th><th>Koniec</th><th>Skóre</th></tr></thead><tbody>'+rows+'</tbody></table>';
}
function renderMap(){
  const rows=pseudoMap.map(m=>'<tr><td class="maptag">'+esc(m.placeholder)+'</td><td class="mono">'+esc(m.original)+'</td><td class="type">'+esc(m.entity_type)+'</td></tr>').join("");
  $("mapWrap").innerHTML='<table><thead><tr><th>Tag</th><th>Pôvodná hodnota</th><th>Typ</th></tr></thead><tbody>'+rows+'</tbody></table>';
}
function restore(){
  let out=$("restoreIn").value;
  pseudoMap.forEach(m=>{out=out.split(m.placeholder).join(m.original);});
  $("restoreOut").textContent=out;
  $("restoreOut").style.display="";
}
function showErr(m){$("err").textContent=m;$("err").classList.add("show");}
$("go").addEventListener("click",run);
$("restoreBtn").addEventListener("click",restore);
</script>
</body>
</html>"""

app = Flask(__name__)


@app.route("/api/anonymize", methods=["POST"])
def api_anonymize():
    data = request.get_json(force=True, silent=True) or {}
    text = (data.get("text") or "").strip()
    language = data.get("language") if data.get("language") in SUPPORTED_LANGUAGES else "en"
    approach = data.get("approach") or "replace"
    custom_terms = data.get("custom_terms") or []
    try:
        threshold = float(data.get("threshold", 0.0))
    except (TypeError, ValueError):
        threshold = 0.0
    if not text:
        return jsonify({"error": "Prázdny text."}), 400

    results = analyzer.analyze(text=text, language=language, score_threshold=threshold)
    results = results + custom_term_results(text, custom_terms)

    # odstráň duplicitné rozsahy (nechaj vyššie skóre) — napr. keď to chytí model aj vlastné pravidlo
    best = {}
    for r in results:
        k = (r.start, r.end)
        if k not in best or r.score > best[k].score:
            best[k] = r
    results = sorted(best.values(), key=lambda r: r.start)

    findings = [{"entity_type": r.entity_type, "text": text[r.start:r.end],
                 "start": r.start, "end": r.end, "score": round(r.score, 2)} for r in results]

    if approach == "pseudonymize":
        entity_mapping = {}
        anon = anonymizer.anonymize(
            text=text, analyzer_results=results,
            operators={"DEFAULT": OperatorConfig("entity_counter", {"entity_mapping": entity_mapping})})
        mapping = [{"placeholder": ph, "original": orig, "entity_type": et}
                   for et, d in entity_mapping.items() for orig, ph in d.items()]
        return jsonify({"anonymized_text": anon.text, "findings": findings,
                        "count": len(findings), "mapping": mapping})

    anon = anonymizer.anonymize(text=text, analyzer_results=results, operators=operators(approach))
    return jsonify({"anonymized_text": anon.text, "findings": findings,
                    "count": len(findings), "mapping": []})


@app.route("/healthz")
def healthz():
    return "ok", 200


@app.route("/")
def index():
    return Response(INDEX_HTML, mimetype="text/html")
