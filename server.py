import os
import re
from flask import Flask, request, jsonify, Response
from presidio_analyzer import AnalyzerEngine, RecognizerRegistry, RecognizerResult
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_analyzer.predefined_recognizers import (
    CreditCardRecognizer, IbanRecognizer, EmailRecognizer,
    PhoneRecognizer, IpRecognizer, CryptoRecognizer, UrlRecognizer,
)
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
# Globálne pattern rozpoznávače (karta, IBAN, email, telefón, IP, krypto, URL) sú viazané
# na jazyky z konfigurácie a pre "sk" sa nenačítajú. Doplníme ich ručne:
for _cls in (CreditCardRecognizer, IbanRecognizer, EmailRecognizer,
             PhoneRecognizer, IpRecognizer, CryptoRecognizer, UrlRecognizer):
    registry.add_recognizer(_cls(supported_language="sk"))
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
  :root{--bg:#0a111f;--panel:#0f1729;--panel2:#131d33;--line:#243049;--line2:#2e3c59;
    --ink:#e7ecf5;--muted:#8b9bb4;--muted2:#6b7a96;--accent:#6366f1;--accent2:#4f46e5;--ok:#34d399}
  *{box-sizing:border-box}
  *::-webkit-scrollbar{width:10px;height:10px}
  *::-webkit-scrollbar-thumb{background:var(--line2);border-radius:6px}
  *::-webkit-scrollbar-track{background:transparent}
  body{margin:0;background:var(--bg);color:var(--ink);
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
  .layout{display:flex;min-height:100vh}
  .side{width:300px;flex-shrink:0;background:var(--panel);border-right:1px solid var(--line);
    padding:24px 22px;display:flex;flex-direction:column;gap:20px;position:sticky;top:0;height:100vh;overflow-y:auto}
  .brand{display:flex;align-items:center;gap:11px}
  .logo{width:30px;height:30px;border-radius:8px;flex-shrink:0;
    background:linear-gradient(135deg,var(--accent),#22d3ee);box-shadow:0 4px 14px -4px var(--accent)}
  .brand h1{font-size:15px;margin:0;line-height:1.2}
  .brand p{font-size:11.5px;color:var(--muted);margin:1px 0 0}
  .ctl label{display:block;font-size:12px;font-weight:600;color:var(--muted);
    text-transform:uppercase;letter-spacing:.04em;margin-bottom:7px}
  select{width:100%;padding:10px 12px;background:var(--panel2);color:var(--ink);
    border:1px solid var(--line);border-radius:9px;font-size:14px;outline:none;transition:border-color .15s}
  select:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(99,102,241,.18)}
  .slider-row{display:flex;justify-content:space-between;align-items:baseline;margin-bottom:6px}
  .slider-row .val{color:var(--accent);font-weight:700;font-size:13px}
  input[type=range]{width:100%;accent-color:var(--accent)}
  .scale{display:flex;justify-content:space-between;font-size:11px;color:var(--muted2);margin-top:2px}
  textarea.mini{width:100%;min-height:84px;resize:vertical;background:var(--panel2);color:var(--ink);
    border:1px solid var(--line);border-radius:9px;padding:10px 12px;font-size:13px;line-height:1.5;
    font-family:ui-monospace,Menlo,Consolas,monospace;outline:none;transition:border-color .15s}
  textarea.mini:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(99,102,241,.18)}
  .minihint{font-size:11px;color:var(--muted2);margin:6px 0 0;line-height:1.45}
  button.run{margin-top:auto;background:var(--accent);color:#fff;border:0;border-radius:10px;
    padding:13px;font-size:14px;font-weight:700;cursor:pointer;transition:background .15s,transform .05s}
  button.run:hover{background:var(--accent2)}
  button.run:active{transform:translateY(1px)}
  button.run:disabled{opacity:.7;cursor:default}
  .spin{display:inline-block;width:14px;height:14px;border:2px solid rgba(255,255,255,.4);
    border-top-color:#fff;border-radius:50%;animation:sp .7s linear infinite;vertical-align:-2px;margin-right:7px}
  @keyframes sp{to{transform:rotate(360deg)}}
  .main{flex:1;padding:30px 34px;min-width:0}
  .cols{display:grid;grid-template-columns:1fr 1fr;gap:22px}
  .col-head{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;min-height:30px}
  .col-head h2{margin:0;font-size:13px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted)}
  .head-actions{display:flex;gap:8px}
  .iconbtn{background:var(--panel2);border:1px solid var(--line);color:var(--ink);border-radius:8px;
    padding:6px 11px;font-size:12.5px;font-weight:600;cursor:pointer;transition:.15s}
  .iconbtn:hover:not(:disabled){border-color:var(--accent);color:#c7d2fe}
  .iconbtn:active:not(:disabled){transform:translateY(1px)}
  .iconbtn:disabled{opacity:.4;cursor:default}
  .iconbtn.ok{border-color:var(--ok);color:var(--ok)}
  textarea{width:100%;min-height:280px;resize:vertical;background:var(--panel);color:var(--ink);
    border:1px solid var(--line);border-radius:12px;padding:16px;font-size:14px;line-height:1.6;
    font-family:ui-monospace,Menlo,Consolas,monospace;outline:none;transition:border-color .15s}
  textarea:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(99,102,241,.15)}
  .output{min-height:280px;background:var(--panel);border:1px solid var(--line);border-radius:12px;
    padding:16px;font-size:14px;line-height:1.85;font-family:ui-monospace,Menlo,Consolas,monospace;
    white-space:pre-wrap;word-break:break-word}
  .placeholder{color:var(--muted2)}
  .tok{border-radius:5px;padding:1px 6px;font-weight:700;font-size:13px}
  .err{display:none;margin-top:14px;background:#3b1116;color:#fca5a5;border:1px solid #7f1d1d;
    border-radius:9px;padding:11px 14px;font-size:13px}
  .err.show{display:block}
  .stats{display:flex;flex-wrap:wrap;gap:8px;margin-top:24px}
  .chip{display:inline-block;border-radius:999px;padding:3px 11px;font-size:11.5px;font-weight:700;letter-spacing:.02em}
  .findings{margin-top:18px}
  .findings h2{font-size:13px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);margin:0 0 12px}
  table{width:100%;border-collapse:collapse;font-size:13.5px}
  th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--line)}
  th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.03em}
  tbody tr{transition:background .12s}
  tbody tr:hover{background:rgba(99,102,241,.06)}
  td.type{font-weight:600;color:#a5b4fc}
  td.mono{font-family:ui-monospace,Menlo,monospace}
  .empty{color:var(--muted2);font-size:13px;padding:12px 0}
  .bar{height:5px;border-radius:3px;background:linear-gradient(90deg,var(--accent),#22d3ee);
    display:inline-block;vertical-align:middle;margin-right:8px}
  .restore{margin-top:32px;border-top:1px solid var(--line);padding-top:24px}
  .restore h2{font-size:13px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);margin:0 0 6px}
  .restore .hint{font-size:12.5px;color:var(--muted);margin:0 0 12px;line-height:1.5}
  .restore textarea{min-height:120px}
  .run2{margin-top:12px;background:var(--accent);color:#fff;border:0;border-radius:9px;
    padding:11px 16px;font-size:14px;font-weight:700;cursor:pointer;transition:background .15s}
  .run2:hover{background:var(--accent2)}
  .rest-head{display:none;justify-content:space-between;align-items:center;margin:18px 0 8px}
  .rest-head .rlabel{font-size:12px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
  #mapWrap{margin-top:18px}
  .maptag{font-family:ui-monospace,Menlo,monospace;font-weight:700}
  @media(max-width:880px){.layout{flex-direction:column}.side{width:auto;position:static;height:auto}.cols{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class="layout">
  <aside class="side">
    <div class="brand"><div class="logo"></div><div><h1>PII De-Identification</h1><p>Microsoft Presidio</p></div></div>
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
      <p class="minihint">Minimálna istota nálezu (0–1). Nižšie = nájde aj menej isté veci (viac falošných poplachov); vyššie = len isté nálezy. Regex (karta, IBAN, e-mail) máva skóre ≈1, mená z jazykového modelu zvyčajne nižšie — preto ak mená vypadávajú, prah zníž.</p>
    </div>
    <div class="ctl">
      <label for="customTerms">Vlastné mená / pravidlá</label>
      <textarea id="customTerms" class="mini" placeholder="Jedno meno na riadok, napr.:&#10;Marek Novák&#10;Žofia"></textarea>
      <p class="minihint">Vždy sa označia (bez ohľadu na veľké/malé písmená) a dostanú tag ako ostatné mená.</p>
    </div>
    <div class="ctl">
      <label for="allowList">Nikdy neanonymizovať</label>
      <textarea id="allowList" class="mini" placeholder="Jedna hodnota na riadok, napr.:&#10;Anthropic&#10;Bratislava"></textarea>
      <p class="minihint">Tieto presné hodnoty ostanú v texte aj keď ich model označí (bez ohľadu na veľké/malé písmená).</p>
    </div>
    <button class="run" id="go">Anonymizovať</button>
  </aside>
  <main class="main">
    <div class="cols">
      <div class="col">
        <div class="col-head"><h2>Vstup</h2><div class="head-actions">
          <button class="iconbtn" id="sample">Príklad</button>
          <button class="iconbtn" id="clearIn">Vyčistiť</button>
        </div></div>
        <textarea id="text" placeholder="Vlož text, ktorý chceš anonymizovať…"></textarea>
      </div>
      <div class="col">
        <div class="col-head"><h2>Výstup</h2><button class="iconbtn" id="copyOut" disabled>Kopírovať</button></div>
        <div class="output" id="output"><span class="placeholder">Výsledok sa zobrazí tu.</span></div>
      </div>
    </div>
    <div class="err" id="err"></div>
    <div class="stats" id="stats"></div>
    <div class="findings">
      <h2>Nájdené entity (<span id="count">0</span>)</h2>
      <div id="tableWrap"><div class="empty">Zatiaľ nič — spusti anonymizáciu.</div></div>
    </div>
    <div class="restore" id="restore" style="display:none">
      <h2>De-anonymizácia — mapa žije len v tvojom prehliadači</h2>
      <p class="hint">Vlož text, ktorý ti prišiel späť (napr. odpoveď z LLM) s tagmi typu &lt;Meno1&gt;. Nahradia sa pôvodnými hodnotami z mapy nižšie. Na server sa neposiela nič.</p>
      <textarea id="restoreIn" placeholder="Sem vlož text s tagmi…"></textarea>
      <button class="run2" id="restoreBtn">Obnoviť pôvodné hodnoty</button>
      <div class="rest-head" id="restHead"><span class="rlabel">Obnovený text</span><button class="iconbtn" id="copyRestore">Kopírovať</button></div>
      <div class="output" id="restoreOut" style="display:none"></div>
      <div id="mapWrap"></div>
    </div>
  </main>
</div>
<script>
const $=id=>document.getElementById(id);
const esc=s=>s.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
let pseudoMap=[], lastOutput="";

const ENT_COLORS={
  PERSON:["#332a57","#c4b5fd"],LOCATION:["#0e3a39","#5eead4"],EMAIL_ADDRESS:["#16305c","#93c5fd"],
  PHONE_NUMBER:["#123620","#86efac"],CREDIT_CARD:["#3d2f10","#fcd34d"],IBAN_CODE:["#3a2410","#fdba74"],
  IP_ADDRESS:["#3b1d2a","#fda4af"],DATE_TIME:["#1f2b40","#9fb4d4"],ORGANIZATION:["#2f1d40","#d8b4fe"],
  URL:["#10324a","#7dd3fc"],CRYPTO:["#27340f","#bef264"],NRP:["#3b1526","#fb7185"],US_SSN:["#33223a","#e9a5d8"]
};
const LABEL2TYPE={Meno:"PERSON",Miesto:"LOCATION",Email:"EMAIL_ADDRESS",Telefon:"PHONE_NUMBER",
  Karta:"CREDIT_CARD",IBAN:"IBAN_CODE",IP:"IP_ADDRESS",Datum:"DATE_TIME",Organizacia:"ORGANIZATION",
  Krypto:"CRYPTO",URL:"URL",NRP:"NRP",SSN:"US_SSN"};
function entType(inner){
  if(ENT_COLORS[inner])return inner;
  const m=inner.match(/^([^\d]+?)\d*$/);
  if(m){const b=m[1];if(ENT_COLORS[b])return b;if(LABEL2TYPE[b])return LABEL2TYPE[b];}
  return null;
}
function colorFor(t){return ENT_COLORS[t]||["#243049","#a5b4fc"];}

async function copyText(text,btn){
  let ok=false;
  try{if(navigator.clipboard&&window.isSecureContext){await navigator.clipboard.writeText(text);ok=true;}}catch(e){}
  if(!ok){const ta=document.createElement("textarea");ta.value=text;ta.style.position="fixed";ta.style.opacity="0";
    document.body.appendChild(ta);ta.focus();ta.select();try{ok=document.execCommand("copy");}catch(e){}document.body.removeChild(ta);}
  if(btn){const o=btn.textContent;btn.textContent="✓ Skopírované";btn.classList.add("ok");
    setTimeout(()=>{btn.textContent=o;btn.classList.remove("ok");},1300);}
}

$("threshold").addEventListener("input",e=>$("thVal").textContent=Number(e.target.value).toFixed(2));

async function run(){
  const text=$("text").value;
  $("err").classList.remove("show");
  if(!text.trim()){showErr("Zadaj nejaký text.");return;}
  const custom_terms=$("customTerms").value.split("\n").map(s=>s.trim()).filter(Boolean);
  const allow_list=$("allowList").value.split("\n").map(s=>s.trim()).filter(Boolean);
  $("go").disabled=true;$("go").innerHTML='<span class="spin"></span>Spracúvam…';
  try{
    const res=await fetch("/api/anonymize",{method:"POST",headers:{"Content-Type":"application/json"},
      body:JSON.stringify({text,language:$("lang").value,approach:$("approach").value,
        threshold:parseFloat($("threshold").value),custom_terms,allow_list})});
    const data=await res.json();
    if(!res.ok){showErr(data.error||"Chyba servera.");return;}
    render(data);
  }catch(e){showErr("Nepodarilo sa spojiť so serverom.");}
  finally{$("go").disabled=false;$("go").textContent="Anonymizovať";}
}

function render(data){
  lastOutput=data.anonymized_text||"";
  const html=esc(lastOutput).replace(/&lt;([^&]+?)&gt;/g,(full,inner)=>{
    const c=colorFor(entType(inner));
    return '<span class="tok" style="background:'+c[0]+';color:'+c[1]+'">&lt;'+inner+'&gt;</span>';
  });
  $("output").innerHTML=html||'<span class="placeholder">—</span>';
  $("copyOut").disabled=!lastOutput;
  $("count").textContent=data.count;

  pseudoMap=data.mapping||[];
  if(pseudoMap.length){
    $("restore").style.display="";$("restoreIn").value=lastOutput;
    $("restoreOut").style.display="none";$("restHead").style.display="none";renderMap();
  }else{$("restore").style.display="none";}

  const f=data.findings||[];
  renderStats(f);
  if(!f.length){$("tableWrap").innerHTML='<div class="empty">Žiadne osobné údaje neboli nájdené.</div>';return;}
  const rows=f.map((e,i)=>{const c=colorFor(e.entity_type);const w=Math.max(6,Math.round(e.score*46));
    return '<tr><td>'+i+'</td><td><span class="chip" style="background:'+c[0]+';color:'+c[1]+'">'+esc(e.entity_type)+
      '</span></td><td class="mono">'+esc(e.text)+'</td><td>'+e.start+'</td><td>'+e.end+
      '</td><td><span class="bar" style="width:'+w+'px"></span>'+e.score.toFixed(2)+'</td></tr>';}).join("");
  $("tableWrap").innerHTML='<table><thead><tr><th>#</th><th>Typ entity</th><th>Text</th><th>Začiatok</th><th>Koniec</th><th>Skóre</th></tr></thead><tbody>'+rows+'</tbody></table>';
}

function renderStats(f){
  const by={};f.forEach(e=>by[e.entity_type]=(by[e.entity_type]||0)+1);
  const keys=Object.keys(by).sort();
  $("stats").innerHTML=keys.map(k=>{const c=colorFor(k);
    return '<span class="chip" style="background:'+c[0]+';color:'+c[1]+'">'+esc(k)+' · '+by[k]+'</span>';}).join("");
}

function renderMap(){
  const rows=pseudoMap.map(m=>{const c=colorFor(m.entity_type);
    return '<tr><td><span class="chip maptag" style="background:'+c[0]+';color:'+c[1]+'">'+esc(m.placeholder)+
      '</span></td><td class="mono">'+esc(m.original)+'</td><td class="type">'+esc(m.entity_type)+'</td></tr>';}).join("");
  $("mapWrap").innerHTML='<table><thead><tr><th>Tag</th><th>Pôvodná hodnota</th><th>Typ</th></tr></thead><tbody>'+rows+'</tbody></table>';
}

function restore(){
  let out=$("restoreIn").value;
  pseudoMap.forEach(m=>{out=out.split(m.placeholder).join(m.original);});
  $("restoreOut").textContent=out;
  $("restoreOut").style.display="";$("restHead").style.display="flex";
}

function showErr(m){$("err").textContent=m;$("err").classList.add("show");}

$("go").addEventListener("click",run);
$("restoreBtn").addEventListener("click",restore);
$("copyOut").addEventListener("click",()=>copyText(lastOutput,$("copyOut")));
$("copyRestore").addEventListener("click",()=>copyText($("restoreOut").textContent,$("copyRestore")));
$("clearIn").addEventListener("click",()=>{
  $("text").value="";$("output").innerHTML='<span class="placeholder">Výsledok sa zobrazí tu.</span>';
  $("copyOut").disabled=true;$("count").textContent="0";$("stats").innerHTML="";
  $("tableWrap").innerHTML='<div class="empty">Zatiaľ nič — spusti anonymizáciu.</div>';
  $("restore").style.display="none";$("err").classList.remove("show");lastOutput="";
});
$("sample").addEventListener("click",()=>{
  $("text").value="Volám sa Marek Novák a kolegyňa je Žofia Krajčírová. Bývame v Bratislave. Email: marek.novak@firma.sk, telefón +421 902 123 456. Číslo karty 4095 2609 9393 4932, IBAN SK89 0200 0000 0000 0001 2351.";
  $("lang").value="sk";
});
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
    allow_list = data.get("allow_list") or []
    try:
        threshold = float(data.get("threshold", 0.0))
    except (TypeError, ValueError):
        threshold = 0.0
    if not text:
        return jsonify({"error": "Prázdny text."}), 400

    results = analyzer.analyze(text=text, language=language, score_threshold=threshold)
    results = results + custom_term_results(text, custom_terms)

    # zlúč duplicitné rozsahy (vyššie skóre vyhráva)
    best = {}
    for r in results:
        k = (r.start, r.end)
        if k not in best or r.score > best[k].score:
            best[k] = r
    results = sorted(best.values(), key=lambda r: r.start)

    # výnimky — tieto presné hodnoty sa nikdy neanonymizujú
    allow_lower = {a.strip().lower() for a in allow_list if a and a.strip()}
    if allow_lower:
        results = [r for r in results if text[r.start:r.end].lower() not in allow_lower]

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
