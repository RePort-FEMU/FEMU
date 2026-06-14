#!/usr/bin/env python3
"""
FEMU Web UI — browse, filter and delete batch emulation output.
Usage: python femu-web.py [output_dir] [--port 5000] [--no-browser]
"""

import argparse, json, shutil, socket, sys
from pathlib import Path
from flask import Flask, jsonify, request, Response

app = Flask(__name__)
OUTPUT_DIR: Path = Path(".")

# ── Data ───────────────────────────────────────────────────────────────────────

def load_findings(fw_dir: Path) -> tuple[dict, Path | None]:
    log = fw_dir / "container.log"
    log = log if log.exists() else None
    direct = fw_dir / "findings.json"
    if direct.exists():
        try:
            return json.loads(direct.read_text()), log
        except Exception:
            pass
    if (fw_dir / "workDir").is_dir():
        for c in sorted((fw_dir / "workDir").glob("*/findings.json")):
            try:
                f = json.loads(c.read_text())
                if log is None:
                    wlog = c.parent / "qemu.verify.serial.log"
                    if wlog.exists():
                        log = wlog
                return f, log
            except Exception:
                continue
    return {"stage": "unknown"}, log

def _is_fw(d: Path) -> bool:
    # A firmware run directory: has findings.json, or — for runs that timed out
    # or crashed before findings were written — a container.log / workDir.
    if (d / "findings.json").exists() or (d / "container.log").exists():
        return True
    return (d / "workDir").is_dir()

def _load_summary() -> dict[tuple[str, str], str]:
    """Map (brand, name) -> stage from the batch summary.json, for runs that
    have no findings.json of their own (e.g. timeout / unknown)."""
    sp = OUTPUT_DIR / "summary.json"
    out: dict[tuple[str, str], str] = {}
    if not sp.exists():
        return out
    try:
        rows = json.loads(sp.read_text())
    except Exception:
        return out
    for r in rows if isinstance(rows, list) else []:
        fw = Path(str(r.get("firmware", "")))
        if not fw.name:
            continue
        brand = fw.parent.name or "(root)"
        out[(brand, fw.stem)] = r.get("stage", "unknown")
    return out

def _discover_logs(fw_dir: Path) -> list[dict]:
    logs = []
    if (fw_dir / "container.log").exists():
        logs.append({"label": "Container", "path": str(fw_dir / "container.log")})

    def _kernel_logs(base: Path) -> list[dict]:
        result = []
        kl = base / "kernelLogs"
        if kl.is_dir():
            for p in sorted(kl.glob("*.log")):
                label = p.name
                if label.startswith("qemu."):
                    label = label[5:]
                if label.endswith(".serial.log"):
                    label = label[:-11]
                elif label.endswith(".log"):
                    label = label[:-4]
                result.append({"label": label, "path": str(p)})
        return result

    logs.extend(_kernel_logs(fw_dir))
    wd = fw_dir / "workDir"
    if wd.is_dir():
        for sub in sorted(wd.iterdir()):
            if sub.is_dir():
                logs.extend(_kernel_logs(sub))
    return logs

def _entry(brand: str, name: str, findings: dict, fw_dir: Path,
           stage_fallback: str | None = None) -> dict:
    emu   = findings.get("emulation") or {}
    net   = findings.get("network") or {}
    inj   = findings.get("initInjection") or {}
    cands = net.get("candidates", [])
    reach = net.get("reachability") or {}
    tcp   = sorted({p["port"] for p in net.get("ports", [])
                    if isinstance(p, dict) and p.get("proto") == "tcp" and p.get("port")})
    logs  = _discover_logs(fw_dir)
    stage = findings.get("stage", "unknown")
    # When this run produced no findings.json, fall back to the batch summary
    # so timeout / unknown runs still get their real stage instead of "unknown".
    if stage == "unknown" and stage_fallback:
        stage = stage_fallback
    return {
        "brand": brand, "name": name,
        "stage": stage,
        "ip":    cands[0].get("ip","") if cands and isinstance(cands[0], dict) else "",
        "arch":  f"{emu.get('architecture','')}{emu.get('endianness','')}",
        "initArg":     emu.get("initArg",""),
        "injected":    inj.get("modifiedGuestFile",""),
        "networkType": net.get("networkType",""),
        "bridge": net.get("netBridge",""), "iface": net.get("netInterface",""),
        "ips":    [c["ip"] for c in cands if isinstance(c, dict) and c.get("ip")],
        "ping":    reach.get("ping", False),
        "service": reach.get("service", False),
        "ports":   tcp[:20],
        "services_count": len(findings.get("services") or {}),
        "services_list": sorted({k.split("/")[-1] for k in (findings.get("services") or {}).keys() if k}),
        "has_log": bool(logs),
        "log_path": logs[0]["path"] if logs else "",
        "logs": logs,
    }

def scan() -> list[dict]:
    summary = _load_summary()
    out = []
    for item in sorted(OUTPUT_DIR.iterdir()):
        if item.name in ("summary.json", "images") or not item.is_dir():
            continue
        if _is_fw(item):
            f, _ = load_findings(item)
            out.append(_entry("(root)", item.name, f, item, summary.get(("(root)", item.name))))
        else:
            for fw in sorted(item.iterdir()):
                if fw.is_dir() and _is_fw(fw):
                    f, _ = load_findings(fw)
                    out.append(_entry(item.name, fw.name, f, fw, summary.get((item.name, fw.name))))
    return out

# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return HTML

@app.route("/api/data")
def api_data():
    return jsonify({"dir": str(OUTPUT_DIR), "entries": scan()})

@app.route("/api/delete", methods=["POST"])
def api_delete():
    d = request.get_json(force=True) or {}
    brand, name = d.get("brand",""), d.get("name","")
    if name:
        target = OUTPUT_DIR / name if brand == "(root)" else OUTPUT_DIR / brand / name
    elif brand and brand != "(root)":
        target = OUTPUT_DIR / brand
    else:
        return jsonify({"ok": False, "error": "Invalid target"}), 400
    target = target.resolve()
    if not str(target).startswith(str(OUTPUT_DIR.resolve())):
        return jsonify({"ok": False, "error": "Forbidden"}), 403
    if not target.exists():
        return jsonify({"ok": False, "error": "Not found"}), 404
    try:
        shutil.rmtree(target)
        return jsonify({"ok": True})
    except PermissionError as e:
        return jsonify({"ok": False, "error": str(e), "need_sudo": True}), 403

@app.route("/api/log")
def api_log():
    p = Path(request.args.get("path","")).resolve()
    if not str(p).startswith(str(OUTPUT_DIR.resolve())):
        return "Forbidden", 403
    if not p.exists():
        return "Not found", 404
    try:
        text = p.read_text(errors="replace")
    except PermissionError:
        return "Permission denied", 403
    resp = Response(text, mimetype="text/plain")
    if request.args.get("download"):
        resp.headers["Content-Disposition"] = f'attachment; filename="{p.name}"'
    return resp

@app.route("/api/logsearch")
def api_logsearch():
    q = request.args.get("q","").lower().strip()
    if not q:
        return jsonify([])
    matches = []
    for entry in scan():
        lp = entry.get("log_path", "")
        if not lp:
            continue
        p = Path(lp).resolve()
        if not str(p).startswith(str(OUTPUT_DIR.resolve())):
            continue
        try:
            if q in p.read_text(errors="replace").lower():
                matches.append({"brand": entry["brand"], "name": entry["name"]})
        except (PermissionError, OSError):
            continue
    return jsonify(matches)

# ── HTML ───────────────────────────────────────────────────────────────────────

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>FEMU Results</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
<style>
:root {
  --bg:#0d1117; --surf:#161b22; --surf2:#1c2128;
  --border:#30363d; --text:#e6edf3; --muted:#8b949e;
  --green:#3fb950; --yellow:#d29922; --red:#f85149;
  --purple:#a371f7; --blue:#58a6ff;
}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,sans-serif;font-size:14px;}

/* Header */
header{display:flex;align-items:center;gap:12px;padding:10px 20px;background:var(--surf);border-bottom:1px solid var(--border);position:sticky;top:0;z-index:20;}
header h1{font-size:16px;white-space:nowrap;}
#hdr-dir{color:var(--muted);font-size:12px;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.btn{background:var(--surf2);border:1px solid var(--border);color:var(--text);padding:4px 12px;border-radius:6px;cursor:pointer;font-size:13px;}
.btn:hover{border-color:var(--blue);}
.btn.danger{border-color:#6e3535;color:var(--red);}
.btn.danger:hover{background:var(--red);color:#fff;border-color:var(--red);}

/* Stats row */
.stats-row{display:flex;gap:16px;padding:16px 20px;border-bottom:1px solid var(--border);}
.chart-wrap{flex:1;display:flex;gap:8px;height:220px;}
.chart-box{flex:1;position:relative;overflow:hidden;background:var(--surf);border:1px solid var(--border);border-radius:8px;padding:12px 16px;height:100%;}
.stat-cards{flex:1;display:grid;grid-template-columns:repeat(2,1fr);gap:6px;align-content:start;}
.stat-card{background:var(--surf);border:1px solid var(--border);border-radius:8px;padding:9px 14px;display:flex;flex-direction:column;justify-content:center;}
.sv{font-size:22px;font-weight:700;line-height:1.2;}
.sl{font-size:10px;color:var(--muted);margin-top:2px;white-space:nowrap;}
.sv.g{color:var(--green);} .sv.y{color:var(--yellow);} .sv.r{color:var(--red);} .sv.b{color:var(--blue);}


/* Filters */
.filters{display:flex;gap:8px;padding:8px 20px;background:var(--surf);border-bottom:1px solid var(--border);flex-wrap:wrap;align-items:center;}
.filters input,.filters select{background:var(--bg);border:1px solid var(--border);color:var(--text);padding:5px 10px;border-radius:6px;font-size:13px;}
.filters input{flex:1;min-width:160px;outline:none;}
.filters input:focus{border-color:var(--blue);}
#fc{color:var(--muted);font-size:12px;margin-left:auto;}

/* Table */
.tbl-wrap{overflow-x:auto;}
table{width:100%;border-collapse:collapse;}
th{padding:7px 12px;background:var(--surf);text-align:left;font-size:12px;color:var(--muted);border-bottom:1px solid var(--border);white-space:nowrap;cursor:pointer;user-select:none;}
th:hover{color:var(--text);}
th.sa::after{content:" ↑";} th.sd::after{content:" ↓";}
tr.fr{cursor:pointer;}
tr.fr:hover td{background:var(--surf2);}
tr.fr td{padding:6px 12px;border-bottom:1px solid var(--border);font-size:13px;white-space:nowrap;}
td.fw-name{font-family:monospace;font-size:12px;max-width:260px;overflow:hidden;text-overflow:ellipsis;}
td.act{width:40px;text-align:center;}
.badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:600;color:#fff;white-space:nowrap;}
.xbtn{background:none;border:1px solid transparent;color:var(--muted);padding:2px 6px;border-radius:4px;cursor:pointer;font-size:13px;}
.xbtn:hover{background:var(--red);color:#fff;border-color:var(--red);}

/* Detail row */
tr.dr td{padding:0;}
tr.dr.h{display:none;}
.dbox{background:var(--surf2);padding:12px 20px 16px;border-bottom:1px solid var(--border);}
.dgrid{display:flex;flex-wrap:wrap;gap:8px 28px;margin-bottom:10px;font-size:13px;}
.dgrid>div>span{color:var(--muted);font-size:11px;display:block;}
.ok{color:var(--green);} .fail{color:var(--red);}
.lgrp{display:inline-flex;}
.lbtn{background:none;border:1px solid var(--border);border-right:none;color:var(--blue);padding:3px 10px;border-radius:4px 0 0 4px;cursor:pointer;font-size:12px;}
.lbtn:hover{border-color:var(--blue);background:var(--surf);}
.dlbtn{display:inline-flex;align-items:center;background:none;border:1px solid var(--border);color:var(--muted);padding:3px 8px;border-radius:0 4px 4px 0;cursor:pointer;}
.dlbtn:hover{border-color:var(--blue);color:var(--blue);background:var(--surf);}
pre.log{background:var(--bg);border:1px solid var(--border);padding:8px 12px;margin-top:8px;border-radius:4px;font-size:11px;max-height:280px;overflow-y:auto;white-space:pre-wrap;word-break:break-all;color:var(--muted);display:none;}

/* Modal */
.overlay{position:fixed;inset:0;background:rgba(0,0,0,.6);display:flex;align-items:center;justify-content:center;z-index:100;}
.overlay.h{display:none;}
.mbox{background:var(--surf);border:1px solid var(--border);border-radius:10px;padding:22px 24px;max-width:380px;width:90%;}
.mbox p{margin-bottom:18px;line-height:1.5;}
.mrow{display:flex;gap:8px;justify-content:flex-end;}

.empty{padding:40px;text-align:center;color:var(--muted);}
.h{display:none;}
</style>
</head>
<body>

<header>
  <h1>⚡ FEMU Results</h1>
  <span id="hdr-dir"></span>
  <button class="btn" onclick="loadData()">↻ Refresh</button>
</header>

<div class="stats-row">
  <div class="chart-wrap" id="chart-wrap">
    <div class="chart-box"><canvas id="chart"></canvas></div>
    <div class="chart-box"><canvas id="chart2"></canvas></div>
    <div class="chart-box" style="flex:1.5"><canvas id="chart3"></canvas></div>
  </div>
  <div class="stat-cards" id="stat-cards"></div>
</div>

<div class="filters">
  <input id="search" type="search" placeholder="Search firmware…" oninput="applyFilters()">
  <select id="fBrand" onchange="applyFilters()"><option value="">All brands</option></select>
  <select id="fStage" onchange="applyFilters()">
    <option value="">All stages</option>
    <option value="success">success</option>
    <option value="partial_success">partial_success</option>
    <option value="probe_failed">probe_failed</option>
    <option value="extraction_failed">extraction_failed</option>
    <option value="prepare_failed">prepare_failed</option>
    <option value="timeout">timeout</option>
    <option value="unknown">unknown</option>
  </select>
  <button class="btn danger h" id="delBrandBtn" onclick="deleteBrand()">Delete brand</button>
  <input id="logSearch" type="search" placeholder="Search in logs…" oninput="onLogSearch()" style="min-width:180px;">
  <span id="logSpinner" style="color:var(--muted);font-size:12px;display:none">Searching…</span>
  <span id="fc"></span>
</div>

<div class="tbl-wrap">
<table>
  <thead><tr>
    <th data-col="brand">Brand</th>
    <th data-col="stage">Stage</th>
    <th data-col="ip">IP</th>
    <th data-col="arch">Arch</th>
    <th data-col="networkType">Network</th>
    <th data-col="ping">Reach</th>
    <th data-col="ports" style="text-align:right">Ports</th>
    <th data-col="services_count">Services</th>
    <th data-col="initArg">Init</th>
    <th data-col="name">Firmware</th>
    <th></th>
  </tr></thead>
  <tbody id="tbody"></tbody>
</table>
</div>

<div class="overlay h" id="modal">
  <div class="mbox">
    <p id="modal-msg"></p>
    <div class="mrow">
      <button class="btn" onclick="closeModal()">Cancel</button>
      <button class="btn danger" id="modal-ok">Delete</button>
    </div>
  </div>
</div>

<script>
const SC = {
  success:'#2ea043', partial_success:'#9e6a03',
  probe_failed:'#cf222e', extraction_failed:'#8957e5',
  prepare_failed:'#e3652a', timeout:'#1f6feb', unknown:'#6e7681',
};
const SORDER = ['success','partial_success','probe_failed',
                'extraction_failed','prepare_failed','timeout','unknown'];

let all=[], cur=[], sortCol='brand', sortDir=1, openRow=-1;
let chart=null, chart2=null, chart3=null, pending=null;
let logMatches=null, logDebounce=null;

function h(s){ return String(s??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

// ── Load ───────────────────────────────────────────────────────────────────
async function loadData(){
  document.getElementById('tbody').innerHTML='<tr><td colspan="11" class="empty">Loading…</td></tr>';
  try {
    const data = await fetch('/api/data').then(r=>r.json());
    all = data.entries;
    document.getElementById('hdr-dir').textContent = data.dir;
    const brands = [...new Set(all.map(e=>e.brand))].sort();
    document.getElementById('fBrand').innerHTML = '<option value="">All brands</option>' +
      brands.map(b=>`<option>${h(b)}</option>`).join('');
    applyFilters();
  } catch(e) {
    document.getElementById('tbody').innerHTML=`<tr><td colspan="11" class="empty">Error: ${e}</td></tr>`;
  }
}

// ── Log search ─────────────────────────────────────────────────────────────
function onLogSearch(){
  clearTimeout(logDebounce);
  const q=document.getElementById('logSearch').value.trim();
  if(!q){ logMatches=null; applyFilters(); return; }
  logDebounce=setTimeout(async()=>{
    document.getElementById('logSpinner').style.display='';
    try{
      const res=await fetch(`/api/logsearch?q=${encodeURIComponent(q)}`);
      const list=await res.json();
      logMatches=new Set(list.map(m=>m.brand+'|'+m.name));
    }catch(e){ logMatches=new Set(); }
    document.getElementById('logSpinner').style.display='none';
    applyFilters();
  }, 400);
}

// ── Filters ────────────────────────────────────────────────────────────────
function applyFilters(){
  const q  = document.getElementById('search').value.toLowerCase();
  const fb = document.getElementById('fBrand').value;
  const fs = document.getElementById('fStage').value;
  const sortKey = e => {
    if(sortCol==='ports') return e.ports.length;
    if(sortCol==='services_count') return e.services_count;
    if(sortCol==='ping') return (e.ping?2:0)+(e.service?1:0);
    return String(e[sortCol]??'');
  };
  cur = all.filter(e=>
    (!q  || e.name.toLowerCase().includes(q) || e.brand.toLowerCase().includes(q)) &&
    (!fb || e.brand===fb) &&
    (!fs || e.stage===fs) &&
    (!logMatches || logMatches.has(e.brand+'|'+e.name))
  ).sort((a,b)=>{
    const av=sortKey(a), bv=sortKey(b);
    return av<bv?-sortDir: av>bv?sortDir: 0;
  });
  document.getElementById('fc').textContent = `${cur.length} / ${all.length}`;
  const btn = document.getElementById('delBrandBtn');
  if(fb && fb!=='(root)'){ btn.textContent=`Delete brand "${fb}"`; btn.classList.remove('h'); }
  else btn.classList.add('h');
  renderTable(cur);
  try {
    renderStats(cur);
    renderChart(cur);
    renderArchChart(cur);
    renderServicesChart(cur);
  } catch(err){ console.error('chart render failed:', err); }
  openRow=-1;
}

// ── Stats ──────────────────────────────────────────────────────────────────
function renderStats(entries){
  const c={}; SORDER.forEach(s=>c[s]=0);
  entries.forEach(e=>c[e.stage]=(c[e.stage]||0)+1);
  const n=entries.length, suc=c.success||0, par=c.partial_success||0;
  const fail=(c.probe_failed||0)+(c.extraction_failed||0)+(c.prepare_failed||0)+(c.timeout||0);
  const pctSuc=n?Math.round(100*suc/n):0;
  const pctCov=n?Math.round(100*(suc+par)/n):0;
  const pingN=entries.filter(e=>e.ping).length;
  const webN=entries.filter(e=>e.service).length;
  const reachN=entries.filter(e=>e.ping||e.service).length;
  const reachPct=n?Math.round(100*reachN/n):0;
  const withSvc=entries.filter(e=>e.services_count>0).length;
  const pctWeb=n?Math.round(100*webN/n):0;
  document.getElementById('stat-cards').innerHTML=[
    ['Total',          n,          ''],
    ['With services',  withSvc,    withSvc?'b':''],
    ['Pingable',       pingN,      pingN?'g':''],
    ['Failed',         fail,       fail?'r':''],
    ['Web reachable',  webN,       webN?'g':''],
    ['Web %',      pctWeb+'%', pctWeb>=50?'g':pctWeb>=20?'y':'r'],
    ['Reachable',      reachN,     reachN?'g':''],
    ['Reachable %',    reachPct+'%', reachPct>=50?'g':reachPct>=20?'y':'r'],
  ].map(([l,v,col])=>`<div class="stat-card"><div class="sv ${col}">${v}</div><div class="sl">${l}</div></div>`).join('');
}

// ── Chart ──────────────────────────────────────────────────────────────────
function renderChart(entries){
  if(typeof Chart==='undefined') return;
  const c={}; SORDER.forEach(s=>c[s]=0);
  entries.forEach(e=>c[e.stage]=(c[e.stage]||0)+1);
  const active=SORDER.filter(s=>c[s]>0);
  if(chart){chart.destroy();chart=null;}
  const canvas=document.getElementById('chart');
  if(!canvas||!active.length) return;
  chart=new Chart(canvas,{
    type:'doughnut',
    data:{
      labels:active.map(s=>s.replace(/_/g,' ')),
      datasets:[{data:active.map(s=>c[s]),backgroundColor:active.map(s=>SC[s]||'#6e7681'),borderWidth:2,borderColor:'#161b22'}]
    },
    options:{
      responsive:true,maintainAspectRatio:false,
      plugins:{
        legend:{position:'right',labels:{color:'#e6edf3',boxWidth:12,padding:10,font:{size:13}}},
        tooltip:{callbacks:{label:ctx=>` ${ctx.label}: ${ctx.raw}`}},
        title:{display:true,text:'Stage Distribution',color:'#8b949e',font:{size:11},padding:{bottom:4}}
      }
    }
  });
}

// ── Arch chart ─────────────────────────────────────────────────────────────
function renderArchChart(entries){
  if(typeof Chart==='undefined') return;
  if(chart2){chart2.destroy();chart2=null;}
  const counts={};
  entries.forEach(e=>{ if(e.arch) counts[e.arch]=(counts[e.arch]||0)+1; });
  const arches=Object.keys(counts).sort();
  const canvas=document.getElementById('chart2');
  if(!canvas||!arches.length) return;
  const COLORS=['#58a6ff','#3fb950','#e3652a','#d29922','#a371f7','#db61a2','#1f6feb','#8b949e'];
  chart2=new Chart(canvas,{
    type:'doughnut',
    data:{
      labels:arches,
      datasets:[{data:arches.map(a=>counts[a]),backgroundColor:arches.map((_,i)=>COLORS[i%COLORS.length]),borderWidth:2,borderColor:'#161b22'}]
    },
    options:{
      responsive:true,maintainAspectRatio:false,
      plugins:{
        legend:{position:'right',labels:{color:'#e6edf3',boxWidth:12,padding:10,font:{size:13}}},
        tooltip:{callbacks:{label:ctx=>` ${ctx.label}: ${ctx.raw}`}},
        title:{display:true,text:'Architecture',color:'#8b949e',font:{size:11},padding:{bottom:4}}
      }
    }
  });
}

// ── Services chart ─────────────────────────────────────────────────────────
function renderServicesChart(entries){
  if(typeof Chart==='undefined') return;
  if(chart3){chart3.destroy();chart3=null;}
  const counts={};
  entries.forEach(e=>{ (e.services_list||[]).forEach(s=>{ counts[s]=(counts[s]||0)+1; }); });
  const sorted=Object.entries(counts).sort((a,b)=>b[1]-a[1]).slice(0,12);
  const canvas=document.getElementById('chart3');
  if(!canvas) return;
  if(!sorted.length){
    const ctx=canvas.getContext('2d');
    ctx.clearRect(0,0,canvas.width,canvas.height);
    return;
  }
  const COLORS=['#58a6ff','#3fb950','#e3652a','#d29922','#a371f7','#db61a2','#1f6feb','#8b949e'];
  chart3=new Chart(canvas,{
    type:'bar',
    data:{
      labels:sorted.map(([s])=>s),
      datasets:[{data:sorted.map(([,n])=>n),backgroundColor:sorted.map((_,i)=>COLORS[i%COLORS.length]),borderWidth:0,borderRadius:3}]
    },
    options:{
      indexAxis:'y',
      responsive:true,maintainAspectRatio:false,
      plugins:{
        legend:{display:false},
        tooltip:{callbacks:{label:ctx=>` ${ctx.raw} firmware`}},
        title:{display:true,text:'Services found',color:'#8b949e',font:{size:11},padding:{bottom:4}}
      },
      scales:{
        x:{ticks:{color:'#8b949e',font:{size:10}},grid:{color:'#21262d'},border:{display:false}},
        y:{ticks:{color:'#e6edf3',font:{size:11}},grid:{display:false},border:{display:false}}
      }
    }
  });
}

// ── Table ──────────────────────────────────────────────────────────────────
function renderTable(entries){
  if(!entries.length){
    document.getElementById('tbody').innerHTML='<tr><td colspan="11" class="empty">No results</td></tr>';
    return;
  }
  const TRASH=`<svg width="13" height="13" viewBox="0 0 16 16" fill="currentColor"><path d="M6.5 1h3a.5.5 0 0 1 0 1h-3a.5.5 0 0 1 0-1zM2 4.5A.5.5 0 0 1 2.5 4h11a.5.5 0 0 1 0 1H13v7.5A1.5 1.5 0 0 1 11.5 14h-7A1.5 1.5 0 0 1 3 12.5V5h-.5A.5.5 0 0 1 2 4.5zM4 5v7.5a.5.5 0 0 0 .5.5h7a.5.5 0 0 0 .5-.5V5H4zm2 1.5a.5.5 0 0 1 .5.5v4a.5.5 0 0 1-1 0V7a.5.5 0 0 1 .5-.5zm3 0a.5.5 0 0 1 .5.5v4a.5.5 0 0 1-1 0V7a.5.5 0 0 1 .5-.5z"/></svg>`;
  document.getElementById('tbody').innerHTML=entries.map((e,i)=>{
    const col=SC[e.stage]||'#6e7681';
    const ping=e.ping?`<span class="ok" title="ping">●</span>`:`<span class="fail" title="no ping">○</span>`;
    const svc =e.service?`<span class="ok" title="service">●</span>`:`<span class="fail" title="no service">○</span>`;
    const net =e.networkType?h(e.networkType):'-';
    const ports=e.ports.length?`<span style="color:var(--blue)">${e.ports.length}</span>`:`<span style="color:var(--muted)">—</span>`;
    const initShort=e.initArg?h(e.initArg.replace(/rdinit=|init=/g,'').split(' ')[0]):'<span style="color:var(--muted)">—</span>';
    const sl=e.services_list||[];
    let svcs;
    if(!sl.length){ svcs='<span style="color:var(--muted)">—</span>'; }
    else {
      const names=sl.slice(0,2).map(h).join(', ');
      const more=sl.length>2?' <span style="color:var(--muted)">+'+(sl.length-2)+'</span>':'';
      svcs='<span style="font-size:11px;color:var(--blue)" title="'+h(sl.join(', '))+'">'+names+more+'</span>';
    }
    return `<tr class="fr" data-i="${i}">
      <td>${h(e.brand)}</td>
      <td><span class="badge" style="background:${col}">${h(e.stage.replace(/_/g,' '))}</span></td>
      <td style="font-family:monospace;font-size:12px">${h(e.ip)}</td>
      <td>${h(e.arch)}</td>
      <td style="font-size:12px;color:var(--muted)">${net}</td>
      <td style="letter-spacing:4px">${ping}${svc}</td>
      <td style="text-align:right">${ports}</td>
      <td style="max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${svcs}</td>
      <td class="fw-name" style="max-width:160px;font-size:11px;color:var(--muted)" title="${e.initArg?h(e.initArg):''}">${initShort}</td>
      <td class="fw-name" title="${h(e.name)}">${h(e.name)}</td>
      <td class="act"><button class="xbtn" data-brand="${h(e.brand)}" data-name="${h(e.name)}" title="Delete">${TRASH}</button></td>
    </tr>
    <tr class="dr h" id="dr${i}"><td colspan="11"></td></tr>`;
  }).join('');
}

// ── Row click ──────────────────────────────────────────────────────────────
document.getElementById('tbody').addEventListener('click', e=>{
  const xbtn=e.target.closest('.xbtn');
  if(xbtn){ askDelete(xbtn.dataset.brand, xbtn.dataset.name); return; }
  const lbtn=e.target.closest('.lbtn');
  if(lbtn){ toggleLog(lbtn); return; }
  const row=e.target.closest('tr.fr');
  if(row) toggleDetail(parseInt(row.dataset.i));
});

// ── Detail ─────────────────────────────────────────────────────────────────
function toggleDetail(i){
  const dr=document.getElementById(`dr${i}`);
  if(!dr) return;
  if(!dr.classList.contains('h')){ dr.classList.add('h'); openRow=-1; return; }
  if(openRow>=0){ const p=document.getElementById(`dr${openRow}`); if(p) p.classList.add('h'); }
  openRow=i;
  const e=cur[i];
  const ping=e.ping?'<span class="ok">✓ ping</span>':'<span class="fail">✗ ping</span>';
  const svc =e.service?'<span class="ok">✓ service</span>':'<span class="fail">✗ service</span>';
  dr.querySelector('td').innerHTML=`<div class="dbox"><div class="dgrid">
    ${e.arch?`<div><span>Arch</span>${h(e.arch)}</div>`:''}
    ${e.initArg?`<div><span>Init arg</span>${h(e.initArg)}</div>`:''}
    ${e.injected?`<div><span>Injected</span>${h(e.injected)}</div>`:''}
    ${e.networkType?`<div><span>Network</span>${h(e.networkType)} · ${h(e.bridge)}/${h(e.iface)}</div>`:''}
    ${e.ips.length?`<div><span>IPs</span>${e.ips.map(h).join(', ')}</div>`:''}
    ${e.ip?`<div><span>Reachability</span>${ping} ${svc}</div>`:''}
    ${e.ports.length?`<div><span>TCP ports</span>${h(e.ports.join(', '))}</div>`:''}
  </div>
  ${(e.logs&&e.logs.length)
    ?'<div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:2px">'+e.logs.map(lg=>'<span class="lgrp"><button class="lbtn" data-path="'+h(lg.path)+'"><svg width="12" height="12" viewBox="0 0 16 16" fill="currentColor" style="vertical-align:-1px;margin-right:4px"><path d="M5 4a.5.5 0 0 0 0 1h6a.5.5 0 0 0 0-1H5zm-.5 2.5A.5.5 0 0 1 5 6h6a.5.5 0 0 1 0 1H5a.5.5 0 0 1-.5-.5zM5 8a.5.5 0 0 0 0 1h6a.5.5 0 0 0 0-1H5zm0 2a.5.5 0 0 0 0 1h3a.5.5 0 0 0 0-1H5z"/><path d="M2 2a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V2zm10-1H4a1 1 0 0 0-1 1v12a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1V2a1 1 0 0 0-1-1z"/></svg>'+h(lg.label)+'</button><a class="dlbtn" title="Download" href="/api/log?download=1&path='+encodeURIComponent(lg.path)+'"><svg width="12" height="12" viewBox="0 0 16 16" fill="currentColor"><path d="M.5 9.9a.5.5 0 0 1 .5.5v2.5a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-2.5a.5.5 0 0 1 1 0v2.5a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2v-2.5a.5.5 0 0 1 .5-.5z"/><path d="M7.646 11.854a.5.5 0 0 0 .708 0l3-3a.5.5 0 0 0-.708-.708L8.5 10.293V1.5a.5.5 0 0 0-1 0v8.793L5.354 8.146a.5.5 0 1 0-.708.708l3 3z"/></svg></a></span>').join('')+'</div><pre class="log" style="margin-top:8px;overflow-y:auto;max-height:280px"></pre>'
    :'<span style="color:var(--muted);font-size:12px">No log available</span>'}
  </div>`;
  dr.classList.remove('h');
}

async function toggleLog(btn){
  const pre=btn.closest('.dbox').querySelector('pre.log');
  if(pre.dataset.path===btn.dataset.path&&pre.style.display==='block'){
    pre.style.display='none'; pre.dataset.path=''; return;
  }
  pre.dataset.path=btn.dataset.path;
  pre.textContent='Loading…'; pre.style.display='block';
  try {
    const res=await fetch(`/api/log?path=${encodeURIComponent(btn.dataset.path)}`);
    pre.textContent=await res.text();
    pre.scrollTop=pre.scrollHeight;
  } catch(err){ pre.textContent='Error: '+err; }
}

// ── Delete ─────────────────────────────────────────────────────────────────
function askDelete(brand,name){
  pending={brand,name};
  document.getElementById('modal-msg').textContent=
    `Delete ${name ? `"${name}"` : `brand "${brand}" and all its firmware`}?`;
  document.getElementById('modal').classList.remove('h');
}
function deleteBrand(){
  const fb=document.getElementById('fBrand').value;
  if(fb) askDelete(fb,'');
}
function closeModal(){
  document.getElementById('modal').classList.add('h');
  pending=null;
}
document.getElementById('modal-ok').addEventListener('click', async()=>{
  closeModal();
  if(!pending) return;
  const {brand,name}=pending; pending=null;
  const data=await fetch('/api/delete',{
    method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({brand,name}),
  }).then(r=>r.json());
  if(data.ok){
    all = name ? all.filter(e=>!(e.brand===brand&&e.name===name)) : all.filter(e=>e.brand!==brand);
    const brands=[...new Set(all.map(e=>e.brand))].sort();
    const sel=document.getElementById('fBrand');
    sel.innerHTML='<option value="">All brands</option>'+brands.map(b=>`<option>${h(b)}</option>`).join('');
    if(!brands.includes(brand)) sel.value='';
    applyFilters();
  } else {
    alert(`Delete failed: ${data.error}${data.need_sudo?'\nThis requires sudo — delete manually.':''}`);
  }
});
document.getElementById('modal').addEventListener('click',e=>{ if(e.target===document.getElementById('modal')) closeModal(); });

// ── Sort ───────────────────────────────────────────────────────────────────
document.querySelectorAll('th[data-col]').forEach(th=>{
  th.addEventListener('click',()=>{
    const col=th.dataset.col;
    sortDir=sortCol===col?-sortDir:1; sortCol=col;
    document.querySelectorAll('th').forEach(t=>t.classList.remove('sa','sd'));
    th.classList.add(sortDir===1?'sa':'sd');
    applyFilters();
  });
});

loadData();
</script>
</body>
</html>"""

# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    global OUTPUT_DIR
    ap = argparse.ArgumentParser(description="FEMU web UI")
    ap.add_argument("output", nargs="?", default="./outputs")
    ap.add_argument("--port", type=int, default=5000)
    args = ap.parse_args()
    OUTPUT_DIR = Path(args.output).resolve()
    if not OUTPUT_DIR.is_dir():
        print(f"Error: {OUTPUT_DIR} is not a directory", file=sys.stderr)
        sys.exit(1)
    try:
        ip = socket.gethostbyname(socket.gethostname())
    except Exception:
        ip = "0.0.0.0"
    print(f"  FEMU Web UI → http://{ip}:{args.port}")
    app.run(host="0.0.0.0", port=args.port, debug=False, use_reloader=False)

if __name__ == "__main__":
    main()
