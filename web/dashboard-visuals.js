/* Interactive, dependency-free threat-intelligence visualizations.
 * All values are derived from the exported web/data.json; no inferred facts. */
(function(){
  const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  const host=id=>document.getElementById(id);
  const empty="比較できるデータがまだありません。定期収集で履歴が蓄積すると表示されます。";
  const palette=["#70b7ff","#61d6a8","#ffc66d","#b69cff","#ff8190","#62d5df","#f39ac7","#a8d889"];
  const eventTypes=[["new","新規","#70b7ff"],["changed","内容更新","#61d6a8"],["reclassified","再判定","#ffc66d"]];
  let rangeDays=14;
  let currentData=null;
  function svgWrap(inner,h=250){return '<svg viewBox="0 0 760 '+h+'" role="img" aria-label="データ可視化" preserveAspectRatio="xMidYMid meet">'+inner+'</svg>';}
  function dateKey(value){
    const d=new Date(value);
    return Number.isNaN(d.getTime())?"":d.toISOString().slice(0,10);
  }
  function dayKeys(n){
    const out=[], now=new Date();
    for(let i=n-1;i>=0;i--){const d=new Date(Date.UTC(now.getUTCFullYear(),now.getUTCMonth(),now.getUTCDate()-i));out.push(d.toISOString().slice(0,10));}
    return out;
  }
  function filteredEvents(data,n=rangeDays){
    const allowed=new Set(dayKeys(n));
    return (data.events||[]).filter(e=>allowed.has(dateKey(e.detected_at)));
  }
  function setupPanels(){
    if(host("vizControls"))return;
    const grid=document.querySelector(".viz-grid");
    if(!grid)return;
    const toolbar=document.createElement("section");
    toolbar.id="vizControls";
    toolbar.className="viz-toolbar";
    toolbar.innerHTML='<div><strong>分析期間</strong><span class="viz-toolbar-note">期間を切り替えると推移・イベント構成・カレンダーが連動します</span></div><div class="viz-range-buttons" role="group" aria-label="分析期間">'+[7,14,30,90].map(n=>'<button type="button" data-range="'+n+'" aria-pressed="'+(n===rangeDays)+'">'+n+'日</button>').join("")+'</div><div id="vizRangeSummary" class="viz-range-summary"></div>';
    grid.parentNode.insertBefore(toolbar,grid);
    toolbar.addEventListener("click",e=>{
      const b=e.target.closest("button[data-range]");
      if(!b||!currentData)return;
      rangeDays=Number(b.dataset.range)||14;
      toolbar.querySelectorAll("button[data-range]").forEach(x=>x.setAttribute("aria-pressed",String(x===b)));
      renderTimeViews(currentData);
    });
    const extras=document.createElement("div");
    extras.className="viz-grid viz-extra-grid";
    extras.innerHTML='<section class="viz-panel"><h2>🧭 イベント構成</h2><div class="sub">選択期間内の新規・更新・再判定の内訳</div><div id="vizEventMix"></div></section>'+
      '<section class="viz-panel"><h2>🗓️ 日別アクティビティ</h2><div class="sub">日ごとの検知密度。空白日はイベント記録なし</div><div id="vizCalendar"></div></section>'+
      '<section class="viz-panel" style="grid-column:1/-1"><h2>🔬 証拠の厚みマップ</h2><div class="sub">インシデント候補ごとの独立情報源数・証拠数・観測数・証拠強度。被害確率や深刻度の順位ではありません。</div><div id="vizEvidence"></div></section>';
    grid.insertAdjacentElement("afterend",extras);
    const style=document.createElement("style");
    style.textContent='.viz-toolbar{display:flex;align-items:center;justify-content:space-between;gap:14px;flex-wrap:wrap;margin:0 0 16px;padding:14px 16px;background:#101a2b;border:1px solid #293956;border-radius:13px}.viz-toolbar>div:first-child{display:flex;flex-direction:column;gap:3px}.viz-toolbar-note,.viz-range-summary{font-size:11px;color:#91a0b8}.viz-range-buttons{display:flex;gap:6px;flex-wrap:wrap}.viz-range-buttons button{padding:8px 13px;background:#17243a;border:1px solid #344766;color:#cbd8ec}.viz-range-buttons button[aria-pressed=true]{background:#29466b;border-color:#70b7ff;color:#fff}.viz-extra-grid{margin-top:0}.viz-calendar{display:grid;grid-template-columns:repeat(7,minmax(0,1fr));gap:5px}.viz-cal-cell{aspect-ratio:1;border-radius:5px;display:flex;align-items:center;justify-content:center;font-size:10px;color:#e9eef8;min-width:0}.viz-cal-day{background:#18243a;border:1px solid #293650}.viz-cal-blank{background:transparent}.viz-scatter-legend{display:flex;gap:12px;flex-wrap:wrap;font-size:11px;color:#9aa8c2;margin-top:8px}.viz-scatter-legend span{display:flex;align-items:center;gap:5px}@media(max-width:600px){.viz-toolbar{align-items:flex-start}.viz-range-summary{width:100%}.viz-cal-cell{font-size:9px}}';
    document.head.appendChild(style);
  }
  function renderTrend(data){
    const events=filteredEvents(data), keys=dayKeys(rangeDays);
    const days=keys.map(key=>({key,label:key.slice(5).replace("-","/"),new:0,changed:0,reclassified:0,other:0,total:0}));
    const byKey=Object.fromEntries(days.map(x=>[x.key,x]));
    events.forEach(e=>{const d=byKey[dateKey(e.detected_at)];if(!d)return;const t=eventTypes.some(x=>x[0]===e.event_type)?e.event_type:"other";d[t]++;d.total++;});
    const max=Math.max(1,...days.map(x=>x.total)),base=190,top=24,chartH=base-top,slot=700/days.length,bar=Math.max(2,slot*.62);
    let out='<line x1="38" y1="'+base+'" x2="740" y2="'+base+'" stroke="#40506b"/>';
    [0,.5,1].forEach(t=>{const y=base-chartH*t;out+='<line x1="38" y1="'+y+'" x2="740" y2="'+y+'" stroke="#293650" stroke-dasharray="4 5"/><text x="30" y="'+(y+4)+'" text-anchor="end" fill="#8d9bb4" font-size="11">'+Math.round(max*t)+'</text>';});
    days.forEach((d,i)=>{const x=45+i*slot+(slot-bar)/2;let y=base;eventTypes.concat([["other","その他","#8996aa"]]).forEach(t=>{const h=d[t[0]]/max*chartH;if(h>0){y-=h;out+='<rect x="'+x+'" y="'+y+'" width="'+bar+'" height="'+h+'" fill="'+t[2]+'"><title>'+d.key+' · '+t[1]+' '+d[t[0]]+'件</title></rect>';}});out+='<text x="'+(x+bar/2)+'" y="214" text-anchor="middle" fill="#91a0b8" font-size="'+(rangeDays>30?8:10)+'">'+(rangeDays>30?d.key.slice(8):d.label)+'</text>';});
    host("vizTrend").innerHTML=svgWrap(out,232)+'<div class="viz-legend">'+eventTypes.map(t=>'<span><i style="background:'+t[2]+'"></i>'+t[1]+'</span>').join("")+'<span>合計 '+events.length+'件 · '+rangeDays+'日間</span></div>';
  }
  function renderEventMix(data){
    const events=filteredEvents(data),counts={new:0,changed:0,reclassified:0,other:0};
    events.forEach(e=>{counts[e.event_type]===undefined?counts.other++:counts[e.event_type]++;});
    const labels=eventTypes.concat([["other","その他","#8996aa"]]),max=Math.max(1,...Object.values(counts));
    let out="";
    labels.forEach((t,i)=>{const y=12+i*48,w=counts[t[0]]/max*440;out+='<text x="8" y="'+(y+16)+'" fill="#c8d3e6" font-size="13">'+t[1]+'</text><rect x="150" y="'+y+'" width="460" height="20" rx="5" fill="#202d45"/><rect x="150" y="'+y+'" width="'+w+'" height="20" rx="5" fill="'+t[2]+'"/><text x="'+Math.min(680,160+w)+'" y="'+(y+16)+'" fill="#eef3fc" font-size="12">'+counts[t[0]]+'件</text>';});
    host("vizEventMix").innerHTML=events.length?svgWrap(out,210):'<div class="viz-empty">'+empty+'</div>';
  }
  function renderCalendar(data){
    const events=filteredEvents(data),counts={};
    events.forEach(e=>{const k=dateKey(e.detected_at);if(k)counts[k]=(counts[k]||0)+1;});
    const keys=dayKeys(rangeDays),max=Math.max(1,...Object.values(counts));
    const cells=keys.map(k=>{const v=counts[k]||0,alpha=v?0.18+0.82*v/max:0.06;return '<div class="viz-cal-cell viz-cal-day" title="'+k+'：'+v+'件" style="background:rgba(112,183,255,'+alpha+')">'+k.slice(8)+'<span style="font-size:9px;margin-left:2px">'+(v||"")+'</span></div>';});
    const first=new Date(keys[0]+"T00:00:00Z").getUTCDay();
    for(let i=0;i<first;i++)cells.unshift('<div class="viz-cal-cell viz-cal-blank"></div>');
    host("vizCalendar").innerHTML='<div class="viz-calendar">'+["日","月","火","水","木","金","土"].map(x=>'<div class="viz-cal-cell" style="color:#91a0b8">'+x+'</div>').join("")+cells.join("")+'</div><div class="viz-note">表示期間 '+rangeDays+'日 · 記録のない日は0件です。データは直近500イベントのエクスポート範囲に依存します。</div>';
  }
  function renderTimeViews(data){
    renderTrend(data);renderEventMix(data);renderCalendar(data);
    const events=filteredEvents(data);
    host("vizRangeSummary").textContent=rangeDays+"日間 · 対象イベント "+events.length+"件（エクスポート済み履歴内）";
  }
  function renderBars(id,items,label,value,color){
    const rows=(items||[]).slice(0,10);if(!rows.length){host(id).innerHTML='<div class="viz-empty">'+empty+'</div>';return;}
    const max=Math.max(1,...rows.map(x=>Number(x[value]||0))),rowH=31,h=rows.length*rowH+12;
    let out="";
    rows.forEach((x,i)=>{const y=8+i*rowH,w=Number(x[value]||0)/max*430;out+='<text x="8" y="'+(y+16)+'" fill="#c8d3e6" font-size="12">'+esc(x[label]||"未分類")+'</text><rect x="245" y="'+y+'" width="440" height="17" rx="4" fill="#202d45"/><rect x="245" y="'+y+'" width="'+w+'" height="17" rx="4" fill="'+color+'"><title>'+esc(x[label])+': '+Number(x[value]||0)+'</title></rect><text x="'+Math.min(700,253+w)+'" y="'+(y+14)+'" fill="#eef3fc" font-size="11">'+Number(x[value]||0)+'</text>';});
    host(id).innerHTML=svgWrap(out,h);
  }
  function renderEvidence(data){
    const rows=(data.intelligence_incidents||[]).filter(x=>Number.isFinite(Number(x.evidence_count))&&Number.isFinite(Number(x.independent_source_count)));
    if(!rows.length){host("vizEvidence").innerHTML='<div class="viz-empty">'+empty+'<br>インシデント候補の証拠情報が蓄積すると表示します。</div>';return;}
    const maxX=Math.max(2,...rows.map(x=>Number(x.independent_source_count))),maxY=Math.max(2,...rows.map(x=>Number(x.evidence_count)));
    const left=62,right=720,top=24,bottom=260,w=right-left,h=bottom-top;
    let out='<line x1="'+left+'" y1="'+bottom+'" x2="'+right+'" y2="'+bottom+'" stroke="#60718d"/><line x1="'+left+'" y1="'+top+'" x2="'+left+'" y2="'+bottom+'" stroke="#60718d"/>';
    for(let i=0;i<=4;i++){const x=left+w*i/4,y=bottom-h*i/4;out+='<line x1="'+x+'" y1="'+top+'" x2="'+x+'" y2="'+bottom+'" stroke="#293650" stroke-dasharray="3 5"/><text x="'+x+'" y="280" text-anchor="middle" fill="#91a0b8" font-size="10">'+Math.round(maxX*i/4)+'</text><text x="48" y="'+(y+4)+'" text-anchor="end" fill="#91a0b8" font-size="10">'+Math.round(maxY*i/4)+'</text>';}
    rows.slice(0,50).forEach((x,i)=>{const sx=left+Number(x.independent_source_count)/maxX*w,sy=bottom-Number(x.evidence_count)/maxY*h,r=4+Math.min(8,Math.sqrt(Number(x.observation_count||0))*2),conf=Math.max(0,Math.min(100,Number(x.confidence||0))),color=conf>=70?"#61d6a8":conf>=35?"#ffc66d":"#ff8190";out+='<circle cx="'+sx+'" cy="'+sy+'" r="'+r+'" fill="'+color+'" fill-opacity=".78" stroke="#eaf1ff" stroke-width="1"><title>'+esc(x.victim||x.incident_id)+' · 独立情報源 '+Number(x.independent_source_count)+' · 証拠 '+Number(x.evidence_count)+' · 観測 '+Number(x.observation_count)+' · 証拠強度 '+conf+'/100</title></circle>';});
    host("vizEvidence").innerHTML=svgWrap(out,295)+'<div class="viz-legend"><span>横軸：独立情報源数</span><span>縦軸：証拠数</span><span>円の大きさ：観測数</span><span>色：証拠強度（緑 高・黄 中・赤 低）</span></div><div class="viz-relations">'+rows.slice(0,12).map(x=>'<div><strong>'+esc(x.victim||x.incident_id)+'</strong><span>独立情報源 '+Number(x.independent_source_count)+' · 証拠 '+Number(x.evidence_count)+' · 観測 '+Number(x.observation_count)+' · 証拠強度 '+Number(x.confidence||0)+'/100</span></div>').join("")+'</div><p class="viz-note">証拠強度は説明可能な評価値であり、侵害確率・被害確率ではありません。攻撃者の主張のみでは強度に上限があります。</p>';
  }
  function renderNetwork(data){
    const links=(data.intelligence&&data.intelligence.relationships||[]).slice(0,45);
    if(!links.length){host("vizNetwork").innerHTML='<div class="viz-empty">'+empty+'<br>関連性が検出された時点でネットワーク図に表示します。</div>';return;}
    const names=[...new Set(links.flatMap(x=>[x.left_victim,x.right_victim]).filter(Boolean))].slice(0,18);
    if(names.length<2){host("vizNetwork").innerHTML='<div class="viz-empty">'+empty+'</div>';return;}
    const cx=380,cy=170,rx=285,ry=125,coords={};
    names.forEach((n,i)=>{const a=-Math.PI/2+2*Math.PI*i/names.length;coords[n]={x:cx+rx*Math.cos(a),y:cy+ry*Math.sin(a)};});
    const visible=links.filter(x=>coords[x.left_victim]&&coords[x.right_victim]).slice(0,35);
    let out="";
    visible.forEach(l=>{const a=coords[l.left_victim],b=coords[l.right_victim];out+='<line x1="'+a.x+'" y1="'+a.y+'" x2="'+b.x+'" y2="'+b.y+'" stroke="#657b9e" stroke-width="1.5" opacity=".62"><title>'+esc(l.relation)+'：'+esc(l.explanation)+'</title></line>';});
    names.forEach((n,i)=>{const p=coords[n];out+='<circle cx="'+p.x+'" cy="'+p.y+'" r="7" fill="'+palette[i%palette.length]+'" stroke="#eaf1ff" stroke-width="1"/><text x="'+p.x+'" y="'+(p.y+20)+'" text-anchor="middle" fill="#d8e2f3" font-size="11">'+esc(n.length>13?n.slice(0,12)+"…":n)+'</text>';});
    host("vizNetwork").innerHTML=svgWrap(out,350)+'<div class="viz-legend"><span><i style="background:#657b9e"></i>分析エンジンが抽出した関連候補</span><span>'+names.length+'企業・'+visible.length+'関係</span></div><p class="viz-note">線は共通企業・攻撃種別・登録済み公開サイト等に基づく候補関係です。攻撃主体や同一事件の確定を示しません。</p><div class="viz-relations">'+visible.slice(0,12).map(l=>'<div><strong>'+esc(l.left_victim)+' ↔ '+esc(l.right_victim)+'</strong><span>'+esc(l.relation)+' · '+esc(l.explanation)+'</span></div>').join("")+'</div>';
  }
  function renderSectors(data){
    const counts={};
    (data.intelligence_incidents||[]).forEach(x=>{const sector=String(x.sector||"").trim();if(sector)counts[sector]=(counts[sector]||0)+1;});
    const items=Object.entries(counts).map(([sector,count])=>({sector,count})).sort((a,b)=>b.count-a.count);
    renderBars("vizSectors",items,"sector","count","#b69cff");
  }
  window.renderVisualizations=function(data){
    if(!data)return;
    currentData=data;setupPanels();renderTimeViews(data);
    renderBars("vizCompanies",data.company_radar,"company","event_count","#70b7ff");
    renderBars("vizGroups",data.group_activity,"group","changed_pages","#61d6a8");
    renderSectors(data);renderNetwork(data);renderEvidence(data);
  };
})();