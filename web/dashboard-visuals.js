/* Responsive, dependency-free dashboard visualizations. All values come from web/data.json. */
(function(){
  const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  const host=id=>document.getElementById(id);
  const empty="比較できるデータがまだありません。定期収集で履歴が蓄積すると表示されます。";
  const palette=["#70b7ff","#61d6a8","#ffc66d","#b69cff","#ff8190","#62d5df","#f39ac7","#a8d889"];
  function svgWrap(inner,h=250){return '<svg viewBox="0 0 760 '+h+'" role="img" aria-label="データ可視化" preserveAspectRatio="xMidYMid meet">'+inner+'</svg>';}
  function renderTrend(data){
    const events=(data.events||[]).filter(x=>x.detected_at);
    const now=new Date(), days=[];
    for(let i=13;i>=0;i--){const d=new Date(now);d.setDate(d.getDate()-i);const key=d.toISOString().slice(0,10);days.push({key,label:(d.getMonth()+1)+"/"+d.getDate(),count:0,new:0,changed:0,reclassified:0});}
    const byKey=Object.fromEntries(days.map(x=>[x.key,x]));
    events.forEach(e=>{const d=new Date(e.detected_at);if(Number.isNaN(d.getTime()))return;const x=byKey[d.toISOString().slice(0,10)];if(x){x.count++;if(x[e.event_type]!==undefined)x[e.event_type]++;}});
    const max=Math.max(1,...days.map(x=>x.count)), base=190, top=24, chartH=base-top, slot=700/days.length, bar=slot*.58;
    let out='<line x1="38" y1="'+base+'" x2="740" y2="'+base+'" stroke="#40506b"/>';
    [0,.5,1].forEach(t=>{const y=base-chartH*t;out+='<line x1="38" y1="'+y+'" x2="740" y2="'+y+'" stroke="#293650" stroke-dasharray="4 5"/><text x="30" y="'+(y+4)+'" text-anchor="end" fill="#8d9bb4" font-size="11">'+Math.round(max*t)+'</text>';});
    days.forEach((d,i)=>{const x=45+i*slot+(slot-bar)/2,h=d.count/max*chartH;out+='<rect x="'+x+'" y="'+(base-h)+'" width="'+bar+'" height="'+Math.max(1,h)+'" rx="4" fill="'+(d.count?'#70b7ff':'#283650')+'"><title>'+d.key+'：'+d.count+'件</title></rect><text x="'+(x+bar/2)+'" y="214" text-anchor="middle" fill="#91a0b8" font-size="10">'+d.label+'</text>';});
    host("vizTrend").innerHTML=svgWrap(out,232)+'<div class="viz-legend"><span><i style="background:#70b7ff"></i>検知イベント件数</span><span>直近14日 · 合計 '+days.reduce((a,x)=>a+x.count,0)+'件</span></div>';
  }
  function renderBars(id,items,label,value,color){
    const rows=(items||[]).slice(0,10);if(!rows.length){host(id).innerHTML='<div class="viz-empty">'+empty+'</div>';return;}
    const max=Math.max(1,...rows.map(x=>Number(x[value]||0))), rowH=31, h=rows.length*rowH+12;
    let out='';
    rows.forEach((x,i)=>{const y=8+i*rowH,w=Number(x[value]||0)/max*430;out+='<text x="8" y="'+(y+16)+'" fill="#c8d3e6" font-size="12">'+esc(x[label]||"未分類")+'</text><rect x="245" y="'+y+'" width="440" height="17" rx="4" fill="#202d45"/><rect x="245" y="'+y+'" width="'+w+'" height="17" rx="4" fill="'+color+'"><title>'+esc(x[label])+': '+Number(x[value]||0)+'</title></rect><text x="'+Math.min(700,253+w)+'" y="'+(y+14)+'" fill="#eef3fc" font-size="11">'+Number(x[value]||0)+'</text>';});
    host(id).innerHTML=svgWrap(out,h);
  }
  function renderNetwork(data){
    const links=(data.intelligence&&data.intelligence.relationships||[]).slice(0,45);
    if(!links.length){host("vizNetwork").innerHTML='<div class="viz-empty">'+empty+'<br>関連性が検出された時点でネットワーク図に表示します。</div>';return;}
    const names=[...new Set(links.flatMap(x=>[x.left_victim,x.right_victim]).filter(Boolean))].slice(0,18);
    if(names.length<2){host("vizNetwork").innerHTML='<div class="viz-empty">'+empty+'</div>';return;}
    const cx=380,cy=170,rx=285,ry=125,coords={};
    names.forEach((n,i)=>{const a=-Math.PI/2+2*Math.PI*i/names.length;coords[n]={x:cx+rx*Math.cos(a),y:cy+ry*Math.sin(a)};});
    const visible=links.filter(x=>coords[x.left_victim]&&coords[x.right_victim]).slice(0,35);
    let out='';
    visible.forEach(l=>{const a=coords[l.left_victim],b=coords[l.right_victim];out+='<line x1="'+a.x+'" y1="'+a.y+'" x2="'+b.x+'" y2="'+b.y+'" stroke="#657b9e" stroke-width="1.5" opacity=".62"><title>'+esc(l.relation)+'：'+esc(l.explanation)+'</title></line>';});
    names.forEach((n,i)=>{const p=coords[n];out+='<circle cx="'+p.x+'" cy="'+p.y+'" r="7" fill="'+palette[i%palette.length]+'" stroke="#eaf1ff" stroke-width="1"/><text x="'+p.x+'" y="'+(p.y+20)+'" text-anchor="middle" fill="#d8e2f3" font-size="11">'+esc(n.length>13?n.slice(0,12)+"…":n)+'</text>';});
    host("vizNetwork").innerHTML=svgWrap(out,350)+'<div class="viz-legend"><span><i style="background:#657b9e"></i>分析エンジンが抽出した関連候補</span><span>'+names.length+'企業・'+visible.length+'関係</span></div><p class="viz-note">線は共通企業・攻撃種別・登録済み公開サイト等に基づく候補関係です。攻撃主体や同一事件の確定を示しません。</p>'+'<div class="viz-relations">'+visible.slice(0,12).map(l=>'<div><strong>'+esc(l.left_victim)+' ↔ '+esc(l.right_victim)+'</strong><span>'+esc(l.relation)+' · '+esc(l.explanation)+'</span></div>').join("")+'</div>';
  }

  function renderSectors(data){
    const counts={};
    (data.intelligence_incidents||[]).forEach(x=>{const sector=String(x.sector||"").trim();if(sector)counts[sector]=(counts[sector]||0)+1;});
    const items=Object.entries(counts).map(([sector,count])=>({sector,count})).sort((a,b)=>b.count-a.count);
    renderBars("vizSectors",items,"sector","count","#b69cff");
  }
  window.renderVisualizations=function(data){
    if(!data)return;
    renderTrend(data);
    renderBars("vizCompanies",data.company_radar,"company","event_count","#70b7ff");
    renderBars("vizGroups",data.group_activity,"group","changed_pages","#61d6a8");\n    renderSectors(data);
    renderNetwork(data);
  };
})();
