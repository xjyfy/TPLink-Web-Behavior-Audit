// 轻量图表：折线(带悬浮提示)、环形图、横向条(可点击)
const PALETTE = ['#1f6feb','#2ea44f','#d97706','#c41d7f','#7c3aed','#0891b2','#65a30d','#ea580c','#4f46e5','#0d9488','#db2777','#64748b'];

const Charts = {
  line(canvasId, labels, values, color='#1f6feb') {
    const cv = document.getElementById(canvasId);
    if (!cv) return;
    const ctx = cv.getContext('2d');
    const W = cv.width, H = cv.height, padL=34, padR=14, padT=14, padB=24;
    function draw(hiIdx) {
      ctx.clearRect(0,0,W,H);
      const max = Math.max(...values, 1);
      const stepX = (W-padL-padR)/Math.max(values.length-1,1);
      ctx.strokeStyle='#eef2f7'; ctx.lineWidth=1; ctx.fillStyle='#94a3b8'; ctx.font='10px sans-serif';
      for(let i=0;i<=4;i++){
        const y = padT+(H-padT-padB)*i/4;
        ctx.beginPath(); ctx.moveTo(padL,y); ctx.lineTo(W-padR,y); ctx.stroke();
        ctx.fillText(Math.round(max*(4-i)/4), 4, y+3);
      }
      ctx.beginPath();
      values.forEach((v,i)=>{
        const x=padL+i*stepX, y=H-padB-(v/max)*(H-padT-padB);
        i?ctx.lineTo(x,y):ctx.moveTo(x,y);
      });
      ctx.lineTo(padL+(values.length-1)*stepX, H-padB);
      ctx.lineTo(padL, H-padB); ctx.closePath();
      ctx.fillStyle=color+'22'; ctx.fill();
      ctx.beginPath(); ctx.strokeStyle=color; ctx.lineWidth=2;
      values.forEach((v,i)=>{
        const x=padL+i*stepX, y=H-padB-(v/max)*(H-padT-padB);
        i?ctx.lineTo(x,y):ctx.moveTo(x,y);
      });
      ctx.stroke();
      for(let i=0;i<values.length;i+=Math.ceil(values.length/8)){
        ctx.fillText(labels[i].slice(5,10), padL+i*stepX-14, H-8);
      }
      if (hiIdx!=null && hiIdx>=0 && hiIdx<values.length) {
        const cx=padL+hiIdx*stepX, cy=H-padB-(values[hiIdx]/max)*(H-padT-padB);
        ctx.beginPath(); ctx.arc(cx,cy,4,0,Math.PI*2); ctx.fillStyle=color; ctx.fill();
        const txt = labels[hiIdx]+'  '+values[hiIdx];
        ctx.font='12px sans-serif';
        const tw = ctx.measureText(txt).width+16;
        let bx = cx-tw/2; bx=Math.max(4,Math.min(bx,W-tw-4));
        ctx.fillStyle='rgba(31,45,61,.92)';
        ctx.fillRect(bx, 4, tw, 22);
        ctx.fillStyle='#fff'; ctx.fillText(txt, bx+8, 19);
      }
    }
    draw(null);
    cv.onmousemove = (e)=>{
      const rect = cv.getBoundingClientRect();
      const sx = cv.width/rect.width;
      const mx = (e.clientX-rect.left)*sx;
      const stepX = (W-padL-padR)/Math.max(values.length-1,1);
      const idx = Math.round((mx-padL)/stepX);
      draw(idx>=0&&idx<values.length?idx:null);
    };
  },

  donut(containerId, items) {
    const el = document.getElementById(containerId);
    if (!el) return;
    const total = items.reduce((s,x)=>s+x.n,0) || 1;
    let acc = 0;
    const R=70, r=42;
    let paths = '';
    items.slice(0,10).forEach((it,i)=>{
      const a0 = acc/total*Math.PI*2 - Math.PI/2;
      acc += it.n;
      const a1 = acc/total*Math.PI*2 - Math.PI/2;
      const large = (a1-a0)>Math.PI?1:0;
      const x0=R+R*Math.cos(a0), y0=R+R*Math.sin(a0);
      const x1=R+R*Math.cos(a1), y1=R+R*Math.sin(a1);
      paths += `<path d="M${R},${R} L${x0},${y0} A${R},${R} 0 ${large} 1 ${x1},${y1} Z" fill="${PALETTE[i%PALETTE.length]}"/>`;
    });
    const legend = items.slice(0,10).map((it,i)=>`
      <div class="lg-row"><span class="dot" style="background:${PALETTE[i%PALETTE.length]}"></span>
      <span class="lg-k">${it.k||'(空)'}</span><span class="lg-v">${it.n}</span></div>`).join('');
    el.innerHTML = `<div class="donut-wrap">
      <svg viewBox="0 0 140 140" width="140" height="140">${paths}
        <circle cx="70" cy="70" r="${r}" fill="#fff"/>
        <text x="70" y="68" text-anchor="middle" font-size="16" font-weight="700" fill="#1f2d3d">${total}</text>
        <text x="70" y="84" text-anchor="middle" font-size="10" fill="#94a3b8">总计</text>
      </svg>
      <div class="lg">${legend}</div></div>`;
  },

  bars(containerId, items, onClick) {
    const el = document.getElementById(containerId);
    if (!el) return;
    const vals = items.map(i=>i.n);
    const max = Math.max(...vals, 1);
    const min = Math.min(...vals, 0);
    const clip = (min > max * 0.5) ? min : 0;
    const range = (max - clip) || 1;
    const n = items.length;
    el.innerHTML = items.map((it,i)=>{
      const pct = Math.max(2, ((it.n - clip) / range * 100)).toFixed(1);
      // 同色系从上到下由深到浅（蓝色系，第1条最深）
      const light = 35 + (i / Math.max(n-1,1)) * 45; // 35% -> 80%
      const color = `hsl(215, 80%, ${light}%)`;
      return `<div class="bar-row ${onClick?'clickable':''}" data-k="${(it.k||'').replace(/"/g,'&quot;')}">
        <span class="rank">${i+1}</span>
        <div class="track"><div class="fill" style="width:${pct}%;background:${color}"></div></div>
        <span class="k" title="${it.k||'(空)'}">${it.k||'(空)'}</span>
        <span class="v">${it.n}</span>
      </div>`;
    }).join('');
    if (onClick) {
      el.querySelectorAll('.bar-row').forEach(row => {
        row.onclick = () => onClick(row.getAttribute('data-k'));
      });
    }
  }
};
