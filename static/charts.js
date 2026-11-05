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
        const lb = (labels[i]&&labels[i].length>=16) ? labels[i].slice(11,16) : (labels[i]?labels[i].slice(5,10):'');
        ctx.fillText(lb, padL+i*stepX-14, H-8);
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
      <span class="lg-k">${it.k||'(空)'}</span><span class="lg-v" style="color:${PALETTE[i%PALETTE.length]}">${it.n}</span></div>`).join('');
    el.innerHTML = `<div class="donut-wrap">
      <div class="donut-svg"><svg viewBox="0 0 140 140" width="140" height="140">${paths}
        <circle cx="70" cy="70" r="${r}" fill="#fff"/>
        <text x="70" y="68" text-anchor="middle" font-size="16" font-weight="700" fill="#1f2d3d">${total}</text>
        <text x="70" y="84" text-anchor="middle" font-size="10" fill="#94a3b8">总计</text>
      </svg></div>
      <div class="lg">${legend}</div></div>`;
  },

  bars(containerId, items, onClick, opts) {
    const el = document.getElementById(containerId);
    if (!el) return;
    opts = opts || {};
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
      const k = (it.k||'').replace(/"/g,'&quot;');
      const iconHtml = opts.showIcons
        ? `<img src="/app_icon/${encodeURIComponent(it.k||'')}" class="bar-icon" alt="" onerror="this.style.display='none'"> `
        : '';
      // 备注名：opts.showNote 时在 IP 列内、IP 与次数之间左对齐展示（同列固定宽度，保持图表对齐）
      const note = (it.note||'').replace(/"/g,'&quot;');
      const noteHtml = opts.showNote
        ? `<span class="note" title="${note}">${note}</span>`
        : '';
      // 在线着色：opts.showOnline 且后端给出 online 标记时，IP 用绿(在线)/灰(离线)
      // 网站名展示：opts.showSiteName 时优先显示网站名(无则"未知")+境内绿点/非境内黄点，点击切换为域名
      let ipHtml;
      if (opts.showSiteName) {
        const site = (it.site_name||'').trim();
        const dot = it.geo_tag === 'CN' ? 'dot-green' : 'dot-yellow';
        ipHtml = `<span class="dot ${dot}"></span>` +
                 `<span class="site-txt" data-domain="${k}" data-site="${site.replace(/"/g,'&quot;')}" title="${k}">${site ? site : '未知'}</span>`;
      } else if (opts.showNote) {
        ipHtml = `<span class="ip ${opts.showOnline ? (it.online ? 'online' : 'offline') : ''}">${it.k||'(空)'}</span>`;
      } else {
        ipHtml = (it.k||'(空)');
      }
      return `<div class="bar-row ${onClick?'clickable':''}" data-k="${k}">
        <span class="rank">${(opts.rankField && it[opts.rankField]) ? it[opts.rankField] : i+1}</span>
        <div class="track"><div class="fill" style="width:${pct}%;background:${color}"></div></div>
        <span class="k ${opts.showNote?'has-note':''}" title="${it.k||'(空)'}">${iconHtml}${ipHtml}${noteHtml}</span>
        <span class="v">${it.n}</span>
      </div>`;
    }).join('');
    if (onClick) {
      el.querySelectorAll('.bar-row').forEach(row => {
        row.onclick = () => onClick(row.getAttribute('data-k'));
      });
    }
    // 网站名/域名点击切换由 app.js 全局事件委托统一处理（避免双重触发）
  },

  // 词云：热门应用展示。字号随热门程度变化 + 每项带应用图标。
  // 采用螺旋布局：越热门(次数越多)越靠近中心，外圈依次缩小。
  tagCloud(containerId, items, onClick, opts) {
    const el = document.getElementById(containerId);
    if (!el) return;
    opts = opts || {};
    if (!items || !items.length) { el.innerHTML=''; return; }
    // 热门优先（越大越先放、越靠中心）
    const sorted = items.slice().sort((a,b)=>b.n-a.n);
    const max = Math.max(...items.map(i=>i.n), 1);
    const min = Math.min(...items.map(i=>i.n), 0);
    const span = (max-min) || 1;
    const minF = 12, maxF = 30;
    // 离屏 canvas 测量文字宽度，估算每个标签尺寸
    const mctx = document.createElement('canvas').getContext('2d');
    const tags = sorted.map((it,i)=>{
      const name = (it.k==null?'':String(it.k));
      const size = Math.round(minF + (it.n-min)/span*(maxF-minF));
      mctx.font = `600 ${size}px sans-serif`;
      const tw = Math.ceil(mctx.measureText(name).width);
      // 小词(非热门)随机轻微旋转填缝；热门大词保持水平更醒目
      const rot = size < 22 ? (Math.random()*44-22)*Math.PI/180 : 0;
      return { name, size, w: tw+26, h: Math.round(size*1.5)+6, rot,
               color: PALETTE[i % PALETTE.length], n: it.n };
    });
    // 容器尺寸
    el.style.position='relative'; el.style.overflow='hidden';
    const W = el.clientWidth || 520;
    const H = 320;
    el.style.height = H+'px';
    const cx = W/2, cy = H/2;
    // 像素级螺旋放置 + 旋转后包围盒碰撞检测：越热门越靠中心，外圈依次缩小
    const placed = [];
    const bbox = t => {
      const c=Math.abs(Math.cos(t.rot)), s=Math.abs(Math.sin(t.rot));
      return { w: c*t.w+s*t.h, h: s*t.w+c*t.h };
    };
    const collide = (x,y,w,h) => placed.some(p => Math.abs(x-p.x)<(w+p.w)/2 && Math.abs(y-p.y)<(h+p.h)/2);
    const positions = tags.map(t=>{
      const bb = bbox(t);
      let θ=Math.random()*Math.PI*2, r=0, x=cx, y=cy;
      for (let k=0;k<20000;k++){
        r += 0.6; θ += 0.1;
        x = cx + r*Math.cos(θ);
        y = cy + r*Math.sin(θ);
        if (!collide(x,y,bb.w,bb.h)){ placed.push({x,y,w:bb.w,h:bb.h}); return {x,y}; }
        if (r > Math.hypot(W,H)) break;
      }
      placed.push({x,y,w:bb.w,h:bb.h});
      return {x,y};
    });
    el.innerHTML = tags.map((t,i)=>{
      const p = positions[i];
      const k = (t.name==null?'':String(t.name)).replace(/"/g,'&quot;');
      const rotDeg = Math.round(t.rot*180/Math.PI);
      const icon = `<img src="/app_icon/${encodeURIComponent(t.name)}" class="cloud-icon" alt="" onerror="this.style.display='none'"> `;
      return `<span class="cloud-tag ${onClick?'clickable':''}" data-k="${k}"
        style="left:${Math.round(p.x)}px;top:${Math.round(p.y)}px;font-size:${t.size}px;color:${t.color};transform:translate(-50%,-50%) rotate(${rotDeg}deg)"
        title="${t.name||'(空)'}：${t.n} 次">${icon}${t.name||'(空)'}</span>`;
    }).join('');
    if (onClick) {
      el.querySelectorAll('.cloud-tag.clickable').forEach(tag => {
        tag.onclick = () => onClick(tag.getAttribute('data-k'));
      });
    }
  }
};
