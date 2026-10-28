// 页面逻辑
const api = (p) => fetch(p).then(r => r.json());

function fillLocalDefault() {
  // datetime-local 默认值：最近 1 小时
  const f = document.getElementById('fStart');
  if (f && !f.value) {
    const end = new Date();
    const start = new Date(end.getTime() - 3600 * 1000);
    f.value = toLocal(start);
    document.getElementById('fEnd').value = toLocal(end);
  }
  const es = document.getElementById('eStart');
  if (es && !es.value) {
    const end = new Date();
    const start = new Date(end.getTime() - 3600 * 1000);
    es.value = toLocal(start);
    document.getElementById('eEnd').value = toLocal(end);
  }
}
function toLocal(d) {
  const p = n => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth()+1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
}
function dtLocal(s) { return s ? s.replace(' ', 'T').slice(0,16) : ''; }
function dtToDb(v) { return v ? v.replace('T', ' ') + ':00' : ''; }

const TAG = { web:'网站', url:'URL', app:'应用', dns:'DNS', other:'其他' };

// ---------- 总览 ----------
if (document.getElementById('mCpu')) {
  // 宿主机指标
  function loadMetrics() {
    api('/api/host_metrics').then(m => {
      document.getElementById('mCpu').textContent = m.cpu + '%';
      document.getElementById('mMem').textContent = m.mem + '%';
      document.getElementById('mDisk').textContent = m.disk + '%';
      document.getElementById('mDown').textContent = m.down_kbps + ' KB/s';
      document.getElementById('mUp').textContent = '上行 ' + m.up_kbps + ' KB/s';
      document.getElementById('mCpuBar').style.width = m.cpu + '%';
      document.getElementById('mMemBar').style.width = m.mem + '%';
      document.getElementById('mDiskBar').style.width = m.disk + '%';
      // 副信息：CPU核心数 / 内存总量 / 磁盘总量 / 网卡接口速率
      document.getElementById('mCpuSub').textContent = (m.cpu_cores||0) + ' 核';
      document.getElementById('mMemSub').textContent = '总 ' + m.mem_total_gb + ' GB';
      document.getElementById('mDiskSub').textContent = '总 ' + m.disk_total_gb + ' GB · ' + (m.disk_drive||'') + '盘';
      const sp = (m.net_speed_mbps||0) >= 1000
        ? ((m.net_speed_mbps||0)/1000).toFixed(1) + ' Gbps'
        : (m.net_speed_mbps||0) + ' Mbps';
      document.getElementById('mNetSpeed').textContent = '接口 ' + sp + (m.net_iface ? ' · ' + m.net_iface : '');
    });
  }
  loadMetrics(); setInterval(loadMetrics, 2000);

  // 系统时间 + 运行时长
  function tickClock() {
    const now = new Date();
    const days = ['日','一','二','三','四','五','六'];
    document.getElementById('sysDate').textContent =
      `今天是 ${now.getFullYear()}年${now.getMonth()+1}月${now.getDate()}日 星期${days[now.getDay()]}`;
    const p = n => String(n).padStart(2,'0');
    document.getElementById('sysTime').textContent =
      `${p(now.getHours())}:${p(now.getMinutes())}:${p(now.getSeconds())}`;
  }
  tickClock(); setInterval(tickClock, 1000);
  api('/api/uptime').then(u => {
    document.getElementById('sysUptime').textContent =
      `系统已运行：${u.days}天${u.hours}小时${u.minutes}分${u.seconds}秒`;
  });

  // 趋势图固定 24 小时
  api('/api/stats/trend?hours=24').then(t => Charts.line('trend', t.map(x=>x.hr), t.map(x=>x.n), '#1f6feb'));
  api('/api/stats/online_trend?hours=24').then(t => Charts.line('onlineTrend', t.map(x=>x.hr), t.map(x=>x.n), '#2ea44f'));

  // 时间范围联动图表
  function rangeQs() {
    const h = document.querySelector('.range-btn.active').getAttribute('data-h');
    const end = new Date();
    const start = new Date(end.getTime() - h*3600*1000);
    const fmt = d => {
      const p = n => String(n).padStart(2,'0');
      return `${d.getFullYear()}-${p(d.getMonth()+1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:00`;
    };
    const q = new URLSearchParams();
    q.set('start', fmt(start));
    q.set('end', fmt(end));
    return q.toString();
  }
  function updateFullLinks() {
    // 让"全部"链接继承当前时间范围，而不是全表统计
    const q = rangeQs();
    document.querySelectorAll('.full-link').forEach(a => {
      const base = a.getAttribute('href').split('?')[0];
      a.setAttribute('href', base + '?' + q);
    });
  }
  function loadRangeCharts() {
    api('/api/stats/domains?limit=10&' + rangeQs()).then(d => Charts.bars('domBars', d, k => goLogs({keyword:k})));
    api('/api/stats/apps?limit=10&' + rangeQs()).then(d => Charts.bars('appBars', d, k => goLogs({app_name:k}), {showIcons:true}));
    api('/api/stats/app_categories?' + rangeQs()).then(d => Charts.donut('catChart', d));
    api('/api/stats/protocol_top?' + rangeQs()).then(d => Charts.bars('protoBars', d));
    // 终端IP TOP10（单列，与其它图表同宽；IP 后显示备注名，在线绿色/离线灰色）
    api('/api/stats/hosts?limit=10&' + rangeQs()).then(d => Charts.bars('hostBars', d, k => goLogs({host_ip:k}), {showNote:true, showOnline:true}));
    // 娱乐应用 TOP10：统计网络购物/网络音乐/视频直播三类应用的终端IP使用次数排行
    api('/api/stats/entertainment_hosts?limit=10&' + rangeQs()).then(d => Charts.bars('entBars', d, k => goLogs({host_ip:k}), {showNote:true, showOnline:true}));
  }
  loadRangeCharts();
  updateFullLinks();
  document.querySelectorAll('.range-btn').forEach(b => b.onclick = () => {
    document.querySelectorAll('.range-btn').forEach(x=>x.classList.remove('active'));
    b.classList.add('active');
    loadRangeCharts();
    updateFullLinks();
  });
}

function goLogs(params) {
  const q = new URLSearchParams(params);
  window.location.href = '/logs?' + q.toString();
}

// ---------- 日志查询 ----------
let curPage = 1;
let totalPages = 1;
if (document.getElementById('logBody')) {
  fillLocalDefault();
  // 从 URL 预填筛选（图表点击跳转过来）
  const up = new URLSearchParams(location.search);
  if (up.get('host_ip')) document.getElementById('fHost').value = up.get('host_ip');
  if (up.get('app_name')) document.getElementById('fApp').value = up.get('app_name');
  if (up.get('keyword')) document.getElementById('fKw').value = up.get('keyword');
  if (up.get('event_type')) document.getElementById('fType').value = up.get('event_type');
  let hostMode = 'ip'; // 'ip' or 'note'
  // 应用类别多选：[] 表示"全部"；否则为已选类别名数组
  let selectedCats = [];
  (function initCatSelect(){
    const sel = document.getElementById('catSel');
    if (!sel) return;
    const btn = document.getElementById('catBtn');
    const menu = document.getElementById('catMenu');
    const grid = document.getElementById('catGrid');
    document.addEventListener('click', e => {
      if (!sel.contains(e.target)) menu.style.display = 'none';
    });
    btn.onclick = (e) => { e.stopPropagation(); menu.style.display = menu.style.display==='none' ? 'block' : 'none'; };
    fetch('/api/categories').then(r=>r.json()).then(d => {
      (d.rows||[]).forEach(c => {
        const lb = document.createElement('label');
        lb.className='cat-opt';
        const cb=document.createElement('input'); cb.type='checkbox'; cb.className='cat-cb'; cb.value=c.k;
        const sp=document.createElement('span'); sp.textContent = c.k;
        lb.appendChild(cb); lb.appendChild(sp);
        grid.appendChild(lb);
      });
      updateCatState();
    });
    function updateCatState(){
      const boxes=[...grid.querySelectorAll('.cat-cb')];
      const allBox=boxes.find(b=>b.value==='');
      const spec=boxes.filter(b=>b.value!=='');
      if (allBox.checked) { spec.forEach(b=>b.checked=false); selectedCats=[]; }
      else selectedCats = spec.filter(b=>b.checked).map(b=>b.value);
      spec.forEach(b=>b.disabled = (selectedCats.length>=5 && !b.checked));
      btn.textContent = (allBox.checked || selectedCats.length===0) ? '全部'
        : selectedCats.length===1 ? selectedCats[0]
        : selectedCats.slice(0,2).join('、') + ' 等' + selectedCats.length + ' 项';
      btn.title='当前选择：' + ((allBox.checked||selectedCats.length===0) ? '全部' : selectedCats.join('、'));
    }
    grid.addEventListener('change', e=>{
      const cb=e.target.closest('.cat-cb'); if(!cb) return;
      if (cb.value==='') {
        grid.querySelectorAll('.cat-cb').forEach(b=>{ if(b.value!=='') b.checked=false; });
      } else if (cb.checked) {
        const allBox=grid.querySelector('.cat-cb[value=""]');
        if (allBox) allBox.checked=false;
        const spec=[...grid.querySelectorAll('.cat-cb')].filter(b=>b.value!==''&&b.checked);
        if (spec.length>5) cb.checked=false; // 最多5种
      }
      updateCatState();
    });
  })();
  function renderHostCell(r) {
    if (hostMode === 'note') {
      return r.host_note ? r.host_note : (r.host_ip||'');
    }
    return (r.host_ip||'') + (r.host_note ? `<br><span class="hnote">${r.host_note}</span>` : '');
  }
  function updateHostHead() {
    document.getElementById('hostHeadMode').textContent = hostMode === 'note' ? '(按备注)' : '(按IP)';
  }
  document.getElementById('hostHead').onclick = () => {
    hostMode = hostMode === 'ip' ? 'note' : 'ip';
    updateHostHead(); loadLogs();
  };
  updateHostHead();

  function buildLogsQs() {
    const q = new URLSearchParams({
      start: dtToDb(document.getElementById('fStart').value),
      end: dtToDb(document.getElementById('fEnd').value),
      host_ip: document.getElementById('fHost').value.trim(),
      event_type: document.getElementById('fType').value,
      app_category: selectedCats.join(','),
      app_name: document.getElementById('fApp').value.trim(),
      keyword: document.getElementById('fKw').value.trim(),
      page: curPage, size: 50
    });
    q.forEach((v,k)=>{ if(!v) q.delete(k); });
    return q;
  }
  function loadLogs() {
    const q = buildLogsQs();
    api('/api/logs?' + q.toString()).then(d => {
      totalPages = Math.max(1, Math.ceil(d.total / 50));
      document.getElementById('totalLbl').textContent = `共 ${d.total} 条`;
      document.getElementById('pageInfo').textContent = `第 ${d.page} / ${totalPages} 页`;
      document.getElementById('prevBtn').disabled = d.page <= 1;
      document.getElementById('nextBtn').disabled = d.page >= totalPages;
      document.getElementById('firstBtn').disabled = d.page <= 1;
      document.getElementById('lastBtn').disabled = d.page >= totalPages;
      const upd = document.getElementById('lastUpd');
      if (upd) {
        const now = new Date();
        upd.textContent = '更新于 ' + now.toLocaleTimeString('zh-CN', {hour12:false});
      }
      document.getElementById('logBody').innerHTML = d.rows.map(r => `
        <tr>
          <td>${r.ts}</td>
          <td>${renderHostCell(r)}</td>
          <td><span class="tag tag-${r.event_type}">${TAG[r.event_type]||r.event_type}</span></td>
          <td>${r.app_category||''}</td>
          <td>${r.app_name||''}</td>
          <td>${r.domain||r.url||''}</td>
          <td class="raw" title="${(r.raw||'').replace(/"/g,'&quot;')}">${r.raw||''}</td>
        </tr>`).join('');
    });
  }
  document.getElementById('searchBtn').onclick = () => { curPage = 1; loadLogs(); };
  document.getElementById('exportLogsBtn').onclick = () => {
    const q = buildLogsQs();
    q.delete('page'); q.delete('size');
    window.location = '/api/logs/export.csv?' + q.toString();
  };
  document.getElementById('prevBtn').onclick = () => { if(curPage>1){curPage--;loadLogs();} };
  document.getElementById('nextBtn').onclick = () => { curPage++; loadLogs(); };
  document.getElementById('firstBtn').onclick = () => { curPage = 1; loadLogs(); };
  document.getElementById('lastBtn').onclick = () => { curPage = totalPages; loadLogs(); };
  document.getElementById('jumpBtn').onclick = () => {
    const p = parseInt(document.getElementById('jumpPage').value);
    if (p >= 1 && p <= totalPages) { curPage = p; loadLogs(); }
  };
  document.getElementById('jumpPage').addEventListener('keydown', e => {
    if (e.key === 'Enter') document.getElementById('jumpBtn').click();
  });
  loadLogs();
  setInterval(() => {
    if (document.getElementById('liveChk').checked) {
      // 自动刷新时窗口滑动为最近1小时
      const end = new Date();
      const start = new Date(end.getTime() - 3600 * 1000);
      document.getElementById('fStart').value = toLocal(start);
      document.getElementById('fEnd').value = toLocal(end);
      curPage = 1;
      loadLogs();
    }
  }, 5000);
}

// ---------- 导出 ----------
if (document.getElementById('exportBtn')) {
  fillLocalDefault();
  document.getElementById('exportBtn').onclick = () => {
    const s = dtToDb(document.getElementById('eStart').value);
    const e = dtToDb(document.getElementById('eEnd').value);
    window.location = `/api/export.csv?start=${s}&end=${e}`;
  };
  document.getElementById('clearBtn').onclick = async () => {
    if (!confirm('确认清空该时间段已导出的日志？此操作不可恢复。')) return;
    const s = dtToDb(document.getElementById('eStart').value);
    const e = dtToDb(document.getElementById('eEnd').value);
    const r = await fetch('/api/clear', {method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({start:s, end:e})}).then(r=>r.json());
    document.getElementById('clearResult').textContent = r.ok ? `已删除 ${r.deleted} 条日志` : ('失败: '+(r.error||''));
  };
  document.getElementById('importBtn').onclick = async () => {
    const f = document.getElementById('csvFile').files[0];
    if (!f) return;
    const fd = new FormData(); fd.append('file', f);
    const r = await fetch('/api/import_csv', {method:'POST', body:fd}).then(r=>r.json());
    document.getElementById('importResult').textContent = r.ok ? `成功导入 ${r.imported} 条` : ('失败: '+(r.error||''));
  };
  // 系统设置：保留天数 + 不保存上网行为日志开关
  api('/api/settings').then(s => {
    document.getElementById('setDays').value = s.keep_days;
    document.getElementById('dropWebUsage').checked = !!s.drop_web_usage;
  });
  document.getElementById('saveDaysBtn').onclick = async () => {
    const days = parseInt(document.getElementById('setDays').value);
    const r = await fetch('/api/settings', {method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({keep_days:days})}).then(r=>r.json());
    document.getElementById('daysResult').textContent = r.ok ? `已保存：保留 ${days} 天` : ('失败: '+(r.error||''));
  };
  document.getElementById('saveDropBtn').onclick = async () => {
    const on = document.getElementById('dropWebUsage').checked;
    const r = await fetch('/api/settings', {method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({drop_web_usage: on})}).then(r=>r.json());
    document.getElementById('dropResult').textContent = r.ok
      ? (on ? '已开启：上网行为日志将被丢弃（约 2 秒内生效）' : '已关闭：上网行为日志将正常入库（约 2 秒内生效）')
      : ('失败: '+(r.error||''));
  };
  document.getElementById('restartBtn').onclick = async () => {
    if (!confirm('确认重启服务？重启期间约 3 秒无法访问。')) return;
    const r = await fetch('/api/restart', {method:'POST'}).then(r=>r.json());
    document.getElementById('restartResult').textContent = r.msg || '重启中...';
    setTimeout(() => window.location.href = '/', 3000);
  };
}

// ---------- 改密 ----------
document.getElementById('chgPwBtn')?.addEventListener('click', async () => {
  const oldp = prompt('请输入当前密码：'); if (oldp===null) return;
  const newp = prompt('请输入新密码（至少6位）：'); if (newp===null) return;
  const r = await fetch('/api/change_password', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({old_password:oldp, new_password:newp})}).then(r=>r.json());
  alert(r.ok ? '密码修改成功' : '原密码错误');
});

// ---------- 终端管理 ----------
if (document.getElementById('hostBody')) {
  let hostPage = 1;
  const HOST_SIZE = 20;
  function loadHosts() {
    const kw = document.getElementById('hKw').value.trim();
    const q = new URLSearchParams({page: hostPage, size: HOST_SIZE});
    if (kw) q.set('keyword', kw);
    api('/api/hosts?' + q.toString()).then(d => {
      document.getElementById('onlineCnt').textContent = d.online_total;
      document.getElementById('allCnt').textContent = d.all_total;
      document.getElementById('hTotal').textContent = `共 ${d.total} 台设备`;
      const totalPages = Math.max(1, Math.ceil(d.total / HOST_SIZE));
      document.getElementById('hPageInfo').textContent = `第 ${d.page} / ${totalPages} 页`;
      document.getElementById('hPrev').disabled = d.page <= 1;
      document.getElementById('hNext').disabled = d.page >= totalPages;
      document.getElementById('hostBody').innerHTML = d.rows.map(h => {
        const ip = h.ip||'';
        const p = n => String(n).padStart(2,'0');
        const o = new Date(Date.now()-3600*1000);
        const oneHourAgo = `${o.getFullYear()}-${p(o.getMonth()+1)}-${p(o.getDate())}T${p(o.getHours())}:${p(o.getMinutes())}`;
        const ipLink = ip ? `<a href="/logs?host_ip=${encodeURIComponent(ip)}&start=${oneHourAgo}" style="color:#1f6feb">${ip}</a>` : '';
        return `
        <tr>
          <td><input id="note_${(h.mac||'').replace(/[^a-zA-Z0-9]/g,'')}" value="${(h.note||'').replace(/"/g,'&quot;')}" style="width:160px;padding:4px;border:1px solid #ccc;border-radius:4px"></td>
          <td>${h.online?'<span class="dot-online"></span>在线':'<span class="dot-offline"></span>离线'}</td>
          <td><code>${h.mac||''}</code></td>
          <td style="color:#555">${h.hostname||''}</td>
          <td>${ipLink}</td>
          <td>${h.first_seen||''}</td>
          <td>${h.last_seen||''}</td>
          <td><button data-mac="${h.mac||''}" class="saveNote">保存</button> <button data-mac="${h.mac||''}" class="delHost" style="color:#c41d7f">删除</button></td>
        </tr>`;
      }).join('') || '<tr><td colspan="8" style="color:#999">暂无终端数据（收到 DHCP 日志后自动生成）</td></tr>';
      document.querySelectorAll('.saveNote').forEach(b => b.onclick = async () => {
        const mac = b.getAttribute('data-mac');
        const id = 'note_' + mac.replace(/[^a-zA-Z0-9]/g,'');
        const note = document.getElementById(id).value;
        const r = await fetch('/api/hosts/note', {method:'POST', headers:{'Content-Type':'application/json'},
          body: JSON.stringify({mac, note})}).then(r=>r.json());
        b.textContent = r.ok ? '已保存' : '失败';
        setTimeout(()=>b.textContent='保存', 1500);
      });
      document.querySelectorAll('.delHost').forEach(b => b.onclick = async () => {
        const mac = b.getAttribute('data-mac');
        if (!confirm('确认删除该终端记录？删除后若 DHCP 日志再次出现将自动重新添加。')) return;
        const r = await fetch('/api/hosts/delete', {method:'POST', headers:{'Content-Type':'application/json'},
          body: JSON.stringify({mac})}).then(r=>r.json());
        if (r.ok) loadHosts(); else alert('删除失败：'+(r.error||''));
      });
    });
  }
  document.getElementById('hSearch').onclick = () => { hostPage = 1; loadHosts(); };
  document.getElementById('hExport').onclick = () => { window.location = '/api/hosts.csv'; };
  document.getElementById('hImport').onclick = () => document.getElementById('hCsvFile').click();
  document.getElementById('hCsvFile').addEventListener('change', async () => {
    const f = document.getElementById('hCsvFile').files[0];
    document.getElementById('hCsvFile').value = '';
    const msg = document.getElementById('hImportMsg');
    if (!f) return;
    const fd = new FormData(); fd.append('file', f);
    const r = await fetch('/api/hosts/import', {method:'POST', body:fd}).then(r=>r.json());
    msg.textContent = r.ok
      ? ('✔ 成功导入 ' + r.imported + ' 条，跳过 ' + r.skipped + ' 条（MAC 为主键自动覆盖）')
      : ('导入失败：' + (r.error||''));
    if (r.ok) loadHosts();
  });
  document.getElementById('hPrev').onclick = () => { if(hostPage>1){hostPage--;loadHosts();} };
  document.getElementById('hNext').onclick = () => { hostPage++; loadHosts(); };
  loadHosts();
}

// ---------- 数据来源设备 ----------
if (document.getElementById('devBody')) {
  function loadDevices() {
    api('/api/devices').then(list => {
      document.getElementById('devBody').innerHTML = list.map(d => `
        <tr>
          <td><code>${d.device_ip||''}</code></td>
          <td>${d.device_name||''}</td>
          <td><input id="dev_${(d.device_ip||'').replace(/[^a-zA-Z0-9]/g,'')}" value="${(d.custom_name||'').replace(/"/g,'&quot;')}" placeholder="自定义显示名" style="width:200px;padding:4px;border:1px solid #ccc;border-radius:4px"></td>
          <td>${d.n}</td>
          <td>${d.last_seen||''}</td>
          <td>${d.enabled===0?'<span style="color:#c41d7f">已禁用</span>':'<span class="dot-online"></span>启用'}</td>
          <td>
            <button data-ip="${d.device_ip||''}" class="saveDev">保存</button>
            <button data-ip="${d.device_ip||''}" data-en="${d.enabled===0?1:0}" class="togDev">${d.enabled===0?'启用':'禁用'}</button>
          </td>
        </tr>`).join('') || '<tr><td colspan="7" style="color:#999">暂无设备数据</td></tr>';
      document.querySelectorAll('.saveDev').forEach(b => b.onclick = async () => {
        const ip = b.getAttribute('data-ip');
        const id = 'dev_' + ip.replace(/[^a-zA-Z0-9]/g,'');
        const name = document.getElementById(id).value;
        const r = await fetch('/api/devices/name', {method:'POST', headers:{'Content-Type':'application/json'},
          body: JSON.stringify({device_ip:ip, custom_name:name})}).then(r=>r.json());
        b.textContent = r.ok ? '已保存' : '失败';
      });
      document.querySelectorAll('.togDev').forEach(b => b.onclick = async () => {
        const ip = b.getAttribute('data-ip');
        const en = b.getAttribute('data-en');
        const action = en==='1' ? '启用' : '禁用';
        if (en==='0' && !confirm('确认禁用该设备？禁用后其上报的 syslog 将被丢弃。')) return;
        const r = await fetch('/api/devices/toggle', {method:'POST', headers:{'Content-Type':'application/json'},
          body: JSON.stringify({device_ip:ip, enabled:en==='1'})}).then(r=>r.json());
        if (r.ok) loadDevices(); else alert('操作失败：'+(r.error||''));
      });
    });
  }
  loadDevices();
}
