import '@fortawesome/fontawesome-free/css/all.min.css'
import '../css/style.css'
import Swal from 'sweetalert2'

const API = ''
let attacker = { active: false, poll: null }
let defender = { active: false, poll: null }
let scanner = { scanning: false, poll: null, devices: [] }
let kicks = []

// ===== UTILS =====
const $ = s => document.querySelector(s)
const $$ = s => document.querySelectorAll(s)
const formatTime = s => s > 0 ? [Math.floor(s/3600), Math.floor(s%3600/60), s%60].map(v => String(v).padStart(2,'0')).join(':') : '--:--:--'
const stripAnsi = s => s.replace(/\x1b\[[0-9;]*m/g, '')
const toast = (icon, title) => Swal.fire({ icon, title, background: '#111', color: '#fff', timer: 1500, showConfirmButton: false })

// ===== THEME =====
function setTheme(t) { document.body.className = `theme-${t}`; localStorage.setItem('theme', t) }
function loadTheme() { const t = localStorage.getItem('theme') || 'hacker'; $('#themeSelector').value = t; setTheme(t) }

// ===== NAV =====
function initNav() {
  $$('.nav-btn').forEach(btn => btn.onclick = () => {
    $$('.nav-btn').forEach(b => b.classList.remove('active'))
    btn.classList.add('active')
    $$('.page-section').forEach(p => p.classList.remove('active'))
    $(`#page-${btn.dataset.page}`).classList.add('active')
  })
}

function initTabs() {
  $$('.tab-btn').forEach(btn => btn.onclick = () => {
    $$('.tab-btn').forEach(b => b.classList.remove('active'))
    btn.classList.add('active')
    $$('.tab-content').forEach(c => c.classList.add('hidden'))
    $(`#tab-${btn.dataset.tab}`).classList.remove('hidden')
  })
}

// ===== INTERFACES =====
async function loadInterfaces() {
  try {
    const res = await fetch(`${API}/api/interfaces`)
    const { interfaces } = await res.json()
    
    const opts = '<option value="">Select...</option>' + interfaces.map(i => 
      `<option value="${i.name}" data-info='${JSON.stringify(i)}'>${i.name} (${i.ip})</option>`
    ).join('')
    
    $('#attackInterface').innerHTML = opts
    $('#defenderInterface').innerHTML = opts
    $('#scannerInterface').innerHTML = opts
  } catch(e) { console.error(e) }
}

function showNetworkInfo(el, iface) {
  if (!iface) { el.innerHTML = '<span class="opacity-50">Select interface</span>'; return }
  
  let html = `
    <div class="info-row"><span>Interface</span><span>${iface.name}</span></div>
    <div class="info-row"><span>Type</span><span class="capitalize">${iface.type || 'unknown'}</span></div>
    <div class="info-row"><span>IP</span><span>${iface.ip || '-'}</span></div>
    <div class="info-row"><span>Gateway</span><span>${iface.gateway || '-'}</span></div>
    <div class="info-row"><span>MAC</span><span class="text-xs">${iface.mac || '-'}</span></div>
  `
  
  // Add WiFi info if available
  if (iface.wifi) {
    const w = iface.wifi
    html += `
      <div class="info-row mt-2 pt-2 border-t border-gray-700"><span>SSID</span><span>${w.ssid || '-'}</span></div>
      <div class="info-row"><span>Band</span><span>${w.band || '-'}</span></div>
      <div class="info-row"><span>Radio</span><span>${w.radio_type || '-'}</span></div>
      <div class="info-row"><span>Channel</span><span>${w.channel || '-'}</span></div>
      <div class="info-row"><span>Signal</span><span>${w.signal || '-'}</span></div>
      <div class="info-row"><span>Speed</span><span>${w.rx_rate || '-'}</span></div>
    `
  }
  
  el.innerHTML = html
}

// ===== ATTACKER =====
async function startAttack() {
  const iface = $('#attackInterface').value
  if (!iface) return toast('error', 'Select interface')
  
  const ok = await Swal.fire({
    icon: 'warning', title: 'Start Attack?', text: 'Only use on authorized networks!',
    showCancelButton: true, confirmButtonText: 'Start', confirmButtonColor: '#dc2626',
    background: '#111', color: '#fff'
  })
  if (!ok.isConfirmed) return
  
  try {
    const res = await fetch(`${API}/api/start`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        interface: iface,
        interval: +$('#attackInterval').value,
        enable_ipv6: $('#ipv6Ra').checked,
        fake_ip: $('#fakeIp').value || null,
        target_ips: $('#targetIps').value || null,
        cidrlen: +$('#cidrLen').value
      })
    })
    const data = await res.json()
    if (data.success) { attacker.active = true; updateAttackerUI(); pollAttacker() }
    else toast('error', data.error)
  } catch(e) { toast('error', 'Connection failed') }
}

async function stopAttack() {
  try {
    await fetch(`${API}/api/stop`, { method: 'POST' })
    attacker.active = false
    updateAttackerUI()
    clearInterval(attacker.poll)
  } catch(e) { console.error(e) }
}

function updateAttackerUI() {
  const btn = $('#attackBtn')
  if (attacker.active) {
    btn.innerHTML = '<i class="fas fa-stop"></i>STOP ATTACK'
    btn.className = 'btn-action btn-success'
    $('#attackStatus').className = 'status-dot status-active'
    $('#attackStatusText').textContent = 'Active'
  } else {
    btn.innerHTML = '<i class="fas fa-play"></i>START ATTACK'
    btn.className = 'btn-action btn-danger'
    $('#attackStatus').className = 'status-dot status-inactive'
    $('#attackStatusText').textContent = 'Inactive'
  }
}

function pollAttacker() {
  attacker.poll = setInterval(async () => {
    try {
      const res = await fetch(`${API}/api/status`)
      const s = await res.json()
      
      $('#statCycles').textContent = s.statistics.cycles || 0
      $('#statPackets').textContent = s.statistics.packets_sent || 0
      $('#statHosts').textContent = s.network_info?.target_hosts || 0
      $('#statCycleDuration').innerHTML = `${s.statistics.last_cycle_duration || 0}<small>ms</small>`
      
      if (s.statistics.start_time) {
        $('#attackUptime').textContent = formatTime(Math.floor(Date.now()/1000 - s.statistics.start_time))
      }
      
      if (!s.active && attacker.active) { attacker.active = false; updateAttackerUI(); clearInterval(attacker.poll) }
      
      const logs = await fetch(`${API}/api/logs?limit=50`).then(r => r.json())
      if (logs.logs?.length) {
        $('#attackLogs').innerHTML = logs.logs.map(l => `<div class="log-entry">${stripAnsi(l.message)}</div>`).join('')
        $('#attackLogs').scrollTop = $('#attackLogs').scrollHeight
      }
    } catch(e) {}
  }, 1000)
}


// ===== DEFENDER =====
async function startDefender() {
  const iface = $('#defenderInterface').value
  if (!iface) return toast('error', 'Select interface')
  
  try {
    const res = await fetch(`${API}/api/defender/start`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ interface: iface })
    })
    const data = await res.json()
    if (data.success) { defender.active = true; updateDefenderUI(); pollDefender() }
    else toast('error', data.error)
  } catch(e) { toast('error', 'Connection failed') }
}

async function stopDefender() {
  try {
    await fetch(`${API}/api/defender/stop`, { method: 'POST' })
    defender.active = false
    updateDefenderUI()
    clearInterval(defender.poll)
  } catch(e) { console.error(e) }
}

function updateDefenderUI() {
  const btn = $('#defenderBtn')
  if (defender.active) {
    btn.innerHTML = '<i class="fas fa-stop"></i>STOP'
    btn.className = 'btn-action btn-danger'
    $('#defenderStatus').className = 'status-dot status-active'
    $('#defenderStatusText').textContent = 'Active'
  } else {
    btn.innerHTML = '<i class="fas fa-play"></i>START MONITORING'
    btn.className = 'btn-action btn-success'
    $('#defenderStatus').className = 'status-dot status-inactive'
    $('#defenderStatusText').textContent = 'Inactive'
  }
}

function pollDefender() {
  defender.poll = setInterval(async () => {
    try {
      const s = await fetch(`${API}/api/defender/status`).then(r => r.json())
      
      $('#defStatPackets').textContent = s.statistics?.total_packets || 0
      $('#defStatSuspicious').textContent = s.statistics?.suspicious_packets || 0
      $('#defStatFlaggedIps').textContent = s.statistics?.flagged_ips || 0
      $('#defStatFlaggedMacs').textContent = s.statistics?.flagged_macs || 0
      
      if (s.start_time) {
        $('#defenderUptime').textContent = formatTime(Math.floor(Date.now()/1000 - s.start_time))
      }
      
      if (!s.active && defender.active) { defender.active = false; updateDefenderUI(); clearInterval(defender.poll) }
      
      // Alerts
      const alerts = await fetch(`${API}/api/defender/alerts?limit=50`).then(r => r.json())
      renderAlerts(alerts.alerts || [])
      $('#alertsCount').textContent = alerts.alerts?.length || 0
      
      // Flagged
      const flagged = await fetch(`${API}/api/defender/flagged`).then(r => r.json())
      renderFlagged(flagged)
      $('#flaggedCount').textContent = Object.keys(flagged.ips||{}).length + Object.keys(flagged.macs||{}).length
    } catch(e) {}
  }, 1000)
}

function renderAlerts(alerts) {
  const el = $('#alertsList')
  if (!alerts.length) { el.innerHTML = '<div class="empty-state"><i class="fas fa-shield-alt"></i><p>No alerts</p></div>'; return }
  
  el.innerHTML = alerts.map(a => `
    <div class="alert-item ${a.severity}">
      <div class="flex justify-between items-center mb-1">
        <span class="badge">${a.severity?.toUpperCase()}</span>
        <span class="text-xs opacity-50">${new Date(a.timestamp).toLocaleTimeString()}</span>
      </div>
      <div class="font-semibold">${a.type}</div>
      <div class="text-xs opacity-70">${a.message}</div>
      ${a.ip ? `<div class="text-xs opacity-50 mt-1">IP: ${a.ip}</div>` : ''}
    </div>
  `).join('')
}

function renderFlagged(data) {
  const items = []
  Object.entries(data.ips || {}).forEach(([ip, info]) => items.push({ type: 'IP', addr: ip, count: info.total_incidents || 0 }))
  Object.entries(data.macs || {}).forEach(([mac, info]) => items.push({ type: 'MAC', addr: mac, count: info.total_incidents || 0 }))
  
  const tbody = $('#flaggedTableBody')
  if (!items.length) { tbody.innerHTML = '<tr><td colspan="4" class="text-center opacity-50 py-4">No flagged</td></tr>'; return }
  
  tbody.innerHTML = items.map(i => `
    <tr>
      <td><span class="px-1.5 py-0.5 rounded text-xs ${i.type === 'IP' ? 'bg-orange-600' : 'bg-yellow-600 text-black'}">${i.type}</span></td>
      <td class="font-mono">${i.addr}</td>
      <td>${i.count}</td>
      <td>
        ${i.type === 'IP' ? `<button class="btn-sm bg-red-600 mr-1" onclick="kick('${i.addr}')"><i class="fas fa-bolt"></i></button>` : ''}
        <button class="btn-sm bg-gray-600" onclick="unflag('${i.addr}','${i.type.toLowerCase()}')"><i class="fas fa-times"></i></button>
      </td>
    </tr>
  `).join('')
}

function renderKicks() {
  const el = $('#kicksList')
  $('#kicksCount').textContent = kicks.length
  if (!kicks.length) { el.innerHTML = '<div class="empty-state"><i class="fas fa-bolt"></i><p>No kicks</p></div>'; return }
  
  el.innerHTML = kicks.map((k, i) => `
    <div class="alert-item ${k.status === 'attacking' ? 'medium' : k.status === 'stopped' ? 'low' : k.ok ? 'low' : 'critical'}">
      <div class="flex justify-between items-center">
        <span class="badge">${k.status === 'attacking' ? 'ATTACKING' : k.status === 'stopped' ? 'STOPPED' : k.ok ? 'SENT' : 'ERROR'}</span>
        <span class="text-xs opacity-50">${new Date(k.time).toLocaleTimeString()}</span>
      </div>
      <div class="flex justify-between items-center mt-1">
        <span class="text-sm">Target: <span class="font-mono">${k.ip}</span></span>
        ${k.status === 'attacking' ? `<button class="btn-sm bg-red-600" onclick="stopKick(${i})"><i class="fas fa-stop"></i> Stop</button>` : ''}
      </div>
    </div>
  `).join('')
}

window.kick = async function(ip) {
  const ok = await Swal.fire({
    icon: 'warning', title: 'Kick?', text: `Disconnect ${ip}?`,
    showCancelButton: true, confirmButtonText: 'KICK', confirmButtonColor: '#dc2626',
    background: '#111', color: '#fff'
  })
  if (!ok.isConfirmed) return
  
  // Add to kicks with attacking status
  const kickEntry = { ip, status: 'attacking', ok: true, time: Date.now() }
  kicks.unshift(kickEntry)
  renderKicks()
  
  try {
    const res = await fetch(`${API}/api/defender/disconnect_ip`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip })
    })
    const data = await res.json()
    kickEntry.ok = data.success
    if (!data.success) kickEntry.status = 'error'
    renderKicks()
    toast(data.success ? 'success' : 'error', data.success ? 'Attack sent' : data.error)
  } catch(e) { 
    kickEntry.ok = false
    kickEntry.status = 'error'
    renderKicks()
  }
}

window.stopKick = function(index) {
  if (kicks[index]) {
    kicks[index].status = 'stopped'
    renderKicks()
    toast('info', 'Kick stopped')
  }
}

window.unflag = async function(addr, type) {
  try {
    await fetch(`${API}/api/defender/unflag`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ address: addr, type })
    })
    toast('success', 'Removed')
  } catch(e) {}
}

// ===== SCANNER =====
async function startScan() {
  const iface = $('#scannerInterface').value
  if (!iface) return toast('error', 'Select interface')
  
  try {
    scanner.scanning = true
    updateScannerUI()
    
    const res = await fetch(`${API}/api/scanner/scan`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        interface: iface,
        timeout: +$('#scanTimeout').value || 3
      })
    })
    const data = await res.json()
    if (data.success) {
      pollScanner()
    } else {
      scanner.scanning = false
      updateScannerUI()
      toast('error', data.error)
    }
  } catch(e) {
    scanner.scanning = false
    updateScannerUI()
    toast('error', 'Connection failed')
  }
}

function updateScannerUI() {
  const btn = $('#scanBtn')
  if (scanner.scanning) {
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i>SCANNING...'
    btn.disabled = true
    btn.className = 'btn-action btn-secondary'
    $('#scannerStatus').className = 'status-dot status-active'
    $('#scannerStatusText').textContent = 'Scanning'
  } else {
    btn.innerHTML = '<i class="fas fa-search"></i>SCAN NETWORK'
    btn.disabled = false
    btn.className = 'btn-action btn-primary'
    $('#scannerStatus').className = 'status-dot status-inactive'
    $('#scannerStatusText').textContent = 'Ready'
  }
}

function pollScanner() {
  const check = async () => {
    try {
      const status = await fetch(`${API}/api/scanner/status`).then(r => r.json())
      
      if (!status.scanning) {
        scanner.scanning = false
        updateScannerUI()
        
        // Get devices
        const data = await fetch(`${API}/api/scanner/devices`).then(r => r.json())
        scanner.devices = data.devices || []
        renderDevices()
        
        $('#scanDevices').textContent = scanner.devices.length
        $('#scanOnline').textContent = scanner.devices.length
        $('#scanSubnet').textContent = data.subnet || '-'
        $('#scanTime').textContent = data.last_scan ? new Date(data.last_scan * 1000).toLocaleTimeString() : '-'
        
        return
      }
      
      setTimeout(check, 500)
    } catch(e) {
      scanner.scanning = false
      updateScannerUI()
    }
  }
  check()
}

// Track active attacks per device
let deviceAttacks = {}

function renderDevices() {
  const tbody = $('#deviceTableBody')
  const search = ($('#deviceSearch')?.value || '').toLowerCase()
  
  let devices = scanner.devices
  if (search) {
    devices = devices.filter(d => 
      d.ip.includes(search) || 
      d.mac.toLowerCase().includes(search) || 
      d.vendor.toLowerCase().includes(search) ||
      d.hostname.toLowerCase().includes(search)
    )
  }
  
  if (!devices.length) {
    tbody.innerHTML = '<tr><td colspan="5" class="text-center opacity-50 py-8">No devices found</td></tr>'
    return
  }
  
  tbody.innerHTML = devices.map(d => {
    const isAttacking = deviceAttacks[d.ip]?.active
    return `
    <tr class="${d.is_gateway ? 'bg-yellow-900/20' : d.is_self ? 'bg-blue-900/20' : ''}">
      <td class="font-mono">
        ${d.ip}
        ${d.is_gateway ? '<span class="ml-1 text-xs text-yellow-500">(GW)</span>' : ''}
        ${d.is_self ? '<span class="ml-1 text-xs text-blue-500">(You)</span>' : ''}
      </td>
      <td class="font-mono text-xs">${d.mac}</td>
      <td class="text-sm">${d.vendor}</td>
      <td><span class="px-2 py-0.5 rounded text-xs bg-green-600">Online</span></td>
      <td>
        ${d.is_self ? '-' : isAttacking 
          ? `<button class="btn-sm bg-green-600" onclick="stopDeviceAttack('${d.ip}')"><i class="fas fa-stop"></i></button>`
          : `<button class="btn-sm bg-red-600" onclick="startDeviceAttack('${d.ip}')"><i class="fas fa-bolt"></i></button>`
        }
      </td>
    </tr>
  `}).join('')
}

window.startDeviceAttack = async function(ip) {
  const iface = $('#scannerInterface').value
  if (!iface) return toast('error', 'Select interface first')
  
  try {
    const res = await fetch(`${API}/api/defender/disconnect_ip`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip })
    })
    const data = await res.json()
    if (data.success) {
      deviceAttacks[ip] = { active: true, time: Date.now() }
      renderDevices()
      toast('success', `Attacking ${ip}`)
    } else {
      toast('error', data.error)
    }
  } catch(e) {
    toast('error', 'Failed')
  }
}

window.stopDeviceAttack = function(ip) {
  deviceAttacks[ip] = { active: false }
  renderDevices()
  toast('info', `Stopped ${ip}`)
}

function exportDevices() {
  if (!scanner.devices.length) return toast('error', 'No devices to export')
  
  const csv = 'IP,MAC,Vendor,Hostname\n' + scanner.devices.map(d => 
    `${d.ip},${d.mac},${d.vendor},${d.hostname}`
  ).join('\n')
  
  const blob = new Blob([csv], { type: 'text/csv' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `network-scan-${new Date().toISOString().slice(0,10)}.csv`
  a.click()
  URL.revokeObjectURL(url)
  toast('success', 'Exported')
}

// ===== PANIC EXIT =====
let panicTimer = null
let panicCountdown = 0

async function panicExit() {
  // Stop all attacks
  try {
    await fetch(`${API}/api/stop`, { method: 'POST' })
    await fetch(`${API}/api/defender/stop`, { method: 'POST' })
  } catch(e) {}
  
  // Close window/kill app
  try {
    await fetch(`${API}/api/shutdown`, { method: 'POST' })
  } catch(e) {}
  
  window.close()
}

async function setPanicTimer() {
  const { value: time } = await Swal.fire({
    title: 'Set Panic Timer',
    html: `
      <div class="flex gap-2 justify-center">
        <input id="panicMin" type="number" class="swal2-input" style="width:80px" placeholder="Min" value="0" min="0">
        <input id="panicSec" type="number" class="swal2-input" style="width:80px" placeholder="Sec" value="30" min="0" max="59">
      </div>
      <p class="text-xs opacity-50 mt-2">App will auto-exit after timer</p>
    `,
    background: '#111', color: '#fff',
    showCancelButton: true,
    confirmButtonText: 'Start Timer',
    confirmButtonColor: '#dc2626',
    preConfirm: () => {
      const min = +document.getElementById('panicMin').value || 0
      const sec = +document.getElementById('panicSec').value || 0
      return min * 60 + sec
    }
  })
  
  if (time && time > 0) {
    startPanicCountdown(time)
  }
}

function startPanicCountdown(seconds) {
  panicCountdown = seconds
  const el = $('#panicCountdown')
  el.classList.remove('hidden')
  
  if (panicTimer) clearInterval(panicTimer)
  
  panicTimer = setInterval(() => {
    panicCountdown--
    const min = Math.floor(panicCountdown / 60)
    const sec = panicCountdown % 60
    el.textContent = `EXIT: ${min}:${String(sec).padStart(2, '0')}`
    
    if (panicCountdown <= 0) {
      clearInterval(panicTimer)
      panicExit()
    }
  }, 1000)
  
  toast('warning', `Panic timer: ${seconds}s`)
}

function cancelPanicTimer() {
  if (panicTimer) {
    clearInterval(panicTimer)
    panicTimer = null
    panicCountdown = 0
    $('#panicCountdown').classList.add('hidden')
    toast('info', 'Timer cancelled')
  }
}

// ===== INIT =====
document.addEventListener('DOMContentLoaded', () => {
  loadTheme()
  initNav()
  initTabs()
  loadInterfaces()
  renderKicks()
  
  $('#themeSelector').onchange = e => setTheme(e.target.value)
  
  $('#attackInterface').onchange = e => {
    const opt = e.target.selectedOptions[0]
    showNetworkInfo($('#attackNetworkInfo'), opt?.dataset.info ? JSON.parse(opt.dataset.info) : null)
  }
  
  $('#defenderInterface').onchange = e => {
    const opt = e.target.selectedOptions[0]
    showNetworkInfo($('#defenderNetworkInfo'), opt?.dataset.info ? JSON.parse(opt.dataset.info) : null)
  }
  
  $('#attackBtn').onclick = () => attacker.active ? stopAttack() : startAttack()
  $('#defenderBtn').onclick = () => defender.active ? stopDefender() : startDefender()
  $('#clearLogs').onclick = () => $('#attackLogs').innerHTML = '<div class="log-entry opacity-50">[*] Cleared</div>'
  $('#clearFlags').onclick = async () => {
    if ((await Swal.fire({ icon: 'warning', title: 'Clear all?', showCancelButton: true, background: '#111', color: '#fff' })).isConfirmed) {
      await fetch(`${API}/api/defender/clear_flags`, { method: 'POST' })
      toast('success', 'Cleared')
    }
  }
  $('#clearKicks').onclick = () => { kicks = []; renderKicks() }
  
  // Scanner events
  $('#scanBtn').onclick = () => !scanner.scanning && startScan()
  $('#deviceSearch').oninput = () => renderDevices()
  $('#exportDevices').onclick = () => exportDevices()
  
  // Auto refresh
  let autoRefreshInterval = null
  $('#autoRefresh').onchange = e => {
    if (e.target.checked) {
      autoRefreshInterval = setInterval(() => {
        if (!scanner.scanning) startScan()
      }, 30000)
    } else {
      clearInterval(autoRefreshInterval)
    }
  }
  
  // Panic Exit events
  $('#panicNow').onclick = async () => {
    const ok = await Swal.fire({
      icon: 'warning', title: 'PANIC EXIT?', text: 'Stop all and close app?',
      showCancelButton: true, confirmButtonText: 'EXIT NOW', confirmButtonColor: '#dc2626',
      background: '#111', color: '#fff'
    })
    if (ok.isConfirmed) panicExit()
  }
  
  $('#panicTimer').onclick = () => {
    if (panicTimer) {
      cancelPanicTimer()
    } else {
      setPanicTimer()
    }
  }
  
  // Keyboard shortcuts: ALT+X = instant exit, ALT+F = timer, ALT+V = minimize
  document.addEventListener('keydown', async e => {
    if (e.altKey && e.key.toLowerCase() === 'x') {
      e.preventDefault()
      panicExit()
    }
    if (e.altKey && e.key.toLowerCase() === 'f') {
      e.preventDefault()
      if (panicTimer) cancelPanicTimer()
      else setPanicTimer()
    }
    if (e.altKey && e.key.toLowerCase() === 'v') {
      e.preventDefault()
      try {
        const res = await fetch(`${API}/api/hide`, { method: 'POST' })
        const data = await res.json()
        if (!data.success) {
          // Fallback to minimize if hide fails
          await fetch(`${API}/api/minimize`, { method: 'POST' })
        }
      } catch(err) {}
    }
  })
  
  // Check initial state
  fetch(`${API}/api/status`).then(r => r.json()).then(s => {
    if (s.active) { attacker.active = true; updateAttackerUI(); pollAttacker() }
  }).catch(() => {})
  
  fetch(`${API}/api/defender/status`).then(r => r.json()).then(s => {
    if (s.active) { defender.active = true; updateDefenderUI(); pollDefender() }
  }).catch(() => {})
})
