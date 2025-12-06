import '@fortawesome/fontawesome-free/css/all.min.css'
import '../css/style.css'
import Swal from 'sweetalert2'

const API = ''
let attacker = { active: false, poll: null }
let defender = { active: false, poll: null }
// Target settings (saved locally)
let targetSettings = { targetIps: '', fakeIp: '' }

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
  // Defender tabs
  $$('.tab-btn').forEach(btn => btn.onclick = () => {
    $$('.tab-btn').forEach(b => b.classList.remove('active'))
    btn.classList.add('active')
    $$('.tab-content').forEach(c => c.classList.add('hidden'))
    $(`#tab-${btn.dataset.tab}`).classList.remove('hidden')
  })
  
  // Attacker tabs
  $$('.atk-tab-btn').forEach(btn => btn.onclick = () => {
    $$('.atk-tab-btn').forEach(b => b.classList.remove('active'))
    btn.classList.add('active')
    $$('.atk-tab-content').forEach(c => c.classList.add('hidden'))
    $(`#atktab-${btn.dataset.atktab}`).classList.remove('hidden')
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
        fake_ip: $('#fakeIp').value.trim() || null,
        target_ips: $('#targetedMode').checked ? ($('#targetIps').value.trim() || null) : null,
        cidrlen: $('#targetedMode').checked ? 24 : (+$('#cidrLen').value || 24)
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

async function forceStopAttack() {
  // Force stop - reset everything regardless of state
  try {
    await fetch(`${API}/api/stop`, { method: 'POST' })
  } catch(e) {}
  
  attacker.active = false
  if (attacker.poll) clearInterval(attacker.poll)
  attacker.poll = null
  updateAttackerUI()
  
  // Reset stats display
  $('#statCycles').textContent = '0'
  $('#statPackets').textContent = '0'
  $('#statHosts').textContent = '0'
  $('#statCycleDuration').innerHTML = '0<small>ms</small>'
  $('#attackUptime').textContent = '--:--:--'
  
  toast('info', 'Force stopped')
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
  if (!items.length) { tbody.innerHTML = '<tr><td colspan="3" class="text-center opacity-50 py-4">No flagged</td></tr>'; return }
  
  tbody.innerHTML = items.map(i => `
    <tr>
      <td><span class="px-1.5 py-0.5 rounded text-xs ${i.type === 'IP' ? 'bg-orange-600' : 'bg-yellow-600 text-black'}">${i.type}</span></td>
      <td class="font-mono">${i.addr}</td>
      <td>${i.count}</td>
    </tr>
  `).join('')
}

// ===== TARGET SETTINGS =====
function loadTargetSettings() {
  const saved = localStorage.getItem('targetSettings')
  if (saved) {
    targetSettings = JSON.parse(saved)
  }
  $('#targetedMode').checked = targetSettings.targetedMode || false
  $('#targetIps').value = targetSettings.targetIps || ''
  $('#fakeIp').value = targetSettings.fakeIp || ''
  $('#cidrLen').value = targetSettings.cidrLen || 24
  updateTargetUI()
}

function saveTargetSettings() {
  targetSettings.targetedMode = $('#targetedMode').checked
  targetSettings.targetIps = $('#targetIps').value.trim()
  targetSettings.fakeIp = $('#fakeIp').value.trim()
  targetSettings.cidrLen = +$('#cidrLen').value || 24
  localStorage.setItem('targetSettings', JSON.stringify(targetSettings))
  updateTargetUI()
  toast('success', 'Settings saved')
}

function updateTargetUI() {
  const targeted = $('#targetedMode').checked
  
  // Show/hide relevant inputs
  if (targeted) {
    $('#targetIpsGroup').classList.remove('hidden')
    $('#cidrGroup').classList.add('hidden')
    
    // Auto-set attack types for targeted mode (only ARP is effective)
    $('#arpPoison').checked = true
    $('#ipv6Ra').checked = false
    $('#deadRouter').checked = false
    $('#ipv6Ra').disabled = true
    $('#deadRouter').disabled = true
  } else {
    $('#targetIpsGroup').classList.add('hidden')
    $('#cidrGroup').classList.remove('hidden')
    
    // Re-enable all attack types for subnet mode
    $('#ipv6Ra').disabled = false
    $('#deadRouter').disabled = false
  }
  
  // Update status
  const el = $('#targetStatus')
  if (targeted) {
    const ips = $('#targetIps').value.trim()
    const count = ips ? ips.split(',').filter(ip => ip.trim()).length : 0
    if (count > 0) {
      el.innerHTML = `<i class="fas fa-crosshairs text-red-500"></i> Targeted: ${count} IP(s) - ARP only`
    } else {
      el.innerHTML = `<i class="fas fa-exclamation-triangle text-yellow-500"></i> Enter target IPs above`
    }
  } else {
    const cidr = $('#cidrLen').value || 24
    const hosts = Math.pow(2, 32 - cidr) - 2
    el.innerHTML = `<i class="fas fa-globe text-blue-500"></i> Subnet mode: ~${hosts} hosts (/${cidr})`
  }
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
  loadTargetSettings()
  
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
  $('#forceStopBtn').onclick = () => forceStopAttack()
  $('#defenderBtn').onclick = () => defender.active ? stopDefender() : startDefender()
  $('#clearLogs').onclick = () => $('#attackLogs').innerHTML = '<div class="log-entry opacity-50">[*] Cleared</div>'
  $('#clearFlags').onclick = async () => {
    if ((await Swal.fire({ icon: 'warning', title: 'Clear all?', showCancelButton: true, background: '#111', color: '#fff' })).isConfirmed) {
      await fetch(`${API}/api/defender/clear_flags`, { method: 'POST' })
      toast('success', 'Cleared')
    }
  }
  
  // Target settings
  $('#saveTargets').onclick = () => saveTargetSettings()
  $('#targetedMode').onchange = () => updateTargetUI()
  $('#targetIps').oninput = () => updateTargetUI()
  $('#cidrLen').oninput = () => updateTargetUI()
  
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
  })
  
  // Check initial state
  fetch(`${API}/api/status`).then(r => r.json()).then(s => {
    if (s.active) { attacker.active = true; updateAttackerUI(); pollAttacker() }
  }).catch(() => {})
  
  fetch(`${API}/api/defender/status`).then(r => r.json()).then(s => {
    if (s.active) { defender.active = true; updateDefenderUI(); pollDefender() }
  }).catch(() => {})
})
