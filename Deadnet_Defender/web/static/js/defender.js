// Deadnet Defender - Web Interface JavaScript (No Template Strings)

let updateInterval = null;
let lastAlertCount = 0;
let lastFlaggedIPsCount = 0;
let currentNetworkInfo = null;
let allLogs = [];
let currentLogTab = 'packets';
let lastPacketCounts = {
    total: 0,
    arp: 0,
    ipv6: 0
};
let lastLogId = 0;

function toggleTheme() {
    const html = document.documentElement;
    if (html.classList.contains('dark')) {
        html.classList.remove('dark');
        localStorage.setItem('theme', 'light');
    } else {
        html.classList.add('dark');
        localStorage.setItem('theme', 'dark');
    }
}

function loadTheme() {
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme === 'light') {
        document.documentElement.classList.remove('dark');
    } else {
        document.documentElement.classList.add('dark');
    }
}

document.addEventListener('DOMContentLoaded', function() {
    loadTheme();
    loadInterfaces();
    startStatusUpdates();
    
    const interfaceSelect = document.getElementById('interfaceSelect');
    interfaceSelect.addEventListener('change', function() {
        if (this.value) {
            const selectedOption = this.options[this.selectedIndex];
            document.getElementById('selectedInterfaceName').textContent = selectedOption.textContent;
            document.getElementById('selectedInterfaceDisplay').classList.remove('hidden');
            
            currentNetworkInfo = {
                adapter: selectedOption.textContent,
                ip: selectedOption.getAttribute('data-ip') || '-',
                mac: selectedOption.getAttribute('data-mac') || '-',
                gateway: selectedOption.getAttribute('data-gateway') || '-',
                subnet: selectedOption.getAttribute('data-subnet') || '-'
            };
            updateNetworkInfo();
        } else {
            document.getElementById('selectedInterfaceDisplay').classList.add('hidden');
            currentNetworkInfo = null;
            clearNetworkInfo();
        }
    });
});

function updateNetworkInfo() {
    if (!currentNetworkInfo) return;
    document.getElementById('netAdapter').textContent = currentNetworkInfo.adapter;
    document.getElementById('netLocalIP').textContent = currentNetworkInfo.ip;
    document.getElementById('netMAC').textContent = currentNetworkInfo.mac;
    document.getElementById('netGateway').textContent = currentNetworkInfo.gateway;
    document.getElementById('netSubnet').textContent = currentNetworkInfo.subnet;
}

function clearNetworkInfo() {
    document.getElementById('netAdapter').textContent = '-';
    document.getElementById('netLocalIP').textContent = '-';
    document.getElementById('netMAC').textContent = '-';
    document.getElementById('netGateway').textContent = '-';
    document.getElementById('netSubnet').textContent = '-';
}

async function loadInterfaces() {
    try {
        const response = await fetch('/api/interfaces');
        const data = await response.json();
        const select = document.getElementById('interfaceSelect');
        select.innerHTML = '<option value="">Select interface...</option>';
        
        data.interfaces.forEach(function(iface) {
            const option = document.createElement('option');
            option.value = iface.name;
            option.textContent = iface.friendly_name || iface.ip;
            option.setAttribute('data-ip', iface.ip);
            option.setAttribute('data-mac', iface.mac || '');
            option.setAttribute('data-gateway', iface.gateway || 'N/A');
            option.setAttribute('data-subnet', iface.subnet || 'N/A');
            select.appendChild(option);
        });
    } catch (error) {
        Swal.fire({ icon: 'error', title: 'Error', text: 'Failed to load network interfaces' });
    }
}

async function startMonitoring() {
    const iface = document.getElementById('interfaceSelect').value;
    
    if (!iface) {
        Swal.fire({
            icon: 'warning',
            title: 'No Interface Selected',
            text: 'Please select a network interface first'
        });
        return;
    }
    
    try {
        const response = await fetch('/api/start', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ interface: iface })
        });
        
        const data = await response.json();
        
        if (data.success) {
            document.getElementById('startBtn').disabled = true;
            document.getElementById('interfaceSelect').disabled = true;
            
            updateStatusBadge('active', 'MONITORING');
            
            Swal.fire({
                icon: 'success',
                title: 'Monitoring Started',
                text: 'Network monitoring is now active',
                timer: 2000,
                showConfirmButton: false
            });
        } else {
            throw new Error(data.error);
        }
    } catch (error) {
        console.error('Error starting monitoring:', error);
        Swal.fire({
            icon: 'error',
            title: 'Error',
            text: error.message || 'Failed to start monitoring'
        });
    }
}

async function stopMonitoring() {
    try {
        const response = await fetch('/api/stop', {
            method: 'POST'
        });
        
        const data = await response.json();
        
        if (data.success) {
            document.getElementById('startBtn').disabled = false;
            document.getElementById('interfaceSelect').disabled = false;
            
            updateStatusBadge('idle', 'IDLE');
            
            Swal.fire({
                icon: 'info',
                title: 'Monitoring Stopped',
                text: 'Network monitoring has been stopped',
                timer: 2000,
                showConfirmButton: false
            });
        } else {
            Swal.fire({
                icon: 'warning',
                title: 'No Active Monitoring',
                text: 'There is no monitoring session to stop'
            });
        }
    } catch (error) {
        console.error('Error stopping monitoring:', error);
        Swal.fire({
            icon: 'error',
            title: 'Error',
            text: error.message || 'Failed to stop monitoring'
        });
    }
}

function updateStatusBadge(status, text) {
    const indicator = document.getElementById('statusIndicator');
    const dot = indicator.querySelector('span.w-2');
    const label = indicator.querySelectorAll('span')[1];
    
    if (status === 'active') {
        indicator.className = 'flex items-center space-x-2 px-3 py-1.5 rounded-full bg-green-100 dark:bg-green-900/30';
        dot.className = 'w-2 h-2 rounded-full bg-green-500 pulse';
        label.className = 'text-xs font-medium text-green-700 dark:text-green-400';
    } else {
        indicator.className = 'flex items-center space-x-2 px-3 py-1.5 rounded-full bg-gray-100 dark:bg-slate-700';
        dot.className = 'w-2 h-2 rounded-full bg-gray-400 dark:bg-gray-500';
        label.className = 'text-xs font-medium text-gray-600 dark:text-gray-300';
    }
    label.textContent = text;
}

function startStatusUpdates() {
    updateInterval = setInterval(async function() {
        await updateStatus();
        await updateAlerts();
        await updateFlagged();
    }, 1000);
}

async function updateStatus() {
    try {
        const response = await fetch('/api/status');
        const data = await response.json();
        
        document.getElementById('statPackets').textContent = data.statistics.total_packets.toLocaleString();
        document.getElementById('statSuspicious').textContent = data.statistics.suspicious_packets.toLocaleString();
        document.getElementById('statFlaggedIPs').textContent = data.statistics.flagged_ips.toLocaleString();
        
        // Update suspicious packet breakdown
        document.getElementById('packetSuspiciousARP').textContent = (data.statistics.suspicious_arp || 0).toLocaleString();
        document.getElementById('packetSuspiciousIPv6').textContent = (data.statistics.suspicious_ipv6 || 0).toLocaleString();
        
        // Calculate specific attack types from alerts
        const deadRouterCount = allLogs.filter(function(log) { 
            return log.type && log.type.indexOf('DEAD_ROUTER') !== -1 && log.suspicious; 
        }).length;
        const arpSpoofingCount = allLogs.filter(function(log) { 
            return log.type && log.type.indexOf('ARP_SPOOFING') !== -1 && log.suspicious; 
        }).length;
        
        document.getElementById('packetDeadRouter').textContent = deadRouterCount.toLocaleString();
        document.getElementById('packetARPSpoofing').textContent = arpSpoofingCount.toLocaleString();
        
        // Generate normal traffic logs
        if (data.active) {
            const currentCounts = {
                total: data.statistics.total_packets,
                arp: data.statistics.arp_packets || 0,
                ipv6: data.statistics.ipv6_packets || 0
            };
            
            // Add normal packet logs if counts increased
            if (currentCounts.arp > lastPacketCounts.arp) {
                const diff = currentCounts.arp - lastPacketCounts.arp;
                addNormalLog('ARP', 'ARP packets detected on network', diff, {
                    protocol: 'ARP',
                    request: 'Address resolution requests'
                });
            }
            
            if (currentCounts.ipv6 > lastPacketCounts.ipv6) {
                const diff = currentCounts.ipv6 - lastPacketCounts.ipv6;
                addNormalLog('IPv6', 'IPv6 packets detected on network', diff, {
                    ipv6: 'fe80::xxxx (link-local)',
                    protocol: 'IPv6',
                    request: 'Router discovery & neighbor solicitation'
                });
            }
            
            // Add general traffic log
            if (currentCounts.total > lastPacketCounts.total && currentCounts.total % 50 === 0) {
                addNormalLog('TRAFFIC', 'Network traffic detected', currentCounts.total - lastPacketCounts.total, {
                    protocol: 'TCP/UDP/DNS',
                    request: 'HTTP requests, DNS queries, general data transfer'
                });
            }
            
            lastPacketCounts = currentCounts;
        }
        
        if (data.active && data.uptime) {
            const m = String(Math.floor(data.uptime / 60)).padStart(2, '0');
            const s = String(data.uptime % 60).padStart(2, '0');
            document.getElementById('statUptime').textContent = m + ':' + s;
        } else {
            document.getElementById('statUptime').textContent = '00:00';
        }
    } catch (error) {}
}

function addNormalLog(type, message, count, extraInfo) {
    extraInfo = extraInfo || {};
    
    const log = {
        id: ++lastLogId,
        timestamp: new Date().toISOString(),
        message: message + (count > 1 ? ' (' + count + ' packets)' : ''),
        type: type,
        severity: null,
        ip: extraInfo.ip || null,
        ipv6: extraInfo.ipv6 || null,
        mac: extraInfo.mac || null,
        protocol: extraInfo.protocol || null,
        request: extraInfo.request || null,
        suspicious: false
    };
    
    allLogs.unshift(log);
    
    // Keep last 200 logs
    if (allLogs.length > 200) {
        allLogs.pop();
    }
    
    if (currentLogTab === 'packets') {
        appendLogToContainer(log);
    }
}

function appendLogToContainer(log) {
    const container = document.getElementById('logsContainer');
    
    // Remove "waiting" message if exists
    if (container.children.length === 1 && container.children[0].textContent.includes('Waiting')) {
        container.innerHTML = '';
    }
    
    const logElement = createLogElement(log);
    container.insertBefore(logElement, container.firstChild);
    
    // Keep only 3 visible logs in DOM
    while (container.children.length > 3) {
        container.removeChild(container.lastChild);
    }
}

function createLogElement(log) {
    const div = document.createElement('div');
    const isSuspicious = log.suspicious || false;
    div.className = 'log-item p-2 rounded-lg ' + (isSuspicious ? 'bg-red-50 dark:bg-red-900/10' : 'bg-gray-50 dark:bg-slate-700/50');
    div.setAttribute('data-suspicious', isSuspicious);
    
    const colors = {
        'critical': '#dc2626',
        'high': '#f97316',
        'medium': '#eab308',
        'low': '#3b82f6'
    };
    div.style.setProperty('--log-color', colors[log.severity] || (isSuspicious ? '#ef4444' : '#6b7280'));
    
    const time = new Date(log.timestamp).toLocaleTimeString();
    const severityColors = {
        'critical': 'text-red-600 dark:text-red-400',
        'high': 'text-orange-600 dark:text-orange-400',
        'medium': 'text-yellow-600 dark:text-yellow-400',
        'low': 'text-blue-600 dark:text-blue-400'
    };
    
    const severityBadge = log.severity ? 
        '<span class="text-xs font-bold ' + (severityColors[log.severity] || severityColors['low']) + '">' + log.severity.toUpperCase() + '</span>' : 
        '<span class="text-xs font-semibold ' + (isSuspicious ? 'text-red-600 dark:text-red-400' : 'text-green-600 dark:text-green-400') + '">' + (isSuspicious ? 'THREAT' : 'NORMAL') + '</span>';
    
    // Build compact details
    let detailsArray = [];
    
    if (log.type) {
        detailsArray.push('<span class="font-mono text-gray-700 dark:text-gray-300">' + log.type + '</span>');
    }
    
    if (log.ip || log.ipv6) {
        detailsArray.push('<span><i class="fas fa-network-wired text-blue-500"></i> <span class="font-mono">' + (log.ip || log.ipv6) + '</span></span>');
    }
    
    if (log.mac) {
        detailsArray.push('<span><i class="fas fa-ethernet text-purple-500"></i> <span class="font-mono text-xs">' + log.mac + '</span></span>');
    }
    
    if (log.protocol) {
        detailsArray.push('<span><i class="fas fa-layer-group text-cyan-500"></i> ' + log.protocol + '</span>');
    }
    
    const detailsHtml = detailsArray.length > 0 ? 
        '<div class="flex flex-wrap items-center gap-2 text-xs text-gray-600 dark:text-gray-400 mt-1">' + detailsArray.join('') + '</div>' : '';
    
    div.innerHTML = '<div class="flex items-center justify-between mb-1">' +
                    '<span class="text-xs font-mono text-gray-500 dark:text-gray-400">' + time + '</span>' +
                    severityBadge +
                    '</div>' +
                    '<div class="text-xs font-medium text-gray-900 dark:text-white leading-tight">' + log.message + '</div>' +
                    detailsHtml;
    return div;
}

async function updateAlerts() {
    try {
        const response = await fetch('/api/alerts?limit=100');
        const data = await response.json();
        
        if (data.alerts.length === lastAlertCount && data.alerts.length > 0) return;
        
        // Only add new alerts
        if (data.alerts.length > lastAlertCount) {
            const newAlerts = data.alerts.slice(0, data.alerts.length - lastAlertCount);
            
            newAlerts.forEach(function(alert) {
                const log = {
                    id: ++lastLogId,
                    timestamp: alert.timestamp,
                    message: alert.message,
                    type: alert.type,
                    severity: alert.severity,
                    ip: alert.ip,
                    mac: alert.mac,
                    suspicious: true
                };
                
                allLogs.unshift(log);
                
                if (currentLogTab === 'packets') {
                    appendLogToContainer(log);
                }
            });
            
            // Keep last 200 logs
            if (allLogs.length > 200) {
                allLogs = allLogs.slice(0, 200);
            }
        }
        
        lastAlertCount = data.alerts.length;
    } catch (error) {}
}

function renderLogs() {
    const container = document.getElementById('logsContainer');
    container.innerHTML = '';
    
    if (allLogs.length === 0) {
        container.innerHTML = '<p class="text-sm text-gray-500 dark:text-gray-400">Waiting for activity...</p>';
    } else {
        // Only render first 3 logs
        const logsToRender = allLogs.slice(0, 3);
        logsToRender.forEach(function(log) {
            container.appendChild(createLogElement(log));
        });
    }
}

function createFlaggedIPEl(ip, info) {
    const div = document.createElement('div');
    div.className = 'p-3 rounded-lg bg-orange-50 dark:bg-orange-900/20 border border-orange-200 dark:border-orange-800';
    div.innerHTML = '<div class="flex justify-between items-start mb-2">' +
                    '<span class="font-mono font-semibold text-sm text-orange-700 dark:text-orange-400">' + ip + '</span>' +
                    '<div class="flex gap-1.5">' +
                    '<button onclick="disconnectIP(\'' + ip + '\')" class="text-xs bg-red-600 hover:bg-red-700 text-white px-2 py-1 rounded-md transition-colors">KICK</button>' +
                    '<button onclick="unflagAddress(\'ip\',\'' + ip + '\')" class="text-xs bg-gray-500 hover:bg-gray-600 text-white px-2 py-1 rounded-md transition-colors">Remove</button>' +
                    '</div></div>' +
                    '<div class="space-y-0.5 text-xs text-gray-600 dark:text-gray-400">' +
                    '<div><span class="font-medium">First:</span> ' + new Date(info.first_seen).toLocaleString() + '</div>' +
                    '<div><span class="font-medium">Last:</span> ' + new Date(info.last_seen).toLocaleString() + '</div>' +
                    '<div><span class="font-medium">Incidents:</span> ' + info.total_incidents + '</div></div>';
    return div;
}

function createThreatCard(ip, info) {
    const div = document.createElement('div');
    div.className = 'threat-card p-3 rounded-lg';
    div.style.setProperty('--threat-color', '#f97316');
    
    // Get MAC addresses from incidents
    const macs = [];
    if (info.incidents) {
        info.incidents.forEach(function(incident) {
            if (incident.mac && macs.indexOf(incident.mac) === -1) {
                macs.push(incident.mac);
            }
        });
    }
    
    const macList = macs.length > 0 ? macs.join(', ') : 'N/A';
    
    div.innerHTML = '<div class="flex justify-between items-start mb-2">' +
                    '<div class="flex-1">' +
                    '<div class="font-mono font-semibold text-sm text-orange-700 dark:text-orange-400 mb-1">' + ip + '</div>' +
                    '<div class="text-xs text-gray-600 dark:text-gray-400 font-mono">' + macList + '</div>' +
                    '</div>' +
                    '<div class="flex gap-1.5">' +
                    '<button onclick="disconnectIP(\'' + ip + '\')" class="text-xs bg-red-600 hover:bg-red-700 text-white px-2 py-1 rounded-md transition-colors">KICK</button>' +
                    '<button onclick="unflagAddress(\'ip\',\'' + ip + '\')" class="text-xs bg-gray-500 hover:bg-gray-600 text-white px-2 py-1 rounded-md transition-colors">Remove</button>' +
                    '</div></div>' +
                    '<div class="space-y-0.5 text-xs text-gray-600 dark:text-gray-400">' +
                    '<div><span class="font-medium">First:</span> ' + new Date(info.first_seen).toLocaleString() + '</div>' +
                    '<div><span class="font-medium">Last:</span> ' + new Date(info.last_seen).toLocaleString() + '</div>' +
                    '<div><span class="font-medium">Incidents:</span> ' + info.total_incidents + '</div></div>';
    return div;
}

async function updateFlagged() {
    try {
        const response = await fetch('/api/flagged');
        const data = await response.json();
        
        if (data.ips) {
            const ips = Object.entries(data.ips);
            if (ips.length !== lastFlaggedIPsCount) {
                lastFlaggedIPsCount = ips.length;
                const container = document.getElementById('flaggedContainer');
                container.innerHTML = '';
                if (ips.length === 0) {
                    container.innerHTML = '<p class="text-sm text-gray-500 dark:text-gray-400">No threats detected</p>';
                } else {
                    ips.forEach(function(e) { container.appendChild(createThreatCard(e[0], e[1])); });
                }
            }
        }
    } catch (error) {}
}

function switchLogTab(tab) {
    currentLogTab = tab;
    const tabPackets = document.getElementById('tabAllPackets');
    const tabFlagged = document.getElementById('tabFlagged');
    const logsContainer = document.getElementById('logsContainer');
    const flaggedContainer = document.getElementById('flaggedContainer');
    const clearBtn = document.getElementById('clearBtn');
    
    if (tab === 'packets') {
        tabPackets.className = 'flex-1 py-2 text-sm font-medium rounded-lg bg-blue-500 text-white';
        tabFlagged.className = 'flex-1 py-2 text-sm font-medium rounded-lg bg-gray-200 dark:bg-slate-700 text-gray-700 dark:text-gray-300';
        logsContainer.classList.remove('hidden');
        flaggedContainer.classList.add('hidden');
        clearBtn.innerHTML = '<i class="fas fa-trash mr-1"></i> Clear';
        clearBtn.onclick = clearAlerts;
    } else {
        tabFlagged.className = 'flex-1 py-2 text-sm font-medium rounded-lg bg-orange-500 text-white';
        tabPackets.className = 'flex-1 py-2 text-sm font-medium rounded-lg bg-gray-200 dark:bg-slate-700 text-gray-700 dark:text-gray-300';
        flaggedContainer.classList.remove('hidden');
        logsContainer.classList.add('hidden');
        clearBtn.innerHTML = '<i class="fas fa-ban mr-1"></i> Clear All';
        clearBtn.onclick = clearAllFlags;
    }
}


async function unflagAddress(type, address) {
    try {
        await fetch('/api/unflag', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ type: type, address: address })
        });
        await updateFlagged();
        await updateStatus();
    } catch (error) {}
}

async function clearAllFlags() {
    const result = await Swal.fire({
        icon: 'warning',
        title: 'Clear All Flags?',
        text: 'This will remove all flagged IPs and MACs',
        showCancelButton: true,
        confirmButtonText: 'Yes, clear all',
        confirmButtonColor: '#dc2626'
    });
    
    if (result.isConfirmed) {
        await fetch('/api/clear_flags', { method: 'POST' });
        await updateFlagged();
        await updateStatus();
        Swal.fire({ icon: 'success', title: 'Cleared', timer: 2000, showConfirmButton: false });
    }
}

async function disconnectIP(ip) {
    const result = await Swal.fire({
        icon: 'warning',
        title: 'Force Disconnect Attack?',
        html: '<p>Launching counter-attack against: <strong>' + ip + '</strong></p><p class="text-xs mt-2">ARP Poisoning + ICMP Unreachable</p>',
        showCancelButton: true,
        confirmButtonText: 'Yes, kick them out!',
        confirmButtonColor: '#dc2626'
    });
    
    if (result.isConfirmed) {
        try {
            const response = await fetch('/api/disconnect_ip', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip: ip })
            });
            const data = await response.json();
            
            if (data.success) {
                Swal.fire({ icon: 'success', title: 'Counter-Attack Launched!', html: '<p>' + ip + ' is being disconnected</p>', timer: 3000, showConfirmButton: false });
            }
        } catch (error) {
            Swal.fire({ icon: 'error', title: 'Error', text: 'Failed to disconnect IP' });
        }
    }
}

function clearAlerts() {
    allLogs = [];
    lastAlertCount = 0;
    lastLogId = 0;
    lastPacketCounts = { total: 0, arp: 0, ipv6: 0 };
    renderLogs();
}
