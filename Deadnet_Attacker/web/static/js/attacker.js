// Deadnet Attacker - Web Interface JavaScript

let updateInterval = null;
let lastLogCount = 0;

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
});

function updateIntervalDisplay() {
    const intensity = document.getElementById('attackIntensity').value;
    const customDiv = document.getElementById('customIntervalDiv');
    
    if (intensity === 'custom') {
        customDiv.classList.remove('hidden');
    } else {
        customDiv.classList.add('hidden');
    }
}

function generateRandomIP() {
    // Get gateway IP from network info
    const gatewayIP = document.getElementById('netGateway').textContent;
    
    // If we have a valid gateway IP, base fake IP on gateway subnet
    if (gatewayIP && gatewayIP !== '-' && /^(\d{1,3}\.){3}\d{1,3}$/.test(gatewayIP)) {
        const parts = gatewayIP.split('.');
        const gatewayLastOctet = parseInt(parts[3]);
        
        // Generate random IP in same subnet, avoiding gateway IP
        let newLastOctet;
        do {
            // Add random offset to gateway's last octet
            const offset = Math.floor(Math.random() * 100) + 10; // 10-109
            newLastOctet = (gatewayLastOctet + offset) % 255;
            if (newLastOctet < 2) newLastOctet = 2; // Avoid .0 and .1
            if (newLastOctet > 254) newLastOctet = 254; // Max valid host
        } while (newLastOctet === gatewayLastOctet); // Don't use gateway IP
        
        return parts[0] + '.' + parts[1] + '.' + parts[2] + '.' + newLastOctet;
    }
    
    // Fallback: Generate random IP in 192.168.x.x range
    const octet3 = Math.floor(Math.random() * 256);
    const octet4 = Math.floor(Math.random() * 200) + 10; // 10-209
    return '192.168.' + octet3 + '.' + octet4;
}

function generateRandomMAC() {
    // Generate random MAC address
    const hex = '0123456789ABCDEF';
    let mac = '';
    for (let i = 0; i < 6; i++) {
        if (i > 0) mac += ':';
        mac += hex[Math.floor(Math.random() * 16)];
        mac += hex[Math.floor(Math.random() * 16)];
    }
    return mac;
}

function toggleTargetedInput() {
    const checkbox = document.getElementById('chkTargeted');
    const input = document.getElementById('targetIPsInput');
    
    input.disabled = !checkbox.checked;
    if (!checkbox.checked) {
        input.value = '';
    }
}

function toggleFakeIPInput() {
    const checkbox = document.getElementById('chkFakeIP');
    const input = document.getElementById('fakeIPInput');
    const gatewayIP = document.getElementById('netGateway').textContent;
    
    if (checkbox.checked) {
        // Check if interface is selected
        if (!gatewayIP || gatewayIP === '-') {
            Swal.fire({
                icon: 'warning',
                title: 'Interface Not Selected',
                text: 'Please select a network interface first to generate a fake IP based on your gateway subnet.',
                showConfirmButton: true
            });
            // Uncheck the checkbox
            checkbox.checked = false;
            return;
        } else {
            // Enable input and auto-generate based on gateway subnet
            input.disabled = false;
            input.value = generateRandomIP();
        }
    } else {
        input.disabled = true;
        input.value = '';
    }
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
            option.textContent = iface.friendly_name || iface.name;
            option.setAttribute('data-ip', iface.ip || '');
            option.setAttribute('data-gateway', iface.gateway || '');
            option.setAttribute('data-subnet', iface.subnet || '');
            option.setAttribute('data-mac', iface.mac || '');
            select.appendChild(option);
        });
        
        select.addEventListener('change', function() {
            if (this.value) {
                const option = this.options[this.selectedIndex];
                updateNetworkInfo({
                    adapter: this.value,
                    ip: option.getAttribute('data-ip') || '-',
                    gateway: option.getAttribute('data-gateway') || '-',
                    subnet: option.getAttribute('data-subnet') || '-',
                    mac: option.getAttribute('data-mac') || '-'
                });
            } else {
                clearNetworkInfo();
            }
        });
    } catch (error) {
        Swal.fire({ icon: 'error', title: 'Error', text: 'Failed to load network interfaces' });
    }
}

function updateNetworkInfo(info) {
    document.getElementById('netAdapter').textContent = info.adapter;
    document.getElementById('netLocalIP').textContent = info.ip;
    document.getElementById('netGateway').textContent = info.gateway;
    document.getElementById('netSubnet').textContent = info.subnet;
    document.getElementById('netMAC').textContent = info.mac;
}

function clearNetworkInfo() {
    document.getElementById('netAdapter').textContent = '-';
    document.getElementById('netLocalIP').textContent = '-';
    document.getElementById('netGateway').textContent = '-';
    document.getElementById('netSubnet').textContent = '-';
    document.getElementById('netMAC').textContent = '-';
}

async function startAttack() {
    const iface = document.getElementById('interfaceSelect').value;
    
    if (!iface) {
        Swal.fire({
            icon: 'warning',
            title: 'No Interface Selected',
            text: 'Please select a network interface first'
        });
        return;
    }
    
    const attacks = {
        arp_poison: document.getElementById('chkArp').checked,
        ipv6_ra: document.getElementById('chkIpv6').checked,
        dead_router: document.getElementById('chkDeadRouter').checked
    };
    
    if (!attacks.arp_poison && !attacks.ipv6_ra && !attacks.dead_router) {
        Swal.fire({
            icon: 'warning',
            title: 'No Attack Selected',
            text: 'Please select at least one attack mode'
        });
        return;
    }
    
    // Get attack interval
    const intensitySelect = document.getElementById('attackIntensity').value;
    let interval = 5; // default
    
    if (intensitySelect === 'custom') {
        interval = parseFloat(document.getElementById('customInterval').value);
        if (isNaN(interval) || interval < 0.5 || interval > 60) {
            Swal.fire({
                icon: 'warning',
                title: 'Invalid Interval',
                text: 'Custom interval must be between 0.5 and 60 seconds'
            });
            return;
        }
    } else {
        interval = parseFloat(intensitySelect);
    }
    
    const result = await Swal.fire({
        icon: 'warning',
        title: 'Start Attack?',
        html: '<p>This will launch network attacks on the selected interface.</p>' +
              '<p class="text-sm mt-2">Interval: <strong>' + interval + 's</strong></p>' +
              '<p class="text-red-600 font-bold mt-2">Make sure you have authorization!</p>',
        showCancelButton: true,
        confirmButtonText: 'Yes, start attack',
        confirmButtonColor: '#dc2626',
        cancelButtonText: 'Cancel'
    });
    
    if (!result.isConfirmed) return;
    
    // Get extended control options
    const targetIPs = document.getElementById('chkTargeted').checked ? document.getElementById('targetIPsInput').value : null;
    const fakeIP = document.getElementById('chkFakeIP').checked ? document.getElementById('fakeIPInput').value : null;
    
    // Validate target IPs
    if (targetIPs && targetIPs.trim()) {
        const ips = targetIPs.split(',').map(ip => ip.trim());
        for (const ip of ips) {
            if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) {
                Swal.fire({
                    icon: 'warning',
                    title: 'Invalid Target IP',
                    text: `Invalid IP format: ${ip}`
                });
                return;
            }
        }
    }
    
    // Validate fake IP
    if (fakeIP && !/^(\d{1,3}\.){3}\d{1,3}$/.test(fakeIP)) {
        Swal.fire({
            icon: 'warning',
            title: 'Invalid IP',
            text: 'Please enter a valid IP address format'
        });
        return;
    }
    
    try {
        const response = await fetch('/api/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                interface: iface,
                attacks: attacks,
                interval: interval,
                fake_ip: fakeIP,
                target_ips: targetIPs
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            document.getElementById('startBtn').disabled = true;
            document.getElementById('interfaceSelect').disabled = true;
            document.getElementById('attackIntensity').disabled = true;
            document.getElementById('customInterval').disabled = true;
            document.getElementById('chkArp').disabled = true;
            document.getElementById('chkIpv6').disabled = true;
            document.getElementById('chkDeadRouter').disabled = true;
            document.getElementById('chkTargeted').disabled = true;
            document.getElementById('targetIPsInput').disabled = true;
            document.getElementById('chkFakeIP').disabled = true;
            document.getElementById('fakeIPInput').disabled = true;
            
            updateStatusBadge('active', 'ATTACKING');
            
            Swal.fire({
                icon: 'success',
                title: 'Attack Started',
                text: 'Network attack is now active',
                timer: 2000,
                showConfirmButton: false
            });
        } else {
            throw new Error(data.error);
        }
    } catch (error) {
        Swal.fire({ icon: 'error', title: 'Error', text: error.message || 'Failed to start attack' });
    }
}

async function stopAttack() {
    try {
        const response = await fetch('/api/stop', { method: 'POST' });
        const data = await response.json();
        
        if (data.success) {
            document.getElementById('startBtn').disabled = false;
            document.getElementById('interfaceSelect').disabled = false;
            document.getElementById('attackIntensity').disabled = false;
            document.getElementById('customInterval').disabled = false;
            document.getElementById('chkArp').disabled = false;
            document.getElementById('chkIpv6').disabled = false;
            document.getElementById('chkDeadRouter').disabled = false;
            document.getElementById('chkTargeted').disabled = false;
            document.getElementById('chkFakeIP').disabled = false;
            
            // Reset extended controls
            document.getElementById('chkTargeted').checked = false;
            document.getElementById('targetIPsInput').value = '';
            document.getElementById('targetIPsInput').disabled = true;
            document.getElementById('chkFakeIP').checked = false;
            document.getElementById('fakeIPInput').value = '';
            document.getElementById('fakeIPInput').disabled = true;
            
            updateStatusBadge('idle', 'IDLE');
            
            Swal.fire({
                icon: 'info',
                title: 'Attack Stopped',
                text: 'Network attack has been stopped',
                timer: 2000,
                showConfirmButton: false
            });
        } else {
            Swal.fire({
                icon: 'warning',
                title: 'No Active Attack',
                text: 'There is no attack session to stop'
            });
        }
    } catch (error) {
        Swal.fire({ icon: 'error', title: 'Error', text: 'Failed to stop attack' });
    }
}

function updateStatusBadge(status, text) {
    const indicator = document.getElementById('statusIndicator');
    const dot = indicator.querySelector('span.w-2');
    const label = indicator.querySelectorAll('span')[1];
    
    if (status === 'active') {
        indicator.className = 'flex items-center space-x-2 px-3 py-1.5 rounded-full bg-red-100 dark:bg-red-900/30';
        dot.className = 'w-2 h-2 rounded-full bg-red-500 pulse';
        label.className = 'text-xs font-medium text-red-700 dark:text-red-400';
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
        await updateLogs();
    }, 1000);
}

async function updateStatus() {
    try {
        const response = await fetch('/api/status');
        const data = await response.json();
        
        document.getElementById('statCycles').textContent = (data.statistics.cycles || 0).toLocaleString();
        document.getElementById('statPackets').textContent = (data.statistics.packets_sent || 0).toLocaleString();
        document.getElementById('statCycleTime').textContent = (data.statistics.last_cycle_duration || 0).toFixed(1) + 's';
        
        // Update interval display
        const intensitySelect = document.getElementById('attackIntensity');
        if (data.active) {
            const interval = intensitySelect.value === 'custom' ? 
                document.getElementById('customInterval').value : 
                intensitySelect.value;
            document.getElementById('statInterval').textContent = interval + 's';
        } else {
            document.getElementById('statInterval').textContent = '-';
        }
        
        if (data.active && data.statistics.start_time) {
            const uptime = Math.floor(Date.now() / 1000) - Math.floor(new Date(data.statistics.start_time).getTime() / 1000);
            const m = String(Math.floor(uptime / 60)).padStart(2, '0');
            const s = String(uptime % 60).padStart(2, '0');
            document.getElementById('statUptime').textContent = m + ':' + s;
        } else {
            document.getElementById('statUptime').textContent = '00:00';
        }
        
        // Only update network info if attack is active (to prevent overwriting user selection)
        if (data.active && data.network_info) {
            updateNetworkInfo({
                adapter: data.interface || '-',
                ip: data.network_info.ip || '-',
                gateway: data.network_info.gateway || '-',
                subnet: data.network_info.subnet || '-',
                mac: data.network_info.mac || '-'
            });
        }
    } catch (error) {}
}

async function updateLogs() {
    try {
        const response = await fetch('/api/logs');
        const data = await response.json();
        
        if (data.logs.length === lastLogCount) return;
        lastLogCount = data.logs.length;
        
        const container = document.getElementById('logsContainer');
        container.innerHTML = '';
        
        if (data.logs.length === 0) {
            container.innerHTML = '<p class="text-sm text-gray-500 dark:text-gray-400">Waiting for attack...</p>';
        } else {
            // Only show last 3 logs
            data.logs.slice(-3).reverse().forEach(function(log) {
                container.appendChild(createLogElement(log));
            });
        }
    } catch (error) {}
}

function createLogElement(log) {
    const div = document.createElement('div');
    div.className = 'log-item p-2 rounded-lg bg-gray-50 dark:bg-slate-700/50';
    div.style.setProperty('--log-color', '#ef4444');
    
    const time = new Date(log.timestamp).toLocaleTimeString();
    const typeColors = {
        'ARP': 'text-cyan-600 dark:text-cyan-400',
        'IPv6': 'text-purple-600 dark:text-purple-400',
        'DEAD_ROUTER': 'text-red-600 dark:text-red-400',
        'INFO': 'text-blue-600 dark:text-blue-400'
    };
    
    const typeClass = typeColors[log.type] || typeColors['INFO'];
    
    div.innerHTML = '<div class="flex items-center justify-between mb-1">' +
                    '<span class="text-xs font-mono text-gray-500 dark:text-gray-400">' + time + '</span>' +
                    '<span class="text-xs font-semibold ' + typeClass + '">' + log.type + '</span>' +
                    '</div>' +
                    '<div class="text-xs text-gray-900 dark:text-white leading-tight">' + log.message + '</div>';
    return div;
}

function clearLogs() {
    lastLogCount = 0;
    document.getElementById('logsContainer').innerHTML = '<p class="text-sm text-gray-500 dark:text-gray-400">Waiting for attack...</p>';
}
