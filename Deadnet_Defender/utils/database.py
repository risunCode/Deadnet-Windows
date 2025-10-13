#!/usr/bin/env python3
"""
Database module for Deadnet Defender
Manages flagged IPs, MACs, and alerts
"""

import json
import os
from datetime import datetime
from collections import defaultdict


class DefenderDatabase:
    """Simple JSON-based database for storing flagged addresses and alerts"""
    
    def __init__(self, db_file='defender_data.json'):
        self.db_file = db_file
        self.data = {
            'flagged_ips': {},
            'flagged_macs': {},
            'alerts': [],
            'statistics': {
                'total_alerts': 0,
                'last_updated': None
            }
        }
        self.load()
    
    def load(self):
        """Load database from file"""
        if os.path.exists(self.db_file):
            try:
                with open(self.db_file, 'r') as f:
                    self.data = json.load(f)
                print(f"[+] Database loaded: {len(self.data['flagged_ips'])} IPs, {len(self.data['flagged_macs'])} MACs flagged")
            except Exception as e:
                print(f"[!] Error loading database: {e}")
    
    def save(self):
        """Save database to file"""
        try:
            self.data['statistics']['last_updated'] = datetime.now().isoformat()
            with open(self.db_file, 'w') as f:
                json.dump(self.data, f, indent=2)
        except Exception as e:
            print(f"[!] Error saving database: {e}")
    
    def flag_ip(self, ip, alert_type, severity, message):
        """Flag an IP address as suspicious"""
        if ip not in self.data['flagged_ips']:
            self.data['flagged_ips'][ip] = {
                'first_seen': datetime.now().isoformat(),
                'incidents': []
            }
        
        self.data['flagged_ips'][ip]['incidents'].append({
            'timestamp': datetime.now().isoformat(),
            'type': alert_type,
            'severity': severity,
            'message': message
        })
        
        self.data['flagged_ips'][ip]['last_seen'] = datetime.now().isoformat()
        self.data['flagged_ips'][ip]['total_incidents'] = len(self.data['flagged_ips'][ip]['incidents'])
        
        self.save()
    
    def flag_mac(self, mac, alert_type, severity, message):
        """Flag a MAC address as suspicious"""
        if mac not in self.data['flagged_macs']:
            self.data['flagged_macs'][mac] = {
                'first_seen': datetime.now().isoformat(),
                'incidents': []
            }
        
        self.data['flagged_macs'][mac]['incidents'].append({
            'timestamp': datetime.now().isoformat(),
            'type': alert_type,
            'severity': severity,
            'message': message
        })
        
        self.data['flagged_macs'][mac]['last_seen'] = datetime.now().isoformat()
        self.data['flagged_macs'][mac]['total_incidents'] = len(self.data['flagged_macs'][mac]['incidents'])
        
        self.save()
    
    def add_alert(self, alert):
        """Add an alert to the database"""
        self.data['alerts'].append(alert)
        self.data['statistics']['total_alerts'] += 1
        
        # Keep only last 1000 alerts
        if len(self.data['alerts']) > 1000:
            self.data['alerts'] = self.data['alerts'][-1000:]
        
        self.save()
    
    def get_flagged_ips(self):
        """Get all flagged IP addresses"""
        return self.data['flagged_ips']
    
    def get_flagged_macs(self):
        """Get all flagged MAC addresses"""
        return self.data['flagged_macs']
    
    def get_flagged_count(self, flag_type):
        """Get count of flagged addresses"""
        if flag_type == 'ip':
            return len(self.data['flagged_ips'])
        elif flag_type == 'mac':
            return len(self.data['flagged_macs'])
        return 0
    
    def unflag_ip(self, ip):
        """Remove IP from flagged list"""
        if ip in self.data['flagged_ips']:
            del self.data['flagged_ips'][ip]
            self.save()
    
    def unflag_mac(self, mac):
        """Remove MAC from flagged list"""
        if mac in self.data['flagged_macs']:
            del self.data['flagged_macs'][mac]
            self.save()
    
    def clear_all_flags(self):
        """Clear all flagged addresses"""
        self.data['flagged_ips'] = {}
        self.data['flagged_macs'] = {}
        self.save()
    
    def get_statistics(self):
        """Get database statistics"""
        return {
            'total_flagged_ips': len(self.data['flagged_ips']),
            'total_flagged_macs': len(self.data['flagged_macs']),
            'total_alerts': self.data['statistics']['total_alerts'],
            'last_updated': self.data['statistics']['last_updated']
        }
