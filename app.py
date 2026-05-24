import os
import csv
import json
import asyncio
import re
import sqlite3
import platform
import subprocess
import time
import ipaddress
from flask import Flask, render_template, jsonify, request, send_file
import io

try:
    from pysnmp.hlapi.v3arch.asyncio import (
        SnmpEngine, CommunityData, UdpTransportTarget, ContextData,
        ObjectType, ObjectIdentity, get_cmd, bulk_cmd
    )
    HAS_PYSNMP = True
except ImportError as e:
    HAS_PYSNMP = False
    print(f"⚠️ 模組載入失敗: {e}")

app = Flask(__name__)
DB_FILE = 'devices.db'

def is_valid_ipv4(ip_str): return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip_str) is not None

def safe_int(val, default=3):
    try:
        if val is None or str(val).strip() == '': return default
        return int(val)
    except (ValueError, TypeError):
        return default

def check_ping(ip):
    try:
        is_windows = platform.system().lower() == 'windows'
        param = '-n' if is_windows else '-c'
        command = ['ping', param, '1', ip]
        
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=1.5)
        if result.returncode != 0: return False
            
        out_text = result.stdout.decode('cp950' if is_windows else 'utf-8', errors='ignore')
        if "無法連線" in out_text or "unreachable" in out_text or "逾時" in out_text or "timed out" in out_text:
            return False
        if is_windows and "TTL=" not in out_text: return False
        return True
    except: return False

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute('''CREATE TABLE IF NOT EXISTS devices (ip TEXT PRIMARY KEY, name TEXT, level INTEGER, community TEXT, location TEXT, visible INTEGER, type TEXT, brand TEXT, model TEXT, sys_descr TEXT, x REAL, y REAL)''')
    try: conn.execute("ALTER TABLE devices ADD COLUMN sys_descr TEXT")
    except: pass
    try: conn.execute("ALTER TABLE devices ADD COLUMN status TEXT DEFAULT 'up'")
    except: pass
    # 💡 擴充資料庫：新增儲存 SNMP OID 原始資料的欄位
    try: conn.execute("ALTER TABLE devices ADD COLUMN snmp_raw TEXT DEFAULT '{}'")
    except: pass
    
    conn.execute('CREATE TABLE IF NOT EXISTS layout_slots (slot_id INTEGER, ip TEXT, x REAL, y REAL, PRIMARY KEY (slot_id, ip))')
    conn.execute('CREATE TABLE IF NOT EXISTS edges (id TEXT PRIMARY KEY, source TEXT, target TEXT, speed INTEGER, oid_info TEXT, port_info TEXT, from_port TEXT, to_port TEXT)')
    try: conn.execute("ALTER TABLE edges ADD COLUMN from_port TEXT")
    except: pass
    try: conn.execute("ALTER TABLE edges ADD COLUMN to_port TEXT")
    except: pass
    conn.commit()

    CSV_FILE = 'devices.csv'
    if os.path.exists(CSV_FILE):
        with open(CSV_FILE, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    conn.execute('''INSERT INTO devices (ip, name, level, community, location, visible, type, brand, model) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''', 
                        (row.get('ip','').strip(), row.get('name','').strip(), safe_int(row.get('level')), row.get('community','public').strip(), row.get('location','').strip(), safe_int(row.get('visible', 1), 1), row.get('type','交換器').strip(), row.get('brand','Unknown').strip(), row.get('model','').strip()))
                except sqlite3.IntegrityError: pass
        conn.commit(); os.rename(CSV_FILE, 'devices_backup.csv')
    conn.close()

def read_db_devices():
    conn = get_db()
    cursor = conn.execute("SELECT * FROM devices")
    devices = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return sorted(devices, key=lambda d: (0, [int(p) for p in d['ip'].split('.')], d['level']) if is_valid_ipv4(d['ip']) else (1, d['level'], d['ip']))

def write_db_devices(devices):
    conn = get_db()
    cursor = conn.cursor()
    for dev in devices:
        cursor.execute("SELECT ip FROM devices WHERE ip=?", (dev['ip'],))
        if cursor.fetchone():
            cursor.execute('''UPDATE devices SET name=?, level=?, community=?, location=?, visible=?, type=?, brand=?, model=?, sys_descr=COALESCE(?, sys_descr), status=?, snmp_raw=COALESCE(?, snmp_raw) WHERE ip=?''', 
                           (dev.get('name'), safe_int(dev.get('level')), dev.get('community'), dev.get('location'), safe_int(dev.get('visible', 1), 1), dev.get('type'), dev.get('brand'), dev.get('model'), dev.get('sys_descr'), dev.get('status', 'up'), dev.get('snmp_raw'), dev['ip']))
        else:
            cursor.execute('''INSERT INTO devices (ip, name, level, community, location, visible, type, brand, model, sys_descr, status, snmp_raw) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''', 
                           (dev['ip'], dev.get('name'), safe_int(dev.get('level')), dev.get('community'), dev.get('location'), safe_int(dev.get('visible', 1), 1), dev.get('type'), dev.get('brand'), dev.get('model'), dev.get('sys_descr'), dev.get('status', 'up'), dev.get('snmp_raw') or '{}'))
    conn.commit(); conn.close()

def parse_snmp_val(val_obj):
    try:
        if hasattr(val_obj, 'asOctets'):
            octets = val_obj.asOctets()
            if not octets: return ""
            if all(32 <= b <= 126 or b in (9, 10, 13) for b in octets):
                return octets.decode('ascii', errors='ignore').strip()
            return ':'.join(f'{b:02X}' for b in octets)
    except: pass
    return str(val_obj).strip()

def extract_brand_model(descr):
    if not descr: return "Unknown", ""
    brand = "Unknown"
    d_lower = descr.lower()
    
    if "ruckus" in d_lower or "ironware" in d_lower: brand = "Ruckus"
    elif "aruba" in d_lower: brand = "Aruba"
    elif "palo alto" in d_lower: brand = "Palo Alto"
    elif "forti" in d_lower: brand = "Fortinet"
    elif "routeros" in d_lower or "mikrotik" in d_lower: brand = "MikroTik"
    elif "d-link" in d_lower or "dgs" in d_lower: brand = "D-Link"
    elif "cisco" in d_lower: brand = "Cisco"
    elif "hp" in d_lower or "procurve" in d_lower: brand = "HP"
    elif "qnap" in d_lower or "qsw" in d_lower: brand = "QNAP"
    elif "dell" in d_lower: brand = "Dell"

    model_str = ""
    m = re.search(r'(CRS\d+[A-Za-z0-9\+\-]+|CX\d{4}[A-Za-z0-9\-]*|ICX\s?\d{4}[A-Za-z0-9\-]*|DGS-\d+[A-Za-z0-9\-]*|QSW-[A-Za-z0-9\-]+|FortiGate-\d+[A-Za-z0-9]*|WS-C\d+[A-Za-z0-9\-]*|C\d{4}[A-Za-z0-9\-]+|[XN]\d{4}[A-Za-z0-9\-]*|PA-\d+[A-Za-z0-9\-]*)', descr, re.IGNORECASE)
    
    if m: model_str = m.group(1).strip()
    else: model_str = descr[:50] + "..." if len(descr) > 50 else descr
        
    return brand, model_str

async def async_get_device_info(ip, community):
    if not HAS_PYSNMP: return "未安裝 PySNMP", "", ""
    snmpEngine = SnmpEngine()
    sys_descr, sys_name, sys_location = "無回應", "", ""
    try:
        transport = await UdpTransportTarget.create((ip, 161), timeout=2.0, retries=2)
        err, stat, idx, varBinds = await get_cmd(
            snmpEngine, CommunityData(community, mpModel=1), transport, ContextData(), 
            ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0')), 
            ObjectType(ObjectIdentity('1.3.6.1.2.1.1.5.0')),
            ObjectType(ObjectIdentity('1.3.6.1.2.1.1.6.0'))
        )
        if not err and not stat:
            for varBind in varBinds:
                oid = str(varBind[0])
                val = parse_snmp_val(varBind[1]).replace('\r', '').replace('\n', ' | ')
                if '1.3.6.1.2.1.1.1.0' in oid: sys_descr = val
                elif '1.3.6.1.2.1.1.5.0' in oid: sys_name = val
                elif '1.3.6.1.2.1.1.6.0' in oid: sys_location = val
    except: pass
    finally: snmpEngine.close_dispatcher()
    return sys_descr, sys_name, sys_location

async def async_get_device_full_data(ip, community):
    if not HAS_PYSNMP: return {}, {}, {}, {}, {}, {}, {}, {}
    snmpEngine = SnmpEngine()
    auth = CommunityData(community, mpModel=1)
    async def walk(oid_prefix):
        results = {}
        try:
            transport = await UdpTransportTarget.create((ip, 161), timeout=3.0, retries=2)
            ctx = ContextData()
            current_oid = ObjectType(ObjectIdentity(oid_prefix))
            for _ in range(30): 
                err, stat, idx, binds = await bulk_cmd(snmpEngine, auth, transport, ctx, 0, 15, current_oid)
                if err or stat or not binds: break
                last_oid = None; out_of_tree = False
                for row in binds:
                    for name, val in (row if isinstance(row, list) else [row]):
                        oid_str = str(name); last_oid = name
                        if not oid_str.startswith(oid_prefix): out_of_tree = True; break
                        idx_str = oid_str.replace(oid_prefix + '.', '')
                        results[idx_str] = parse_snmp_val(val)
                    if out_of_tree: break
                if out_of_tree or not last_oid: break
                current_oid = ObjectType(ObjectIdentity(last_oid))
        except: pass
        return results

    res = await asyncio.gather(
        walk('1.0.8802.1.1.2.1.4.1.1.9'), walk('1.0.8802.1.1.2.1.4.1.1.7'), walk('1.0.8802.1.1.2.1.4.1.1.6'), walk('1.0.8802.1.1.2.1.4.1.1.8'),
        walk('1.3.6.1.2.1.31.1.1.1.1'), walk('1.3.6.1.2.1.31.1.1.1.15'), walk('1.3.6.1.2.1.2.2.1.5'), walk('1.3.6.1.2.1.2.2.1.6')
    )
    snmpEngine.close_dispatcher()
    return res

def snmp_get_device_full_data(ip, community):
    loop = asyncio.new_event_loop(); asyncio.set_event_loop(loop)
    try: return loop.run_until_complete(async_get_device_full_data(ip, community))
    finally: loop.close()

def snmp_get_device_info_sync(ip, community):
    loop = asyncio.new_event_loop(); asyncio.set_event_loop(loop)
    try: return loop.run_until_complete(async_get_device_info(ip, community))
    finally: loop.close()

def is_same_port(p1, p2):
    p1 = str(p1).strip().lower()
    p2 = str(p2).strip().lower()
    if not p1 or not p2: return False
    if p1 == p2: return True
    if p1.endswith(p2) or p2.endswith(p1): return True
    n1 = re.findall(r'\d+', p1)
    n2 = re.findall(r'\d+', p2)
    if n1 and n2 and n1 == n2: return True
    if len(n1) == 1 and len(n2) >= 1 and n1[0] == n2[-1]: return True
    if len(n2) == 1 and len(n1) >= 1 and n2[0] == n1[-1]: return True
    return False

def discover_topology(devices):
    scan_start_time = time.time()
    new_devices_added = 0
    scanned_devices_count = 0

    nodes = []
    edges = []
    sysname_to_ip_map = {}
    database_changed = False 
    active_devices = [d for d in devices if d.get('visible', 1) == 1]
    hidden_ips = {d['ip'] for d in devices if d.get('visible', 1) == 0}

    connections = {} 
    device_full_data_cache = {}
    global_mac_to_port = {}

    for dev in devices:
        ip = dev['ip']
        lvl = safe_int(dev.get('level'))

        if ip in hidden_ips or not is_valid_ipv4(ip):
            sysname_to_ip_map[dev.get('name', '').split('.')[0].strip().lower()] = ip
            continue
            
        if lvl >= 5:
            sysname_to_ip_map[dev.get('name', '').split('.')[0].strip().lower()] = ip
            dev['status'] = dev.get('status', 'up')
            dev['sys_descr'] = '邊緣/終端設備 (系統依設定略過主動掃描)'
            continue

        scanned_devices_count += 1
        sys_descr, sys_name, sys_location = snmp_get_device_info_sync(ip, dev['community'])
        
        if sys_name and sys_name != "無回應":
            dev['status'] = 'up' 
            dev['sys_descr'] = sys_descr
            
            if sys_location and (not dev.get('location') or dev.get('location') == '自動探索'):
                dev['location'] = sys_location
                database_changed = True
                
            sysname_to_ip_map[sys_name.split('.')[0].strip().lower()] = ip
            if dev.get('name') != sys_name:
                dev['name'] = sys_name
                database_changed = True
                
            auto_brand, auto_model = extract_brand_model(sys_descr)
            if not dev.get('brand') or dev.get('brand') == 'Unknown':
                dev['brand'] = auto_brand
                database_changed = True
            if not dev.get('model'):
                dev['model'] = auto_model
                database_changed = True
            
            full_data = snmp_get_device_full_data(ip, dev['community'])
            device_full_data_cache[ip] = full_data
            
            # 💡 核心變更：將原始 OID MIB 樹狀資料轉成 JSON 並綁定在節點上準備寫入資料庫！
            dev['snmp_raw'] = json.dumps(full_data, ensure_ascii=False) if full_data else "{}"
            
            if full_data and len(full_data) >= 8:
                if_names = full_data[4]
                if_macs = full_data[7]
                for idx, mac_raw in if_macs.items():
                    mac_clean = re.sub(r'[^a-fA-F0-9]', '', mac_raw).lower()
                    if mac_clean and len(mac_clean) == 12:
                        p_name = str(if_names.get(idx, f"Port {idx}")).strip('"')
                        global_mac_to_port[mac_clean] = (ip, p_name)
        else:
            if check_ping(ip):
                dev['status'] = 'warning' 
                dev['sys_descr'] = '⚠️ SNMP 連線失敗 (可能被防火牆阻擋或密碼錯誤)，但 Ping 測試正常！'
            else:
                dev['status'] = 'down' 
                dev['sys_descr'] = '🔴 設備無回應 (SNMP 與 Ping 均逾時失敗)'

    added_node_ips = set() 
    color_map = {1: '#ff9999', 2: '#99ccff', 3: '#99ff99', 4: '#ffcc99', 5: '#e6e6fa', 6: '#f8d7da'}

    for dev in active_devices:
        ip = dev['ip']
        name = dev.get('name', '')
        lvl = safe_int(dev.get('level'))
        status = dev.get('status', 'up')
        
        full_data = device_full_data_cache.get(ip)
            
        if not full_data or len(full_data) < 8: 
            if ip not in added_node_ips:
                node_data = {'id': ip, 'ip': ip, 'sysName': name, 'brand': dev.get('brand', 'Unknown'), 'model': dev.get('model', '').strip(), 'location': dev.get('location', '').strip(), 'level': lvl, 'shape': 'box', 'color': color_map.get(lvl, '#e0e0e0'), 'sysDescr': dev.get('sys_descr', '無資訊'), 'status': status, 'snmp_raw': dev.get('snmp_raw', '{}')}
                if dev.get('x') is not None and dev.get('y') is not None: node_data['x'] = dev['x']; node_data['y'] = dev['y']
                nodes.append(node_data); added_node_ips.add(ip)
            continue
        
        lldp_sysnames, lldp_portdescs, lldp_portids, lldp_mgmtips, if_names, if_high_speeds, if_speeds, if_macs = full_data

        parsed_neighbors = []
        all_suffixes = set(lldp_sysnames.keys()) | set(lldp_portdescs.keys()) | set(lldp_portids.keys()) | set(lldp_mgmtips.keys())

        for suffix in all_suffixes:
            sysname_val = lldp_sysnames.get(suffix, '')
            remote_sysname = str(sysname_val).strip('"').split('.')[0]
            if remote_sysname.lower() == 'none': remote_sysname = ''
            
            parts = suffix.split('.')
            if len(parts) >= 3: local_port_idx = parts[1]
            else: local_port_idx = parts[-1]
            
            local_port_name = str(if_names.get(local_port_idx, f"Port {local_port_idx}")).strip('"')
            speed = 0
            try: speed = int(if_high_speeds.get(local_port_idx, 0))
            except: pass
            if speed <= 0:
                try: 
                    raw_bps = int(if_speeds.get(local_port_idx, 0))
                    speed = 10000 if raw_bps >= 4294967295 else raw_bps // 1000000
                except: pass
            if speed <= 0: speed = 1000 
            
            remote_port_desc = str(lldp_portdescs.get(suffix, '')).strip('"')
            remote_port_id = str(lldp_portids.get(suffix, '')).strip('"')
            
            desc_mac_clean = re.sub(r'[^a-fA-F0-9]', '', remote_port_desc).lower()
            id_mac_clean = re.sub(r'[^a-fA-F0-9]', '', remote_port_id).lower()
            is_mac_desc = len(desc_mac_clean) == 12 and bool(re.match(r'^([0-9A-F]{2}[:-]){5}([0-9A-F]{2})$', remote_port_desc, re.I))
            is_mac_id = len(id_mac_clean) == 12 and bool(re.match(r'^([0-9A-F]{2}[:-]){5}([0-9A-F]{2})$', remote_port_id, re.I))
            
            remote_ip = ''
            for mgmt_suffix, val in lldp_mgmtips.items():
                if mgmt_suffix.startswith(suffix + '.'):
                    ip_parts = mgmt_suffix.split('.')
                    if len(ip_parts) >= 4: remote_ip = f"{ip_parts[-4]}.{ip_parts[-3]}.{ip_parts[-2]}.{ip_parts[-1]}"
                    break

            resolved_by_mac = False
            target_node_id = None
            remote_port = "未知埠"
            
            if is_mac_desc and desc_mac_clean in global_mac_to_port:
                target_node_id = global_mac_to_port[desc_mac_clean][0]
                remote_port = global_mac_to_port[desc_mac_clean][1]
                resolved_by_mac = True
            elif is_mac_id and id_mac_clean in global_mac_to_port:
                target_node_id = global_mac_to_port[id_mac_clean][0]
                remote_port = global_mac_to_port[id_mac_clean][1]
                resolved_by_mac = True
                
            if not resolved_by_mac:
                if not remote_port_desc and not is_mac_id and remote_ip in device_full_data_cache:
                    remote_if_names = device_full_data_cache[remote_ip][4]
                    if remote_port_id in remote_if_names:
                        remote_port_desc = str(remote_if_names[remote_port_id]).strip('"')

                if remote_port_desc and not is_mac_desc: remote_port = remote_port_desc
                elif remote_port_id and not is_mac_id: remote_port = f"Port {remote_port_id}" if remote_port_id.isdigit() else remote_port_id
                elif is_mac_desc: remote_port = f"MAC: {remote_port_desc}"
                else: remote_port = "未知埠"

                if remote_ip and any(d['ip'] == remote_ip for d in devices): target_node_id = remote_ip
                elif remote_sysname and remote_sysname.lower() in sysname_to_ip_map: target_node_id = sysname_to_ip_map[remote_sysname.lower()]
                else:
                    if remote_sysname:
                        for d in devices:
                            if remote_sysname.lower() in d.get('name', '').strip().lower():
                                target_node_id = d['ip']; break
                                
                if not target_node_id: target_node_id = remote_ip if remote_ip else remote_sysname 

            if not target_node_id: continue

            target_lvl = next((safe_int(d.get('level')) for d in devices if d['ip'] == target_node_id), lvl + 1)
            if target_lvl > 6: target_lvl = 6

            if target_node_id in hidden_ips: continue
            if target_node_id and remote_ip and not is_valid_ipv4(target_node_id) and is_valid_ipv4(remote_ip):
                for d in devices:
                    if d['ip'] == target_node_id: d['ip'] = remote_ip; break
                target_node_id = remote_ip; database_changed = True

            if target_node_id not in added_node_ips and not any(d['ip'] == target_node_id for d in devices):
                new_level = lvl + 1 if lvl < 6 else 6
                default_visible = 0 if new_level >= 5 else 1
                devices.append({'ip': target_node_id, 'name': remote_sysname, 'level': new_level, 'community': 'public', 'location': '自動探索', 'visible': default_visible, 'type': '交換器', 'brand': 'Unknown', 'model': '', 'status': 'up', 'snmp_raw': '{}'})
                database_changed = True
                new_devices_added += 1
                
                if default_visible == 0: hidden_ips.add(target_node_id); continue
                nodes.append({'id': target_node_id, 'ip': target_node_id, 'sysName': remote_sysname, 'brand': 'Unknown', 'model': '', 'location': '自動探索', 'level': new_level, 'shape': 'box', 'color': color_map.get(new_level, '#d3d3d3'), 'sysDescr': '請至設備管理分頁設定', 'status': 'up', 'snmp_raw': '{}'})
                added_node_ips.add(target_node_id)

            parsed_neighbors.append({
                'target_node_id': target_node_id, 'local_port_name': local_port_name, 
                'remote_port': remote_port, 'speed': speed, 'target_lvl': target_lvl
            })

        port_best_neighbor = {}
        for pn in parsed_neighbors:
            pname = pn['local_port_name']
            if pname not in port_best_neighbor: port_best_neighbor[pname] = pn
            else:
                if pn['target_lvl'] < port_best_neighbor[pname]['target_lvl']: port_best_neighbor[pname] = pn

        for pname, best in port_best_neighbor.items():
            target_node_id = best['target_node_id']
            remote_port = best['remote_port']
            speed = best['speed']
            target_lvl = best['target_lvl']

            node_A, node_B = sorted([ip, target_node_id])
            link_key = (node_A, node_B)
            from_node = ip if lvl <= target_lvl else target_node_id
            to_node = target_node_id if lvl <= target_lvl else ip
            
            if link_key not in connections:
                connections[link_key] = { 'raw_records': [], 'direction': (from_node, to_node) }
                
            if ip == node_A: port_A, port_B = pname, remote_port
            else: port_A, port_B = remote_port, pname
                
            connections[link_key]['raw_records'].append({
                'port_A': port_A, 'port_B': port_B, 'speed': speed
            })

        if ip not in added_node_ips:
            node_data = {'id': ip, 'ip': ip, 'sysName': name, 'brand': dev.get('brand', 'Unknown'), 'model': dev.get('model', '').strip(), 'location': dev.get('location', '').strip(), 'level': lvl, 'shape': 'box', 'color': color_map.get(lvl, '#e0e0e0'), 'sysDescr': dev.get('sys_descr', '無資訊'), 'status': status, 'snmp_raw': dev.get('snmp_raw', '{}')}
            if dev.get('x') is not None and dev.get('y') is not None: node_data['x'] = dev['x']; node_data['y'] = dev['y']
            nodes.append(node_data); added_node_ips.add(ip)

    def merge_ports_list(port_list):
        merged = []
        for p in port_list:
            p = str(p).strip()
            if not p: continue
            found = False
            for i, mp in enumerate(merged):
                if is_same_port(p, mp):
                    if len(p) > len(mp): merged[i] = p
                    elif p.lower().startswith('gigabit') and not mp.lower().startswith('gigabit'): merged[i] = p
                    found = True
                    break
            if not found: merged.append(p)
        return merged

    def filter_ghosts(plist):
        if any('/' in p for p in plist):
            return [p for p in plist if '/' in p or not re.match(r'^(port|lag|trk|bond|po)\s*-?\d+$', p, re.I)]
        return plist

    conn = get_db()
    conn.execute("DELETE FROM edges")
    
    node_levels = {d['ip']: safe_int(d.get('level')) for d in devices}
    has_uplink = {}
    for link_key, data in connections.items():
        nA, nB = link_key
        lA = node_levels.get(nA, 99)
        lB = node_levels.get(nB, 99)
        if lA > lB: has_uplink[nA] = True
        elif lB > lA: has_uplink[nB] = True

    for link_key, data in connections.items():
        nA, nB = link_key
        lA = node_levels.get(nA, 99)
        lB = node_levels.get(nB, 99)
        
        if lA == lB and has_uplink.get(nA) and has_uplink.get(nB): continue 
            
        from_node, to_node = data['direction']
        
        a_ports_raw, b_ports_raw, valid_speeds = [], [], []
        for rec in data['raw_records']:
            a_ports_raw.append(rec['port_A'])
            b_ports_raw.append(rec['port_B'])
            if rec['speed'] > 0: valid_speeds.append(rec['speed'])

        a_merged = merge_ports_list(a_ports_raw)
        b_merged = merge_ports_list(b_ports_raw)
        
        a_final = filter_ghosts(a_merged)
        b_final = filter_ghosts(b_merged)

        base_speed = min(valid_speeds) if valid_speeds else 1000

        len_a = len(a_final)
        len_b = len(b_final)
        if len_a > 0 and len_b > 0: multiplier = min(len_a, len_b)
        else: multiplier = max(1, len_a, len_b)
            
        total_speed = base_speed * multiplier

        a_display = sorted(a_final)[:multiplier] if a_final else ['未知']
        b_display = sorted(b_final)[:multiplier] if b_final else ['未知']
        
        if from_node == nA:
            a_ports_str = ", ".join(a_display)
            b_ports_str = ", ".join(b_display)
        else:
            a_ports_str = ", ".join(b_display)
            b_ports_str = ", ".join(a_display)
            
        edge_id = f"{from_node}-{to_node}"
        edges.append({'id': edge_id, 'from': from_node, 'to': to_node, 'speed': total_speed, 'from_port': a_ports_str, 'to_port': b_ports_str})
        conn.execute("INSERT INTO edges (id, source, target, speed, from_port, to_port) VALUES (?, ?, ?, ?, ?, ?)", (edge_id, from_node, to_node, total_speed, a_ports_str, b_ports_str))
        
    conn.commit(); conn.close()
    write_db_devices(devices)
    
    elapsed_time = round(time.time() - scan_start_time, 2)
    return {'nodes': nodes, 'edges': edges, 'stats': {'elapsed': elapsed_time, 'scanned': scanned_devices_count, 'added': new_devices_added}}

@app.route('/api/scan_subnet', methods=['POST'])
def scan_subnet():
    data = request.json
    subnet_str = data.get('subnet', '').strip()
    
    raw_communities = data.get('community', 'public').strip()
    communities = [c.strip() for c in raw_communities.split(',') if c.strip()]
    if not communities:
        communities = ['public']
    
    try:
        network = ipaddress.IPv4Network(subnet_str, strict=False)
        ips = [str(ip) for ip in network.hosts()]
        if len(ips) > 512:
            return jsonify({'success': False, 'message': '網段過大，為確保系統穩定，請限制在 /23 (510 台) 以內。'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'無效的網段格式，請輸入如 192.168.0.1/24。'})

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    async def scan_single(ip):
        snmpEngine = SnmpEngine()
        descr, name, location = "", "", ""
        successful_comm = ""
        
        for comm in communities:
            try:
                transport = await UdpTransportTarget.create((ip, 161), timeout=0.6, retries=0)
                err, stat, idx, varBinds = await get_cmd(
                    snmpEngine, CommunityData(comm, mpModel=1), transport, ContextData(), 
                    ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0')), 
                    ObjectType(ObjectIdentity('1.3.6.1.2.1.1.5.0')),
                    ObjectType(ObjectIdentity('1.3.6.1.2.1.1.6.0'))
                )
                if not err and not stat:
                    for varBind in varBinds:
                        oid = str(varBind[0])
                        val = parse_snmp_val(varBind[1]).replace('\r', '').replace('\n', ' | ')
                        if '1.3.6.1.2.1.1.1.0' in oid: descr = val
                        elif '1.3.6.1.2.1.1.5.0' in oid: name = val
                        elif '1.3.6.1.2.1.1.6.0' in oid: location = val
                    
                    if name and name != "無回應":
                        successful_comm = comm 
                        break 
            except:
                pass
                
        snmpEngine.close_dispatcher()
        
        if name and name != "無回應":
            brand, model_str = extract_brand_model(descr)
            return {
                "ip": ip, "name": name, "level": 3, "community": successful_comm, 
                "location": location, "visible": 1, "type": "交換器", 
                "brand": brand, "model": model_str, "sys_descr": descr
            }
        return None

    async def run_scan():
        sem = asyncio.Semaphore(100)
        async def bounded_scan(ip):
            async with sem: return await scan_single(ip)
        tasks = [bounded_scan(ip) for ip in ips]
        results = await asyncio.gather(*tasks)
        return [r for r in results if r is not None]

    discovered = loop.run_until_complete(run_scan())
    loop.close()
    
    return jsonify({'success': True, 'devices': discovered})

# ==============================================================================
# Web 路由
# ==============================================================================
@app.route('/')
def index(): return render_template('topology.html')

@app.route('/devices')
def devices_page(): return render_template('devices.html')

@app.route('/report')
def report_page(): return render_template('report.html')

@app.route('/api/devices', methods=['GET'])
def get_devices(): return jsonify(read_db_devices())

@app.route('/api/devices/bulk', methods=['POST'])
def bulk_save_devices():
    data = request.json
    validated_devices = []
    seen_ips = set()
    for d in data:
        ip = d.get('ip', '').strip()
        if not ip or ip in seen_ips: continue
        seen_ips.add(ip)
        validated_devices.append({'ip': ip, 'name': d.get('name', '').strip(), 'level': safe_int(d.get('level')), 'community': d.get('community', 'public').strip(), 'location': d.get('location', '').strip(), 'visible': safe_int(d.get('visible', 1), 1), 'type': d.get('type', '交換器').strip(), 'brand': d.get('brand', 'Unknown').strip(), 'model': d.get('model', '').strip()})
    write_db_devices(validated_devices)
    return jsonify({'success': True})

@app.route('/api/topology', methods=['GET'])
def get_topology():
    try:
        devices = read_db_devices()
        topo = discover_topology(devices)
        return jsonify(topo)
    except Exception as e: return jsonify({'nodes': [], 'edges': [], 'error': str(e)}), 500

@app.route('/api/topology/fast', methods=['GET'])
def get_topology_fast():
    conn = get_db()
    devs = conn.execute("SELECT * FROM devices WHERE visible=1").fetchall()
    eds = conn.execute("SELECT * FROM edges").fetchall()
    conn.close()
    if not devs: return jsonify({'empty': True})
    color_map = {1: '#ff9999', 2: '#99ccff', 3: '#99ff99', 4: '#ffcc99', 5: '#e6e6fa', 6: '#f8d7da'}
    nodes = []
    for row in devs:
        d = dict(row)
        node_data = {'id': d['ip'], 'ip': d['ip'], 'sysName': d['name'], 'brand': d.get('brand') or 'Unknown', 'model': d.get('model') or '', 'location': d.get('location') or '', 'level': d['level'], 'shape': 'box', 'color': color_map.get(d['level'], '#e0e0e0'), 'sysDescr': d.get('sys_descr') or '無快取硬體資訊', 'status': d.get('status') if d.get('status') else 'up', 'snmp_raw': d.get('snmp_raw') or '{}'}
        if d.get('x') is not None and d.get('y') is not None: node_data['x'] = d['x']; node_data['y'] = d['y']
        nodes.append(node_data)
    edges_list = [{'id': e['id'], 'from': e['source'], 'to': e['target'], 'speed': e['speed'] or 1000, 'from_port': e['from_port'] or '未知', 'to_port': e['to_port'] or '未知'} for e in eds]
    return jsonify({'empty': False, 'nodes': nodes, 'edges': edges_list})

@app.route('/api/backup/export/<fmt>', methods=['GET'])
def export_devices(fmt):
    devices = read_db_devices()
    if fmt == 'json': return jsonify(devices)
    elif fmt == 'csv':
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=['ip', 'name', 'level', 'community', 'location', 'visible', 'type', 'brand', 'model', 'sys_descr', 'x', 'y', 'status'])
        writer.writeheader()
        for d in devices: writer.writerow(d)
        output.seek(0)
        return send_file(io.BytesIO(output.getvalue().encode('utf-8-sig')), mimetype='text/csv', as_attachment=True, download_name='network_devices_backup.csv')
    return "不支援的格式", 400

@app.route('/api/backup/import/<fmt>', methods=['POST'])
def import_devices(fmt):
    try:
        imported_list = []
        if fmt == 'json': imported_list = request.json
        elif fmt == 'csv':
            file = request.files.get('file')
            if not file: return jsonify({'success': False, 'message': '找不到上傳的檔案'}), 400
            stream = io.StringIO(file.stream.read().decode("utf-8-sig"), newline=None)
            reader = csv.DictReader(stream)
            imported_list = [row for row in reader]

        if not imported_list or not isinstance(imported_list, list): return jsonify({'success': False, 'message': '資料結構有誤，無法匯入'}), 400

        conn = get_db()
        conn.execute("DELETE FROM devices")
        for d in imported_list:
            if not d.get('ip'): continue
            conn.execute('''
                INSERT INTO devices (ip, name, level, community, location, visible, type, brand, model, sys_descr, x, y, status, snmp_raw)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                str(d.get('ip')).strip(), str(d.get('name', '')).strip(), safe_int(d.get('level')),
                str(d.get('community', 'public')).strip(), str(d.get('location', '')).strip(),
                safe_int(d.get('visible', 1), 1), str(d.get('type', '交換器')).strip(),
                str(d.get('brand', 'Unknown')).strip(), str(d.get('model', '')).strip(),
                str(d.get('sys_descr', '')), 
                float(d['x']) if d.get('x') not in (None, '') else None,
                float(d['y']) if d.get('y') not in (None, '') else None,
                str(d.get('status', 'up')), str(d.get('snmp_raw', '{}'))
            ))
        conn.commit(); conn.close()
        return jsonify({'success': True, 'message': f'成功導入 {len(imported_list)} 台設備資料！'})
    except Exception as e: return jsonify({'success': False, 'message': f'導入失敗：{str(e)}'}), 500

@app.route('/api/topology/slots/save', methods=['POST'])
def save_to_slot():
    data = request.json
    slot_id = data.get('slot') 
    positions = data.get('positions')
    conn = get_db()
    conn.execute("DELETE FROM layout_slots WHERE slot_id = ?", (slot_id,))
    for ip, coords in positions.items(): conn.execute("INSERT INTO layout_slots (slot_id, ip, x, y) VALUES (?, ?, ?, ?)", (slot_id, ip, coords['x'], coords['y']))
    for ip, coords in positions.items(): conn.execute("UPDATE devices SET x=?, y=? WHERE ip=?", (coords['x'], coords['y'], ip))
    conn.commit(); conn.close()
    return jsonify({'success': True, 'message': f'排版已成功記憶至版面 {slot_id}'})

@app.route('/api/topology/slots/load', methods=['POST'])
def load_from_slot():
    slot_id = request.json.get('slot')
    conn = get_db()
    cursor = conn.execute("SELECT * FROM layout_slots WHERE slot_id = ?", (slot_id,))
    rows = cursor.fetchall()
    if not rows: return jsonify({'success': False, 'message': f'版面 {slot_id} 目前是空的！'})
    conn.execute("UPDATE devices SET x=NULL, y=NULL")
    positions = {}
    for row in rows:
        conn.execute("UPDATE devices SET x=?, y=? WHERE ip=?", (row['x'], row['y'], row['ip']))
        positions[row['ip']] = {'x': row['x'], 'y': row['y']}
    conn.commit(); conn.close()
    return jsonify({'success': True, 'positions': positions})

@app.route('/api/topology/slots/clear', methods=['POST'])
def clear_slots():
    data = request.get_json(silent=True) or {}
    slot_id = data.get('slot', 'all')
    conn = get_db()
    if slot_id != 'all':
        conn.execute("DELETE FROM layout_slots WHERE slot_id = ?", (slot_id,))
        msg = f'版面 {slot_id} 的記憶已清除！'
    else:
        conn.execute("DELETE FROM layout_slots")
        msg = '所有版面記憶已徹底清空！'
    conn.commit(); conn.close()
    return jsonify({'success': True, 'message': msg})

@app.route('/api/topology/slots/status', methods=['GET'])
def get_slots_status():
    conn = get_db()
    cursor = conn.execute("SELECT slot_id, COUNT(*) as count FROM layout_slots GROUP BY slot_id")
    status = {row['slot_id']: row['count'] for row in cursor.fetchall()}
    conn.close()
    return jsonify(status)

@app.route('/api/topology/positions/reset', methods=['POST'])
def reset_positions():
    conn = get_db()
    conn.execute("UPDATE devices SET x=NULL, y=NULL")
    conn.commit(); conn.close()
    return jsonify({'success': True})

if __name__ == '__main__':
    init_db()
    app.run(host='127.0.0.1', port=5000, debug=True)