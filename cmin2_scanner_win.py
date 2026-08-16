
import ipaddress
import random
import subprocess
import json
import tempfile
import os
from tqdm import tqdm

# 49個 CMIN2 網段區間（由十進制整數組成）
CMIN2_RANGES = [
    (3749060608, 3749060863), (3749120000, 3749121023), (3749121024, 3749122047),
    (3749124608, 3749125119), (3749125120, 3749125631), (3749126144, 3749126399),
    (3749126656, 3749126911), (3749126912, 3749127167), (3749127168, 3749127423),
    (3749127424, 3749127679), (3749136896, 3749137407), (3749140480, 3749140991),
    (3749143552, 3749143807), (3749182464, 3749182975), (3749216256, 3749217279),
    (3749217280, 3749217791), (3749217792, 3749218303), (3749218304, 3749218815),
    (3749218816, 3749219327), (3749219328, 3749220351), (3749220352, 3749221375),
    (3749221376, 3749221887), (3749221888, 3749222399), (3749222400, 3749222911),
    (3749222912, 3749223423), (3749223424, 3749223935), (3749223936, 3749224447),
    (3749224448, 3749225471), (3749225472, 3749226495), (3749226496, 3749227519),
    (3749227520, 3749228031), (3749228032, 3749228543), (3749228544, 3749230591),
    (3749230592, 3749231615), (3749231616, 3749232639), (3749232640, 3749233151),
    (3749233152, 3749233663), (3749233664, 3749234687), (3749234688, 3749235199),
    (3749235200, 3749235711), (3749235712, 3749236735), (3749236736, 3749237247),
    (3749237248, 3749237503), (3749237504, 3749237759), (3749237760, 3749238271),
    (3749238272, 3749238527), (3749238528, 3749238783), (3749238784, 3749240831),
    (3749240832, 3749249023)
]

# =====================================================================
# ⚠️ 指定 Windows 上 scamper.exe 的路徑
# 如果跟腳本放同一資料夾，直接寫 "scamper.exe"
# 如果放在其他地方，請寫絕對路徑如 "C:\\scamper\\scamper.exe"
# =====================================================================
SCAMPER_CMD = "scamper.exe" 

def is_cmin2(ip_str):
    try:
        ip_int = int(ipaddress.IPv4Address(ip_str))
        for start, end in CMIN2_RANGES:
            if start <= ip_int <= end:
                return True
    except:
        pass
    return False

def get_shuffled_ips(raw_text):
    ip_pool = []
    lines = [line.strip() for line in raw_text.strip().split("\n") if line.strip()]
    for item in lines:
        try:
            net = ipaddress.ip_network(item, strict=False)
            hosts = list(net.hosts()) if net.num_addresses > 2 else [net.network_address]
            ip_pool.extend([str(ip) for ip in hosts])
        except Exception as e:
            print(f"Skipping invalid network: {item}, error: {e}")
    random.shuffle(ip_pool)
    return ip_pool

def scamper_ping(ip_list, max_delay=50, pps=2000):
    valid_ips = []
    # Windows 暫存檔機制優化
    temp_ip_file = os.path.join(tempfile.gettempdir(), f"scamper_ips_{random.randint(1000,9999)}.txt")
    with open(temp_ip_file, 'w') as f:
        f.write('\n'.join(ip_list))

    try:
        print(f"Starting scamper ping for {len(ip_list)} IPs (Speed: {pps} pps)...")
        # =====================================================================
        # ⚠️ 這裡的 "-p", str(pps) 控制了 Ping 的併發發包速率
        # =====================================================================
        cmd = [SCAMPER_CMD, "-c", "ping -c 1", "-p", str(pps), "-O", "json", "-f", temp_ip_file]
        
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        
        with tqdm(total=len(ip_list), desc="Ping Progress", unit="IP") as pbar:
            for line in process.stdout:
                if not line.strip(): continue
                try:
                    data = json.loads(line)
                    if data.get("type") == "ping":
                        pbar.update(1)
                        ip = data.get("dst")
                        rtt = None
                        
                        responses = data.get("responses", [])
                        if isinstance(responses, list) and len(responses) > 0:
                            rtt = responses[0].get("rtt")
                        elif isinstance(responses, dict):
                            rtt = responses.get("rtt")
                            
                        if rtt is None and "replies" in data:
                            replies = data.get("replies", [])
                            if replies and len(replies) > 0:
                                rtt = replies[0].get("rtt")
                            
                        if rtt is not None:
                            if float(rtt) < float(max_delay):
                                valid_ips.append(ip)
                except Exception as e:
                    continue
        process.wait()
    finally:
        if os.path.exists(temp_ip_file):
            os.remove(temp_ip_file)
    return valid_ips

def scamper_trace_and_filter(ip_list):
    final_ips = []
    temp_ip_file = os.path.join(tempfile.gettempdir(), f"scamper_ips_{random.randint(1000,9999)}.txt")
    with open(temp_ip_file, 'w') as f:
        f.write('\n'.join(ip_list))

    try:
        print(f"Starting traceroute and filtering for {len(ip_list)} IPs...")
    # =====================================================================
    # ⚠️ 【修改位置 1】 # Trace 階段同樣預設限制 500 pps 避免頻寬塞爆
    # （家用寬頻建議 1000-2000，大頻寬伺服器可調至 5000-10000）
    # =====================================================================
        cmd = [SCAMPER_CMD, "-c", "trace", "-p", "500", "-O", "json", "-f", temp_ip_file]
        
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        
        with tqdm(total=len(ip_list), desc="Trace Progress", unit="IP") as pbar:
            for line in process.stdout:
                if not line.strip(): continue
                try:
                    data = json.loads(line)
                    if data.get("type") == "trace":
                        pbar.update(1)
                        target_ip = data.get("dst")
                        hops = data.get("hops", [])
                        
                        hit_cmin2 = False
                        for hop in hops:
                            hop_ip = hop.get("addr")
                            if hop_ip and is_cmin2(hop_ip):
                                hit_cmin2 = True
                                break
                        
                        if hit_cmin2:
                            final_ips.append(target_ip)
                except:
                    continue
        process.wait()
    finally:
        if os.path.exists(temp_ip_file):
            os.remove(temp_ip_file)
    return final_ips

if __name__ == "__main__":
    
    # 這裡輸入你想掃描的原始 IP 網段
    raw_inputs = """
    172.64.144.0/20
    """
    # =====================================================================
    # ⚠️ 【修改位置 2】改延遲閾值：把下面的 50 改成你想要的毫秒數（例如 30 或 70）
    # =====================================================================
    max_ping_delay = 50  # 延遲閾值 (ms)
    # =====================================================================
    # ⚠️ 【修改位置 3】改 Ping 併發數：把下面的 2000 改成你每秒想發送的封包數
    # （家用寬頻建議 1000-2000，大頻寬伺服器可調至 5000-10000）
    # =====================================================================
    ping_pps = 500      # Ping 併發速度 (pps)
    
    ips = get_shuffled_ips(raw_inputs)
    print(f"Total shuffled IPs: {len(ips)}")
    if not ips:
        exit()

    low_latency_ips = scamper_ping(ips, max_delay=max_ping_delay, pps=ping_pps)
    print(f"Low latency IPs (< {max_ping_delay}ms): {len(low_latency_ips)}")
    if not low_latency_ips:
        print("No IPs matched the latency criteria. Exiting.")
        exit()

    cmin2_routed_ips = scamper_trace_and_filter(low_latency_ips)
    
    print("\n" + "="*50)
    print("Final Result (Low Latency & Routed via CMIN2 AS58807):")
    print("="*50)
    if cmin2_routed_ips:
        for ip in cmin2_routed_ips:
            print(ip)
    else:
        print("No IPs matched all criteria.")
