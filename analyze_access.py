import re
import collections
import os
import ipaddress

log_file_path = "access.log"
report_file_path = "suspicious_ips_report.txt"
list_file_path = "suspicious_ips_list.txt"
white_ip_file_path = "whiteIP.txt"

# Regex for parsing Apache combined access log
# Group 1: IP
# Group 2: Timestamp
# Group 3: Request ("GET /path HTTP/1.1")
# Group 4: Status code
# Group 5: Response size
# Group 6: Referer (optional)
# Group 7: User-Agent (optional)
log_pattern = re.compile(r'^(\S+) \S+ \S+ \[(.*?)\] "(.*?)" (\d+) (\S+)(?: "(.*?)" "(.*?)")?')

bot_ua_keywords = [
    'bot', 'spider', 'crawler', 'scraper', 'slurp', 'mediapartners', 'semrush', 
    'petalbot', 'sogou', 'bytespider', 'chatgpt', 'claudebot', 'bingbot', 'applebot',
    'googlebot', 'yandex', 'baiduspider'
]
script_ua_keywords = [
    'curl', 'python', 'wget', 'go-http-client', 'java', 'libwww', 'ruby', 
    'wordpress', 'httpclient', 'urllib', 'mechanize'
]
suspicious_paths = [
    '.git', '.env', 'phpinfo', 'php-cgi', 'systembc', 'wp-login.php', 
    'passwd', 'cmd', 'upl.php', 'config.php', 'admin.php', '.sql', '.bak'
]

ip_stats = collections.defaultdict(lambda: {
    'count': 0,
    '404_count': 0,
    'reasons': set()
})

white_ips = set()
if os.path.exists(white_ip_file_path):
    with open(white_ip_file_path, 'r', encoding='utf-8') as f:
        for line in f:
            ip = line.strip()
            if ip:
                white_ips.add(ip)
    print(f"已載入 {len(white_ips)} 個白名單 IP。")

print(f"開始分析 {log_file_path} ...")

try:
    with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            match = log_pattern.match(line)
            if not match:
                # Try to get IP from the beginning of the line
                parts = line.split()
                if len(parts) > 0:
                    ip = parts[0]
                    ip_stats[ip]['count'] += 1
                    ip_stats[ip]['reasons'].add("日誌格式異常 (Malformed Log Line)")
                continue
            
            groups = match.groups()
            ip = groups[0]
            request = groups[2]
            status = groups[3]
            user_agent = groups[6] if len(groups) >= 7 and groups[6] is not None else "-"
            
            ip_stats[ip]['count'] += 1
            if status == '404':
                ip_stats[ip]['404_count'] += 1
                
            path = ""
            req_parts = request.split()
            if len(req_parts) >= 2:
                path = req_parts[1]
                
            # 1. Check UA for bot/script keywords
            ua_lower = user_agent.lower()
            if any(kw in ua_lower for kw in bot_ua_keywords):
                ip_stats[ip]['reasons'].add("已知爬蟲/機器人 User-Agent")
            elif any(kw in ua_lower for kw in script_ua_keywords):
                ip_stats[ip]['reasons'].add("程式腳本發出之請求 (如 curl/python/wget)")
            elif user_agent == "-" or len(user_agent.strip()) < 10:
                ip_stats[ip]['reasons'].add("空缺或極短的 User-Agent")
                
            # 2. Check for suspicious paths
            path_lower = path.lower()
            if any(kw in path_lower for kw in suspicious_paths):
                ip_stats[ip]['reasons'].add("掃描可疑路徑 (如 .env, .git, phpinfo 等)")

    suspicious_ips = {}
    for ip, stats in ip_stats.items():
        reasons = set(stats['reasons'])
        
        # 3. Check for high 404 rate
        if stats['count'] > 5 and (stats['404_count'] / stats['count']) > 0.3:
            reasons.add("異常高的 404 錯誤率 (>30%)")
            
        if reasons and ip not in white_ips and stats['count'] > 1:
            suspicious_ips[ip] = {
                'count': stats['count'],
                'reasons': list(reasons)
            }

    # Output to report file
    with open(report_file_path, 'w', encoding='utf-8') as f:
        f.write("可疑 IP 行為報告\n")
        f.write("=====================================\n\n")
        
        grouped_by_reasons = collections.defaultdict(list)
        for ip, info in suspicious_ips.items():
            reasons_str = "、".join(sorted(info['reasons']))
            grouped_by_reasons[reasons_str].append((ip, info['count']))
            
        # Sort groups by reason string
        for reasons_str in sorted(grouped_by_reasons.keys()):
            items = grouped_by_reasons[reasons_str]
            f.write(f"可疑行為說明: {reasons_str}\n")
            
            # Sort IPs within group by count descending
            items_sorted = sorted(items, key=lambda x: x[1], reverse=True)
            for ip, count in items_sorted:
                f.write(f"IP來源: {ip} 總請求次數: {count}\n")
            f.write("-" * 40 + "\n\n")

    # Output to list file
    with open(list_file_path, 'w', encoding='utf-8') as f:
        # Sort groups by reason string
        for reasons_str in sorted(grouped_by_reasons.keys()):
            items = grouped_by_reasons[reasons_str]
            f.write(f"可疑行為說明: {reasons_str}\n")
            
            subnets = set()
            for ip, count in items:
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    if isinstance(ip_obj, ipaddress.IPv4Address):
                        parts = ip.split('.')
                        subnets.add(f"{parts[0]}.{parts[1]}.{parts[2]}.0/24")
                    else:
                        net = ipaddress.ip_network(f"{ip}/64", strict=False)
                        subnets.add(str(net))
                except ValueError:
                    subnets.add(ip)
            
            # Sort subnets numerically
            def subnet_sort_key(s):
                try:
                    return ipaddress.ip_network(s)
                except:
                    return str(s)
                    
            for subnet in sorted(subnets, key=subnet_sort_key):
                f.write(f"{subnet}\n")
            f.write("\n")

    print(f"分析完成! 共發現 {len(suspicious_ips)} 個可疑IP。")
    print(f"詳細報告已輸出至: {report_file_path}")
    print(f"單純IP列表已輸出至: {list_file_path}")

except FileNotFoundError:
    print(f"錯誤: 找不到檔案 {log_file_path}")
except Exception as e:
    print(f"發生未知的錯誤: {e}")
