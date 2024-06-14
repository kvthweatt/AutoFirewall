import time, os, requests, subprocess, dns.resolver
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class MultiFileChangeHandler(FileSystemEventHandler):
    def __init__(self, files_to_monitor):
        self.files_to_monitor = files_to_monitor
        self.last_sizes = {file_path: os.path.getsize(file_path) for file_path in files_to_monitor}
    
    def on_modified(self, event):
        if event.src_path in self.files_to_monitor:
            file_path = event.src_path
            current_size = os.path.getsize(file_path)
            last_size = self.last_sizes[file_path]
            if current_size > last_size:
                with open(file_path, 'r') as file:
                    file.seek(last_size)
                    changes = file.read()
                    self.get_ip_info(changes)
                self.last_sizes[file_path] = current_size

    def get_ip_info(self, changes):
        for line in changes.splitlines():
            data = list(line.split(" "))
            ip = data[0]
            try:
                method = data[1]
            except:
                pass
            if self.is_valid_ip(ip):
                print(f"[FIREWALL] {data}")
                data = ""
                with open("C:\\path\\to\\your\\blocked_ips.txt", "r") as f:
                    f.seek(0)
                    data = f.read()
                    f.close()
                data = list(data.split("\n"))
                if str(ip) in data:
                    print("[FIREWALL] - IP blocked.")
                else:
                    if self.is_ip_malicious(ip):
                        print(f"[FIREWALL] IP {ip} is listed as malicious!\n")
                        with open("C:\\path\\to\\your\\blocked_ips.txt", "a") as f:
                            f.write(f'\n{ip}')
                            f.close()
                        self.block_ip(ip)
                info = self.fetch_ip_info(ip)
                if info:
                    print(f"IP Information for {ip}:")
                    try:
                        print(f"Coordinates: {info['loc']}")
                    except:
                        print("Coordinates hidden.")
                    try:
                        print(f"Hostname: {info['hostname']}")
                    except:
                        print("Hostname hidden. ---------------- SUSPICIOUS IP ----------------")
                    try:
                        print(f"City: {info['city']}")
                    except:
                        print("City hidden.")
                    try:
                        print(f"Region: {info['region']}")
                    except:
                        print("Region hidden.")
                    try:
                        print(f"Country: {info['country']}")
                    except:
                        print("Country hidden.")
                    try:
                        print(f"Org: {info['org']}")
                    except:
                        print("Organization hidden.")
                    try:
                        print(f"Postal code: {info['postal']}")
                    except:
                        print("Postal code hidden.")
                    try:
                        print(f"Timezone: {info['timezone']}\n")
                    except:
                        print("Timezone hidden.")
                    
    def is_valid_ip(self, ip):
        import re
        ip_pattern = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
        return ip_pattern.match(ip) is not None

    def fetch_ip_info(self, ip):
        try:
            response = requests.get(f"http://ipinfo.io/{ip}/json")
            if response.status_code == 200:
                return response.json()
            else:
                print(f"Failed to fetch IP info for {ip}: {response.status_code}")
        except Exception as e:
            print(f"Error fetching IP info for {ip}: {e}")
        return None

    def is_ip_malicious(self, ip):
        rval = False
        url = 'https://api.abuseipdb.com/api/v2/check'
        rdata = []
        headers = {
            'Accept': 'application/json',
            'Key': 'your_api_key'
        }
        params = {
            'ipAddress': ip,
            'maxAgeInDays': 90  # Check reports within the last 90 days
        }
        try:
            response = requests.get(url, headers=headers, params=params)
            if response.status_code == 200:
                data = response.json()
                if data['data']['abuseConfidenceScore'] > 0:
                    print("[FIREWALL] Confirmed on AbuseIPdb")
                    rval = True
                elif data['data']['abuseConfidenceScore'] == 0:
                    print("[FIREWALL] Passed on AbuseIPdb")
            else:
                print(f"Error checking IP {ip} on AbuseIPdb: {response.status_code}")
        except Exception as e:
            print(f"Error checking IP {ip} on AbuseIPdb: {e}")
        # VirusTotal
        url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
        params = {'ip': ip, 'apikey': 'your_api_key'}
        try:
            response = requests.get(url, params=params)
            if response.status_code == 200:
                data = response.json()
                # Assuming an IP is malicious if detected_urls are present
                if 'detected_urls' in data and len(data['detected_urls']) > 0:
                    print("[FIREWALL] Confirmed on VirusTotal")
                    rval = True
                elif 'detected_urls' not in data and len(data['detected_urls']) == 0:
                    print("[FIREWALL] Passed on VirusTotal")
                else:
                    print(f"Error checking IP {ip} on VirusTotal: {response.status_code}")
            else:
                print(f"Error checking IP {ip} on VirusTotal: {response.status_code}")
        except Exception as e:
            print(f"Error checking IP {ip} on VirusTotal: {e}")
        # AlienVault
        headers = {
            'X-OTX-API-KEY': "your_api_key"
        }
        url = f'https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general'
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            if 'pulse_info' in data and data['pulse_info']['count'] > 0:
                print("[FIREWALL] Confirmed on AlienVault")
                rval = True
            elif 'pulse_info' not in data and data['pulse_info']['count'] == 0:
                print("[FIREWALL] Passed on AlienVault")
            else:
                print(f"Error checking IP {ip} on AlienVault: {response.status_code}")
        else:
            print(f"Error checking IP {ip} on AlienVault: {response.status_code}")
        # SpamHaus
        dnsbl_zone = 'zen.spamhaus.org'
        try:
            query = '.'.join(reversed(ip.split('.'))) + '.' + dnsbl_zone
            response = dns.resolver.resolve(query, 'A')
            if response:
                print("[FIREWALL] Confirmed on SpamHaus")
                rval = True
        except dns.resolver.NXDOMAIN as e:
            print(f"Error checking IP on SpamHaus: {e}")
        except dns.resolver.NoAnswer as e:
            print(f"Error checking IP on SpamHaus: {e}")
        except dns.exception.DNSException as e:
            print(f"Error checking IP on SpamHaus: {e}")
        url = 'https://api.shodan.io/shodan/host/{ip}?key=your_api_key'
        response = requests.get(url)
        
        if response.status_code == 200:
            data = response.json()
            
            # Check if there are any vulnerabilities or suspicious activity
            if 'vulns' in data or 'data' in data:
                print("[FIREWALL] Confirmed on Shodan")
                rval = True
            else:
                print("[FIREWALL] Passed on Shodan")
        else:
            print(f"Error checking IP {ip} on Shodan: {response.status_code}")
        url = f'https://api.greynoise.io/v3/community/{ip}'
        headers = {
            'key': 'your_api_key'
        }
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            if data['classification'] == 'malicious':
                print("[FIREWALL] Confirmed on GreyNoise")
                rval = True
            else:
                print("[FIREWALL] Passed on GreyNoise")
        else:
            print(f"Error checking IP {ip} on GreyNoise: {response.status_code}")
        return rval # End of is_ip_malicious()

    def block_ip(self, ip):
        try:
            command = f'netsh advfirewall firewall add rule name="Block IP {ip}" dir=in action=block remoteip={ip}'
            subprocess.run(command, shell=True, check=True)
            print(f"[FIREWALL] Successfully blocked IP {ip} using Windows Firewall. IP details below.\n")
        except subprocess.CalledProcessError as e:
            print(f"Failed to block IP {ip}: {e}")

def monitor_files(files_to_monitor):
    event_handler = MultiFileChangeHandler(files_to_monitor)
    observer = Observer()
    for file_path in files_to_monitor:
        observer.schedule(event_handler, path=os.path.dirname(file_path), recursive=False)
    observer.start()
    print(f"Monitoring {', '.join(files_to_monitor)} for changes...")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    files_to_monitor = [
        "C:\\path\\your\\ip.log",
        "C:\\path\\your\\other\\ip.log"
    ]
    monitor_files(files_to_monitor)
