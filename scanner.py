import nmap
import sys
import json

def scan_target(target):
    scanner = nmap.PortScanner()
    results = {}

    print("\n[+] Starting advanced scan...\n")

    try:
        scanner.scan(hosts=target, arguments='-sS -sV -O')

        for host in scanner.all_hosts():
            print("====================================")
            print(f"[+] Host: {host}")
            print(f"[+] State: {scanner[host].state()}")

            host_data = {
                "state": scanner[host].state(),
                "os": [],
                "ports": []
            }

            # OS Detection
            if 'osmatch' in scanner[host] and scanner[host]['osmatch']:
                print("\n[+] OS Detection:")
                for os in scanner[host]['osmatch']:
                    print(f"  -> {os['name']}")
                    host_data["os"].append(os['name'])
            else:
                print("\n[!] OS detection not available")

            # Port scanning
            print("\n[+] Open Ports & Services:")
            for proto in scanner[host].all_protocols():
                for port in sorted(scanner[host][proto].keys()):
                    service = scanner[host][proto][port]['name']
                    state = scanner[host][proto][port]['state']

                    print(f"  Port: {port} | {state} | {service}")

                    host_data["ports"].append({
                        "port": port,
                        "state": state,
                        "service": service
                    })

            results[host] = host_data

        # Save JSON report
        with open("scan_results.json", "w") as file:
            json.dump(results, file, indent=4)

        print("\n[+] Scan completed. Results saved to scan_results.json")

    except Exception as e:
        print("[!] Error:", e)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = input("Enter IP or range (e.g. 192.168.1.0/24): ")

    scan_target(target)