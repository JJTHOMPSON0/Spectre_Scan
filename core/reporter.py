import json
from datetime import datetime

def save_report(target, results, filename):

    data = {
        "target": target,
        "scan_time": str(datetime.now()),
        "results": results
    }

    with open(filename, "w") as f:
        json.dump(data, f, indent=4)

    print(f"\n[+] Report saved: {filename}")