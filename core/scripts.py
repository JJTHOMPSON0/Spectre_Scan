import requests
import ftplib
import socket

def run_default_scripts(ip, port, banner):
    """
    Simulates Nmap's -sC default scripts based on the port or service banner.
    """
    output = []
    
    # HTTP Scripts (Port 80, 443, 8080 or if "HTTP" is in the banner)
    if port in [80, 443, 8080] or "HTTP" in str(banner).upper():
        try:
            # http-title script
            url = f"http://{ip}:{port}"
            r = requests.get(url, timeout=2, verify=False)
            if '<title>' in r.text.lower():
                # Quick and dirty HTML parsing for the title
                title = r.text.lower().split('<title>')[1].split('</title>')[0].strip()
                output.append(f"|_ http-title: {title}")
                
            # http-methods script (Check if dangerous methods like PUT are allowed)
            options = requests.options(url, timeout=2, verify=False)
            if 'Allow' in options.headers:
                output.append(f"|_ http-methods: Supported Methods: {options.headers['Allow']}")
        except Exception:
            pass

    # FTP Scripts (Port 21)
    elif port == 21 or "FTP" in str(banner).upper():
        try:
            # ftp-anon script: Check for anonymous login
            ftp = ftplib.FTP()
            ftp.connect(ip, port, timeout=3)
            ftp.login('anonymous', 'anonymous@')
            output.append("|_ ftp-anon: Anonymous FTP login allowed (FTP code 230)")
            ftp.quit()
        except Exception as e:
            if "530" in str(e): # 530 is permission denied
                pass
            else:
                output.append(f"|_ ftp-anon: Error checking anonymous login")

    # SSH Scripts (Port 22)
    elif port == 22 or "SSH" in str(banner).upper():
        # ssh-hostkey script logic would go here (grabbing the rsa/ecdsa keys)
        output.append("|_ ssh-auth-methods: publickey, password (guessed)")

    return output
