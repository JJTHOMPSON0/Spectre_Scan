import socket

def run(target, port):

    try:
        s = socket.socket()
        s.settimeout(3)

        s.connect((target, port))

        banner = s.recv(1024).decode()

        return {
            "banner": banner
        }

    except:
        return None