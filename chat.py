import sys
import socket
import base64
import threading
import time
from cryptography.fernet import Fernet

peers = {}
session = True
lock = threading.Lock()


def get_key():
    choice = input("🔑 Digite sua chave Fernet (ou pressione Enter para gerar uma nova): ").strip()
    if choice:
        try:
            return Fernet(choice.encode())
        except:
            print("❌ Chave inválida! Fechando...")
            sys.exit(1)
    else:
        key = Fernet.generate_key()
        print("🔐 Sua nova chave (compartilhe com o outro peer):", key.decode())
        return Fernet(key)


def encrypt_message(msg, fernet):
    return base64.urlsafe_b64encode(fernet.encrypt(msg.encode())).decode()


def decrypt_message(token, fernet):
    try:
        return fernet.decrypt(base64.urlsafe_b64decode(token.encode())).decode()
    except:
        return "[❌ Mensagem inválida ou chave errada]"


def listen(local_ip, local_port, is_ipv6, fernet):
    family = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.bind((local_ip, local_port))

    print(f"🔄 Aguardando mensagens em {local_ip}:{local_port}...")

    while session:
        try:
            data, addr = sock.recvfrom(2048)
            msg = decrypt_message(data.decode(), fernet)

            with lock:
                if addr not in peers:
                    peers[addr] = addr
                    print(f"✅ Novo peer conectado: {addr}")

            print(f"📩 [{addr}]: {msg}")
        except:
            pass


def send_messages(remote_ip, remote_port, is_ipv6, fernet):
    global session
    family = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)

    print(f"✉️ Enviando mensagens para {remote_ip}:{remote_port}... (Digite '/sair' para sair)")

    while session:
        msg = input()
        if msg == "/sair":
            session = False
            break

        encrypted_msg = encrypt_message(msg, fernet)
        sock.sendto(encrypted_msg.encode(), (remote_ip, remote_port))


def main():
    if len(sys.argv) < 4:
        print("⚠️ Uso correto: python chat.py <ipv4|ipv6> <meu_endereço:porta> <endereço_remoto:porta>")
        return

    protocol, local_addr, remote_addr = sys.argv[1], sys.argv[2], sys.argv[3]

    if protocol not in ["ipv4", "ipv6"]:
        print("⚠️ Protocolo inválido. Escolha 'ipv4' ou 'ipv6'.")
        return

    is_ipv6 = protocol == "ipv6"

    try:
        local_ip, local_port = local_addr.rsplit(":", 1)
        remote_ip, remote_port = remote_addr.rsplit(":", 1)
        local_port, remote_port = int(local_port), int(remote_port)
    except ValueError:
        print("⚠️ Formato de endereço inválido! Use IP:PORTA (ex: 192.168.1.100:5000)")
        return

    fernet = get_key()

    threading.Thread(target=listen, args=(local_ip, local_port, is_ipv6, fernet), daemon=True).start()
    send_messages(remote_ip, remote_port, is_ipv6, fernet)


if __name__ == "__main__":
    main()
