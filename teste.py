import sys
import socket
import base64
import threading
import time
from cryptography.fernet import Fernet
from abc import ABC, abstractmethod

# ------------------------- Singleton (Gerenciamento de Estado) -------------------------
class ChatState:
    _instance = None
    
    def __new__(cls):
        if not cls._instance:
            cls._instance = super().__new__(cls)
            cls.peers = {}
            cls.session = True
            cls.lock = threading.Lock()
        return cls._instance

# ------------------------- Factory Method (Criação de Sockets) -------------------------
class SocketFactory:
    @staticmethod
    def create_socket(is_ipv6: bool) -> socket.socket:
        return socket.socket(
            socket.AF_INET6 if is_ipv6 else socket.AF_INET,
            socket.SOCK_DGRAM
        )

# ------------------------- Strategy (Criptografia) -------------------------
class EncryptionStrategy(ABC):
    @abstractmethod
    def encrypt(self, message: str) -> str: ...
    
    @abstractmethod
    def decrypt(self, token: str) -> str: ...

class FernetStrategy(EncryptionStrategy):
    def __init__(self, key: str):
        self.fernet = Fernet(key.encode())
    
    def encrypt(self, message: str) -> str:
        return base64.urlsafe_b64encode(self.fernet.encrypt(message.encode())).decode()
    
    def decrypt(self, token: str) -> str:
        try:
            return self.fernet.decrypt(base64.urlsafe_b64decode(token.encode())).decode()
        except:
            return "[❌ Erro de descriptografia]"

# ------------------------- Observer (Notificações) -------------------------
class ChatNotifier:
    def __init__(self):
        self.observers = []
    
    def add_observer(self, observer):
        self.observers.append(observer)
    
    def notify(self, event_type, data):
        for observer in self.observers:
            observer.update(event_type, data)

class ConsoleObserver:
    def update(self, event_type, data):
        if event_type == "new_peer":
            print(f"✅ Novo peer: {data}")
        elif event_type == "message":
            print(f"📩 [{data['sender']}]: {data['message']}")
        elif event_type == "error":
            print(f"❌ Erro: {data}")

# ------------------------- Command (Comandos do Usuário) -------------------------
class CommandHandler:
    def __init__(self):
        self.commands = {}
    
    def register_command(self, name, handler):
        self.commands[name] = handler
    
    def execute(self, input_str):
        if input_str.startswith("/"):
            cmd, *args = input_str[1:].split()
            if cmd in self.commands:
                return self.commands[cmd](*args)
        return False

class ExitCommand:
    def __init__(self, state):
        self.state = state
    
    def __call__(self):
        self.state.session = False
        return True

# ------------------------- Facade (Interface de Rede) -------------------------
class NetworkManager:
    def __init__(self, factory, strategy, notifier):
        self.socket_factory = factory
        self.crypto = strategy
        self.notifier = notifier
        self.state = ChatState()
    
    def start_server(self, ip, port, is_ipv6):
        try:
            sock = self.socket_factory.create_socket(is_ipv6)
            sock.bind((ip, port))
            return sock
        except Exception as e:
            self.notifier.notify("error", f"Falha ao iniciar servidor: {str(e)}")
            raise
    
    def send_message(self, message, destination, is_ipv6):
        try:
            sock = self.socket_factory.create_socket(is_ipv6)
            encrypted = self.crypto.encrypt(message)
            sock.sendto(encrypted.encode(), destination)
        except Exception as e:
            self.notifier.notify("error", f"Falha ao enviar mensagem: {str(e)}")

# ------------------------- Circuit Breaker (Resiliência) -------------------------
class CircuitBreaker:
    def __init__(self, max_failures=3, reset_timeout=30):
        self.max_failures = max_failures
        self.reset_timeout = reset_timeout
        self.failures = 0
        self.last_failure = None
    
    def execute(self, operation):
        if self._is_open():
            raise Exception("Circuit breaker aberto")
        try:
            result = operation()
            self._reset()
            return result
        except Exception as e:
            self._record_failure()
            raise e
    
    def _is_open(self):
        return (self.failures >= self.max_failures and 
                time.time() < self.last_failure + self.reset_timeout)
    
    def _record_failure(self):
        self.failures += 1
        self.last_failure = time.time()
    
    def _reset(self):
        self.failures = 0

# ------------------------- Implementação Principal -------------------------
def get_key():
    choice = input("🔑 Digite sua chave Fernet (ou pressione Enter para gerar uma nova): ").strip()
    if choice:
        try:
            Fernet(choice.encode())
            return choice
        except:
            print("❌ Chave inválida! Fechando...")
            sys.exit(1)
    else:
        key = Fernet.generate_key().decode()
        print("🔐 Sua nova chave (compartilhe com o outro peer):", key)
        return key

def listen(sock, network, notifier):
    state = ChatState()
    while state.session:
        try:
            data, addr = sock.recvfrom(2048)
            msg = network.crypto.decrypt(data.decode())
            
            with state.lock:
                if addr not in state.peers:
                    state.peers[addr] = addr
                    notifier.notify("new_peer", addr)
            
            notifier.notify("message", {"sender": addr, "message": msg})
        except Exception as e:
            notifier.notify("error", str(e))

def main():
    if len(sys.argv) < 4:
        print("⚠️ Uso correto: python chat.py <ipv4|ipv6> <meu_endereço:porta> <endereço_remoto:porta>")
        return

    # Configuração inicial
    state = ChatState()
    notifier = ChatNotifier()
    notifier.add_observer(ConsoleObserver())
    
    # Configuração de rede
    protocol, local_addr, remote_addr = sys.argv[1], sys.argv[2], sys.argv[3]
    is_ipv6 = protocol == "ipv6"
    
    try:
        local_ip, local_port = local_addr.rsplit(":", 1)
        remote_ip, remote_port = remote_addr.rsplit(":", 1)
        local_port, remote_port = int(local_port), int(remote_port)
    except ValueError:
        print("⚠️ Formato de endereço inválido! Use IP:PORTA (ex: 192.168.1.100:5000)")
        return

    # Inicialização de componentes
    network = NetworkManager(
        SocketFactory(),
        FernetStrategy(get_key()),
        notifier
    )
    
    handler = CommandHandler()
    handler.register_command("sair", ExitCommand(state))
    
    # Iniciar servidor
    try:
        server_sock = network.start_server(local_ip, local_port, is_ipv6)
        threading.Thread(target=listen, args=(server_sock, network, notifier), daemon=True).start()
    except:
        return

    print(f"✉️ Enviando mensagens para {remote_ip}:{remote_port}... (Digite '/sair' para sair)")

    # Loop principal
    while state.session:
        try:
            msg = input()
            if handler.execute(msg):
                break
            network.send_message(msg, (remote_ip, remote_port), is_ipv6)
        except KeyboardInterrupt:
            state.session = False
        except Exception as e:
            notifier.notify("error", str(e))

if __name__ == "__main__":
    main()