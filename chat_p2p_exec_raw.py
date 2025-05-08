import os
import socket
import base64
import threading
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import scrolledtext
from abc import ABC, abstractmethod

# Singleton
# O que é: Garante que uma classe tenha apenas uma instância e fornece um ponto de acesso global a ela.

# Por que: O socket deve ser único para evitar múltiplas instâncias 
# e conflitos na porta/local de escuta. 
# Mantém consistência e centraliza o gerenciamento da conexão.
class SocketManager:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return cls._instance

    def get_socket(self):
        return self.sock
    

# Simple Factory
# Garantir que uma classe tenha apenas uma instância
# Por que: Método estático create() encapsula a criação do objeto Fernet
class EncryptionFactory:
    
    def create(key=None):
        return Fernet(key.encode() if key else Fernet.generate_key())


# Strategy
# O que é: Permite que o algoritmo usado por uma classe seja selecionado em tempo de execução.

# Por que: Se desejar trocar o método de criptografia no futuro (ex: para RSA, AES), basta criar uma nova classe seguindo a interface EncryptionStrategy.
class EncryptionStrategy(ABC):
    @abstractmethod
    def encrypt(self, msg): pass

    @abstractmethod
    def decrypt(self, msg): pass

class FernetEncryption(EncryptionStrategy):
    def __init__(self, fernet):
        self.fernet = fernet

    def encrypt(self, msg):
        return base64.urlsafe_b64encode(self.fernet.encrypt(msg.encode())).decode()

    def decrypt(self, token):
        try:
            return self.fernet.decrypt(base64.urlsafe_b64decode(token.encode())).decode()
        except:
            return "[\u274c Mensagem inv\u00e1lida ou chave errada]"

# # Adapter
# O que é: Converte a interface de uma classe em outra interface esperada pelos clientes.

# Por que: Abstrai o formato da mensagem recebida, permitindo flexibilidade para apresentar mensagens de outras formas no futuro (ex: formato JSON, logs).
class MessageAdapter:
    def format(self, addr, msg):
        return f"[{addr}]: {msg}"

# # Command
# O que é: Encapsula uma solicitação como um objeto, permitindo parametrizar ações.

# Por que: Isola o comando de envio da ação de clique no botão. Facilita a automação, testes e desacoplamento da interface gráfica.
class Command:
    def execute(self): pass

class SendMessageCommand(Command):
    def __init__(self, app):
        self.app = app

    def execute(self):
        self.app.send_message()

# Observer
# O que é: Permite que objetos observem mudanças em outro objeto.

# Por que: O campo de texto que exibe as mensagens é notificado quando há algo novo a mostrar, 
# podendo ser facilmente substituído ou expandido (ex: logs, notificações sonoras).
class ChatObserver:
    def update(self, msg): pass

class ChatArea(ChatObserver):
    def __init__(self, widget):
        self.widget = widget

    def update(self, msg):
        self.widget.config(state='normal')
        self.widget.insert(tk.END, msg + "\n")
        self.widget.config(state='disabled')
        self.widget.yview(tk.END)

# Facade
# O que é: Fornece uma interface unificada para um conjunto de interfaces em um subsistema.

# Por que: Simplifica o processo de conexão e configuração dos sockets e criptografia, escondendo a complexidade do ChatApp.
class ConnectionFacade:
    def __init__(self, app):
        self.app = app

    def connect(self, local_ip, local_port, remote_ip, remote_port, key):
        sock = SocketManager().get_socket()
        sock.bind((local_ip, local_port))
        self.app.remote_address = (remote_ip, remote_port)
        self.app.fernet = EncryptionFactory.create(key)
        self.app.encryption = FernetEncryption(self.app.fernet)
        return sock

# Mediator
# O que é: Define um objeto que encapsula como um conjunto de objetos interage.

# Por que: Centraliza a lógica de controle dos eventos da interface (botões, conexões), evitando acoplamento direto entre elementos da interface e a lógica principal.

class ChatMediator:
    def __init__(self, app):
        self.app = app

    def notify(self, event):
        if event == "send":
            self.app.send_command.execute()
        elif event == "connect":
            self.app.handle_connection()

# Template Method
# O que é: Define o esqueleto de um algoritmo, deixando alguns passos para as subclasses.

# Por que: Define um processo padrão para enviar mensagens (preparar → enviar → finalizar), e permite variações reutilizando a estrutura geral.
class MessageSender:
    def send(self, msg):
        self.prepare(msg)
        self.transmit(msg)
        self.finish(msg)

    def prepare(self, msg): pass
    def transmit(self, msg): pass
    def finish(self, msg): pass

class EncryptedSender(MessageSender):
    def __init__(self, app):
        self.app = app

    def prepare(self, msg):
        self.encrypted = self.app.encryption.encrypt(msg)

    def transmit(self, msg):
        self.app.sock.sendto(self.encrypted.encode(), self.app.remote_address)

    def finish(self, msg):
        self.app.chat_display.update(f"[Voc\u00ea]: {msg}")
        self.app.message_entry.delete(0, tk.END)

# Builder
# O que é: Separa a construção de um objeto complexo da sua representação.

# Por que: Organiza e centraliza a criação da interface gráfica, facilitando futuras alterações (como mudar o layout ou criar temas diferentes).
class ChatUIBuilder:
    def __init__(self, app):
        self.app = app

    def build(self):
        app = self.app
        window = tk.Tk()
        window.title("Chat P2P Application")

        app.local_ip_entry = tk.Entry(window, width=20)
        app.local_port_entry = tk.Entry(window, width=5)
        app.remote_ip_entry = tk.Entry(window, width=20)
        app.remote_port_entry = tk.Entry(window, width=5)
        app.key_entry = tk.Entry(window, width=50)

        app.connect_button = tk.Button(window, text="Conectar", command=lambda: app.mediator.notify("connect"))
        chat_area_widget = scrolledtext.ScrolledText(window, state='disabled', width=50, height=20)
        app.message_entry = tk.Entry(window, width=50)
        app.send_button = tk.Button(window, text="Enviar", command=lambda: app.mediator.notify("send"))

        tk.Label(window, text="Meu IP:").grid(row=0, column=0)
        app.local_ip_entry.grid(row=0, column=1)
        tk.Label(window, text="Porta:").grid(row=0, column=2)
        app.local_port_entry.grid(row=0, column=3)

        tk.Label(window, text="IP Remoto:").grid(row=1, column=0)
        app.remote_ip_entry.grid(row=1, column=1)
        tk.Label(window, text="Porta:").grid(row=1, column=2)
        app.remote_port_entry.grid(row=1, column=3)

        tk.Label(window, text="Chave Fernet:").grid(row=2, column=0, columnspan=4)
        app.key_entry.grid(row=3, column=0, columnspan=4)

        app.connect_button.grid(row=4, column=0, columnspan=4)
        chat_area_widget.grid(row=5, column=0, columnspan=4, pady=10)
        app.message_entry.grid(row=6, column=0, columnspan=3, pady=10)
        app.send_button.grid(row=6, column=3)

        app.chat_display = ChatArea(chat_area_widget)
        app.window = window
        window.protocol("WM_DELETE_WINDOW", app.on_closing)

# Aplicativo principal
class ChatApp:
    def __init__(self):
        self.ui_builder = ChatUIBuilder(self)
        self.ui_builder.build()

        self.send_command = SendMessageCommand(self)
        self.mediator = ChatMediator(self)

        self.remote_address = None
        self.sock = None
        self.fernet = None
        self.encryption = None

    def handle_connection(self):
        local_ip = self.local_ip_entry.get()
        local_port = int(self.local_port_entry.get())
        remote_ip = self.remote_ip_entry.get()
        remote_port = int(self.remote_port_entry.get())
        key = self.key_entry.get().strip()

        if not key:
            key = Fernet.generate_key().decode()
            self.key_entry.delete(0, tk.END)
            self.key_entry.insert(0, key)
            self.chat_display.update("\U0001f510 Nova chave gerada e inserida.")

        facade = ConnectionFacade(self)
        self.sock = facade.connect(local_ip, local_port, remote_ip, remote_port, key)

        threading.Thread(target=self.listen, daemon=True).start()
        self.chat_display.update(f"\U0001f517 Conectado a {remote_ip}:{remote_port}")

    def listen(self):
        adapter = MessageAdapter()
        def check_messages():
            try:
                data, addr = self.sock.recvfrom(2048)
                msg = self.encryption.decrypt(data.decode())
                self.chat_display.update(adapter.format(addr, msg))
            except BlockingIOError:
                pass
            except Exception as e:
                print(f"Erro ao receber mensagem: {e}")
            finally:
                self.window.after(100, check_messages)

        self.sock.setblocking(False)
        self.window.after(100, check_messages)

    def send_message(self):
        msg = self.message_entry.get()
        if msg == "/sair":
            self.window.quit()
            return

        sender = EncryptedSender(self)
        sender.send(msg)

    def on_closing(self):
        if self.sock:
            self.sock.close()
        self.window.destroy()
        os._exit(0)


def main():
    app = ChatApp()
    app.window.mainloop()


if __name__ == "__main__":
    main()