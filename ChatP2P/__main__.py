import sys
import socket
import base64
import threading
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import scrolledtext, messagebox

peers = {}  # Dicionário que armazena os peers conectados
session = True  # Variável de controle da sessão de chat
lock = threading.Lock()  # Lock para controlar o acesso simultâneo às mensagens

# GOF Singleton: Garantir que a chave de criptografia seja gerada apenas uma vez por sessão
class ChatApp:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Chat Application")
        
        # Configuração da interface gráfica
        self.local_ip_entry = tk.Entry(self.window, width=20)
        self.local_port_entry = tk.Entry(self.window, width=5)
        self.remote_ip_entry = tk.Entry(self.window, width=20)
        self.remote_port_entry = tk.Entry(self.window, width=5)
        self.key_entry = tk.Entry(self.window, width=50)

        self.connect_button = tk.Button(self.window, text="Conectar", command=self.connect)
        self.chat_area = scrolledtext.ScrolledText(self.window, state='disabled', width=50, height=20)
        self.message_entry = tk.Entry(self.window, width=50)
        self.send_button = tk.Button(self.window, text="Enviar", command=self.send_message)

        # Layout da interface
        tk.Label(self.window, text="Meu IP:").grid(row=0, column=0)
        self.local_ip_entry.grid(row=0, column=1)
        tk.Label(self.window, text="Porta:").grid(row=0, column=2)
        self.local_port_entry.grid(row=0, column=3)

        tk.Label(self.window, text="IP Remoto:").grid(row=1, column=0)
        self.remote_ip_entry.grid(row=1, column=1)
        tk.Label(self.window, text="Porta:").grid(row=1, column=2)
        self.remote_port_entry.grid(row=1, column=3)

        tk.Label(self.window, text="Chave Fernet:").grid(row=2, column=0, columnspan=4)
        self.key_entry.grid(row=3, column=0, columnspan=4)

        self.connect_button.grid(row=4, column=0, columnspan=4)
        self.chat_area.grid(row=5, column=0, columnspan=4, pady=10)
        self.message_entry.grid(row=6, column=0, columnspan=3, pady=10)
        self.send_button.grid(row=6, column=3)

        self.window.protocol("WM_DELETE_WINDOW", self.on_closing)

    def connect(self):
        """
        Conecta o usuário a um peer remoto.
        - Se não for fornecida uma chave, uma nova chave Fernet é gerada.
        - A chave gerada ou fornecida é usada para criptografar/descriptografar as mensagens.
        """
        local_ip = self.local_ip_entry.get()
        local_port = int(self.local_port_entry.get())
        remote_ip = self.remote_ip_entry.get()
        remote_port = int(self.remote_port_entry.get())
        key = self.key_entry.get().strip()

        # GOF Singleton: Verifica se uma chave foi fornecida, caso contrário, gera uma nova chave.
        if not key:
            key = Fernet.generate_key().decode()  # Gera uma chave única para a sessão
            self.key_entry.delete(0, tk.END)
            self.key_entry.insert(0, key)  # Exibe a chave gerada no campo
            self.append_chat("🔐 Nova chave gerada e inserida. Copie e compartilhe com o outro usuário.")
        
        # Instância de criptografia usando a chave fornecida ou gerada
        self.fernet = Fernet(key.encode())

        # Cria uma nova thread para escutar mensagens enquanto a interface gráfica permanece ativa
        threading.Thread(target=self.listen, args=(local_ip, local_port), daemon=True).start()
        self.append_chat(f"🔗 Conectado a {remote_ip}:{remote_port}")

    def listen(self, local_ip, local_port):
        """
        Escuta mensagens enviadas para o endereço local e exibe na interface.
        A escuta é feita em um loop contínuo até o encerramento da aplicação.
        """
        family = socket.AF_INET
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.bind((local_ip, local_port))

        while True:
            try:
                data, addr = sock.recvfrom(2048)
                msg = self.decrypt_message(data.decode())

                # Exibe a mensagem recebida
                self.append_chat(f"[{addr}]: {msg}")
            except Exception as e:
                print(f"Erro ao receber dados: {e}")
                pass

    def send_message(self):
        """
        Envia uma mensagem para o peer remoto.
        A mensagem é criptografada antes de ser enviada.
        """
        msg = self.message_entry.get()
        if msg == "/sair":
            self.window.quit()
            return
        
        remote_ip = self.remote_ip_entry.get()
        remote_port = int(self.remote_port_entry.get())
        encrypted_msg = self.encrypt_message(msg)

        # Envia a mensagem criptografada para o peer remoto
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(encrypted_msg.encode(), (remote_ip, remote_port))
        self.append_chat(f"[Você]: {msg}")
        self.message_entry.delete(0, tk.END)

    def append_chat(self, msg):
        """
        Adiciona a mensagem no histórico de chat da interface.
        """
        self.chat_area.config(state='normal')
        self.chat_area.insert(tk.END, msg + "\n")
        self.chat_area.config(state='disabled')
        self.chat_area.yview(tk.END)

    def encrypt_message(self, msg):
        """
        Criptografa a mensagem usando o algoritmo Fernet.
        """
        return base64.urlsafe_b64encode(self.fernet.encrypt(msg.encode())).decode()

    def decrypt_message(self, token):
        """
        Descriptografa a mensagem recebida usando a chave Fernet.
        """
        try:
            return self.fernet.decrypt(base64.urlsafe_b64decode(token.encode())).decode()
        except:
            return "[❌ Mensagem inválida ou chave errada]"

    def on_closing(self):
        """
        Trata o fechamento da janela e encerra a sessão de chat.
        """
        self.window.destroy()

# Padrão Strategy: Pode-se ver que a parte de criptografia e a lógica de envio/recebimento de mensagens são tratadas de forma modular,
# tornando mais fácil modificar a estratégia de criptografia sem afetar o fluxo de comunicação.

def main():
    app = ChatApp()  # Cria a instância do chat
    app.window.mainloop()  # Inicia o loop de eventos da interface gráfica

if __name__ == "__main__":
    main()
