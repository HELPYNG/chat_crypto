import os
import socket
import base64
import threading
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import scrolledtext, messagebox

class ChatApp:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Chat P2P Application")

        self.local_ip_entry = tk.Entry(self.window, width=20)
        self.local_port_entry = tk.Entry(self.window, width=5)
        self.remote_ip_entry = tk.Entry(self.window, width=20)
        self.remote_port_entry = tk.Entry(self.window, width=5)
        self.key_entry = tk.Entry(self.window, width=50)

        self.connect_button = tk.Button(self.window, text="Conectar", command=self.connect)
        self.chat_area = scrolledtext.ScrolledText(self.window, state='disabled', width=50, height=20)
        self.message_entry = tk.Entry(self.window, width=50)
        self.send_button = tk.Button(self.window, text="Enviar", command=self.send_message)

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

        self.fernet = None
        self.remote_address = None
        self.sock = None
        self.listening_thread = None

    def connect(self):
        local_ip = self.local_ip_entry.get()
        local_port = int(self.local_port_entry.get())
        remote_ip = self.remote_ip_entry.get()
        remote_port = int(self.remote_port_entry.get())
        key = self.key_entry.get().strip()

        if not key:
            key = Fernet.generate_key().decode()
            self.key_entry.delete(0, tk.END)
            self.key_entry.insert(0, key)
            self.append_chat("🔐 Nova chave gerada e inserida.")

        self.fernet = Fernet(key.encode())
        self.remote_address = (remote_ip, remote_port)

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((local_ip, local_port))

        self.listening_thread = threading.Thread(target=self.listen, daemon=True)
        self.listening_thread.start()
        self.append_chat("🔗 Conectado a " + remote_ip + ":" + str(remote_port))

    def listen(self):
        def check_messages():
            try:
                data, addr = self.sock.recvfrom(2048)
                msg = self.decrypt_message(data.decode())
                self.append_chat(f"[{addr}]: {msg}")
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

        encrypted_msg = self.encrypt_message(msg)
        self.sock.sendto(encrypted_msg.encode(), self.remote_address)
        self.append_chat(f"[Você]: {msg}")
        self.message_entry.delete(0, tk.END)

    def append_chat(self, msg):
        self.chat_area.config(state='normal')
        self.chat_area.insert(tk.END, msg + "\n")
        self.chat_area.config(state='disabled')
        self.chat_area.yview(tk.END)

    def encrypt_message(self, msg):
        return base64.urlsafe_b64encode(self.fernet.encrypt(msg.encode())).decode()

    def decrypt_message(self, token):
        try:
            return self.fernet.decrypt(base64.urlsafe_b64decode(token.encode())).decode()
        except:
            return "[❌ Mensagem inválida ou chave errada]"

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