import socket
import json
import base64
import hashlib
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import messagebox

# Configura a chave de criptografia
KEY = base64.urlsafe_b64encode(hashlib.sha256(b'qweasd').digest())
cipher_suite = Fernet(KEY)

# Configuração do servidor
HOST = '201.58.194.75'  # IP do servidor
PORT = 7444             # Porta do servidor

# Função para enviar requisição criptografada
def send_request(request_data):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((HOST, PORT))
        
        # Serializa e criptografa os dados da requisição
        encrypted_data = cipher_suite.encrypt(json.dumps(request_data).encode())
        
        # Envia o comprimento da mensagem criptografada
        message_length = f"{len(encrypted_data):<10}"
        client_socket.sendall(message_length.encode() + encrypted_data)
        
        # Recebe o comprimento da resposta
        encrypted_length = int(client_socket.recv(10).decode().strip())
        
        # Recebe e descriptografa os dados da resposta
        encrypted_response = client_socket.recv(encrypted_length)
        response_data = cipher_suite.decrypt(encrypted_response).decode()
        
        return json.loads(response_data)
    
# Funções para operações de autenticação, envio de mensagem e criação de usuário
def autenticar_usuario():
    nickname = entry_nickname.get()
    senha = entry_password.get()
    request = {
        "flag": 0,
        "User": nickname,
        "Pass": senha
    }
    response = send_request(request)
    messagebox.showinfo("Resposta Autenticação", str(response))
    print("Resposta autenticação:", response)

def criar_usuario():
    nickname = entry_nickname.get()
    senha = entry_password.get()
    request = {
        "flag": 3,
        "User": nickname,
        "Pass": senha
    }
    response = send_request(request)
    messagebox.showinfo("Resposta Criação de Usuário", str(response))
    print("Resposta criação de usuário:", response)

def enviar_mensagem():
    remetente = entry_nickname.get()
    destinatario = entry_destinatario.get()
    conteudo_email = entry_mensagem.get("1.0", tk.END).strip()
    request = {
        "flag": 1,
        "User": remetente,
        "destinatario": destinatario,
        "conteudo_email": conteudo_email
    }
    response = send_request(request)
    messagebox.showinfo("Resposta Envio de Mensagem", str(response))
    print("Resposta envio de mensagem:", response)

# Interface gráfica
root = tk.Tk()
root.title("Cliente de Autenticação")

# Campos para inserir o nickname e a senha
tk.Label(root, text="Nickname:").grid(row=0, column=0, padx=10, pady=5)
entry_nickname = tk.Entry(root)
entry_nickname.grid(row=0, column=1, padx=10, pady=5)

tk.Label(root, text="Senha:").grid(row=1, column=0, padx=10, pady=5)
entry_password = tk.Entry(root, show="*")
entry_password.grid(row=1, column=1, padx=10, pady=5)

# Botões para Autenticar e Criar Usuário
btn_autenticar = tk.Button(root, text="Autenticar", command=autenticar_usuario)
btn_autenticar.grid(row=2, column=0, columnspan=2, pady=5)

btn_criar_usuario = tk.Button(root, text="Criar Usuário", command=criar_usuario)
btn_criar_usuario.grid(row=3, column=0, columnspan=2, pady=5)

# Campos para enviar uma mensagem
tk.Label(root, text="Destinatário:").grid(row=4, column=0, padx=10, pady=5)
entry_destinatario = tk.Entry(root)
entry_destinatario.grid(row=4, column=1, padx=10, pady=5)

tk.Label(root, text="Mensagem:").grid(row=5, column=0, padx=10, pady=5)
entry_mensagem = tk.Text(root, height=5, width=30)
entry_mensagem.grid(row=5, column=1, padx=10, pady=5)

# Botão para Enviar Mensagem
btn_enviar_mensagem = tk.Button(root, text="Enviar Mensagem", command=enviar_mensagem)
btn_enviar_mensagem.grid(row=6, column=0, columnspan=2, pady=5)

root.mainloop()