import tkinter as tk
from tkinter import messagebox, ttk
import sqlite3
import re
import bcrypt
import json
import os
import random
import smtplib
from email.mime.text import MIMEText
from cryptography.fernet import Fernet

# Função para gerar uma chave de criptografia
def generate_key():
    return Fernet.generate_key()

# Função para criptografar dados
def encrypt_data(data):
    key = generate_key()
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(data.encode())
    return encrypted_data, key

# Função para descriptografar dados
def decrypt_data(encrypted_data, key):
    fernet = Fernet(key)
    decrypted_data = fernet.decrypt(encrypted_data).decode()
    return decrypted_data

# Função para criar ou conectar ao banco de dados
def create_connection():
    conn = sqlite3.connect('users.db')
    return conn

# Função para criar as tabelas necessárias
def create_tables():
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            name TEXT,
            age INTEGER,
            email TEXT,
            is_verified INTEGER DEFAULT 0,
            verification_code TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS feedback (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            comment TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS courses (
            id INTEGER PRIMARY KEY,
            title TEXT,
            description TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_courses (
            user_id INTEGER,
            course_id INTEGER,
            progress INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (course_id) REFERENCES courses (id)
        )
    ''')
    conn.commit()
    conn.close()

# Função para enviar e-mail de verificação
def send_verification_email(email, code):
    msg = MIMEText(f'Seu código de verificação é: {code}')
    msg['Subject'] = 'Verificação de E-mail'
    msg['From'] = 'seu_email@example.com'  # Substitua pelo seu e-mail
    msg['To'] = email

    with smtplib.SMTP('smtp.example.com', 587) as server:  # Substitua pelo servidor SMTP
        server.starttls()
        server.login('seu_email@example.com', 'sua_senha')  # Substitua pelo seu e-mail e senha
        server.send_message(msg)

# Função para registrar um novo usuário
def register_user(username, password, name, age, email):
    conn = create_connection()
    cursor = conn.cursor()
    try:
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        verification_code = str(random.randint(100000, 999999))
        cursor.execute('''
            INSERT INTO users (username, password, name, age, email, verification_code)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (username, hashed_password, name, age, email, verification_code))
        conn.commit()
        send_verification_email(email, verification_code)
        messagebox.showinfo("Sucesso", "Usuário registrado com sucesso! Verifique seu e-mail para o código de verificação.")
    except sqlite3.IntegrityError:
        messagebox.showwarning("Atenção", "Nome de usuário já existe.")
    finally:
        conn.close()

# Função para autenticar o usuário
def authenticate(username, password):
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username=?', (username,))
    user = cursor.fetchone()
    conn.close()
    if user and bcrypt.checkpw(password.encode(), user[2].encode()):
        return user
    return None

# Função para verificar o código de verificação
def verify_code(user_id, code):
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT verification_code FROM users WHERE id=?', (user_id,))
    stored_code = cursor.fetchone()
    if stored_code and stored_code[0] == code:
        cursor.execute('UPDATE users SET is_verified=1 WHERE id=?', (user_id,))
        conn.commit()
        messagebox.showinfo("Sucesso", "E-mail verificado com sucesso!")
    else:
        messagebox.showwarning("Atenção", "Código de verificação inválido.")
    conn.close()

# Função para salvar dados do usuário
def save_data():
    user_data = {
        "name": entry_name.get(),
        "age": entry_age.get(),
        "email": entry_email.get()
    }
    
    if not all(user_data.values()):
        messagebox.showwarning("Atenção", "Por favor, preencha todos os campos.")
        return
    
    if not re.match(r"[^@]+@[^@]+\.[^@]+", user_data['email']):
        messagebox.showwarning("Atenção", "Email inválido.")
        return

    encrypted_data, key = encrypt_data(json.dumps(user_data))
    
    with open('user_data.json', 'wb') as json_file:
        json_file.write(encrypted_data)
    
    with open('key.key', 'wb') as key_file:
        key_file.write(key)
    
    messagebox.showinfo("Sucesso", "Dados salvos com sucesso!")

# Função para carregar dados do usuário
def load_data():
    if os.path.exists('user_data.json') and os.path.exists('key.key'):
        with open('key.key', 'rb') as key_file:
            key = key_file.read()
        
        with open('user_data.json', 'rb') as json_file:
            encrypted_data = json_file.read()
            decrypted_data = decrypt_data(encrypted_data, key)
            user_data = json.loads(decrypted_data)
            
            entry_name.delete(0, tk.END)
            entry_age.delete(0, tk.END)
            entry_email.delete(0, tk.END)
            entry_name.insert(0, user_data['name'])
            entry_age.insert(0, user_data['age'])
            entry_email.insert(0, user_data['email'])
    else:
        messagebox.showwarning("Atenção", "Nenhum dado encontrado.")

# Função para exibir estatísticas
def show_statistics():
    if os.path.exists('user_data.json'):
        with open('key.key', 'rb') as key_file:
            key = key_file.read()
        
        with open('user_data.json', 'rb') as json_file:
            encrypted_data = json_file.read()
            decrypted_data = decrypt_data(encrypted_data, key)
            user_data = json.loads(decrypted_data)
            messagebox.showinfo("Estatísticas", f"Nome: {user_data['name']}\nIdade: {user_data['age']}\nEmail: {user_data['email']}")
    else:
        messagebox.showwarning("Atenção", "Nenhum dado encontrado.")

# Função para criar a interface de feedback
def feedback():
    feedback_window = tk.Toplevel(root)
    feedback_window.title("Feedback")

    label_comment = tk.Label(feedback_window, text="Comentário:")
    label_comment.pack(pady=5)
    entry_comment = tk.Entry(feedback_window)
    entry_comment.pack(pady=5)

    def submit_feedback():
        comment = entry_comment.get()
        if not comment:
            messagebox.showwarning("Atenção", "Por favor, insira um comentário.")
            return
        
        user_id = 1  # Aqui você deve pegar o ID do usuário autenticado
        conn = create_connection()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO feedback (user_id, comment) VALUES (?, ?)', (user_id, comment))
        conn.commit()
        conn.close()
        messagebox.showinfo("Sucesso", "Feedback enviado com sucesso!")
        feedback_window.destroy()

    button_submit = tk.Button(feedback_window, text="Enviar", command=submit_feedback)
    button_submit.pack(pady=10)

# Função para criar a interface de registro
def register():
    register_window = tk.Toplevel(root)
    register_window.title("Registro")

    label_username = tk.Label(register_window, text="Usuário:")
    label_username.pack(pady=5)
    entry_username = tk.Entry(register_window)
    entry_username.pack(pady=5)

    label_password = tk.Label(register_window, text="Senha:")
    label_password.pack(pady=5)
    entry_password = tk.Entry(register_window, show='*')
    entry_password.pack(pady=5)

    label_name = tk.Label(register_window, text="Nome:")
    label_name.pack(pady=5)
    entry_name = tk.Entry(register_window)
    entry_name.pack(pady=5)

    label_age = tk.Label(register_window, text="Idade:")
    label_age.pack(pady=5)
    entry_age = tk.Entry(register_window)
    entry_age.pack(pady=5)

    label_email = tk.Label(register_window, text="Email:")
    label_email.pack(pady=5)
    entry_email = tk.Entry(register_window)
    entry_email.pack(pady=5)

    def submit_registration():
        username = entry_username.get()
        password = entry_password.get()
        name = entry_name.get()
        age = entry_age.get()
        email = entry_email.get()
        
        if not all([username, password, name, age, email]):
            messagebox.showwarning("Atenção", "Por favor, preencha todos os campos.")
            return
        
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            messagebox.showwarning("Atenção", "Email inválido.")
            return
        
        register_user(username, password, name, age, email)
        register_window.destroy()

    button_register = tk.Button(register_window, text="Registrar", command=submit_registration)
    button_register.pack(pady=10)

# Função para criar a interface de login
def login():
    login_window = tk.Toplevel(root)
    login_window.title("Login")

    label_username = tk.Label(login_window, text="Usuário:")
    label_username.pack(pady=5)
    entry_username = tk.Entry(login_window)
    entry_username.pack(pady=5)

    label_password = tk.Label(login_window, text="Senha:")
    label_password.pack(pady=5)
    entry_password = tk.Entry(login_window, show='*')
    entry_password.pack(pady=5)

    def authenticate_user():
        username = entry_username.get()
        password = entry_password.get()
        user = authenticate(username, password)
        if user:
            if user[6] == 0:  # Verifica se o e-mail foi verificado
                messagebox.showwarning("Atenção", "Por favor, verifique seu e-mail antes de fazer login.")
                return
            messagebox.showinfo("Sucesso", "Login bem-sucedido!")
            login_window.destroy()
            # Aqui você pode carregar dados do usuário ou abrir a interface principal
        else:
            messagebox.showwarning("Atenção", "Usuário ou senha inválidos.")

    button_login = tk.Button(login_window, text="Entrar", command=authenticate_user)
    button_login.pack(pady=10)

# Criação da interface gráfica principal
root = tk.Tk()
root.title("Plataforma de Educação Digital Segura")

# Criação do banco de dados e tabelas
create_tables()

# Botões de Login e Registro
button_login = tk.Button(root, text="Login", command=login)
button_login.pack(pady=10)

button_register = tk.Button(root, text="Registrar", command=register)
button_register.pack(pady=10)

# Labels e Entradas
label_name = tk.Label(root, text="Nome:")
label_name.pack(pady=5)
entry_name = tk.Entry(root)
entry_name.pack(pady=5)

label_age = tk.Label(root, text="Idade:")
label_age.pack(pady=5)
entry_age = tk.Entry(root)
entry_age.pack(pady=5)

label_email = tk.Label(root, text="Email:")
label_email.pack(pady=5)
entry_email = tk.Entry(root)
entry_email.pack(pady=5)

# Botões
button_save = tk.Button(root, text="Salvar Dados", command=save_data)
button_save.pack(pady=10)

button_load = tk.Button(root, text="Carregar Dados", command=load_data)
button_load.pack(pady=10)

button_stats = tk.Button(root, text="Mostrar Estatísticas", command=show_statistics)
button_stats.pack(pady=10)

button_feedback = tk.Button(root, text="Deixar Feedback", command=feedback)
button_feedback.pack(pady=10)

# Iniciar a interface
root.mainloop()
