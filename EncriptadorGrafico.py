import os
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import filedialog, messagebox

# Funciones de cifrado/descifrado
def generar_clave():
    return Fernet.generate_key()

def cifrar_archivo(ruta_archivo, clave):
    fernet = Fernet(clave)
    with open(ruta_archivo, "rb") as archivo:
        datos = archivo.read()
    datos_cifrados = fernet.encrypt(datos)
    with open(ruta_archivo, "wb") as archivo_cifrado:
        archivo_cifrado.write(datos_cifrados)

def descifrar_archivo(ruta_archivo, clave):
    fernet = Fernet(clave)
    with open(ruta_archivo, "rb") as archivo_cifrado:
        datos_cifrados = archivo_cifrado.read()
    datos_descifrados = fernet.decrypt(datos_cifrados)
    with open(ruta_archivo, "wb") as archivo_descifrado:
        archivo_descifrado.write(datos_descifrados)

def cifrar_directorio(directorio, clave):
    for root, dirs, files in os.walk(directorio):
        for file in files:
            ruta_archivo = os.path.join(root, file)
            cifrar_archivo(ruta_archivo, clave)

def descifrar_directorio(directorio, clave):
    for root, dirs, files in os.walk(directorio):
        for file in files:
            ruta_archivo = os.path.join(root, file)
            descifrar_archivo(ruta_archivo, clave)

# Funciones de la interfaz gráfica
def seleccionar_directorio():
    directorio = filedialog.askdirectory()
    entrada_directorio.delete(0, tk.END)
    entrada_directorio.insert(0, directorio)

def cifrar():
    directorio = entrada_directorio.get()
    if not directorio:
        messagebox.showerror("Error", "Por favor selecciona un directorio.")
        return
    clave = generar_clave()
    cifrar_directorio(directorio, clave)
    messagebox.showinfo("Éxito", f"Archivos cifrados. Clave: {clave.decode()}\nGuarda esta clave de forma segura.")
    print(f"Clave: {clave.decode()}")

def descifrar():
    directorio = entrada_directorio.get()
    clave = entrada_clave.get()
    if not directorio or not clave:
        messagebox.showerror("Error", "Por favor selecciona un directorio y proporciona una clave.")
        return
    try:
        descifrar_directorio(directorio, clave.encode())
        messagebox.showinfo("Éxito", "Archivos descifrados correctamente.")
    except Exception as e:
        messagebox.showerror("Error", f"Error al descifrar los archivos: {e}")

# Configuración de la interfaz gráfica
ventana = tk.Tk()
ventana.title("Cifrado y Descifrado de Archivos")

tk.Label(ventana, text="Directorio:").grid(row=0, column=0, padx=10, pady=10)
entrada_directorio = tk.Entry(ventana, width=50)
entrada_directorio.grid(row=0, column=1, padx=10, pady=10)
btn_seleccionar = tk.Button(ventana, text="Seleccionar", command=seleccionar_directorio)
btn_seleccionar.grid(row=0, column=2, padx=10, pady=10)

tk.Label(ventana, text="Clave (para descifrar):").grid(row=1, column=0, padx=10, pady=10)
entrada_clave = tk.Entry(ventana, width=50)
entrada_clave.grid(row=1, column=1, padx=10, pady=10)

btn_cifrar = tk.Button(ventana, text="Cifrar", command=cifrar)
btn_cifrar.grid(row=2, column=0, padx=10, pady=10)

btn_descifrar = tk.Button(ventana, text="Descifrar", command=descifrar)
btn_descifrar.grid(row=2, column=1, padx=10, pady=10)

ventana.mainloop()