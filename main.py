import requests
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading

# Lista de URLs sensibles de WordPress
SENSITIVE_URLS = [
    '/wp-admin/',
    '/wp-login.php',
    '/wp-config.php',
    '/wp-content/plugins/',
    '/wp-content/themes/',
    '/wp-content/uploads/'
]

# Lista de plugins y temas vulnerables (ejemplo, normalmente obtendrías esta lista de una base de datos de vulnerabilidades)
VULNERABLE_PLUGINS = [
    'revslider',
    'contact-form-7',
    'wp-file-manager'
]


class WordPressScannerGUI:
    def __init__(self, master):
        self.master = master
        master.title("Escáner de Vulnerabilidades de WordPress")
        master.geometry("800x600")

        self.scanning = False  # Flag to control scanning state

        self.create_widgets()

    def create_widgets(self):
        frame = tk.Frame(self.master)
        frame.pack(pady=10)

        self.url_label = tk.Label(frame, text="URL del sitio de WordPress:")
        self.url_label.grid(row=0, column=0, padx=5)

        self.url_entry = tk.Entry(frame, width=50)
        self.url_entry.grid(row=0, column=1, padx=5)

        self.scan_button = tk.Button(frame, text="Escanear", command=self.start_scan)
        self.scan_button.grid(row=1, column=0, columnspan=2, pady=10)

        self.cancel_button = tk.Button(frame, text="Cancelar", command=self.cancel_scan)
        self.cancel_button.grid(row=2, column=0, columnspan=2, pady=10)

        self.status_label = tk.Label(self.master, text="Esperando para escanear...")
        self.status_label.pack(pady=5)

        self.result_text = scrolledtext.ScrolledText(self.master, wrap=tk.WORD, width=90, height=25)
        self.result_text.pack(pady=10)

        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self.master, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(pady=10, fill=tk.X, padx=20)

        self.save_button = tk.Button(self.master, text="Guardar Resultados", command=self.save_results)
        self.save_button.pack(pady=5)

    def start_scan(self):
        url = self.url_entry.get().strip()
        if not url.startswith('http'):
            url = 'http://' + url

        self.result_text.delete('1.0', tk.END)
        self.result_text.insert(tk.END, f"Escaneando el sitio {url}...\n")
        self.status_label.config(text="Escaneando...")
        self.scan_button.config(state=tk.DISABLED)
        self.cancel_button.config(state=tk.NORMAL)
        self.progress_var.set(0)

        self.scanning = True
        threading.Thread(target=self.run_scan, args=(url,), daemon=True).start()

    def run_scan(self, base_url):
        results = []

        # Check sensitive URLs
        for i, url in enumerate(SENSITIVE_URLS):
            if not self.scanning:
                break
            full_url = base_url + url
            response = requests.get(full_url)
            if response.status_code == 200:
                results.append(f"[+] Accessible: {full_url}")
            else:
                results.append(f"[-] Not accessible: {full_url}")
            self.master.after(0, self.update_progress, (i + 1) / len(SENSITIVE_URLS) * 50)

        # Check vulnerable plugins
        for i, plugin in enumerate(VULNERABLE_PLUGINS):
            if not self.scanning:
                break
            full_url = f"{base_url}/wp-content/plugins/{plugin}/"
            response = requests.get(full_url)
            if response.status_code == 200:
                results.append(f"[+] Vulnerable plugin found: {plugin} at {full_url}")
            else:
                results.append(f"[-] Not found: {plugin}")
            self.master.after(0, self.update_progress, 50 + (i + 1) / len(VULNERABLE_PLUGINS) * 50)

        for result in results:
            self.master.after(0, self.update_results, result)
        self.master.after(0, self.scan_complete)

    def cancel_scan(self):
        self.scanning = False
        self.scan_button.config(state=tk.NORMAL)
        self.cancel_button.config(state=tk.DISABLED)
        self.status_label.config(text="Escaneo cancelado.")
        self.result_text.insert(tk.END, "\nEscaneo cancelado por el usuario.\n")

    def update_results(self, result):
        self.result_text.insert(tk.END, result + "\n")
        self.result_text.see(tk.END)

    def update_progress(self, value):
        self.progress_var.set(value)

    def scan_complete(self):
        if self.scanning:
            self.scan_button.config(state=tk.NORMAL)
            self.cancel_button.config(state=tk.DISABLED)
            self.status_label.config(text="Escaneo completado.")
            self.result_text.insert(tk.END, "\nAquí están tus resultados.\n")
        self.scanning = False

    def save_results(self):
        results = self.result_text.get('1.0', tk.END).strip()
        if results:
            with open("scan_results.txt", "w") as file:
                file.write(results)
            messagebox.showinfo("Guardar Resultados",
                                "Los resultados del escaneo se han guardado en 'scan_results.txt'.")
        else:
            messagebox.showwarning("Guardar Resultados", "No hay resultados para guardar.")


if __name__ == "__main__":
    root = tk.Tk()
    gui = WordPressScannerGUI(root)
    root.mainloop()
