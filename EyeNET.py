import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import scapy.all as scapy
import psutil
import threading
import time
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.animation as animation
import numpy as np
from sklearn.ensemble import IsolationForest
import socket
import nmap
import csv
from cryptography.fernet import Fernet
import netifaces
from scapy.all import ARP, Ether, srp
import math
import webbrowser
from PIL import Image, ImageTk, ImageFilter
import requests
from io import BytesIO


class CircularProgressbar(tk.Canvas):
    def __init__(self, parent, size=100, thickness=10, color='#3498db'):
        super().__init__(parent, width=size, height=size, bg='#2c3e50', highlightthickness=0)
        self.size = size
        self.thickness = thickness
        self.color = color
        self.degree = 0
        self.create_oval(thickness, thickness, size-thickness, size-thickness, outline=color, width=thickness)
        self.arc = self.create_arc(thickness, thickness, size-thickness, size-thickness, start=90, extent=0, fill=color)
        self.percentage = self.create_text(size//2, size//2, text="0%", font=("Arial", int(size//5)), fill='white')

    def update_progress(self, value):
        self.degree = int(360 * (value / 100))
        self.itemconfigure(self.arc, extent=-self.degree)
        self.itemconfigure(self.percentage, text=f"{int(value)}%")
        self.update()


class NetworkSecurityTool:
    def __init__(self, master):
        self.master = master
        master.title("EyeNET - Network Security Tool [ HTDark.Com ]")
        master.geometry("1280x800")
        
        self.center_window()

        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.style.configure("TFrame", background="#2c3e50")
        self.style.configure("TLabel", background="#2c3e50", foreground="#ecf0f1", font=("Arial", 10))
        self.style.configure("TButton", font=("Arial", 10), background="#3498db", foreground="#ffffff")
        self.style.map('TButton', background=[('active', '#2980b9')])

        self.notebook = ttk.Notebook(master)
        self.notebook.pack(expand=True, fill='both', padx=10, pady=10)

        self.create_dashboard_tab()
        self.create_network_activity_tab()
        self.create_anomaly_detection_tab()
        self.create_port_scanner_tab()
        self.create_firewall_tab()
        self.create_encryption_tab()
        self.create_network_mapping_tab()
        self.create_vulnerability_scanner_tab()
        self.create_about_tab()
        self.times = []
        self.upload_speeds = []
        self.download_speeds = []
        self.prev_bytes_sent = psutil.net_io_counters().bytes_sent
        self.prev_bytes_recv = psutil.net_io_counters().bytes_recv
        self.start_monitoring()
    
    def create_about_tab(self):
        about_frame = ttk.Frame(self.notebook)
        self.notebook.add(about_frame, text="About")
        canvas = tk.Canvas(about_frame, bg="#2c3e50")
        canvas.pack(fill=tk.BOTH, expand=True)
        image_url = "https://www.telefocal.com/TAwp/wp-content/uploads/2021/03/An-Overview-of-Cyber-Security-870x440.png"
        response = requests.get(image_url)
        img = Image.open(BytesIO(response.content))
        img = img.resize((1280, 800), Image.LANCZOS)
        img = img.filter(ImageFilter.GaussianBlur(radius=5))
        self.bg_image = ImageTk.PhotoImage(img)
        canvas.create_image(0, 0, anchor=tk.NW, image=self.bg_image)
        canvas.create_rectangle(0, 0, 1280, 800, fill="#2c3e50", stipple="gray50")
        canvas.create_text(640, 100, text="EyeNET", fill="#ecf0f1", font=("Arial", 24, "bold"))
        canvas.create_text(640, 140, text="Version 1.0", fill="#bdc3c7", font=("Arial", 16))
        description = (
            "EyeNET is a comprehensive network security tool designed to provide "
            "advanced monitoring, analysis, and protection capabilities for your network. "
            "With features ranging from real-time traffic monitoring to vulnerability scanning, "
            "EyeNET offers a robust suite of tools for network administrators and "
            "security professionals."
        )
        canvas.create_text(640, 250, text=description, fill="#ecf0f1", font=("Arial", 12), width=800, justify=tk.CENTER)
        canvas.create_text(640, 320, text="D3v by LSDeep", fill="#3498db", font=("Arial", 14, "bold"))
        website_link = canvas.create_text(640, 350, text="www.htdark.com", fill="#2980b9", font=("Arial", 12, "underline"))
        canvas.tag_bind(website_link, "<Button-1>", lambda e: webbrowser.open_new("http://www.htdark.com"))
        canvas.tag_bind(website_link, "<Enter>", lambda e: canvas.config(cursor="hand2"))
        canvas.tag_bind(website_link, "<Leave>", lambda e: canvas.config(cursor=""))
        canvas.create_line(140, 420, 1140, 420, fill="#34495e")
        features = [
            "Real-time Network Monitoring",
            "Packet Capture and Analysis",
            "Anomaly Detection",
            "Port Scanning",
            "Firewall Management",
            "File Encryption",
            "Network Mapping",
            "Vulnerability Scanning"
        ]
        canvas.create_text(640, 450, text="Key Features", fill="#ecf0f1", font=("Arial", 16, "bold"))
        for i, feature in enumerate(features):
            canvas.create_text(640, 490 + i*30, text=f"• {feature}", fill="#bdc3c7", font=("Arial", 12))
        canvas.create_text(640, 730, text="© 2024 LSDeep. All rights reserved.", fill="#7f8c8d", font=("Arial", 10))
        

    def center_window(self):
        self.master.update_idletasks()
        width = self.master.winfo_width()
        height = self.master.winfo_height()
        x = (self.master.winfo_screenwidth() // 2) - (width // 2)
        y = (self.master.winfo_screenheight() // 2) - (height // 2)
        self.master.geometry('{}x{}+{}+{}'.format(width, height, x, y))

    def create_dashboard_tab(self):
        dashboard_frame = ttk.Frame(self.notebook)
        self.notebook.add(dashboard_frame, text="Dashboard")

        # network Usage
        graph_frame = ttk.Frame(dashboard_frame)
        graph_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        self.fig, (self.ax1, self.ax2) = plt.subplots(2, 1, figsize=(8, 6), sharex=True)
        self.canvas = FigureCanvasTkAgg(self.fig, master=graph_frame)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=1)
        self.ax1.set_ylabel('Upload Speed (MB/s)')
        self.ax2.set_ylabel('Download Speed (MB/s)')
        self.ax2.set_xlabel('Time')
        self.upload_line, = self.ax1.plot([], [], label='Upload')
        self.download_line, = self.ax2.plot([], [], label='Download')
        self.ax1.legend()
        self.ax2.legend()
        info_frame = ttk.Frame(dashboard_frame)
        info_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")
        ttk.Label(info_frame, text="System Information", font=("Arial", 12, "bold")).pack(pady=5)
        self.cpu_label = ttk.Label(info_frame, text="CPU Usage: N/A")
        self.cpu_label.pack(pady=2)
        self.memory_label = ttk.Label(info_frame, text="Memory Usage: N/A")
        self.memory_label.pack(pady=2)
        self.disk_label = ttk.Label(info_frame, text="Disk Usage: N/A")
        self.disk_label.pack(pady=2)
        interface_frame = ttk.Frame(dashboard_frame)
        interface_frame.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")
        ttk.Label(interface_frame, text="Network Interfaces", font=("Arial", 12, "bold")).pack(pady=5)
        self.interface_listbox = tk.Listbox(interface_frame, height=5, bg="#34495e", fg="#ecf0f1")
        self.interface_listbox.pack(fill=tk.BOTH, expand=1)
        self.update_interface_list()

        log_frame = ttk.Frame(dashboard_frame)
        log_frame.grid(row=1, column=1, padx=10, pady=10, sticky="nsew")
        
        ttk.Label(log_frame, text="Suspicious Activity Log", font=("Arial", 12, "bold")).pack(pady=5)
        self.activity_log = tk.Text(log_frame, height=5, wrap=tk.WORD, bg="#34495e", fg="#ecf0f1")
        self.activity_log.pack(fill=tk.BOTH, expand=1)
        dashboard_frame.grid_columnconfigure(0, weight=1)
        dashboard_frame.grid_columnconfigure(1, weight=1)
        dashboard_frame.grid_rowconfigure(0, weight=1)
        dashboard_frame.grid_rowconfigure(1, weight=1)

    def create_network_activity_tab(self):
        activity_frame = ttk.Frame(self.notebook)
        self.notebook.add(activity_frame, text="Network Activity")

        ttk.Label(activity_frame, text="Recent Network Packets:", font=("Arial", 12, "bold")).pack(pady=5)
        self.packet_listbox = tk.Listbox(activity_frame, bg="#34495e", fg="#ecf0f1")
        self.packet_listbox.pack(fill=tk.BOTH, expand=1, padx=10, pady=5)

        button_frame = ttk.Frame(activity_frame)
        button_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Button(button_frame, text="Save Packet Log", command=self.save_packet_log).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear Log", command=self.clear_packet_log).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Analyze Traffic", command=self.analyze_traffic).pack(side=tk.LEFT, padx=5)

    def create_anomaly_detection_tab(self):
        anomaly_frame = ttk.Frame(self.notebook)
        self.notebook.add(anomaly_frame, text="Anomaly Detection")

        ttk.Label(anomaly_frame, text="Anomaly Detection Log:", font=("Arial", 12, "bold")).pack(pady=5)
        self.anomaly_log = tk.Text(anomaly_frame, bg="#34495e", fg="#ecf0f1")
        self.anomaly_log.pack(fill=tk.BOTH, expand=1, padx=10, pady=5)

        button_frame = ttk.Frame(anomaly_frame)
        button_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Button(button_frame, text="Clear Log", command=self.clear_anomaly_log).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Export Anomalies", command=self.export_anomalies).pack(side=tk.LEFT, padx=5)

    def create_port_scanner_tab(self):
        scanner_frame = ttk.Frame(self.notebook)
        self.notebook.add(scanner_frame, text="Port Scanner")

        input_frame = ttk.Frame(scanner_frame)
        input_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Label(input_frame, text="Target IP:").pack(side=tk.LEFT, padx=5)
        self.target_ip = ttk.Entry(input_frame)
        self.target_ip.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        ttk.Button(input_frame, text="Scan Ports", command=self.scan_ports).pack(side=tk.LEFT, padx=5)

        self.port_scan_result = tk.Text(scanner_frame, bg="#34495e", fg="#ecf0f1")
        self.port_scan_result.pack(fill=tk.BOTH, expand=1, padx=10, pady=5)

    def create_firewall_tab(self):
        firewall_frame = ttk.Frame(self.notebook)
        self.notebook.add(firewall_frame, text="Firewall Rules")

        input_frame = ttk.Frame(firewall_frame)
        input_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Label(input_frame, text="IP to Block:").pack(side=tk.LEFT, padx=5)
        self.block_ip = ttk.Entry(input_frame)
        self.block_ip.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        ttk.Button(input_frame, text="Block IP", command=self.block_ip_address).pack(side=tk.LEFT, padx=5)

        self.firewall_log = tk.Text(firewall_frame, bg="#34495e", fg="#ecf0f1")
        self.firewall_log.pack(fill=tk.BOTH, expand=1, padx=10, pady=5)

    def create_encryption_tab(self):
        encryption_frame = ttk.Frame(self.notebook)
        self.notebook.add(encryption_frame, text="File Encryption")

        button_frame = ttk.Frame(encryption_frame)
        button_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Button(button_frame, text="Encrypt File", command=self.encrypt_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Decrypt File", command=self.decrypt_file).pack(side=tk.LEFT, padx=5)

        self.encryption_log = tk.Text(encryption_frame, bg="#34495e", fg="#ecf0f1")
        self.encryption_log.pack(fill=tk.BOTH, expand=1, padx=10, pady=5)

    def create_network_mapping_tab(self):
        mapping_frame = ttk.Frame(self.notebook)
        self.notebook.add(mapping_frame, text="Network Mapping")

        self.map_button = ttk.Button(mapping_frame, text="Map Network", command=self.start_network_mapping)
        self.map_button.pack(pady=10)

        self.map_progress = CircularProgressbar(mapping_frame)
        self.map_progress.pack(pady=10)
        self.map_progress.pack_forget()

        self.network_map = tk.Text(mapping_frame, bg="#34495e", fg="#ecf0f1")
        self.network_map.pack(fill=tk.BOTH, expand=1, padx=10, pady=5)

    def create_vulnerability_scanner_tab(self):
        vuln_frame = ttk.Frame(self.notebook)
        self.notebook.add(vuln_frame, text="Vulnerability Scanner")
        input_frame = ttk.Frame(vuln_frame)
        input_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Label(input_frame, text="Target IP:").pack(side=tk.LEFT, padx=5)
        self.vuln_target_ip = ttk.Entry(input_frame)
        self.vuln_target_ip.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        self.scan_button = ttk.Button(input_frame, text="Scan Vulnerabilities", command=self.start_vulnerability_scan)
        self.scan_button.pack(side=tk.LEFT, padx=5)
        self.vuln_progress = CircularProgressbar(vuln_frame)
        self.vuln_progress.pack(pady=10)
        self.vuln_progress.pack_forget()
        self.vuln_scan_result = tk.Text(vuln_frame, bg="#34495e", fg="#ecf0f1")
        self.vuln_scan_result.pack(fill=tk.BOTH, expand=1, padx=10, pady=5)
    
    def start_network_mapping(self):
        self.map_button.config(state='disabled')
        self.map_progress.pack()
        self.network_map.delete(1.0, tk.END)
        self.network_map.insert(tk.END, "Mapping network, please wait...\n")
        threading.Thread(target=self.map_network_with_progress, daemon=True).start()

    def update_interface_list(self):
        self.interface_listbox.delete(0, tk.END)
        interfaces = netifaces.interfaces()
        for interface in interfaces:
            self.interface_listbox.insert(tk.END, interface)

    def start_monitoring(self):
        self.ani = animation.FuncAnimation(self.fig, self.update_plot, interval=1000, cache_frame_data=False)
        threading.Thread(target=self.capture_packets, daemon=True).start()
        threading.Thread(target=self.detect_anomalies, daemon=True).start()
        
    def update_plot(self, frame):
        current_time = time.time()
        self.times.append(current_time)
        bytes_sent = psutil.net_io_counters().bytes_sent
        bytes_recv = psutil.net_io_counters().bytes_recv
        upload_speed = (bytes_sent - self.prev_bytes_sent) / 1024 / 1024
        download_speed = (bytes_recv - self.prev_bytes_recv) / 1024 / 1024
        self.upload_speeds.append(upload_speed)
        self.download_speeds.append(download_speed)
        self.prev_bytes_sent = bytes_sent
        self.prev_bytes_recv = bytes_recv

        if len(self.times) > 60:
            self.times.pop(0)
            self.upload_speeds.pop(0)
            self.download_speeds.pop(0)
        self.upload_line.set_data(self.times, self.upload_speeds)
        self.download_line.set_data(self.times, self.download_speeds)
        self.ax1.relim()
        self.ax1.autoscale_view()
        self.ax2.relim()
        self.ax2.autoscale_view()
        self.cpu_label.config(text=f"CPU Usage: {psutil.cpu_percent()}%")
        self.memory_label.config(text=f"Memory Usage: {psutil.virtual_memory().percent}%")
        disk = psutil.disk_usage('/')
        self.disk_label.config(text=f"Disk Usage: {disk.percent}%")
        
        return self.upload_line, self.download_line

    def monitor_network_usage(self):
        prev_bytes_sent = psutil.net_io_counters().bytes_sent
        prev_bytes_recv = psutil.net_io_counters().bytes_recv
        times = []
        sent_speeds = []
        recv_speeds = []
        while True:
            time.sleep(1)
            bytes_sent = psutil.net_io_counters().bytes_sent
            bytes_recv = psutil.net_io_counters().bytes_recv
            upload_speed = (bytes_sent - prev_bytes_sent) / 1024 / 1024
            download_speed = (bytes_recv - prev_bytes_recv) / 1024 / 1024
            times.append(time.time())
            sent_speeds.append(upload_speed)
            recv_speeds.append(download_speed)

            if len(times) > 60:
                times.pop(0)
                sent_speeds.pop(0)
                recv_speeds.pop(0)
            self.fig.data = []
            self.fig.add_trace(go.Scatter(x=times, y=sent_speeds, name="Upload"), row=1, col=1)
            self.fig.add_trace(go.Scatter(x=times, y=recv_speeds, name="Download"), row=2, col=1)
            self.fig.update_layout(height=400, margin=dict(l=20, r=20, t=20, b=20))
            self.fig.update_yaxes(title_text="Speed (MB/s)", row=1, col=1)
            self.fig.update_yaxes(title_text="Speed (MB/s)", row=2, col=1)
            self.fig.update_xaxes(title_text="Time", row=2, col=1)
            self.network_graph.update(self.fig)
            self.cpu_label.config(text=f"CPU Usage: {psutil.cpu_percent()}%")
            self.memory_label.config(text=f"Memory Usage: {psutil.virtual_memory().percent}%")
            disk = psutil.disk_usage('/')
            self.disk_label.config(text=f"Disk Usage: {disk.percent}%")
            prev_bytes_sent = bytes_sent
            prev_bytes_recv = bytes_recv

    def capture_packets(self):
        def packet_callback(packet):
            if packet.haslayer(scapy.IP):
                src_ip = packet[scapy.IP].src
                dst_ip = packet[scapy.IP].dst
                protocol = packet[scapy.IP].proto
                length = len(packet)

                if packet.haslayer(scapy.TCP):
                    src_port = packet[scapy.TCP].sport
                    dst_port = packet[scapy.TCP].dport
                elif packet.haslayer(scapy.UDP):
                    src_port = packet[scapy.UDP].sport
                    dst_port = packet[scapy.UDP].dport
                else:
                    src_port = dst_port = "N/A"

                packet_info = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} | Protocol: {protocol} | Length: {length} bytes"
                self.packet_listbox.insert(tk.END, packet_info)
                self.packet_listbox.see(tk.END)

                if packet.haslayer(scapy.TCP) and packet[scapy.TCP].dport == 22:
                    self.log_suspicious_activity(f"Potential SSH attempt from {src_ip}")

        scapy.sniff(prn=packet_callback, store=0)

    def detect_anomalies(self):
        data = []
        model = IsolationForest(contamination=0.1, random_state=42)

        while True:
            time.sleep(10)
            current_data = [
                psutil.cpu_percent(),
                psutil.virtual_memory().percent,
                psutil.net_io_counters().bytes_sent,
                psutil.net_io_counters().bytes_recv
            ]
            data.append(current_data)
            if len(data) > 100:
                X = np.array(data)
                model.fit(X)
                anomalies = model.predict(X)
                if -1 in anomalies[-10:]:  
                    self.log_anomaly("Detected unusual system behavior")
                data = data[-100:]

    def log_suspicious_activity(self, message):
        self.activity_log.insert(tk.END, f"{time.ctime()}: {message}\n")
        self.activity_log.see(tk.END)

    def log_anomaly(self, message):
        self.anomaly_log.insert(tk.END, f"{time.ctime()}: {message}\n")
        self.anomaly_log.see(tk.END)

    def save_packet_log(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".csv")
        if file_path:
            with open(file_path, 'w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(["Timestamp", "Packet Info"])
                for line in self.packet_listbox.get(0, tk.END):
                    writer.writerow([time.ctime(), line])
            messagebox.showinfo("Success", "Packet log saved successfully!")

    def clear_packet_log(self):
        self.packet_listbox.delete(0, tk.END)

    def clear_anomaly_log(self):
        self.anomaly_log.delete(1.0, tk.END)

    def analyze_traffic(self):
        messagebox.showinfo("Traffic Analysis", "Traffic analysis feature coming soon!")

    def export_anomalies(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt")
        if file_path:
            with open(file_path, 'w') as file:
                file.write(self.anomaly_log.get(1.0, tk.END))
            messagebox.showinfo("Success", "Anomalies exported successfully!")

    def scan_ports(self):
        target = self.target_ip.get()
        nm = nmap.PortScanner()
        nm.scan(target, '1-1024')
        
        self.port_scan_result.delete(1.0, tk.END)
        for host in nm.all_hosts():
            self.port_scan_result.insert(tk.END, f"Host: {host}\n")
            for proto in nm[host].all_protocols():
                self.port_scan_result.insert(tk.END, f"Protocol: {proto}\n")
                ports = nm[host][proto].keys()
                for port in ports:
                    state = nm[host][proto][port]['state']
                    self.port_scan_result.insert(tk.END, f"Port: {port}\tState: {state}\n")

    def block_ip_address(self):
        ip = self.block_ip.get()
        self.firewall_log.insert(tk.END, f"Blocked IP: {ip}\n")
        messagebox.showinfo("Firewall", f"IP {ip} has been blocked.")

    def encrypt_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            key = Fernet.generate_key()
            fernet = Fernet(key)
            
            with open(file_path, 'rb') as file:
                original = file.read()
            
            encrypted = fernet.encrypt(original)
    
            with open(file_path + ".encrypted", 'wb') as encrypted_file:
                encrypted_file.write(encrypted)
            
            self.encryption_log.insert(tk.END, f"File encrypted: {file_path}\nKey: {key.decode()}\n")
            messagebox.showinfo("Success", "File encrypted successfully!")

    def decrypt_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Encrypted Files", "*.encrypted")])
        if file_path:
            key = simpledialog.askstring("Key", "Enter the decryption key:")
            if key:
                fernet = Fernet(key.encode())
                
                with open(file_path, 'rb') as enc_file:
                    encrypted = enc_file.read()
                
                try:
                    decrypted = fernet.decrypt(encrypted)
                    with open(file_path[:-10], 'wb') as dec_file:
                        dec_file.write(decrypted)
                    self.encryption_log.insert(tk.END, f"File decrypted: {file_path[:-10]}\n")
                    messagebox.showinfo("Success", "File decrypted successfully!")
                except:
                    messagebox.showerror("Error", "Decryption failed. Invalid key or corrupted file.")

    def map_network_with_progress(self):
        try:
            ip = socket.gethostbyname(socket.gethostname())
            ip_parts = ip.split('.')
            base_ip = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}."
        except Exception as e:
            self.master.after(0, lambda: messagebox.showerror("Error", f"Unable to get local IP: {str(e)}"))
            self.master.after(0, self.reset_map_ui)
            return

        try:
            arp = ARP(pdst=base_ip + "1/24")
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp

            result = srp(packet, timeout=3, verbose=0)[0]
            devices = []
            total_ips = 254
            for i, (sent, received) in enumerate(result):
                devices.append({'ip': received.psrc, 'mac': received.hwsrc})
                progress = (i + 1) / total_ips * 100
                self.master.after(0, lambda p=progress: self.map_progress.update_progress(p))
                time.sleep(0.05)
            self.master.after(0, lambda: self.network_map.delete(1.0, tk.END))
            self.master.after(0, lambda: self.network_map.insert(tk.END, "Network Map:\n"))
            for device in devices:
                self.master.after(0, lambda d=device: self.network_map.insert(tk.END, f"IP: {d['ip']}, MAC: {d['mac']}\n"))
        except Exception as e:
            self.master.after(0, lambda: messagebox.showerror("Error", f"Error during network mapping: {str(e)}"))
        finally:
            self.master.after(0, self.reset_map_ui)
    def reset_map_ui(self):
        self.map_button.config(state='normal')
        self.map_progress.pack_forget()
        self.map_progress.update_progress(0)
    
    def start_vulnerability_scan(self):
        target = self.vuln_target_ip.get()
        if not target:
            messagebox.showerror("Error", "Please enter a target IP address.")
            return
        self.scan_button.config(state='disabled')
        self.vuln_progress.pack()
        self.vuln_scan_result.delete(1.0, tk.END)
        self.vuln_scan_result.insert(tk.END, f"Scanning {target} for vulnerabilities...\n")
        threading.Thread(target=self.scan_vulnerabilities_with_progress, args=(target,), daemon=True).start()

    def scan_vulnerabilities_with_progress(self, target):
        try:
            nm = nmap.PortScanner()
            nm.scan(target, arguments="-sV -script vuln")
            
            total_steps = 100
            for i in range(total_steps):
                progress = (i + 1) / total_steps * 100
                self.master.after(0, lambda p=progress: self.vuln_progress.update_progress(p))
                time.sleep(0.05)

            self.master.after(0, lambda: self.vuln_scan_result.delete(1.0, tk.END))
            for host in nm.all_hosts():
                self.master.after(0, lambda h=host: self.vuln_scan_result.insert(tk.END, f"Host: {h}\n"))
                for proto in nm[host].all_protocols():
                    self.master.after(0, lambda p=proto: self.vuln_scan_result.insert(tk.END, f"Protocol: {p}\n"))
                    ports = nm[host][proto].keys()
                    for port in ports:
                        state = nm[host][proto][port]['state']
                        service = nm[host][proto][port]['name']
                        self.master.after(0, lambda pt=port, st=state, sv=service: 
                            self.vuln_scan_result.insert(tk.END, f"Port: {pt}\tState: {st}\tService: {sv}\n"))
                        if 'script' in nm[host][proto][port]:
                            for script in nm[host][proto][port]['script']:
                                self.master.after(0, lambda sc=script, res=nm[host][proto][port]['script'][script]: 
                                    self.vuln_scan_result.insert(tk.END, f"  {sc}: {res}\n"))
        except Exception as e:
            self.master.after(0, lambda: self.vuln_scan_result.insert(tk.END, f"Error during vulnerability scan: {str(e)}\n"))
        finally:
            self.master.after(0, self.reset_vuln_ui)

    def reset_vuln_ui(self):
        self.scan_button.config(state='normal')
        self.vuln_progress.pack_forget()
        self.vuln_progress.update_progress(0)

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkSecurityTool(root)
    root.mainloop()
    
    
    
    
    