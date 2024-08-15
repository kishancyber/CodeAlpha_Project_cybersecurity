import subprocess
import time
import tkinter as tk
from tkinter import messagebox
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from collections import defaultdict
import smtplib
from email.mime.text import MIMEText

class NIDSApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Intrusion Detection System")
        self.root.geometry("600x400")
        
        self.alert_counts = defaultdict(int)
        self.log_file = tk.StringVar(value="/var/log/snort/alert")
        self.use_snort = tk.BooleanVar(value=True)
        
        self.create_widgets()

    def create_widgets(self):
        # Start Button
        start_btn = tk.Button(self.root, text="Start Monitoring", command=self.start_monitoring)
        start_btn.pack(pady=10)

        # Choose NIDS Tool (Snort or Suricata)
        nids_label = tk.Label(self.root, text="Choose NIDS Tool:")
        nids_label.pack(pady=5)

        snort_radio = tk.Radiobutton(self.root, text="Snort", variable=self.use_snort, value=True)
        snort_radio.pack()

        suricata_radio = tk.Radiobutton(self.root, text="Suricata", variable=self.use_snort, value=False)
        suricata_radio.pack()

        # Log File Path
        log_label = tk.Label(self.root, text="Log File Path:")
        log_label.pack(pady=5)
        log_entry = tk.Entry(self.root, textvariable=self.log_file)
        log_entry.pack()

        # Canvas for Plotting
        self.figure, self.ax = plt.subplots(figsize=(6, 3))
        self.canvas = FigureCanvasTkAgg(self.figure, master=self.root)
        self.canvas.get_tk_widget().pack()

        # Set Email for Alerts
        email_label = tk.Label(self.root, text="Email for Alerts:")
        email_label.pack(pady=5)
        self.email_entry = tk.Entry(self.root)
        self.email_entry.pack()

    def start_monitoring(self):
        if self.use_snort.get():
            self.start_snort()
        else:
            self.start_suricata()
        
        self.monitor_logs()

    def start_snort(self):
        subprocess.Popen(['snort', '-A', 'console', '-q', '-c', '/etc/snort/snort.conf', '-i', 'eth0'])

    def start_suricata(self):
        subprocess.Popen(['suricata', '-c', '/etc/suricata/suricata.yaml', '-i', 'eth0'])

    def monitor_logs(self):
        try:
            with open(self.log_file.get(), 'r') as f:
                while True:
                    line = f.readline()
                    if line:
                        alert_type = self.parse_alert(line)
                        self.alert_counts[alert_type] += 1
                        self.update_plot()
                        self.check_alert_threshold(alert_type)
                    self.root.update_idletasks()
                    time.sleep(1)
        except FileNotFoundError:
            messagebox.showerror("Error", "Log file not found!")
        except KeyboardInterrupt:
            print("Monitoring stopped.")
    
    def parse_alert(self, log_line):
        if "TCP" in log_line:
            return "TCP"
        elif "UDP" in log_line:
            return "UDP"
        elif "ICMP" in log_line:
            return "ICMP"
        else:
            return "Other"
    
    def update_plot(self):
        self.ax.clear()
        self.ax.bar(self.alert_counts.keys(), self.alert_counts.values(), color='blue')
        self.ax.set_xlabel('Alert Type')
        self.ax.set_ylabel('Count')
        self.ax.set_title('Network Intrusion Alerts')
        self.canvas.draw()

    def check_alert_threshold(self, alert_type):
        if self.alert_counts[alert_type] > 10:  # Example threshold
            self.send_email_alert(alert_type)

    def send_email_alert(self, alert_type):
        if not self.email_entry.get():
            return  # No email provided
        
        msg = MIMEText(f"Alert triggered: {alert_type} has exceeded the threshold.")
        msg['Subject'] = 'NIDS Alert'
        msg['From'] = 'noreply@yourdomain.com'
        msg['To'] = self.email_entry.get()

        try:
            with smtplib.SMTP('smtp.yourdomain.com') as server:
                server.login('username', 'password')
                server.sendmail(msg['From'], [msg['To']], msg.as_string())
                messagebox.showinfo("Email Sent", f"Alert email sent to {self.email_entry.get()}")
        except Exception as e:
            messagebox.showerror("Email Error", f"Failed to send email: {e}")

def main():
    root = tk.Tk()
    app = NIDSApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
