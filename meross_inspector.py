"""Meross Inspector for Windows 10/11. Python stdlib only."""
import concurrent.futures
import hashlib
import ipaddress
import json
import os
import queue
import socket
import threading
import time
import tkinter as tk
import urllib.error
import urllib.request
import uuid
from tkinter import messagebox, ttk

APP_TITLE = 'Meross Inspector para Windows 1.0'
MAX_HOSTS = 254


def local_ipv4_networks():
    networks = set()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(('192.0.2.1', 80))
            ip = ipaddress.IPv4Address(s.getsockname()[0])
            if ip.is_private and not ip.is_loopback:
                networks.add(ipaddress.IPv4Network(f'{ip}/24', strict=False))
    except OSError:
        pass
    try:
        for item in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = ipaddress.IPv4Address(item[4][0])
            if ip.is_private and not ip.is_loopback:
                networks.add(ipaddress.IPv4Network(f'{ip}/24', strict=False))
    except OSError:
        pass
    return sorted(networks, key=str)


def check_ip(value):
    try:
        ip = ipaddress.IPv4Address(value.strip())
    except ipaddress.AddressValueError as exc:
        raise ValueError('Introduce una dirección IPv4 válida.') from exc
    if not ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
        raise ValueError('Solo se admiten direcciones IPv4 privadas de la red local.')
    return str(ip)


def probe(ip, timeout=0.32):
    """Find hosts with TCP/80 open; this does not prove they are Meross devices."""
    try:
        with socket.create_connection((ip, 80), timeout=timeout):
            return ip
    except OSError:
        return None


def meross_request(ip, key, namespace, method='GET', payload=None, timeout=4):
    ip = check_ip(ip)
    if not key:
        raise ValueError('Introduce la clave local Meross (device key).')
    msgid = uuid.uuid4().hex
    stamp = int(time.time())
    signature = hashlib.md5(f'{msgid}{key}{stamp}'.encode('utf-8')).hexdigest()
    packet = {
        'header': {
            'messageId': msgid, 'namespace': namespace, 'method': method,
            'payloadVersion': 1, 'from': '/app/merossinspector/subscribe',
            'timestamp': stamp, 'sign': signature,
        },
        'payload': payload if payload is not None else {},
    }
    body = json.dumps(packet, separators=(',', ':')).encode('utf-8')
    req = urllib.request.Request(
        f'http://{ip}/config', data=body,
        headers={'Content-Type': 'application/json'}, method='POST'
    )
    # Explicitly disable environment proxy settings for local device requests.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=timeout) as response:
            if response.status != 200:
                raise RuntimeError(f'HTTP {response.status}')
            raw = response.read(1024 * 1024 + 1)
            if len(raw) > 1024 * 1024:
                raise RuntimeError('Respuesta demasiado grande.')
    except urllib.error.URLError as exc:
        raise RuntimeError(f'No se pudo conectar: {exc.reason}') from exc
    try:
        answer = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError('La respuesta no contiene JSON válido.') from exc
    header = answer.get('header') or {}
    if header.get('method') == 'ERROR':
        raise RuntimeError(f'El dispositivo rechazó la orden: {answer.get("payload")}')
    if header.get('messageId') != msgid:
        raise RuntimeError('El identificador de respuesta no coincide.')
    return answer


def get_state(data):
    all_data = (data.get('payload') or {}).get('all') or {}
    system = all_data.get('system') or {}
    hardware = system.get('hardware') or {}
    control = all_data.get('control') or {}
    toggle = control.get('toggle') or control.get('togglex') or {}
    if isinstance(toggle, list):
        toggle = next((v for v in toggle if v.get('channel') == 0), {})
    state = toggle.get('onoff')
    return hardware.get('type', 'No identificado'), state


class Inspector(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry('800x630')
        self.minsize(680, 530)
        self.events = queue.Queue()
        self.busy = False
        self.stop_scan = threading.Event()
        self.ip_var = tk.StringVar()
        self.key_var = tk.StringVar()
        networks = local_ipv4_networks()
        self.net_var = tk.StringVar(value=str(networks[0]) if networks else '192.168.1.0/24')
        self.status_var = tk.StringVar(value='Listo. Conecta el PC a la misma red local que el MSS310.')
        self._build()
        self.after(100, self._poll)

    def _build(self):
        root = ttk.Frame(self, padding=16)
        root.pack(fill='both', expand=True)
        ttk.Label(root, text='Meross Inspector', font=('Segoe UI', 21, 'bold')).pack(anchor='w')
        ttk.Label(root, text='MSS310 · escáner IP · diagnóstico · control · medición eléctrica').pack(anchor='w', pady=(0, 14))

        connection = ttk.LabelFrame(root, text='Conexión local', padding=10)
        connection.pack(fill='x', pady=(0, 10))
        connection.columnconfigure(1, weight=1)
        ttk.Label(connection, text='IP del enchufe:').grid(row=0, column=0, sticky='w', pady=4)
        ttk.Entry(connection, textvariable=self.ip_var).grid(row=0, column=1, sticky='ew', padx=8, pady=4)
        ttk.Label(connection, text='Clave local Meross:').grid(row=1, column=0, sticky='w', pady=4)
        ttk.Entry(connection, textvariable=self.key_var, show='•').grid(row=1, column=1, sticky='ew', padx=8, pady=4)
        ttk.Label(connection, text='La clave permanece en memoria y no se guarda en disco.').grid(row=2, column=1, sticky='w')

        scan = ttk.LabelFrame(root, text='Buscar dispositivos en la red', padding=10)
        scan.pack(fill='x', pady=(0, 10))
        scan.columnconfigure(1, weight=1)
        ttk.Label(scan, text='Subred IPv4:').grid(row=0, column=0, sticky='w')
        ttk.Entry(scan, textvariable=self.net_var).grid(row=0, column=1, sticky='ew', padx=8)
        self.scan_btn = ttk.Button(scan, text='Escanear', command=self.scan)
        self.scan_btn.grid(row=0, column=2, padx=4)
        ttk.Button(scan, text='Detener', command=self.stop_scan.set).grid(row=0, column=3, padx=4)
        ttk.Label(scan, text='Equipos con puerto HTTP 80 abierto (no todos serán Meross).').grid(row=1, column=0, columnspan=4, sticky='w', pady=(6, 4))
        self.hosts = tk.Listbox(scan, height=5, exportselection=False)
        self.hosts.grid(row=2, column=0, columnspan=4, sticky='ew')
        self.hosts.bind('<<ListboxSelect>>', self.select_host)

        buttons = ttk.Frame(root)
        buttons.pack(fill='x', pady=(0, 10))
        self.action_buttons = []
        for text, callback in [
            ('Diagnosticar y medir', self.diagnose),
            ('Encender', lambda: self.toggle(1)),
            ('Apagar', lambda: self.toggle(0)),
        ]:
            b = ttk.Button(buttons, text=text, command=callback)
            b.pack(side='left', padx=(0, 8))
            self.action_buttons.append(b)

        output = ttk.LabelFrame(root, text='Resultados', padding=8)
        output.pack(fill='both', expand=True)
        self.log = tk.Text(output, height=10, wrap='word', state='disabled', font=('Consolas', 10))
        self.log.pack(fill='both', expand=True)
        ttk.Label(root, textvariable=self.status_var, wraplength=740).pack(anchor='w', pady=(8, 0))
        self.write('Selecciona una IP detectada o introdúcela manualmente.\n'
                   'El escaneo detecta servicios HTTP; para identificar el MSS310 utiliza Diagnosticar y medir.')

    def write(self, message):
        self.log.configure(state='normal')
        self.log.insert('end', message + '\n')
        self.log.see('end')
        self.log.configure(state='disabled')

    def select_host(self, _event):
        selection = self.hosts.curselection()
        if selection:
            self.ip_var.set(self.hosts.get(selection[0]))

    def _poll(self):
        try:
            while True:
                kind, value = self.events.get_nowait()
                if kind == 'log':
                    self.write(value)
                elif kind == 'status':
                    self.status_var.set(value)
                elif kind == 'host':
                    self.hosts.insert('end', value)
                elif kind == 'done':
                    self.busy = False
                    self.scan_btn.configure(state='normal')
                    for button in self.action_buttons:
                        button.configure(state='normal')
        except queue.Empty:
            pass
        self.after(100, self._poll)

    def start(self, task, status):
        if self.busy:
            messagebox.showinfo('Ocupado', 'Espera a que termine la operación actual.')
            return
        self.busy = True
        self.scan_btn.configure(state='disabled')
        for button in self.action_buttons:
            button.configure(state='disabled')
        self.status_var.set(status)

        def runner():
            try:
                task()
            except Exception as exc:
                self.events.put(('log', f'ERROR: {exc}'))
                self.events.put(('status', 'Operación terminada con error.'))
            finally:
                self.events.put(('done', None))
        threading.Thread(target=runner, daemon=True).start()

    def scan(self):
        try:
            network = ipaddress.IPv4Network(self.net_var.get().strip(), strict=False)
            if not network.is_private or network.is_loopback or network.is_link_local:
                raise ValueError('Usa una subred IPv4 privada, por ejemplo 192.168.1.0/24.')
            if network.num_addresses - 2 > MAX_HOSTS:
                raise ValueError('Por seguridad, el escáner admite como máximo una subred /24 (254 hosts).')
        except ValueError as exc:
            messagebox.showerror('Subred no válida', str(exc))
            return
        self.hosts.delete(0, 'end')
        self.stop_scan.clear()

        def task():
            ips = [str(host) for host in network.hosts()]
            self.events.put(('log', f'Escaneando {network} ({len(ips)} direcciones)...'))
            found = 0
            with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
                futures = {pool.submit(probe, ip): ip for ip in ips}
                for future in concurrent.futures.as_completed(futures):
                    if self.stop_scan.is_set():
                        break
                    host = future.result()
                    if host:
                        found += 1
                        self.events.put(('host', host))
            self.events.put(('log', f'Escaneo terminado. Equipos HTTP encontrados: {found}.'))
            self.events.put(('status', 'Escaneo finalizado. Selecciona una IP para diagnosticar.'))
        self.start(task, 'Buscando dispositivos en la red local...')

    def _credentials(self):
        return check_ip(self.ip_var.get()), self.key_var.get().strip()

    def diagnose(self):
        try:
            ip, key = self._credentials()
        except ValueError as exc:
            messagebox.showerror('IP incorrecta', str(exc))
            return

        def task():
            begin = time.monotonic()
            answer = meross_request(ip, key, 'Appliance.System.All')
            elapsed = round((time.monotonic() - begin) * 1000)
            model, state = get_state(answer)
            state_text = {1: 'ENCENDIDO', 0: 'APAGADO'}.get(state, 'No disponible')
            lines = [f'IP: {ip}', f'Tiempo de respuesta: {elapsed} ms',
                     f'Modelo: {model}', f'Estado: {state_text}']
            try:
                energy = meross_request(ip, key, 'Appliance.Control.Electricity',
                                        payload={'electricity': {'channel': 0}})
                values = (energy.get('payload') or {}).get('electricity') or {}
                if not values:
                    raise RuntimeError('No hay valores de electricidad.')
                if 'power' in values:
                    lines.append(f'Potencia: {float(values["power"]) / 1000:.3f} W')
                if 'voltage' in values:
                    lines.append(f'Tensión: {float(values["voltage"]) / 10:.1f} V')
                if 'current' in values:
                    lines.append(f'Intensidad: {float(values["current"]) / 1000:.3f} A')
            except Exception as exc:
                lines.append(f'Medición no disponible: {exc}')
            self.events.put(('log', '\n'.join(lines) + '\n' + '-' * 45))
            self.events.put(('status', 'Diagnóstico finalizado.'))
        self.start(task, 'Consultando el MSS310...')

    def toggle(self, value):
        try:
            ip, key = self._credentials()
        except ValueError as exc:
            messagebox.showerror('IP incorrecta', str(exc))
            return

        def task():
            response = meross_request(ip, key, 'Appliance.Control.Toggle', 'SET',
                                      {'toggle': {'channel': 0, 'onoff': value}})
            method = (response.get('header') or {}).get('method')
            self.events.put(('log', f'Orden enviada a {ip}: '
                                    f'{"ENCENDER" if value else "APAGAR"}. Respuesta: {method}. '
                                    'Pulsa Diagnosticar y medir para comprobar el estado.'))
            self.events.put(('status', 'Orden enviada; comprueba el estado real con Diagnosticar.'))
        self.start(task, 'Enviando orden al enchufe...')


if __name__ == '__main__':
    app = Inspector()
    app.mainloop()
