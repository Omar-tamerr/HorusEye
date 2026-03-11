"""
HorusEye v2 — Team Collaboration
Shared real-time session for 2+ red teamers — same findings, live updates
Author: Omar Tamer 🇪🇬
"""

import json
import socket
import threading
import time
import hashlib
from typing import Dict, List, Optional, Callable
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich import box

EGYPT_RED  = "#E4002B"
EGYPT_GOLD = "#C09A3C"

COLLAB_PORT = 31337  # HorusEye collab port
PROTOCOL_VERSION = "HorusEye/2.0"

MSG_TYPES = {
    "HELLO":    "handshake",
    "FINDING":  "new attack path found",
    "CRED":     "valid credential found",
    "CRACKED":  "hash cracked",
    "CHECKLIST":"checklist update",
    "CHAT":     "team message",
    "ALERT":    "critical alert",
    "PING":     "keepalive",
    "SYNC":     "full state sync",
}

TEAM_COLORS = ["bold cyan", "bold magenta", "bold yellow", "bold green", "bold blue"]


class CollabServer:
    """Host a collaboration session — other operators connect to you."""

    def __init__(self, console: Console, port: int = COLLAB_PORT,
                 password: str = "", operator_name: str = "Operator-1"):
        self.console = console
        self.port = port
        self.password_hash = hashlib.sha256(password.encode()).hexdigest() if password else ""
        self.operator_name = operator_name
        self.clients: Dict[socket.socket, Dict] = {}
        self.session_state: Dict = {
            "findings": [],
            "valid_creds": [],
            "cracked_hashes": {},
            "checklist": {},
            "timeline": [],
            "domain": "",
        }
        self._lock = threading.Lock()
        self._running = False
        self._server_sock: Optional[socket.socket] = None
        self.on_event: Optional[Callable] = None  # Hook for UI updates

    def start(self, domain: str = "") -> str:
        """Start collaboration server. Returns connection string."""
        self.session_state["domain"] = domain
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind(("0.0.0.0", self.port))
        self._server_sock.listen(10)
        self._running = True

        # Get local IP
        local_ip = self._get_local_ip()
        connect_str = f"{local_ip}:{self.port}"

        # Start accept loop
        t = threading.Thread(target=self._accept_loop, daemon=True)
        t.start()

        self.console.print(Panel(
            f"[bold white]🤝 Collaboration Server STARTED[/bold white]\n\n"
            f"[bold white]📡 Share with team:[/bold white] [bold green]{connect_str}[/bold green]\n"
            f"[bold white]🔑 Password:[/bold white]       [cyan]{'set' if self.password_hash else 'none (open)'}[/cyan]\n"
            f"[bold white]👤 Your name:[/bold white]      [cyan]{self.operator_name}[/cyan]\n\n"
            f"[dim]Team command: horuseye --collab-join {connect_str}[/dim]",
            title="[bold red][ 𓂀 COLLAB SERVER ][/bold red]",
            border_style="green", padding=(1, 3)
        ))

        return connect_str

    def broadcast_finding(self, finding: Dict):
        """Broadcast a new finding to all connected operators."""
        with self._lock:
            self.session_state["findings"].append(finding)
        msg = self._build_msg("FINDING", {"finding": finding})
        self._broadcast(msg)
        self._notify(f"📍 New finding: {finding.get('title', '')[:50]}")

    def broadcast_cred(self, cred: Dict):
        """Broadcast a valid credential."""
        with self._lock:
            self.session_state["valid_creds"].append(cred)
        msg = self._build_msg("CRED", {"cred": cred})
        self._broadcast(msg)
        self._notify(f"🔑 CRED FOUND: {cred.get('domain','')}\\{cred.get('username','')} : {cred.get('password','')}")

    def broadcast_cracked(self, hash_val: str, plaintext: str):
        """Broadcast a cracked hash."""
        with self._lock:
            self.session_state["cracked_hashes"][hash_val] = plaintext
        msg = self._build_msg("CRACKED", {"hash": hash_val, "plaintext": plaintext})
        self._broadcast(msg)
        self._notify(f"💥 HASH CRACKED: ...{hash_val[-8:]} → {plaintext}")

    def broadcast_checklist(self, item_id: str, status: str):
        """Broadcast checklist item update."""
        with self._lock:
            self.session_state["checklist"][item_id] = status
        msg = self._build_msg("CHECKLIST", {"item_id": item_id, "status": status})
        self._broadcast(msg)

    def chat(self, message: str):
        """Send a chat message to all operators."""
        msg = self._build_msg("CHAT", {"message": message, "from": self.operator_name})
        self._broadcast(msg)
        self.console.print(f"[bold cyan][{self.operator_name}][/bold cyan] {message}")

    def get_status(self):
        """Print current session status."""
        clients_count = len(self.clients)
        self.console.print(Panel(
            f"[bold white]👥 Connected Operators:[/bold white] [cyan]{clients_count + 1}[/cyan] (including you)\n"
            f"[bold white]📍 Findings:[/bold white]           [cyan]{len(self.session_state['findings'])}[/cyan]\n"
            f"[bold white]🔑 Valid Creds:[/bold white]        [bold green]{len(self.session_state['valid_creds'])}[/bold green]\n"
            f"[bold white]💥 Cracked:[/bold white]            [cyan]{len(self.session_state['cracked_hashes'])}[/cyan]\n"
            f"[bold white]✅ Checklist:[/bold white]          [cyan]{sum(1 for v in self.session_state['checklist'].values() if v == 'done')}[/cyan] done",
            title="[bold red][ 𓂀 COLLAB STATUS ][/bold red]",
            border_style="cyan", padding=(0, 3)
        ))

        if self.clients:
            t = Table(box=box.SIMPLE)
            t.add_column("Operator", style="cyan")
            t.add_column("IP")
            t.add_column("Connected", style="dim")
            for sock, info in self.clients.items():
                t.add_row(
                    info.get("name", "Unknown"),
                    info.get("ip", ""),
                    info.get("connected_at", "")
                )
            self.console.print(t)

    def stop(self):
        self._running = False
        if self._server_sock:
            self._server_sock.close()
        for sock in list(self.clients.keys()):
            try:
                sock.close()
            except Exception:
                pass
        self.console.print("[bold red]🔴 Collab server stopped[/bold red]")

    # ── PRIVATE ───────────────────────────────────────────────────────────

    def _accept_loop(self):
        while self._running:
            try:
                client_sock, addr = self._server_sock.accept()
                t = threading.Thread(
                    target=self._handle_client,
                    args=(client_sock, addr),
                    daemon=True
                )
                t.start()
            except Exception:
                if self._running:
                    pass

    def _handle_client(self, sock: socket.socket, addr):
        ip = addr[0]
        try:
            # Receive HELLO
            data = self._recv_msg(sock)
            if not data or data.get("type") != "HELLO":
                sock.close()
                return

            # Validate password
            if self.password_hash:
                if data.get("data", {}).get("password_hash") != self.password_hash:
                    self._send_msg(sock, {"type": "ERROR", "data": {"msg": "Bad password"}})
                    sock.close()
                    return

            op_name = data.get("data", {}).get("name", f"Operator-{len(self.clients)+2}")
            color_idx = len(self.clients) % len(TEAM_COLORS)

            with self._lock:
                self.clients[sock] = {
                    "name": op_name,
                    "ip": ip,
                    "color": TEAM_COLORS[color_idx],
                    "connected_at": datetime.now().strftime("%H:%M:%S")
                }

            # Send full state sync
            self._send_msg(sock, self._build_msg("SYNC", self.session_state))

            # Announce
            join_msg = f"[bold green]✅ {op_name} joined from {ip}[/bold green]"
            self.console.print(join_msg)
            self._broadcast(self._build_msg("CHAT", {
                "message": f"{op_name} joined the session",
                "from": "SERVER",
                "type": "system"
            }), exclude=sock)

            # Listen loop
            while self._running:
                msg = self._recv_msg(sock)
                if msg is None:
                    break
                self._handle_message(sock, msg)

        except Exception:
            pass
        finally:
            op_name = self.clients.get(sock, {}).get("name", "Unknown")
            with self._lock:
                self.clients.pop(sock, None)
            self.console.print(f"[yellow]📤 {op_name} disconnected[/yellow]")
            try:
                sock.close()
            except Exception:
                pass

    def _handle_message(self, sender_sock: socket.socket, msg: Dict):
        msg_type = msg.get("type", "")
        data = msg.get("data", {})
        sender_info = self.clients.get(sender_sock, {})
        op_name = sender_info.get("name", "Unknown")
        op_color = sender_info.get("color", "white")

        if msg_type == "CHAT":
            text = data.get("message", "")
            self.console.print(f"[{op_color}][{op_name}][/{op_color}] {text}")
            # Relay to others
            self._broadcast(msg, exclude=sender_sock)

        elif msg_type == "FINDING":
            finding = data.get("finding", {})
            with self._lock:
                self.session_state["findings"].append(finding)
            self.console.print(f"[{op_color}]{op_name}[/{op_color}] found: [yellow]{finding.get('title','')[:50]}[/yellow]")
            self._broadcast(msg, exclude=sender_sock)
            if self.on_event:
                self.on_event("finding", finding)

        elif msg_type == "CRED":
            cred = data.get("cred", {})
            with self._lock:
                self.session_state["valid_creds"].append(cred)
            self.console.print(
                f"[{op_color}]{op_name}[/{op_color}] "
                f"found cred: [bold green]{cred.get('domain','')}\\{cred.get('username','')} : {cred.get('password','')}[/bold green]"
            )
            self._broadcast(msg, exclude=sender_sock)
            if self.on_event:
                self.on_event("cred", cred)

        elif msg_type == "CHECKLIST":
            item_id = data.get("item_id", "")
            status = data.get("status", "")
            with self._lock:
                self.session_state["checklist"][item_id] = status
            self._broadcast(msg, exclude=sender_sock)

        elif msg_type == "PING":
            self._send_msg(sender_sock, {"type": "PING", "data": {}})

    def _broadcast(self, msg: Dict, exclude: Optional[socket.socket] = None):
        dead = []
        for sock in list(self.clients.keys()):
            if sock == exclude:
                continue
            try:
                self._send_msg(sock, msg)
            except Exception:
                dead.append(sock)
        for sock in dead:
            with self._lock:
                self.clients.pop(sock, None)

    def _build_msg(self, msg_type: str, data: Dict) -> Dict:
        return {
            "version": PROTOCOL_VERSION,
            "type": msg_type,
            "from": self.operator_name,
            "ts": datetime.now().isoformat(),
            "data": data
        }

    def _send_msg(self, sock: socket.socket, msg: Dict):
        raw = json.dumps(msg).encode() + b"\n"
        sock.sendall(raw)

    def _recv_msg(self, sock: socket.socket) -> Optional[Dict]:
        try:
            sock.settimeout(60)
            buf = b""
            while b"\n" not in buf:
                chunk = sock.recv(65536)
                if not chunk:
                    return None
                buf += chunk
            return json.loads(buf.split(b"\n")[0])
        except Exception:
            return None

    def _get_local_ip(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def _notify(self, message: str):
        self.console.print(f"[bold red]🔴 BROADCAST:[/bold red] {message}")


class CollabClient:
    """Join an existing collaboration session."""

    def __init__(self, console: Console, operator_name: str = "Operator-2"):
        self.console = console
        self.operator_name = operator_name
        self._sock: Optional[socket.socket] = None
        self._running = False
        self.session_state: Dict = {}
        self.on_event: Optional[Callable] = None

    def connect(self, host: str, port: int = COLLAB_PORT, password: str = "") -> bool:
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.connect((host, port))

            # Send HELLO
            pw_hash = hashlib.sha256(password.encode()).hexdigest() if password else ""
            self._send({
                "type": "HELLO",
                "data": {"name": self.operator_name, "password_hash": pw_hash}
            })

            # Wait for SYNC
            msg = self._recv()
            if msg and msg.get("type") == "SYNC":
                self.session_state = msg.get("data", {})
                self._running = True

                # Start listener
                t = threading.Thread(target=self._listen_loop, daemon=True)
                t.start()

                self.console.print(Panel(
                    f"[bold green]✅ Connected to HorusEye collab session![/bold green]\n\n"
                    f"[bold white]📍 Existing findings:[/bold white] [cyan]{len(self.session_state.get('findings', []))}[/cyan]\n"
                    f"[bold white]🔑 Known creds:[/bold white]       [bold green]{len(self.session_state.get('valid_creds', []))}[/bold green]\n"
                    f"[bold white]🌍 Domain:[/bold white]             [cyan]{self.session_state.get('domain', 'N/A')}[/cyan]",
                    title="[bold red][ 𓂀 COLLAB CLIENT ][/bold red]",
                    border_style="green", padding=(1, 3)
                ))
                return True
            else:
                self.console.print("[bold red]❌ Connection rejected[/bold red]")
                return False

        except ConnectionRefusedError:
            self.console.print(f"[bold red]❌ Cannot connect to {host}:{port} — is the server running?[/bold red]")
            return False
        except Exception as e:
            self.console.print(f"[bold red]❌ Connection error: {e}[/bold red]")
            return False

    def send_finding(self, finding: Dict):
        self._send({"type": "FINDING", "from": self.operator_name,
                    "ts": datetime.now().isoformat(), "data": {"finding": finding}})

    def send_cred(self, cred: Dict):
        self._send({"type": "CRED", "from": self.operator_name,
                    "ts": datetime.now().isoformat(), "data": {"cred": cred}})

    def chat(self, message: str):
        self._send({"type": "CHAT", "from": self.operator_name,
                    "ts": datetime.now().isoformat(), "data": {"message": message, "from": self.operator_name}})
        self.console.print(f"[bold cyan][{self.operator_name}][/bold cyan] {message}")

    def disconnect(self):
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
        self.console.print("[yellow]📤 Disconnected from collab session[/yellow]")

    def _listen_loop(self):
        while self._running:
            try:
                msg = self._recv()
                if msg is None:
                    self.console.print("[yellow]⚠️  Server disconnected[/yellow]")
                    break
                self._handle(msg)
            except Exception:
                if self._running:
                    time.sleep(1)

    def _handle(self, msg: Dict):
        msg_type = msg.get("type", "")
        data = msg.get("data", {})
        sender = msg.get("from", "Server")

        if msg_type == "CHAT":
            text = data.get("message", "")
            if data.get("type") == "system":
                self.console.print(f"[dim][SERVER] {text}[/dim]")
            else:
                self.console.print(f"[bold magenta][{sender}][/bold magenta] {text}")

        elif msg_type == "FINDING":
            finding = data.get("finding", {})
            self.session_state.setdefault("findings", []).append(finding)
            self.console.print(
                f"[bold magenta][{sender}][/bold magenta] "
                f"found: [yellow]{finding.get('title', '')[:60]}[/yellow]"
            )
            if self.on_event:
                self.on_event("finding", finding)

        elif msg_type == "CRED":
            cred = data.get("cred", {})
            self.session_state.setdefault("valid_creds", []).append(cred)
            self.console.print(
                f"[bold red]🔑 [{sender}] CRED: "
                f"{cred.get('domain','')}\\{cred.get('username','')} : {cred.get('password','')}[/bold red]"
            )
            if self.on_event:
                self.on_event("cred", cred)

        elif msg_type == "CRACKED":
            h = data.get("hash", "")
            pt = data.get("plaintext", "")
            self.console.print(f"[bold green]💥 [{sender}] CRACKED: ...{h[-8:]} → {pt}[/bold green]")

        elif msg_type == "ALERT":
            self.console.print(f"\n[bold red on white]🚨 ALERT from {sender}: {data.get('message','')}[/bold red on white]\n")

        elif msg_type == "CHECKLIST":
            item_id = data.get("item_id", "")
            status = data.get("status", "")
            self.session_state.setdefault("checklist", {})[item_id] = status

    def _send(self, msg: Dict):
        if self._sock:
            raw = json.dumps(msg).encode() + b"\n"
            self._sock.sendall(raw)

    def _recv(self) -> Optional[Dict]:
        try:
            self._sock.settimeout(60)
            buf = b""
            while b"\n" not in buf:
                chunk = self._sock.recv(65536)
                if not chunk:
                    return None
                buf += chunk
            return json.loads(buf.split(b"\n")[0])
        except Exception:
            return None
