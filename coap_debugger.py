#!/usr/bin/env python3
"""Standalone Tkinter CoAP/UDP debugging client (Python 3.10+)."""

from __future__ import annotations

import ipaddress
import json
import math
import queue
import secrets
import threading
import time
import tkinter as tk
from dataclasses import asdict, dataclass, field
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk

import aiocoap
from aiocoap.numbers import OptionNumber

from aiocoap_backend import Cancelled, run_exchange
from defaults import (
    CODE_NAMES, DEFAULT_ACK_RANDOM_FACTOR, DEFAULT_ACK_TIMEOUT, DEFAULT_CONTENT_FORMAT,
    DEFAULT_DEVICE_IP, DEFAULT_DEVICE_PORT, DEFAULT_DISPLAY_MODE, DEFAULT_ENCODING,
    DEFAULT_LOCAL_PORT, DEFAULT_MAX_RETRANSMIT, DEFAULT_MESSAGE_LIMIT, DEFAULT_METHOD,
    DEFAULT_MESSAGE_TYPE, DEFAULT_RESPONSE_TIMEOUT, DEFAULT_TOKEN_LENGTH, EXCHANGE_LOG_LIMIT,
    FORMATS, METHODS, OPTIONS, OPTION_CHOICES, RESPONSE_HISTORY_LIMIT, TYPES, OptionSpec,
)


def parse_bytes(text: str, mode: str) -> bytes:
    if mode == "ASCII":
        return text.encode("ascii", errors="strict")
    if mode == "UTF-8":
        return text.encode("utf-8")
    compact = "".join(text.split())
    if mode in ("HEX", "Opaque"):
        if len(compact) % 2 or any(c not in "0123456789abcdefABCDEF" for c in compact):
            raise ValueError("HEX requires pairs of hex digits, separated only by whitespace.")
        return bytes.fromhex(compact)
    if mode == "Binary":
        if len(compact) % 8 or any(c not in "01" for c in compact):
            raise ValueError("Binary requires complete groups of 8 bits (whitespace is allowed).")
        return bytes(int(compact[i:i + 8], 2) for i in range(0, len(compact), 8))
    if mode == "UInt":
        number = int(text.strip(), 0) if text.strip().lower().startswith("0x") else int(text.strip())
        if not 0 <= number <= 0xFFFFFFFF:
            raise ValueError("Unsigned option value must be between 0 and 4294967295.")
        return number.to_bytes((number.bit_length() + 7) // 8, "big")
    if mode == "Empty":
        if text.strip():
            raise ValueError("An Empty option must have no value.")
        return b""
    raise ValueError(f"Unknown encoding: {mode}")


def payload_view(payload: bytes, mode: str) -> str:
    if mode == "HEX":
        return payload.hex(" ")
    if mode == "Binary":
        return " ".join(f"{b:08b}" for b in payload)
    if mode == "ASCII":
        # Preserve arbitrary bytes visibly instead of replacing them with '?'.
        return "".join(chr(b) if 32 <= b < 127 or b in (9, 10, 13)
                       else f"\\x{b:02x}" for b in payload)
    if mode == "UTF-8":
        return payload.decode("utf-8", errors="backslashreplace")
    raise ValueError(f"Unknown display encoding: {mode}")


@dataclass(frozen=True)
class Option:
    number: int
    value: bytes


def validate_options(options: list[Option]) -> None:
    seen: set[int] = set()
    for opt in options:
        if not 1 <= opt.number <= 65535:
            raise ValueError("Option number must be 1 through 65535.")
        if len(opt.value) > 65804:
            raise ValueError("Option value exceeds the wire-format limit.")
        spec = OPTIONS.get(opt.number)
        if spec:
            if not spec.minimum <= len(opt.value) <= spec.maximum:
                raise ValueError(f"{spec.name} requires {spec.minimum}..{spec.maximum} bytes.")
            if opt.number in seen and not spec.repeat:
                raise ValueError(f"{spec.name} cannot be repeated.")
            if spec.kind == "UInt" and opt.value and opt.value[0] == 0:
                raise ValueError(f"{spec.name}: integer options must use shortest encoding (zero is empty).")
            if spec.kind == "UTF-8":
                opt.value.decode("utf-8", errors="strict")
            if opt.number in (23, 27) and int.from_bytes(opt.value, "big") & 7 == 7:
                raise ValueError("Block1/Block2 SZX=7 (BERT) is not valid over UDP.")
            if opt.number == 16 and int.from_bytes(opt.value, "big") == 0:
                raise ValueError("Hop-Limit must be 1 through 255.")
        seen.add(opt.number)
    if 35 in seen and seen.intersection({3, 7, 11, 15, 39}):
        raise ValueError("Proxy-Uri cannot be combined with Uri-Host, Uri-Port, Uri-Path, Uri-Query or Proxy-Scheme.")


@dataclass
class Message:
    """GUI values; serialization and option codecs are owned by aiocoap."""
    type: int
    code: int
    mid: int
    token: bytes = b""
    options: list[Option] = field(default_factory=list)
    payload: bytes = b""

    def to_aiocoap(self) -> aiocoap.Message:
        if not 0 <= self.type <= 3 or not 0 <= self.code <= 255 or not 0 <= self.mid <= 65535:
            raise ValueError("Invalid CoAP header.")
        if len(self.token) > 8:
            raise ValueError("Token must be at most 8 bytes.")
        if self.code == 0 and (self.token or self.options or self.payload):
            raise ValueError("Empty messages cannot contain token, options or payload.")
        validate_options(self.options)
        message = aiocoap.Message(code=self.code, payload=self.payload)
        message.mtype = aiocoap.Type(self.type)
        message.mid = self.mid
        message.token = self.token
        for opt in self.options:
            message.opt.add_option(OptionNumber(opt.number).create_option(decode=opt.value))
        return message

    def encode(self) -> bytes:
        raw = self.to_aiocoap().encode()
        if len(raw) > 65507:
            raise ValueError("Message exceeds the supported UDP datagram limit (65507 bytes).")
        return raw

    @classmethod
    def from_aiocoap(cls, message: aiocoap.Message) -> Message:
        return cls(int(message.mtype), int(message.code), message.mid, message.token,
                   [Option(int(opt.number), opt.encode()) for opt in message.opt.option_list()],
                   message.payload)

    @classmethod
    def decode(cls, raw: bytes) -> Message:
        if len(raw) < 4:
            raise ValueError("Truncated CoAP header.")
        tkl = raw[0] & 15
        if raw[0] >> 6 != 1 or tkl > 8 or len(raw) < 4 + tkl:
            raise ValueError("Unsupported CoAP version, invalid token length or truncated token.")
        if raw[1] == 0:
            if len(raw) != 4:
                raise ValueError("Empty CoAP message contains extra bytes.")
        try:
            native = aiocoap.Message.decode(raw)
        except (aiocoap.error.UnparsableMessage, ValueError, IndexError) as exc:
            raise ValueError(f"Malformed CoAP message: {exc}") from exc
        message = cls.from_aiocoap(native)
        if any(not 1 <= opt.number <= 65535 for opt in message.options):
            raise ValueError("Invalid option number.")
        if not message.payload and raw[-1] == 0xFF:
            canonical = native.copy()
            canonical.direction = aiocoap.message.Direction.OUTGOING
            if raw == canonical.encode() + b"\xff":
                raise ValueError("Payload marker without payload.")
        return message


def describe_option(opt: Option) -> str:
    spec = OPTIONS.get(opt.number)
    name = spec.name if spec else "Unknown"
    if spec and spec.kind == "UInt":
        value = int.from_bytes(opt.value, "big")
        text = str(value)
        if opt.number in (19, 23, 27, 31):
            text += f" (NUM={value >> 4}, M={(value >> 3) & 1}, SZX={value & 7})"
        if opt.number in (12, 17):
            text += next((f" ({f.split(' - ', 1)[1]})" for f in FORMATS[1:]
                          if f.startswith(f"{value} - ")), "")
    elif spec and spec.kind == "UTF-8":
        text = repr(opt.value.decode("utf-8", errors="backslashreplace"))
    elif spec and spec.kind == "Empty":
        text = "(present)"
    else:
        text = opt.value.hex(" ") or "(empty)"
    return f"{opt.number} {name}: {text} [{len(opt.value)} bytes]"


def summarize(message: Message, raw: bytes) -> str:
    code = f"{message.code >> 5}.{message.code & 31:02d}"
    lines = [
        f"CoAP v1 | {TYPES[message.type]} | {code} {CODE_NAMES.get(message.code, 'Unknown code')}",
        f"MID: {message.mid} (0x{message.mid:04x}) | Token: {message.token.hex(' ') or '(empty)'}",
        f"Datagram: {len(raw)} bytes | Payload: {len(message.payload)} bytes",
    ]
    lines.extend(describe_option(opt) for opt in sorted(message.options, key=lambda opt: opt.number))
    if not any(opt.number == 12 for opt in message.options) and message.payload:
        lines.append("Content-Format absent: representation type is unspecified.")
    lines.extend(("", "Raw datagram (HEX):", raw.hex(" ")))
    return "\n".join(lines)


@dataclass(frozen=True)
class Settings:
    ack_timeout: float = DEFAULT_ACK_TIMEOUT
    ack_random_factor: float = DEFAULT_ACK_RANDOM_FACTOR
    max_retransmit: int = DEFAULT_MAX_RETRANSMIT
    response_timeout: float = DEFAULT_RESPONSE_TIMEOUT
    message_limit: int = DEFAULT_MESSAGE_LIMIT
    local_port: int = DEFAULT_LOCAL_PORT
    token_length: int = DEFAULT_TOKEN_LENGTH

    def validate(self) -> None:
        for name in ("ack_timeout", "ack_random_factor", "response_timeout"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (float, int)) or not math.isfinite(value):
                raise ValueError(f"{name} must be a finite number.")
        if self.ack_timeout <= 0 or self.ack_random_factor < 1 or self.response_timeout <= 0:
            raise ValueError("Timeouts must be positive; ACK_RANDOM_FACTOR must be >= 1.")
        for name, low, high in (("max_retransmit", 0, 10), ("message_limit", 4, 65507),
                                ("local_port", 0, 65535), ("token_length", 0, 8)):
            value = getattr(self, name)
            if type(value) is not int or not low <= value <= high:
                raise ValueError(f"{name} must be an integer in {low}..{high}.")
        if not math.isfinite(self.ack_timeout * self.ack_random_factor
                             * (2 ** (self.max_retransmit + 1) - 1)):
            raise ValueError("Combined retry settings overflow the supported timer range.")


def exchange(ip: str, port: int, request: Message, settings: Settings,
             cancel: threading.Event, emit) -> None:
    """One outstanding exchange; emit(kind, value) is never a Tk callback."""
    settings.validate()
    ipaddress.ip_address(ip)
    if not 1 <= port <= 65535:
        raise ValueError("Destination port must be 1 through 65535.")
    raw = request.encode()
    if len(raw) > settings.message_limit:
        raise ValueError(f"{len(raw)}-byte datagram exceeds Settings limit {settings.message_limit}.")
    if request.type not in (0, 1) or request.code not in METHODS.values():
        raise ValueError("Send a CON/NON request or CON Empty ping.")
    if request.code == 0 and request.type != 0:
        raise ValueError("Empty ping must be CON.")
    if any(opt.number == 6 for opt in request.options):
        if request.code != 1 or any(int.from_bytes(opt.value, "big") not in (0, 1)
                                    for opt in request.options if opt.number == 6):
            raise ValueError("Observe requires GET and value 0 or 1.")

    def deliver(kind, value):
        if kind == "response":
            native, raw_response = value
            emit(kind, (Message.from_aiocoap(native), raw_response))
        else:
            emit(kind, value)

    run_exchange(ip, port, request.to_aiocoap(), settings, cancel, deliver,
                 lambda data: Message.decode(data).to_aiocoap())


class App:
    def __init__(self, root: tk.Tk, settings_path: Path | None = None):
        self.root = root
        self.settings_path = settings_path or Path.home() / ".coap-debugger.json"
        self.settings = Settings()
        self.options: list[Option] = []
        self.events: queue.Queue = queue.Queue()
        self.cancel = threading.Event()
        self.worker: threading.Thread | None = None
        self.preview: tuple[str, int, Message, bytes] | None = None
        self.responses: list[tuple[Message, bytes]] = []
        self.next_mid = secrets.randbelow(65536)
        self.closing = False
        root.title("CoAP Debugger - UDP device inspector")
        root.geometry("1000x820")
        root.minsize(800, 650)
        self.ip = tk.StringVar(value=DEFAULT_DEVICE_IP)
        self.port = tk.StringVar(value=str(DEFAULT_DEVICE_PORT))
        self.method = tk.StringVar(value=DEFAULT_METHOD)
        self.msg_type = tk.StringVar(value=DEFAULT_MESSAGE_TYPE)
        self.mid = tk.StringVar()
        self.token = tk.StringVar()
        self.encoding = tk.StringVar(value=DEFAULT_ENCODING)
        self.content_format = tk.StringVar(value=DEFAULT_CONTENT_FORMAT)
        self.display_mode = tk.StringVar(value=DEFAULT_DISPLAY_MODE)
        self.status = tk.StringVar(value="Ready. Add Uri-Path segments or use Set resource.")
        self._build()
        self._load_settings()
        root.protocol("WM_DELETE_WINDOW", self._close)
        self._poll_id = root.after(50, self._poll)

    @staticmethod
    def _text_set(widget, value: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", value)
        widget.configure(state="disabled")

    def _build(self) -> None:
        menu = tk.Menu(self.root)
        settings_menu = tk.Menu(menu, tearoff=False)
        settings_menu.add_command(label="Transmission settings...", command=self._settings_dialog)
        settings_menu.add_command(label="Restore defaults", command=self._restore_settings)
        menu.add_cascade(label="Settings", menu=settings_menu)
        help_menu = tk.Menu(menu, tearoff=False)
        help_menu.add_command(label="Quick help", command=self._help)
        menu.add_cascade(label="Help", menu=help_menu)
        self.root.configure(menu=menu)
        main = ttk.Frame(self.root, padding=10)
        main.pack(fill="both", expand=True)
        endpoint = ttk.LabelFrame(main, text="Destination & message", padding=8)
        endpoint.pack(fill="x")
        fields = (("IP", self.ip, 22), ("Port", self.port, 7),
                  ("Message ID", self.mid, 9), ("Token (HEX)", self.token, 20))
        for col, (label, variable, width) in enumerate(fields):
            ttk.Label(endpoint, text=label).grid(row=0, column=col * 2, sticky="w", padx=3)
            ttk.Entry(endpoint, textvariable=variable, width=width).grid(row=0, column=col * 2 + 1, padx=3)
        ttk.Label(endpoint, text="Method").grid(row=1, column=0, sticky="w", padx=3, pady=6)
        ttk.Combobox(endpoint, textvariable=self.method, values=tuple(METHODS),
                     state="readonly", width=18).grid(row=1, column=1, sticky="w")
        ttk.Label(endpoint, text="Type").grid(row=1, column=2, sticky="w")
        ttk.Combobox(endpoint, textvariable=self.msg_type, values=TYPES[:2],
                     state="readonly", width=6).grid(row=1, column=3, sticky="w")
        ttk.Label(endpoint, text="Blank MID/token = automatic. Token 'empty' = zero bytes.",
                  wraplength=430).grid(row=1, column=4, columnspan=4, sticky="w")

        self.tabs = ttk.Notebook(main)
        self.tabs.pack(fill="both", expand=True, pady=8)
        compose = ttk.Frame(self.tabs, padding=8)
        preview_tab = ttk.Frame(self.tabs, padding=8)
        response_tab = ttk.Frame(self.tabs, padding=8)
        log_tab = ttk.Frame(self.tabs, padding=8)
        self.tabs.add(compose, text="Compose")
        self.tabs.add(preview_tab, text="Message summary")
        self.tabs.add(response_tab, text="Responses")
        self.tabs.add(log_tab, text="Exchange log")
        self.summary = scrolledtext.ScrolledText(preview_tab, wrap="word", state="disabled")
        self.summary.pack(fill="both", expand=True)
        self.log = scrolledtext.ScrolledText(log_tab, wrap="word", state="disabled")
        self.log.pack(fill="both", expand=True)
        opt_frame = ttk.LabelFrame(compose, text="Options - repeats become separate rows; sorted on wire", padding=6)
        opt_frame.pack(fill="both", expand=True)
        self.option_table = ttk.Treeview(opt_frame, columns=("number", "name", "value"),
                                         show="headings", height=7, selectmode="browse")
        for name, width in (("number", 70), ("name", 160), ("value", 550)):
            self.option_table.heading(name, text=name.title())
            self.option_table.column(name, width=width, stretch=name == "value")
        scrollbar = ttk.Scrollbar(opt_frame, orient="vertical", command=self.option_table.yview)
        self.option_table.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.option_table.pack(fill="both", expand=True)
        self.option_table.bind("<Double-1>", lambda _: self._option_dialog(edit=True))
        buttons = ttk.Frame(compose)
        buttons.pack(fill="x", pady=4)
        for label, command in (("Add option...", self._option_dialog),
                               ("Edit...", lambda: self._option_dialog(edit=True)),
                               ("Remove", self._remove_option), ("Set resource...", self._resource_dialog)):
            ttk.Button(buttons, text=label, command=command).pack(side="left", padx=3)
        payload_frame = ttk.LabelFrame(compose, text="Payload - byte encoding is independent of Content-Format", padding=6)
        payload_frame.pack(fill="both", expand=True, pady=4)
        selectors = ttk.Frame(payload_frame)
        selectors.pack(fill="x")
        ttk.Label(selectors, text="Input encoding").pack(side="left")
        ttk.Combobox(selectors, textvariable=self.encoding, values=("ASCII", "HEX", "Binary"),
                     width=9, state="readonly").pack(side="left", padx=5)
        ttk.Label(selectors, text="Content-Format").pack(side="left", padx=5)
        ttk.Combobox(selectors, textvariable=self.content_format, values=FORMATS,
                     width=35).pack(side="left", padx=5)
        ttk.Button(selectors, text="Load bytes...", command=self._load_payload).pack(side="right")
        self.payload_input = scrolledtext.ScrolledText(payload_frame, height=6, wrap="word")
        self.payload_input.pack(fill="both", expand=True, pady=5)
        ttk.Label(payload_frame, text="ASCII is literal text (no escape expansion). HEX: 41 00 ff. Binary: 01000001 00000000. "
                  "Custom Content-Format: enter its numeric ID.", wraplength=850).pack(anchor="w")

        response_controls = ttk.Frame(response_tab)
        response_controls.pack(fill="x")
        self.response_selector = ttk.Combobox(response_controls, state="readonly", width=48)
        self.response_selector.pack(side="left", padx=3)
        self.response_selector.bind("<<ComboboxSelected>>", lambda _: self._show_response())
        ttk.Combobox(response_controls, textvariable=self.display_mode,
                     values=("ASCII", "HEX", "Binary", "UTF-8"), state="readonly",
                     width=9).pack(side="left", padx=3)
        self.display_mode.trace_add("write", lambda *_: self._show_response())
        ttk.Button(response_controls, text="Save payload...", command=self._save_payload).pack(side="right")
        self.response_summary = scrolledtext.ScrolledText(response_tab, height=12, wrap="word", state="disabled")
        self.response_summary.pack(fill="both", expand=True, pady=6)
        ttk.Label(response_tab, text="Decoded payload (non-printable ASCII bytes shown as \\xNN)").pack(anchor="w")
        self.response_payload = scrolledtext.ScrolledText(response_tab, height=10, wrap="word", state="disabled")
        self.response_payload.pack(fill="both", expand=True, pady=5)
        actions = ttk.Frame(main)
        actions.pack(fill="x")
        self.send_button = ttk.Button(actions, text="Send message", command=self._send)
        self.send_button.pack(side="left", padx=3)
        ttk.Button(actions, text="Summarize", command=self._summarize).pack(side="left", padx=3)
        self.cancel_button = ttk.Button(actions, text="Cancel / stop observing",
                                        command=lambda: self.cancel.set(), state="disabled")
        self.cancel_button.pack(side="left", padx=3)
        ttk.Button(actions, text="Clear results", command=self._clear_results).pack(side="right")
        ttk.Label(main, textvariable=self.status, wraplength=950).pack(fill="x", pady=(8, 0))

    def _error(self, exc) -> None:
        self.status.set(str(exc))
        messagebox.showerror("CoAP Debugger", str(exc), parent=self.root)

    def _log(self, text: str) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", f"{time.strftime('%H:%M:%S')} {text}\n")
        if self.log.count("1.0", "end-1c", "chars")[0] > EXCHANGE_LOG_LIMIT:
            self.log.delete("1.0", "end-2000001c")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _refresh_options(self) -> None:
        self.option_table.delete(*self.option_table.get_children())
        for index, opt in enumerate(self.options):
            spec = OPTIONS.get(opt.number)
            self.option_table.insert("", "end", iid=str(index),
                                     values=(opt.number, spec.name if spec else "Custom",
                                             describe_option(opt).split(": ", 1)[1]))

    def _selected_option(self) -> int | None:
        selection = self.option_table.selection()
        return int(selection[0]) if selection else None

    def _remove_option(self) -> None:
        index = self._selected_option()
        if index is not None:
            del self.options[index]
            self._refresh_options()

    def _option_dialog(self, edit: bool = False) -> None:
        index = self._selected_option() if edit else None
        if edit and index is None:
            self._error("Select an option to edit.")
            return
        current = self.options[index] if index is not None else None
        dialog = tk.Toplevel(self.root)
        dialog.title("Edit option" if edit else "Add option")
        dialog.transient(self.root)
        dialog.grab_set()
        frame = ttk.Frame(dialog, padding=12)
        frame.pack(fill="both", expand=True)
        number = tk.StringVar(value=f"{current.number} - {OPTIONS[current.number].name}"
                              if current and current.number in OPTIONS else str(current.number) if current else "11 - Uri-Path")
        kind = tk.StringVar(value=OPTIONS[current.number].kind if current and current.number in OPTIONS else "UTF-8")
        hint = tk.StringVar()
        ttk.Label(frame, text="Option name or numeric ID (custom options supported)").pack(anchor="w")
        combo = ttk.Combobox(frame, textvariable=number, values=OPTION_CHOICES, width=52)
        combo.pack(fill="x", pady=4)
        ttk.Label(frame, textvariable=hint, wraplength=470).pack(anchor="w", pady=4)
        ttk.Combobox(frame, textvariable=kind, values=("UTF-8", "UInt", "Opaque", "ASCII", "HEX", "Binary", "Empty"),
                     state="readonly").pack(anchor="w", pady=4)
        value = scrolledtext.ScrolledText(frame, width=60, height=5)
        value.pack(fill="both", expand=True)
        ttk.Label(frame, text="Opaque = HEX bytes; UInt = decimal or 0x-prefixed integer. "
                  "Encoding is validated against the selected standard option.", wraplength=470).pack(anchor="w", pady=4)

        def choose(*_) -> None:
            try:
                n = int(number.get().split(" - ", 1)[0])
            except ValueError:
                hint.set("Enter a numeric option ID.")
                return
            spec = OPTIONS.get(n)
            if spec:
                kind.set(spec.kind)
                hint.set(f"{spec.kind}, {spec.minimum}..{spec.maximum} bytes; "
                         f"{'repeatable' if spec.repeat else 'once only'}. {spec.hint}")
            else:
                hint.set("Custom option: choose encoding. Unknown critical options may be rejected by the server.")

        combo.bind("<<ComboboxSelected>>", choose)
        number.trace_add("write", choose)
        choose()
        if current:
            spec = OPTIONS.get(current.number)
            initial = (str(int.from_bytes(current.value, "big")) if spec and spec.kind == "UInt"
                       else current.value.decode("utf-8") if spec and spec.kind == "UTF-8"
                       else "" if spec and spec.kind == "Empty" else current.value.hex(" "))
            if not spec:
                kind.set("Opaque")
            value.insert("1.0", initial)

        def save() -> None:
            try:
                opt = Option(int(number.get().split(" - ", 1)[0]),
                             parse_bytes(value.get("1.0", "end-1c"), kind.get()))
                proposed = list(self.options)
                if index is None:
                    proposed.append(opt)
                else:
                    proposed[index] = opt
                validate_options(proposed)
                self.options = proposed
                self._refresh_options()
                dialog.destroy()
            except (ValueError, UnicodeError) as exc:
                messagebox.showerror("Invalid option", str(exc), parent=dialog)

        ttk.Button(frame, text="Save option", command=save).pack(pady=6)

    def _resource_dialog(self) -> None:
        dialog = tk.Toplevel(self.root)
        dialog.title("Set resource")
        dialog.transient(self.root)
        dialog.grab_set()
        frame = ttk.Frame(dialog, padding=12)
        frame.pack()
        ttk.Label(frame, text="Resource, e.g. /my-endpoint or /.well-known/core?rt=sensor",
                  wraplength=500).pack(anchor="w")
        entry = ttk.Entry(frame, width=65)
        entry.pack(pady=8)
        entry.insert(0, "/my-endpoint")
        ttk.Label(frame, text="Replaces Uri-Path / Uri-Query rows. Percent escapes are decoded; "
                  "path segment and query order is preserved.", wraplength=500).pack(anchor="w")

        def save() -> None:
            try:
                self.options = resource_options(entry.get(), self.options)
                self._refresh_options()
                dialog.destroy()
            except (ValueError, UnicodeError) as exc:
                messagebox.showerror("Invalid resource", str(exc), parent=dialog)

        ttk.Button(frame, text="Set resource", command=save).pack(pady=8)

    def _load_payload(self) -> None:
        path = filedialog.askopenfilename(parent=self.root, title="Load payload bytes")
        if not path:
            return
        try:
            data = Path(path).read_bytes()
            self.encoding.set("HEX")
            self.payload_input.delete("1.0", "end")
            self.payload_input.insert("1.0", data.hex(" "))
        except OSError as exc:
            self._error(exc)

    def _build_request(self) -> tuple[str, int, Message, bytes]:
        ip = self.ip.get().strip()
        ipaddress.ip_address(ip)
        port = int(self.port.get())
        if not 1 <= port <= 65535:
            raise ValueError("Port must be 1 through 65535.")
        mid_text = self.mid.get().strip()
        mid = (int(mid_text, 16) if mid_text.lower().startswith("0x") else int(mid_text)) if mid_text else self.next_mid
        token_text = self.token.get().strip()
        token = b"" if token_text == "empty" else parse_bytes(token_text, "HEX") if token_text else secrets.token_bytes(self.settings.token_length)
        payload = parse_bytes(self.payload_input.get("1.0", "end-1c"), self.encoding.get())
        options = list(self.options)
        content = self.content_format.get().strip()
        if content and content != FORMATS[0]:
            number = int(content.split(" - ", 1)[0])
            if not 0 <= number <= 65535:
                raise ValueError("Content-Format ID must be 0 through 65535.")
            options.append(Option(12, parse_bytes(str(number), "UInt")))
        code = METHODS[self.method.get()]
        if code == 0:
            if self.msg_type.get() != "CON" or payload or options or token_text not in ("", "empty"):
                raise ValueError("Empty ping needs CON, no options/payload and blank or empty token.")
            token = b""
        if any(o.number == 6 for o in options):
            if code != 1 or any(int.from_bytes(o.value, "big") not in (0, 1) for o in options if o.number == 6):
                raise ValueError("Observe request needs GET and value 0 (register) or 1 (deregister).")
        request = Message(TYPES.index(self.msg_type.get()), code, mid, token, options, payload)
        raw = request.encode()
        if len(raw) > self.settings.message_limit:
            raise ValueError(f"Message is {len(raw)} bytes; limit is {self.settings.message_limit} in Settings. "
                             "ProsecCoAP defaults to 128 bytes.")
        return ip, port, request, raw

    def _request_fingerprint(self) -> tuple:
        return (self.ip.get(), self.port.get(), self.method.get(), self.msg_type.get(),
                self.mid.get(), self.token.get(), self.encoding.get(), self.content_format.get(),
                self.payload_input.get("1.0", "end-1c"), tuple(self.options), self.settings)

    def _render_preview(self, prepared) -> None:
        ip, port, request, raw = prepared
        retransmission_note = (f"ACK_TIMEOUT={self.settings.ack_timeout}s, "
                               f"ACK_RANDOM_FACTOR={self.settings.ack_random_factor}, "
                               f"MAX_RETRANSMIT={self.settings.max_retransmit}"
                               if request.type == 0 else "NON: no retransmissions")
        self._text_set(self.summary, f"Destination: {ip}:{port} (UDP, no encryption)\n"
                       f"{retransmission_note}\nResponse/Observe idle timeout: {self.settings.response_timeout}s\n\n"
                       + summarize(request, raw) + "\n\nPayload (ASCII):\n"
                       + payload_view(request.payload, "ASCII"))

    def _summarize(self) -> None:
        try:
            prepared = self._build_request()
            self.preview = prepared
            self.preview_fingerprint = self._request_fingerprint()
            self._render_preview(prepared)
            self.tabs.select(1)
            self.status.set("Summary ready. Unchanged fields send exactly this MID, token and datagram.")
        except (ValueError, UnicodeError) as exc:
            self._error(exc)

    def _send(self) -> None:
        if self.worker and self.worker.is_alive():
            return
        try:
            prepared = (self.preview if self.preview is not None
                        and self.preview_fingerprint == self._request_fingerprint()
                        else self._build_request())
            self._render_preview(prepared)
        except (ValueError, UnicodeError) as exc:
            self._error(exc)
            return
        ip, port, request, _ = prepared
        self.next_mid = (request.mid + 1) & 65535
        self.preview = None
        self.cancel = threading.Event()
        self.send_button.configure(state="disabled")
        self.cancel_button.configure(state="normal")
        self.status.set(f"Sending {self.method.get()} to {ip}:{port}...")
        self.tabs.select(3)
        settings = self.settings

        def run() -> None:
            try:
                exchange(ip, port, request, settings, self.cancel,
                         lambda kind, value: self.events.put((kind, value)))
                self.events.put(("done", "Exchange complete."))
            except Cancelled as exc:
                self.events.put(("done", str(exc)))
            except (OSError, ValueError) as exc:
                self.events.put(("error", str(exc)))
            finally:
                self.events.put(("idle", None))

        self.worker = threading.Thread(target=run, daemon=True, name="coap-exchange")
        self.worker.start()

    def _poll(self) -> None:
        self._poll_id = None
        try:
            while True:
                kind, value = self.events.get_nowait()
                if kind == "log":
                    self._log(value)
                elif kind == "response":
                    self.responses.append(value)
                    # Bounded history prevents unbounded growth for long observations.
                    if len(self.responses) > RESPONSE_HISTORY_LIMIT:
                        self.responses.pop(0)
                    labels = tuple(f"{i + 1}: {TYPES[msg.type]} {msg.code >> 5}.{msg.code & 31:02d} "
                                   f"{CODE_NAMES.get(msg.code, '')} | MID {msg.mid} | {len(msg.payload)} payload bytes"
                                   for i, (msg, _) in enumerate(self.responses))
                    self.response_selector.configure(values=labels)
                    self.response_selector.current(len(labels) - 1)
                    self._show_response()
                    self.tabs.select(2)
                elif kind in ("done", "error"):
                    self.status.set(value)
                    self._log(value)
                    if kind == "error" and not self.closing:
                        messagebox.showerror("Exchange failed", value, parent=self.root)
                elif kind == "idle":
                    self.send_button.configure(state="normal")
                    self.cancel_button.configure(state="disabled")
        except queue.Empty:
            pass
        if self.closing and not (self.worker and self.worker.is_alive()):
            self.root.destroy()
        else:
            self._poll_id = self.root.after(50, self._poll)

    def _show_response(self) -> None:
        index = self.response_selector.current()
        if 0 <= index < len(self.responses):
            message, raw = self.responses[index]
            self._text_set(self.response_summary, summarize(message, raw))
            self._text_set(self.response_payload, payload_view(message.payload, self.display_mode.get()))

    def _save_payload(self) -> None:
        index = self.response_selector.current()
        if not 0 <= index < len(self.responses):
            self._error("No response selected.")
            return
        path = filedialog.asksaveasfilename(parent=self.root, title="Save exact response payload bytes")
        if path:
            try:
                Path(path).write_bytes(self.responses[index][0].payload)
            except OSError as exc:
                self._error(exc)

    def _clear_results(self) -> None:
        self.responses.clear()
        self.response_selector.set("")
        self.response_selector.configure(values=())
        for widget in (self.response_summary, self.response_payload, self.log):
            self._text_set(widget, "")

    def _load_settings(self) -> None:
        if not self.settings_path.exists():
            return
        try:
            values = json.loads(self.settings_path.read_text(encoding="utf-8"))
            if not isinstance(values, dict) or set(values) != set(asdict(Settings())):
                raise ValueError("Settings file has missing or unknown fields.")
            proposed = Settings(**values)
            proposed.validate()
            self.settings = proposed
        except (OSError, ValueError, TypeError) as exc:
            self._error(f"Could not load {self.settings_path}: {exc}. Defaults are active; file was not overwritten.")

    def _save_settings(self, proposed: Settings) -> None:
        proposed.validate()
        # Replace atomically; avoid corrupting previously saved settings on a failed write.
        temporary = self.settings_path.with_suffix(".tmp")
        try:
            temporary.write_text(json.dumps(asdict(proposed), indent=2) + "\n", encoding="utf-8")
            temporary.replace(self.settings_path)
        except OSError:
            if temporary.exists():
                temporary.unlink()
            raise
        self.settings = proposed
        self.preview = None
        self.status.set(f"Settings saved to {self.settings_path}. Apply to the next exchange.")

    def _restore_settings(self) -> None:
        if messagebox.askyesno("Restore settings", "Restore and save all default transmission settings?", parent=self.root):
            try:
                self._save_settings(Settings())
            except (OSError, ValueError) as exc:
                self._error(exc)

    def _settings_dialog(self) -> None:
        dialog = tk.Toplevel(self.root)
        dialog.title("Transmission settings")
        dialog.transient(self.root)
        dialog.grab_set()
        frame = ttk.Frame(dialog, padding=12)
        frame.pack()
        labels = {
            "ack_timeout": "ACK_TIMEOUT (seconds, default 2)",
            "ack_random_factor": "ACK_RANDOM_FACTOR (default 1.5)",
            "max_retransmit": "MAX_RETRANSMIT (default 4, excludes initial send)",
            "response_timeout": "Separate response / NON / Observe idle timeout (seconds)",
            "message_limit": "Outgoing datagram limit (ProsecCoAP default: 128 bytes)",
            "local_port": "Local UDP port (0 = OS-selected ephemeral port)",
            "token_length": "Automatic token length (0..8 bytes, default 4)",
        }
        variables = {}
        for row, (key, label) in enumerate(labels.items()):
            ttk.Label(frame, text=label).grid(row=row, column=0, sticky="w", padx=4, pady=4)
            variable = tk.StringVar(value=str(getattr(self.settings, key)))
            variables[key] = variable
            ttk.Entry(frame, textvariable=variable, width=12).grid(row=row, column=1, padx=4, pady=4)
        ttk.Label(frame, text="CON: random initial timeout in [ACK_TIMEOUT, ACK_TIMEOUT x factor], "
                  "then doubled after every retry. An empty ACK stops retries. NON never retries.\n"
                  "One exchange at a time (NSTART=1). Changing defaults may reduce congestion safety.\n"
                  "These settings apply to the next send; device buffer limits must be changed on the device too.",
                  wraplength=590).grid(row=len(labels), column=0, columnspan=2, pady=8)

        def save() -> None:
            try:
                values = {key: (float(var.get()) if key in ("ack_timeout", "ack_random_factor", "response_timeout")
                                else int(var.get())) for key, var in variables.items()}
                self._save_settings(Settings(**values))
                dialog.destroy()
            except (ValueError, OSError) as exc:
                messagebox.showerror("Invalid settings", str(exc), parent=dialog)

        ttk.Button(frame, text="Save settings", command=save).grid(row=len(labels) + 1, column=0, columnspan=2, pady=4)

    def _close(self) -> None:
        self.closing = True
        self.cancel.set()
        self.status.set("Closing; stopping the exchange...")
        if not (self.worker and self.worker.is_alive()):
            if self._poll_id is not None:
                self.root.after_cancel(self._poll_id)
                self._poll_id = None
            self.root.destroy()

    def _help(self) -> None:
        messagebox.showinfo(
            "Quick help",
            "1. Set device IP and UDP port (5683).\n"
            "2. Set resource, e.g. /my-endpoint or /.well-known/core.\n"
            "3. Select method, CON/NON, optional payload and Content-Format.\n"
            "4. Add protocol options, summarize, then send.\n"
            "5. Inspect response header/options/raw datagram and switch payload view.\n\n"
            "ProsecCoAP: default buffer is 128 bytes. Use CON for its examples.\n"
            "ASCII/HEX/Binary describe bytes; Content-Format describes their meaning.\n"
            "Observe GET 0 listens until Cancel or idle timeout. Blocks are manual.\n"
            "No DTLS, TCP, automatic block assembly, OSCORE encryption or EDHOC.\n"
            "UDP is unencrypted; use only networks/devices you are authorized to test.",
            parent=self.root,
        )


def resource_options(resource: str, existing: list[Option]) -> list[Option]:
    from urllib.parse import unquote_to_bytes
    import re

    resource = resource.strip()
    if "://" in resource or "#" in resource:
        raise ValueError("Enter a resource path/query, not a full URL or fragment.")
    if re.search(r"%(?![0-9a-fA-F]{2})", resource):
        raise ValueError("Malformed percent escape in resource.")
    path, separator, query = resource.partition("?")
    # Remove only the leading URI separator: interior and trailing empty segments matter.
    path = path[1:] if path.startswith("/") else path
    proposed = [o for o in existing if o.number not in (11, 15)]
    if path:
        proposed.extend(Option(11, unquote_to_bytes(segment)) for segment in path.split("/"))
    if separator:
        proposed.extend(Option(15, unquote_to_bytes(part)) for part in query.split("&"))
    validate_options(proposed)
    return proposed


def main() -> None:
    try:
        root = tk.Tk()
    except tk.TclError as exc:
        raise SystemExit(f"Cannot start the GUI: {exc}\nInstall Tk and run in a desktop session.") from exc
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()