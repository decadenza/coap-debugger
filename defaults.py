"""Default CoAP settings and protocol metadata for the debugger."""

from __future__ import annotations

from dataclasses import dataclass


DEFAULT_ACK_TIMEOUT = 2.0
DEFAULT_ACK_RANDOM_FACTOR = 1.5
DEFAULT_MAX_RETRANSMIT = 4
DEFAULT_RESPONSE_TIMEOUT = 60.0
DEFAULT_MESSAGE_LIMIT = 128
DEFAULT_LOCAL_PORT = 0
DEFAULT_TOKEN_LENGTH = 4

DEFAULT_DEVICE_IP = "192.168.0.100"
DEFAULT_DEVICE_PORT = 5683
DEFAULT_METHOD = "GET"
DEFAULT_MESSAGE_TYPE = "CON"
DEFAULT_ENCODING = "ASCII"
DEFAULT_DISPLAY_MODE = "ASCII"

RESPONSE_HISTORY_LIMIT = 100
EXCHANGE_LOG_LIMIT = 2_000_000

TYPES = ("CON", "NON", "ACK", "RST")
METHODS = {"GET": 1, "POST": 2, "PUT": 3, "DELETE": 4, "FETCH": 5,
           "PATCH": 6, "iPATCH": 7, "Empty ping": 0}
CODE_NAMES = {
    0: "Empty", **{v: k for k, v in METHODS.items() if v},
    65: "Created", 66: "Deleted", 67: "Valid", 68: "Changed",
    69: "Content", 95: "Continue", 128: "Bad Request", 129: "Unauthorized",
    130: "Bad Option", 131: "Forbidden", 132: "Not Found",
    133: "Method Not Allowed", 134: "Not Acceptable",
    136: "Request Entity Incomplete", 137: "Conflict",
    140: "Precondition Failed", 141: "Request Entity Too Large",
    143: "Unsupported Content-Format", 157: "Too Many Requests",
    160: "Internal Server Error", 161: "Not Implemented",
    162: "Bad Gateway", 163: "Service Unavailable", 164: "Gateway Timeout",
    165: "Proxying Not Supported", 168: "Hop Limit Reached",
}
FORMATS = (
    "None (omit Content-Format)", "0 - text/plain; charset=utf-8",
    "40 - application/link-format", "41 - application/xml",
    "42 - application/octet-stream", "47 - application/exi",
    "50 - application/json", "60 - application/cbor",
    "110 - application/senml+json", "112 - application/senml+cbor",
)
DEFAULT_CONTENT_FORMAT = FORMATS[0]


@dataclass(frozen=True)
class OptionSpec:
    name: str
    kind: str
    minimum: int
    maximum: int
    repeat: bool = False
    hint: str = ""


# The complete RFC 7252 option set, plus common standardized UDP extensions.
# Unknown/new registry entries remain usable through the numeric option editor.
OPTIONS = {
    1: OptionSpec("If-Match", "Opaque", 0, 8, True, "ETag bytes; empty matches any existing resource."),
    3: OptionSpec("Uri-Host", "UTF-8", 1, 255, hint="Logical host, not the UDP destination IP."),
    4: OptionSpec("ETag", "Opaque", 1, 8, True, "Representation identifier bytes."),
    5: OptionSpec("If-None-Match", "Empty", 0, 0, hint="Presence only; no value."),
    6: OptionSpec("Observe", "UInt", 0, 3, hint="GET: 0 register, 1 deregister."),
    7: OptionSpec("Uri-Port", "UInt", 0, 2, hint="Logical URI port; destination port is set above."),
    8: OptionSpec("Location-Path", "UTF-8", 0, 255, True, "One location path segment per row."),
    9: OptionSpec("OSCORE", "Opaque", 0, 255, hint="Raw option only; no OSCORE cryptography."),
    11: OptionSpec("Uri-Path", "UTF-8", 0, 255, True, "One segment per row; omit slash separators."),
    12: OptionSpec("Content-Format", "UInt", 0, 2, hint="Use payload Content-Format selector, or omit it there."),
    14: OptionSpec("Max-Age", "UInt", 0, 4, hint="Seconds; absent response option implies 60."),
    15: OptionSpec("Uri-Query", "UTF-8", 0, 255, True, "One query component per row, without &."),
    16: OptionSpec("Hop-Limit", "UInt", 1, 1, hint="Proxy hop budget, 1 through 255."),
    17: OptionSpec("Accept", "UInt", 0, 2, hint="Desired response Content-Format number."),
    19: OptionSpec("Q-Block1", "UInt", 0, 3, hint="Manual block field: (NUM << 4) | (M << 3) | SZX."),
    20: OptionSpec("Location-Query", "UTF-8", 0, 255, True),
    21: OptionSpec("EDHOC", "Empty", 0, 0, hint="Raw option only; no EDHOC handshake implementation."),
    23: OptionSpec("Block2", "UInt", 0, 3, hint="Manual block field: (NUM << 4) | (M << 3) | SZX."),
    27: OptionSpec("Block1", "UInt", 0, 3, hint="Manual block field: (NUM << 4) | (M << 3) | SZX."),
    28: OptionSpec("Size2", "UInt", 0, 4),
    31: OptionSpec("Q-Block2", "UInt", 0, 3),
    35: OptionSpec("Proxy-Uri", "UTF-8", 1, 1034, hint="Mutually exclusive with Uri-* and Proxy-Scheme."),
    39: OptionSpec("Proxy-Scheme", "UTF-8", 1, 255),
    60: OptionSpec("Size1", "UInt", 0, 4),
    252: OptionSpec("Echo", "Opaque", 1, 40),
    258: OptionSpec("No-Response", "UInt", 0, 1, hint="Bit mask: 2 suppress 2.xx, 8 suppress 4.xx, 16 suppress 5.xx."),
    292: OptionSpec("Request-Tag", "Opaque", 0, 8, True),
}
OPTION_CHOICES = tuple(f"{number} - {spec.name}" for number, spec in OPTIONS.items())