# CoAP Debugger

A standalone, desktop UDP CoAP debugging tool for general CoAP devices and
[ProsecCoAP](https://github.com/decadenza/ProsecCoAP). Inspired by Qt's simple CoAP
client example, implemented in Python with Tkinter and **aiocoap**. It needs no
Qt installation, Arduino tools, or web server. Keep `coap_debugger.py` and
`aiocoap_backend.py` together.

## Python setup

Use **Python 3.10 or newer** with Tkinter and a graphical desktop.

Windows: install Python from python.org with Tcl/Tk support enabled.
macOS: the python.org installer includes Tk; some package-manager Python builds
require their matching Tk package.
Debian/Ubuntu:

```sh
sudo apt install python3 python3-venv python3-tk
```

From this directory:

```sh
python3 -m venv .venv
# Linux / macOS:
source .venv/bin/activate
# Windows PowerShell instead:
# .venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python coap_debugger.py
```

If your system uses `python` rather than `python3`, substitute it in the setup
commands. `requirements.txt` installs the pinned aiocoap dependency. Tkinter is an OS/Python installation component,
not a pip dependency. On a headless machine you must supply a graphical display;
the application is not a browser GUI.

## Send a request

1. Enter the device IP (default **192.168.0.100**) and UDP port (default **5683**).
2. Use **Set resource** to enter `/my-endpoint`, `/sensors/temperature`, or
   `/.well-known/core?rt=sensor`. This replaces only Uri-Path and Uri-Query options.
3. Choose GET/POST/PUT/DELETE, or FETCH/PATCH/iPATCH if supported by the device.
   **CON** enables reliable retransmission; **NON** sends once. **Empty ping**
   with CON, no options/payload, and a blank token checks CoAP reachability;
   a matching empty RST is a successful ping response.
4. Enter a payload as literal **ASCII**, whitespace-separated **HEX**, or
   complete eight-bit **Binary** groups. ASCII does **not** interpret `\n` or
   `\x00` escapes; use HEX/Binary for arbitrary bytes. Newlines in the editor
   are real payload bytes. **Load bytes** reads a file into the HEX editor.
5. Select the payload's **Content-Format**, or enter any decimal ID from
   0 through 65535. This is independent of the editor's byte encoding:
   HEX-encoded JSON still uses Content-Format 50, not 42. Selecting **None**
   omits the option; omission does not imply text/plain. Zero is encoded as an
   empty integer option, not as an omitted option.
6. Add/edit/remove options as needed, then **Summarize** to inspect the exact
   header, token, options, payload, and complete wire datagram. An unchanged
   form sends exactly the summary's generated MID and token. Changing the form
   regenerates the preview on Send. Blank MID is automatically allocated;
   a manual MID accepts decimal or `0x` notation. Blank token generates random
   bytes; type `empty` for zero bytes or supply at most eight HEX bytes.
7. **Send message** runs off the GUI thread. Inspect **Responses** and
   **Exchange log**. The log includes sends, retries, ACKs, ignored packets and
   errors; response summaries include code names, MID, token, options and raw HEX.
   Switch payload display between ASCII, HEX, Binary and UTF-8 without modifying
   the received bytes. **Save payload** exports those exact bytes.

For example, sending ASCII `42` yields bytes `34 32`; Binary
`00110100 00110010` and HEX `34 32` produce the same payload.
Nonprintable/non-ASCII bytes appear as `\xNN` in the ASCII view. UTF-8 displays
valid text and escapes invalid sequences. Response history holds the latest
100 responses; the exchange log retains the latest two million characters.
Clearing results does not cancel an active exchange.

## Protocol options

The editor includes **all RFC 7252 standard options**:
If-Match, Uri-Host, ETag, If-None-Match, Uri-Port, Location-Path, Uri-Path,
Content-Format, Max-Age, Uri-Query, Accept, Location-Query, Proxy-Uri,
Proxy-Scheme and Size1. It also includes Observe, OSCORE, Hop-Limit, EDHOC,
Block1/Block2, Q-Block1/Q-Block2, Size2, Echo, No-Response and Request-Tag.
Enter **any numeric option ID** (1..65535) for additional registered or
vendor-specific options; choose UTF-8, UInt, opaque HEX, ASCII, Binary, or Empty.
Unknown critical options may cause the device to reply 4.02 Bad Option.

Standard option lengths, single/repeated occurrences, unsigned encoding,
UTF-8 and Proxy-Uri conflicts are validated. Options are sorted numerically;
the order of repeated path/query options is preserved. Enter one path segment
per Uri-Path row, without `/`, and one query component per Uri-Query row,
without `&`. The resource helper percent-decodes components, preserving `%2F`
inside a segment. `+` stays a literal plus. Uri-Host/Uri-Port are logical URI
options and do not change the UDP destination fields.

The Content-Format selector adds option 12. To enter Content-Format directly
in the options table, choose **None** in the selector; duplicate option 12 is
an error. Content format/Accept IDs are not restricted to the preset list.
Response-only options are available intentionally for protocol debugging,
but a server may reject them in requests.

**Observe:** GET with Observe=0 keeps the same socket/token open for
notifications. aiocoap acknowledges CON notifications and filters duplicate or
stale Observe sequence numbers, including 24-bit rollover. Cancel or the configured idle timeout sends a best-effort
NON GET Observe=1 from that same socket to deregister. If the device does not
return an Observe option, the exchange completes normally. There is no
automatic lease refresh or persistent
subscription across sends. Explicit Observe=1 requests also work, but cancelling
an existing registration requires its original token and local UDP port.

**Block options:** manual wire-field editing only, not automatic fragmentation
or reassembly. Encode `value = (NUM << 4) | (M << 3) | SZX`, with block size
`2 ** (SZX + 4)`. For ordinary Block1/Block2 over UDP use SZX 0..6, never 7.
Inspect each returned block and request subsequent blocks manually.
Echo challenges are likewise handled by copying the response Echo option into
a subsequent request. OSCORE and EDHOC options are raw bytes/presence only:
this application does not implement their encryption or handshakes.

## Settings and reliability

**Settings > Transmission settings** is separate from the message editor.
Defaults are ACK_TIMEOUT=2 seconds, ACK_RANDOM_FACTOR=1.5, MAX_RETRANSMIT=4,
response/Observe idle timeout=60 seconds, automatic token length=4, local
UDP port=0 (ephemeral), and outgoing message limit=128 bytes.
Settings are stored in `~/.coap-debugger.json`. Invalid files are reported
without being silently overwritten. Restore defaults is available in the menu.
Settings changed during an exchange apply only to the next exchange.

aiocoap's message manager handles retransmissions. CON requests use an initial random interval in [2, 3] seconds and exponential
backoff with the **same datagram/MID/token** on each retry, as in RFC 7252.
Four retransmissions means at most five sends; without any reply, failure
occurs after 31 initial intervals (62..93 seconds with defaults). A matching
empty ACK stops retransmissions and starts the separate-response timeout.
A piggybacked ACK response must match MID and token; a separate response must
match token. Separate CON responses are ACKed. NON sends are never retried.
Only one request is outstanding at once (NSTART=1). Connected UDP filters the
remote endpoint; unrelated or malformed datagrams are logged, not treated as
success. Application errors such as 4.04 are displayed as received responses,
not confused with network failures. An RST to a non-ping request is an error.

No-Response can intentionally suppress replies; an ACK without a response
will eventually reach the configured response timeout. Cancel is available
during waiting/retries. The UI remains responsive throughout network activity.
Do not shorten retry defaults indiscriminately on constrained networks.

## ProsecCoAP compatibility

The upstream [README](https://raw.githubusercontent.com/decadenza/ProsecCoAP/main/README.md)
and [Definitions.h](https://raw.githubusercontent.com/decadenza/ProsecCoAP/main/src/Definitions.h)
describe RFC 7252 UDP messages, port 5683, tokens up to eight bytes, the four
base request methods, and the formats offered here. Their default
`COAP_MAX_MESSAGE_SIZE` is **128 bytes for the entire datagram**, including the
header, token, options and payload. Oversized incoming messages can be dropped.
This tool therefore defaults to the same outgoing limit. Increase it in
Settings only if your server supports a larger buffer (and configure the
server accordingly). General CoAP devices commonly accept larger messages;
1152 bytes is a typical fragmentation-avoiding upper target, not a guarantee.

To use the upstream README's server example:

```text
IP:             your board's actual IP (example: 192.168.0.99)
Port:           5683
Method / type:  GET / CON
Resource:       /my-endpoint
Payload:        empty
Content-Format: None
Token / MID:    blank (automatic)
```

The example returns **2.05 Content**, Content-Format **0**, payload ASCII **42**
(HEX **34 32**). The GUI's requested default IP is intentionally .100, not the
upstream example's .99. Use CON with ProsecCoAP's default `intoResponse()`,
which constructs an ACK response. The client can also display a matching
token/MID ACK reply to NON for interoperability, though general servers should
use NON responses for NON requests.

Compatibility is based on upstream protocol definitions and tested
ProsecCoAP-style UDP fixtures, **not a physical Arduino/ESP board run**. Resources,
methods, Observe behavior, buffer overrides and extension support depend on
your firmware. Do not assume ProsecCoAP supports every extension in the editor.
This is plain **coap:// UDP only**: no DTLS/coaps, TCP, multicast discovery,
automatic proxying, or automatic content deserialization. Use only devices and
networks you are authorized to test; traffic is not encrypted.

## Checks

```sh
python -m unittest discover -s tests -v
```

Tests use standard-library loopback UDP fixtures, with no device or internet
required. GUI smoke tests run only when a graphical display is available
(otherwise they are skipped). On Linux with Xvfb installed:

```sh
xvfb-run -a python -m unittest discover -s tests -v
```

## Maintenance

`coap_debugger.py` owns the GUI, input validation, summaries and payload
conversion. Its small `Message`/`Option` value adapters use **aiocoap's
message and option codecs**; there is no application-owned wire serializer.
`aiocoap_backend.py` owns the asyncio integration and lifecycle. It runs
`Context.request(..., handle_blockwise=False)` with per-message
`TransportTuning`. aiocoap owns token matching, CON backoff, ACK/RST processing
and Observe sequence filtering; only user-facing idle timeouts and cancellation
are implemented by the application.

A connected UDP `MessageInterface` adds raw RX/TX capture, destination filtering,
the outgoing size limit and a selectable local port, without adding a second
CoAP reliability implementation. A small `TokenManager` subclass returns the
selected/preview token, and the message manager starts at the selected MID.
These low-level integration points are necessary because the default high-level
client replaces user-provided tokens/MIDs and does not expose raw packet capture
or portable local-port selection. Empty pings use aiocoap's message layer because
they are not application requests.

**aiocoap is pinned to 0.4.17** because manager wiring is a low-level API, not
a stable high-level contract. Before upgrading, run the complete loopback and
GUI suite, especially exact preview bytes, manual/empty tokens, retries,
separate responses, Observe cancellation and size/local-port controls.
No aiocoap source is copied or modified, and no library globals are monkey-patched.
The package's asynchronous Observe iterator may coalesce rapid updates; the
exchange log still contains every received raw datagram.