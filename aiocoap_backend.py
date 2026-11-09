"""aiocoap integration for exact-wire debugging, isolated from the Tk GUI.

aiocoap owns codecs, token matching, retransmissions, ACK/RST and Observe
ordering. A connected asyncio MessageInterface adds local-port selection and
raw capture. TokenManager allocation is specialized for user-selected tokens.
The integration is version-pinned because the manager wiring is a low-level API.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
import weakref

import aiocoap
from aiocoap.interfaces import EndpointAddress, MessageInterface
from aiocoap.messagemanager import MessageManager
from aiocoap.numbers.constants import TransportTuning
from aiocoap.tokenmanager import TokenManager
from aiocoap.util import hostportjoin


class Cancelled(Exception):
    pass


class DebugTuning(TransportTuning):
    def __init__(self, settings, confirmable):
        self.ACK_TIMEOUT = settings.ack_timeout
        self.ACK_RANDOM_FACTOR = settings.ack_random_factor
        self.MAX_RETRANSMIT = settings.max_retransmit
        self.reliability = confirmable


class DebugTokens(TokenManager):
    def __init__(self, context, token, ping_result):
        super().__init__(context)
        self.selected_token = token
        self.ping_result = ping_result

    def next_token(self):
        # One outstanding exchange; preserve manual, empty and preview tokens.
        return self.selected_token

    def dispatch_error(self, exception, remote):
        if self.ping_result is not None and not self.ping_result.done():
            self.ping_result.set_exception(exception)
        super().dispatch_error(exception, remote)


class Peer(EndpointAddress):
    scheme = "coap"
    is_multicast = False
    is_multicast_locally = False

    def __init__(self, transport):
        self.transport = transport

    @property
    def hostinfo(self):
        host, port, *_ = self.transport.get_extra_info("peername")
        return hostportjoin(host, port)

    @property
    def hostinfo_local(self):
        host, port, *_ = self.transport.get_extra_info("sockname")
        return hostportjoin(host, port)

    @property
    def uri_base(self):
        return "coap://" + self.hostinfo

    @property
    def uri_base_local(self):
        return "coap://" + self.hostinfo_local

    @property
    def blockwise_key(self):
        return self


class DebugUDP(asyncio.DatagramProtocol, MessageInterface):
    def __init__(self, manager, request, settings, emit, decode, ping_result):
        self.manager = manager
        self.request = request
        self.settings = settings
        self.emit = emit
        self.decode = decode
        self.ping_result = ping_result
        self.acknowledged = asyncio.Event()
        self.closed = asyncio.get_running_loop().create_future()
        self.raw_messages = weakref.WeakKeyDictionary()
        self.terminal_notification = None
        self.sends = 0

    def connection_made(self, transport):
        self.transport = transport
        self.peer = Peer(transport)

    def connection_lost(self, exception):
        if exception is not None:
            self.error_received(exception)
        if not self.closed.done():
            self.closed.set_result(None)

    def error_received(self, exception):
        self.emit("log", f"UDP error: {exception}")
        self.manager.dispatch_error(exception, self.peer)

    def datagram_received(self, data, address):
        self.emit("log", f"RX ({len(data)} bytes): {data.hex(' ')}")
        try:
            message = self.decode(data)
        except ValueError as exc:
            self.emit("log", f"Ignored malformed datagram: {exc}")
            return

        message.remote = self.peer
        message.direction = aiocoap.message.Direction.INCOMING
        self.raw_messages[message] = data

        if (
            self.request.opt.observe == 0
            and message.code.is_response()
            and message.token == self.request.token
            and message.opt.observe is None
        ):
            self.terminal_notification = message

        if message.mtype in (aiocoap.ACK, aiocoap.RST):
            # Do not let an unrelated ACK cancel aiocoap's active exchange.
            if message.mid != self.request.mid:
                self.emit("log", "Ignored ACK/RST with unrelated MID.")
                return

            if message.mtype == aiocoap.RST and message.code != aiocoap.EMPTY:
                self.emit("log", "Ignored malformed RST.")
                return

            if (
                message.mtype == aiocoap.ACK
                and message.code != aiocoap.EMPTY
                and not message.code.is_response()
            ):
                self.emit("log", "Ignored ACK with non-response code.")
                return

            if (
                self.ping_result is not None
                and message.mtype == aiocoap.ACK
                and message.code != aiocoap.EMPTY
            ):
                self.emit("log", "Ignored nonempty ACK to Empty ping.")
                return

            if (
                message.code != aiocoap.EMPTY
                and message.token != self.request.token
            ):
                self.emit("log", "Ignored ACK with unrelated token.")
                return

            if message.code == aiocoap.EMPTY and message.mtype == aiocoap.ACK:
                if self.request.mtype != aiocoap.CON:
                    self.emit("log", "Ignored empty ACK for NON request.")
                    return

                if not self.acknowledged.is_set():
                    self.emit(
                        "log",
                        "Empty ACK: aiocoap stopped retries; "
                        "waiting for separate response.",
                    )
                    self.acknowledged.set()

            if message.mtype == aiocoap.RST:
                self.emit("response", (message, data))
                if self.ping_result is not None and not self.ping_result.done():
                    self.ping_result.set_result(message)

        self.manager.dispatch_message(message)

    def send(self, message):
        raw = message.encode()

        if len(raw) > self.settings.message_limit:
            raise ValueError(
                f"{len(raw)}-byte datagram exceeds Settings limit "
                f"{self.settings.message_limit}."
            )

        label = f"TX {message.mtype}"
        if (
            message.mid == self.request.mid
            and message.code == self.request.code
        ):
            self.sends += 1
            if self.sends == 1:
                label = (
                    f"TX to {self.peer.hostinfo}, "
                    f"local {self.peer.hostinfo_local}"
                )
            else:
                label = (
                    f"TX retransmission {self.sends - 1}/"
                    f"{self.settings.max_retransmit}"
                )

        self.transport.sendto(raw)
        self.emit("log", f"{label} ({len(raw)} bytes): {raw.hex(' ')}")

    async def determine_remote(self, message):
        return self.peer

    async def recognize_remote(self, remote):
        return remote is self.peer

    async def shutdown(self):
        self.transport.close()
        await self.closed


class ExchangeLog(logging.Handler):
    def __init__(self, emit):
        super().__init__(logging.INFO)
        self.emit_event = emit

    def emit(self, record):
        self.emit_event("log", "aiocoap: " + record.getMessage())


async def _exchange(ip, port, request, settings, cancel, emit, decode):
    if cancel.is_set():
        raise Cancelled("Cancelled before sending.")

    loop = asyncio.get_running_loop()
    request.transport_tuning = DebugTuning(
        settings,
        request.mtype == aiocoap.CON,
    )

    # Context.request normally replaces tokens and MIDs. These two allocation
    # controls preserve the preview without patching any library globals.
    context = aiocoap.Context(
        loop=loop,
        serversite=None,
        loggername="coap-debugger",
    )
    logger = context.log
    handler = ExchangeLog(emit)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False

    ping_result = (
        loop.create_future()
        if request.code == aiocoap.EMPTY
        else None
    )

    tokens = DebugTokens(context, request.token, ping_result)
    manager = MessageManager(tokens)
    manager.message_id = request.mid
    tokens.token_interface = manager
    context.request_interfaces.append(tokens)

    protocol = DebugUDP(
        manager,
        request,
        settings,
        emit,
        decode,
        ping_result,
    )
    manager.message_interface = protocol

    active = None
    observing = False
    transport_ready = False

    async def cancellation():
        while not cancel.is_set():
            await asyncio.sleep(0.05)

    cancel_task = asyncio.create_task(cancellation())
    ack_task = asyncio.create_task(protocol.acknowledged.wait())

    async def wait_for(future, timeout=None, watch_ack=False):
        deadline = (
            loop.time() + timeout
            if timeout is not None
            else None
        )

        while True:
            watchers = {future, cancel_task}
            if watch_ack:
                watchers.add(ack_task)

            remaining = (
                max(0, deadline - loop.time())
                if deadline is not None
                else None
            )

            done, _ = await asyncio.wait(
                watchers,
                timeout=remaining,
                return_when=asyncio.FIRST_COMPLETED,
            )

            if cancel_task in done:
                raise Cancelled("Cancelled.")

            if future in done:
                return future.result()

            if ack_task in done:
                watch_ack = False
                deadline = loop.time() + settings.response_timeout
            elif not done:
                raise TimeoutError(
                    "Response/Observe idle timeout expired; "
                    "no matching response."
                )

    def show(message):
        emit("response", (message, protocol.raw_messages[message]))

    try:
        family = (
            socket.AF_INET6
            if ipaddress.ip_address(ip).version == 6
            else socket.AF_INET
        )
        local_ip = "::" if family == socket.AF_INET6 else "0.0.0.0"

        await loop.create_datagram_endpoint(
            lambda: protocol,
            remote_addr=(ip, port),
            local_addr=(local_ip, settings.local_port),
            family=family,
        )
        transport_ready = True

        if cancel.is_set():
            raise Cancelled("Cancelled before sending.")

        request.remote = protocol.peer

        # Let the manager assign the reserved MID without its fixed-MID warning.
        request.mid = None

        if ping_result is not None:
            def ping_failed():
                if not ping_result.done():
                    ping_result.set_exception(aiocoap.error.MessageError())

            manager.send_message(request, ping_failed)
            await wait_for(ping_result, watch_ack=True)
            emit("log", "Ping answered with RST: endpoint is reachable.")
            return

        # Debug each datagram separately; do not change manual block options.
        active = context.request(request, handle_blockwise=False)

        response = await wait_for(
            active.response,
            timeout=(
                settings.response_timeout
                if request.transport_tuning.reliability is False
                else None
            ),
            watch_ack=request.transport_tuning.reliability is True,
        )
        show(response)

        if (
            active.observation is not None
            and response.opt.observe is not None
            and response.code.is_successful()
        ):
            observing = True
            emit(
                "log",
                "Observing through aiocoap; Cancel deregisters. "
                "Idle timeout is in Settings.",
            )

            iterator = active.observation.__aiter__()

            while True:
                notification_task = asyncio.create_task(
                    iterator.__anext__()
                )

                try:
                    notification = await wait_for(
                        notification_task,
                        settings.response_timeout,
                    )
                except StopAsyncIteration:
                    # aiocoap's iterator can finish before yielding the final
                    # non-Observe response. Preserve its payload for inspection.
                    if protocol.terminal_notification is not None:
                        show(protocol.terminal_notification)
                    observing = False
                    return
                finally:
                    if not notification_task.done():
                        notification_task.cancel()
                    await asyncio.gather(
                        notification_task,
                        return_exceptions=True,
                    )

                show(notification)

                if notification.opt.observe is None:
                    observing = False
                    return

    except aiocoap.error.ConRetransmitsExceeded as exc:
        raise TimeoutError(
            f"No ACK/response after "
            f"{settings.max_retransmit} retransmissions."
        ) from exc

    except aiocoap.error.MessageError as exc:
        raise ConnectionError(
            "Peer reset the request (RST)."
        ) from exc

    except aiocoap.error.Error as exc:
        raise OSError(
            f"aiocoap exchange failed: {exc}"
        ) from exc

    finally:
        if observing:
            deregister = request.copy(code=aiocoap.GET, mid=None)
            deregister.mtype = aiocoap.NON
            deregister.payload = b""
            deregister.opt.observe = 1
            deregister.opt.content_format = None

            try:
                manager.send_message(deregister, lambda: None)
                emit(
                    "log",
                    "TX NON Observe deregistration (best effort).",
                )
                await asyncio.sleep(0)
            except (OSError, ValueError) as exc:
                emit(
                    "log",
                    f"Observe deregistration failed: {exc}",
                )

        if active is not None:
            if (
                active.observation is not None
                and not active.observation.cancelled
            ):
                active.observation.cancel()

            if not active.response.done():
                active.response.cancel()

        cancel_task.cancel()
        ack_task.cancel()
        await asyncio.gather(
            cancel_task,
            ack_task,
            return_exceptions=True,
        )

        if ping_result is not None:
            if not ping_result.done():
                ping_result.cancel()
            elif not ping_result.cancelled():
                ping_result.exception()

        if (
            active is not None
            and active.response.done()
            and not active.response.cancelled()
        ):
            active.response.exception()

        try:
            if transport_ready:
                await context.shutdown()
        finally:
            logger.removeHandler(handler)
            handler.close()


def run_exchange(ip, port, request, settings, cancel, emit, decode):
    """Run aiocoap in the GUI's worker thread, with deterministic shutdown."""
    asyncio.run(
        _exchange(ip, port, request, settings, cancel, emit, decode)
    )