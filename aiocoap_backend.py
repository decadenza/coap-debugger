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
        return "coap://" + self.hostinfo


def run_exchange(ip, port, request, settings, cancel, emit, decode):
    """Run aiocoap in the GUI's worker thread."""
    asyncio.run(
        _exchange(ip, port, request, settings, cancel, emit, decode)
    )