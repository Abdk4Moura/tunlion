#!/usr/bin/env python3
from dataclasses import dataclass, field
import asyncio
from typing import Optional


@dataclass
class Peer:
    uuid: str
    label: str
    avatar_url: Optional[str] = None
    public_ip: Optional[str] = None

    peer_state: dict = field(
        default_factory={"id": None, "connection": None, "state": "disconnected"}
    )

    transfer_state: dict = field(
        default_factory={
            "file": None,
            "info": None,
            "sending_progress": 0,
            "receiving_progress": 0,
        }
    )

    state: str = "idle"
    error_code: str = None

    # Example event handling using asyncio.Event
    state_changed_event = asyncio.Event()

    async def set_state(self, new_state: str):
        self.state = new_state
        self.state_changed_event.set()  # Signal state change
        if new_state != "error":
            self.error_code = None  # Clear error code


# Example usage
peer = Peer(uuid="some-uuid", label="John Doe")


async def test_():
    await peer.set_state("has_selected_file")
