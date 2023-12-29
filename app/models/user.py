#!/usr/bin/env python3
#
from .peer import Peer  # Assuming Peer model is in the same directory


class User(Peer):
    def serialize(self) -> dict:
        """Serializes User data into a dictionary."""
        return {
            "uuid": self.uuid,
            "public_ip": self.public_ip,
            "label": self.label,
            "avatar_url": self.avatar_url,
            "peer": {"id": self.peer_state["id"]},  # Access nested peer_state
        }
