"""
A/B Dual-Slot Rollback (Blueprint Pillar 13).

Maintains two image/deployment slots (A and B). Patches promote the inactive
slot; a failure flips traffic back to the previous slot deterministically.
"""

from typing import Any, Dict, Optional


class DualSlotManager:
    """Tracks active slot and promotes/rolls back between A and B."""

    def __init__(self, image: str, active_slot: str = "A") -> None:
        self.image = image
        self.slots = {
            "A": {"tag": "1.0.0", "healthy": True},
            "B": {"tag": "1.0.0", "healthy": True},
        }
        self.active_slot = active_slot

    @property
    def active(self) -> Dict[str, Any]:
        return self.slots[self.active_slot]

    @property
    def inactive_slot(self) -> str:
        return "B" if self.active_slot == "A" else "A"

    def promote(self, new_tag: str) -> Dict[str, Any]:
        """Deploy the new tag to the inactive slot and switch traffic."""
        slot = self.inactive_slot
        self.slots[slot] = {"tag": new_tag, "healthy": False}
        return {"slot": slot, "tag": new_tag, "state": "PENDING_VERIFY"}

    def confirm(self, slot: Optional[str] = None) -> Dict[str, Any]:
        """Mark the promoted slot healthy and flip active traffic to it."""
        slot = slot or self.inactive_slot
        self.slots[slot]["healthy"] = True
        previous = self.active_slot
        self.active_slot = slot
        return {"previous_slot": previous, "active_slot": slot}

    def rollback(self) -> Dict[str, Any]:
        """Fail the promoted slot and restore traffic to the previous slot."""
        promoted = self.inactive_slot
        self.slots[promoted]["healthy"] = False
        return {
            "status": "ROLLED_BACK",
            "promoted_slot": promoted,
            "active_slot": self.active_slot,
            "active_tag": self.slots[self.active_slot]["tag"],
        }

    def current_state(self) -> Dict[str, Any]:
        return {
            "image": self.image,
            "active_slot": self.active_slot,
            "active_tag": self.slots[self.active_slot]["tag"],
            "slots": self.slots,
        }
