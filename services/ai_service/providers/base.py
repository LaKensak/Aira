from __future__ import annotations

from abc import ABC, abstractmethod


class Provider(ABC):
    @abstractmethod
    def explain(self, code: str) -> str:  # returns plain text explanation
        ...

