from typing import List, Literal, Optional
from pydantic import BaseModel, Field


Role = Literal["system", "user", "assistant"]


class Message(BaseModel):
    role: Role
    content: str


class ChatRequest(BaseModel):
    provider: Literal["openai", "langflow", "azure", "aira", "claudecode"] = Field(default="aira")
    # session_id: si fourni, le backend charge l'historique et ne dépend pas de messages
    session_id: Optional[str] = None
    # message unique (mode session) OU liste complète (mode legacy sans session)
    message: Optional[str] = None
    messages: Optional[List[Message]] = None
    # Chemin du binaire analysé (optionnel, injecté par le frontend)
    binary_path: Optional[str] = None
    # Optional provider-specific parameters
    temperature: Optional[float] = Field(default=0.2, ge=0.0, le=2.0)
    top_p: Optional[float] = Field(default=1.0, ge=0.0, le=1.0)
    # Langflow overrides
    langflow_flow_id: Optional[str] = None
    # OpenAI/Azure overrides
    model: Optional[str] = None


class ChatResponse(BaseModel):
    provider: str
    model: Optional[str] = None
    output_text: str
    session_id: Optional[str] = None
    raw: dict | None = None


class HistoryResponse(BaseModel):
    session_id: str
    messages: List[Message]
    binary_path: Optional[str] = None


class StaticAnalyzeRequest(BaseModel):
    path: str
    yara: bool = False


class StaticAnalyzeResponse(BaseModel):
    path: str
    info: dict
    yara_matches: Optional[list[dict]] = None
