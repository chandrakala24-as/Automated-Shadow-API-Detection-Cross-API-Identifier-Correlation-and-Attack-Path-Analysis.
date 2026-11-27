"""Request validation."""
from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from .config import MAX_UPLOAD_CHARS
from .engine.models import ANONYMOUS, INVALID
from .engine.scope import validate_base_url

HEADER_NAME = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,100}$")
BLOCKED_HEADERS = {"host", "content-length", "transfer-encoding", "connection"}


class RegisterIn(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    email: str = Field(max_length=200, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    password: str = Field(min_length=10, max_length=200)


class LoginIn(BaseModel):
    email: str = Field(max_length=200)
    password: str = Field(max_length=200)


class IdentityIn(BaseModel):
    name: str = Field(min_length=1, max_length=40, pattern=r"^[A-Za-z0-9 _.-]+$")
    role: Literal["user", "admin"] = "user"
    # None keeps the headers already stored for this account (they are never sent back).
    headers: dict[str, str] | None = None

    @field_validator("headers")
    @classmethod
    def safe_headers(cls, value):
        if value is None:
            return value
        if not value or len(value) > 10:
            raise ValueError("Each account needs between 1 and 10 headers.")
        for name, content in value.items():
            if not HEADER_NAME.match(name) or name.lower() in BLOCKED_HEADERS:
                raise ValueError(f"Header '{name[:40]}' is not allowed.")
            if not content.strip() or len(content) > 4000 or any(c in content for c in "\r\n\0") \
                    or not content.isascii():
                raise ValueError(f"The value of header '{name}' is empty or invalid.")
        return value


class OptionsIn(BaseModel):
    enable_crawl: bool = True
    enable_wordlist: bool = True
    rate: float = Field(25, ge=1, le=100)
    max_requests: int = Field(3000, ge=10, le=20000)


class ProjectIn(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    base_url: str = Field(max_length=300)
    spec_text: str | None = Field(None, max_length=MAX_UPLOAD_CHARS)
    har_text: str | None = Field(None, max_length=MAX_UPLOAD_CHARS)
    identities: list[IdentityIn] = Field(default_factory=list, max_length=6)
    options: OptionsIn = Field(default_factory=OptionsIn)
    authorized: bool

    @field_validator("base_url")
    @classmethod
    def origin_only(cls, value):
        return validate_base_url(value)

    @model_validator(mode="after")
    def checks(self):
        if not self.authorized:
            raise ValueError("Confirm that you own this target or have permission to test it.")
        names = [i.name.strip().lower() for i in self.identities]
        if len(set(names)) != len(names):
            raise ValueError("Test account names must be unique.")
        if {ANONYMOUS, INVALID} & set(names):
            raise ValueError("That test account name is reserved.")
        return self


class TriageIn(BaseModel):
    triage: Literal["open", "fixed", "accepted", "false_positive"]
