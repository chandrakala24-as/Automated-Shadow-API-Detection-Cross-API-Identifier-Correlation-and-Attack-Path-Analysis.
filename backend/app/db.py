"""Database models (SQLite through SQLAlchemy)."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, ForeignKey, String, Text, create_engine, event
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker

from .config import data_dir


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(80))
    email: Mapped[str] = mapped_column(String(200), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class LoginSession(Base):
    __tablename__ = "sessions"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    expires_at: Mapped[datetime]


class Project(Base):
    __tablename__ = "projects"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    base_url: Mapped[str] = mapped_column(String(300))
    spec_text: Mapped[str] = mapped_column(Text, default="")
    har_text: Mapped[str] = mapped_column(Text, default="")
    identities_encrypted: Mapped[str] = mapped_column(Text)
    options: Mapped[dict] = mapped_column(JSON, default=dict)
    is_demo: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    scans: Mapped[list["Scan"]] = relationship(
        back_populates="project", cascade="all, delete-orphan", order_by="Scan.id.desc()")


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    status: Mapped[str] = mapped_column(String(20), default="queued")
    stage: Mapped[str] = mapped_column(String(40), default="Queued")
    progress: Mapped[int] = mapped_column(default=0)
    message: Mapped[str] = mapped_column(Text, default="")
    warnings: Mapped[list] = mapped_column(JSON, default=list)
    stats: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(default=None)
    project: Mapped[Project] = relationship(back_populates="scans")
    endpoints: Mapped[list["EndpointRow"]] = relationship(
        cascade="all, delete-orphan", order_by="EndpointRow.id")
    findings: Mapped[list["FindingRow"]] = relationship(
        cascade="all, delete-orphan", order_by="FindingRow.id")
    links: Mapped[list["LinkRow"]] = relationship(
        cascade="all, delete-orphan", order_by="LinkRow.id")
    paths: Mapped[list["PathRow"]] = relationship(
        cascade="all, delete-orphan", order_by="PathRow.id")


def _scan_fk():
    return mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)


class EndpointRow(Base):
    __tablename__ = "endpoints"
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = _scan_fk()
    method: Mapped[str] = mapped_column(String(8))
    path: Mapped[str] = mapped_column(Text)
    classification: Mapped[str] = mapped_column(String(20))
    data: Mapped[dict] = mapped_column(JSON)


class FindingRow(Base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = _scan_fk()
    type: Mapped[str] = mapped_column(String(40))
    endpoint: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(10))
    score: Mapped[int]
    triage: Mapped[str] = mapped_column(String(20), default="open")
    data: Mapped[dict] = mapped_column(JSON)


class LinkRow(Base):
    __tablename__ = "identifier_links"
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = _scan_fk()
    data: Mapped[dict] = mapped_column(JSON)


class PathRow(Base):
    __tablename__ = "attack_paths"
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = _scan_fk()
    data: Mapped[dict] = mapped_column(JSON)


def make_session_factory(url: str | None = None):
    engine = create_engine(url or f"sqlite:///{data_dir() / 'shadowapi.db'}",
                           connect_args={"check_same_thread": False, "timeout": 30})

    @event.listens_for(engine, "connect")
    def _pragmas(connection, _):
        cursor = connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.close()

    Base.metadata.create_all(engine)
    return sessionmaker(engine, expire_on_commit=False)
