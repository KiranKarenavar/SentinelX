from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
    Index,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database import Base


def utc_now():
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    username: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(50), default="analyst")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
    )

    alerts = relationship("Alert", back_populates="assigned_user")
    incidents = relationship("Incident", back_populates="assigned_user")
    hunting_queries = relationship("HuntingQuery", back_populates="user")


class IOC(Base):
    __tablename__ = "iocs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    indicator: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
    )

    indicator_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    source: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    confidence: Mapped[int] = mapped_column(
        Integer,
        default=0,
    )

    severity: Mapped[str] = mapped_column(
        String(20),
        default="MEDIUM",
    )

    first_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    last_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    malware_family: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    threat_actor: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    mitre_technique: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
    )

    __table_args__ = (
        Index("idx_ioc_indicator", "indicator"),
        Index("idx_ioc_type", "indicator_type"),
        Index("idx_ioc_source", "source"),
    )


class ThreatIntelligence(Base):
    __tablename__ = "threat_intelligence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    source: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    threat_type: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    severity: Mapped[str] = mapped_column(
        String(20),
        default="MEDIUM",
    )

    confidence: Mapped[int] = mapped_column(
        Integer,
        default=0,
    )

    reference_url: Mapped[str | None] = mapped_column(
        String(1000),
        nullable=True,
    )

    raw_data: Mapped[dict | None] = mapped_column(
        JSON,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
    )


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    severity: Mapped[str] = mapped_column(
        String(20),
        default="MEDIUM",
    )

    status: Mapped[str] = mapped_column(
        String(50),
        default="NEW",
    )

    source: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    mitre_technique: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )

    assigned_to: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"),
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
    )

    assigned_user = relationship(
        "User",
        back_populates="alerts",
    )


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    severity: Mapped[str] = mapped_column(
        String(20),
        default="MEDIUM",
    )

    status: Mapped[str] = mapped_column(
        String(50),
        default="OPEN",
    )

    assigned_to: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"),
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
    )

    assigned_user = relationship(
        "User",
        back_populates="incidents",
    )


class Log(Base):
    __tablename__ = "logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
    )

    source: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    log_type: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    level: Mapped[str] = mapped_column(
        String(20),
        default="INFO",
    )

    message: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    source_ip: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    destination_ip: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    raw_data: Mapped[dict | None] = mapped_column(
        JSON,
        nullable=True,
    )


class PhishingEmail(Base):
    __tablename__ = "phishing_emails"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    sender: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    recipient: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    subject: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
    )

    body: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    attachment_name: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
    )

    attachment_hash: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    verdict: Mapped[str] = mapped_column(
        String(50),
        default="UNKNOWN",
    )

    confidence: Mapped[int] = mapped_column(
        Integer,
        default=0,
    )

    analysis_result: Mapped[dict | None] = mapped_column(
        JSON,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
    )


class HoneypotEvent(Base):
    __tablename__ = "honeypot_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
    )

    source_ip: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    destination_ip: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    destination_port: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    protocol: Mapped[str | None] = mapped_column(
        String(20),
        nullable=True,
    )

    username: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    event_type: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    payload: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    severity: Mapped[str] = mapped_column(
        String(20),
        default="MEDIUM",
    )

    raw_data: Mapped[dict | None] = mapped_column(
        JSON,
        nullable=True,
    )


class HuntingQuery(Base):
    __tablename__ = "hunting_queries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"),
        nullable=True,
    )

    query: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    query_type: Mapped[str] = mapped_column(
        String(50),
        default="IOC",
    )

    results_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
    )

    executed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
    )

    user = relationship(
        "User",
        back_populates="hunting_queries",
    )
