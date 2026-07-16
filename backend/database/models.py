import uuid

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship

from database.database import Base


def _uuid() -> str:
    return str(uuid.uuid4())


class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=_uuid)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    scans = relationship("Scan", back_populates="user", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<User id={self.id} email={self.email}>"


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, default=_uuid)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    url = Column(String(2048), nullable=True)

    status = Column(String(64), nullable=False, default="created")

    risk_score = Column(Float, nullable=True)
    severity = Column(String(16), nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    user = relationship("User", back_populates="scans")
    incidents = relationship("Incident", back_populates="scan", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Scan id={self.id} status={self.status} severity={self.severity}>"


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(String(36), primary_key=True, default=_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False, index=True)

    severity = Column(String(16), nullable=False)
    risk_score = Column(Float, nullable=True)
    summary = Column(JSONB, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())

    scan = relationship("Scan", back_populates="incidents")
    iocs = relationship("IOC", back_populates="incident", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Incident id={self.id} scan_id={self.scan_id} severity={self.severity}>"


class IOC(Base):
    __tablename__ = "iocs"

    id = Column(String(36), primary_key=True, default=_uuid)
    incident_id = Column(String(36), ForeignKey("incidents.id"), nullable=False, index=True)

    ioc_type = Column(String(32), nullable=False)
    value = Column(String(2048), nullable=False)

    created_at = Column(DateTime(timezone=True), server_default=func.now())

    incident = relationship("Incident", back_populates="iocs")

    def __repr__(self):
        return f"<IOC type={self.ioc_type} value={self.value}>"


class Statistics(Base):
    __tablename__ = "statistics"

    id = Column(Integer, primary_key=True, default=1)
    total_incidents = Column(Integer, nullable=False, default=0)
    critical_count = Column(Integer, nullable=False, default=0)
    high_count = Column(Integer, nullable=False, default=0)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    def __repr__(self):
        return (
            f"<Statistics total={self.total_incidents} "
            f"critical={self.critical_count} high={self.high_count}>"
        )
