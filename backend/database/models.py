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
    is_superuser = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    scans = relationship("Scan", back_populates="user", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<User id={self.id} email={self.email}>"


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, default=_uuid)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    url = Column(String(2048), nullable=True)

    status = Column(String(64), nullable=False, default="created")

    risk_score = Column(Float, nullable=True)
    severity = Column(String(16), nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    user = relationship("User", back_populates="scans")
    incidents = relationship("Incident", back_populates="scan", cascade="all, delete-orphan", passive_deletes=True)
    
    # Telemetry relationships
    network_activity = relationship("NetworkActivity", back_populates="scan", cascade="all, delete-orphan", passive_deletes=True)
    tls_connections = relationship("TLSConnection", back_populates="scan", cascade="all, delete-orphan", passive_deletes=True)
    form_metrics = relationship("FormMetrics", back_populates="scan", cascade="all, delete-orphan", passive_deletes=True)
    downloads = relationship("Download", back_populates="scan", cascade="all, delete-orphan", passive_deletes=True)
    redirects = relationship("Redirect", back_populates="scan", cascade="all, delete-orphan", passive_deletes=True)
    evasion_techniques = relationship("EvasionTechnique", back_populates="scan", cascade="all, delete-orphan", passive_deletes=True)

    def __repr__(self):
        return f"<Scan id={self.id} status={self.status} severity={self.severity}>"


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(String(36), primary_key=True, default=_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)

    severity = Column(String(16), nullable=False)
    risk_score = Column(Float, nullable=True)
    summary = Column(JSONB, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())

    scan = relationship("Scan", back_populates="incidents")
    iocs = relationship("IOC", back_populates="incident", cascade="all, delete-orphan", passive_deletes=True)

    def __repr__(self):
        return f"<Incident id={self.id} scan_id={self.scan_id} severity={self.severity}>"


class IOC(Base):
    __tablename__ = "iocs"

    id = Column(String(36), primary_key=True, default=_uuid)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)

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


class NetworkActivity(Base):
    __tablename__ = "network_activity"
    id = Column(String(36), primary_key=True, default=_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    method = Column(String(16), nullable=True)
    url = Column(String(2048), nullable=False)
    domain = Column(String(255), nullable=True, index=True)
    ip_address = Column(String(64), nullable=True, index=True)
    status = Column(Integer, nullable=True)
    headers = Column(JSONB, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    scan = relationship("Scan", back_populates="network_activity")

class TLSConnection(Base):
    __tablename__ = "tls_connections"
    id = Column(String(36), primary_key=True, default=_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    domain = Column(String(255), nullable=False, index=True)
    protocol = Column(String(64), nullable=True)
    cipher = Column(String(128), nullable=True)
    issuer = Column(String(512), nullable=True)
    valid_from = Column(DateTime, nullable=True)
    valid_to = Column(DateTime, nullable=True)
    is_suspicious = Column(Boolean, nullable=False, default=False)
    cert_chain = Column(JSONB, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    scan = relationship("Scan", back_populates="tls_connections")

class FormMetrics(Base):
    __tablename__ = "form_metrics"
    id = Column(String(36), primary_key=True, default=_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    action_url = Column(String(2048), nullable=True)
    input_types = Column(JSONB, nullable=True)
    has_password_field = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    scan = relationship("Scan", back_populates="form_metrics")

class Download(Base):
    __tablename__ = "downloads"
    id = Column(String(36), primary_key=True, default=_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    url = Column(String(2048), nullable=False)
    mime_type = Column(String(128), nullable=True)
    filename = Column(String(255), nullable=True)
    size_bytes = Column(Integer, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    scan = relationship("Scan", back_populates="downloads")

class Redirect(Base):
    __tablename__ = "redirects"
    id = Column(String(36), primary_key=True, default=_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    from_url = Column(String(2048), nullable=False)
    to_url = Column(String(2048), nullable=False)
    status_code = Column(Integer, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    scan = relationship("Scan", back_populates="redirects")

class EvasionTechnique(Base):
    __tablename__ = "evasion_techniques"
    id = Column(String(36), primary_key=True, default=_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    technique_name = Column(String(128), nullable=False)
    evidence_snippet = Column(String(2048), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    scan = relationship("Scan", back_populates="evasion_techniques")
