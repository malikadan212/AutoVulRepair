"""
New database models for production-ready architecture
These models will gradually replace the file-based storage system
"""

from sqlalchemy import Column, String, Integer, Text, TIMESTAMP, JSON, DECIMAL, LargeBinary, Boolean, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine, func
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import uuid
import json

Base = declarative_base()

class ScanV2(Base):
    """
    Main scan tracking table - replaces file-based scan directories
    """
    __tablename__ = 'scans_v2'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(String(255), unique=True, nullable=False)  # Keep compatibility
    user_id = Column(String(255))
    repo_url = Column(Text)
    source_type = Column(String(50), nullable=False)  # 'repository', 'snippet', 'file_upload'
    analysis_tool = Column(String(50), nullable=False, default='cppcheck')
    status = Column(String(50), nullable=False, default='queued')
    priority = Column(Integer, default=5)
    created_at = Column(TIMESTAMP, default=datetime.utcnow)
    started_at = Column(TIMESTAMP)
    completed_at = Column(TIMESTAMP)
    error_message = Column(Text)
    metadata_json = Column(JSONB, default={})
    
    # Relationships
    sources = relationship("ScanSource", back_populates="scan", cascade="all, delete-orphan")
    findings = relationship("StaticFinding", back_populates="scan", cascade="all, delete-orphan")
    fuzz_plans = relationship("FuzzPlan", back_populates="scan", cascade="all, delete-orphan")
    campaigns = relationship("FuzzCampaign", back_populates="scan", cascade="all, delete-orphan")
    patches = relationship("RepairPatch", back_populates="scan", cascade="all, delete-orphan")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses"""
        return {
            'id': str(self.id),
            'scan_id': self.scan_id,
            'user_id': self.user_id,
            'repo_url': self.repo_url,
            'source_type': self.source_type,
            'analysis_tool': self.analysis_tool,
            'status': self.status,
            'priority': self.priority,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'error_message': self.error_message,
            'metadata': self.metadata_json
        }
    
    @property
    def duration_seconds(self) -> Optional[int]:
        """Calculate scan duration in seconds"""
        if self.started_at and self.completed_at:
            return int((self.completed_at - self.started_at).total_seconds())
        return None
    
    @property
    def is_completed(self) -> bool:
        """Check if scan is completed (success or failure)"""
        return self.status in ['completed', 'failed']


class ScanSource(Base):
    """
    Store source code files - replaces copying files to scan directories
    """
    __tablename__ = 'scan_sources'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(String(255), ForeignKey('scans_v2.scan_id'), nullable=False)
    file_path = Column(Text, nullable=False)
    file_content = Column(Text, nullable=False)
    file_size = Column(Integer, nullable=False)
    file_hash = Column(String(64), nullable=False)  # SHA-256
    created_at = Column(TIMESTAMP, default=datetime.utcnow)
    
    # Relationships
    scan = relationship("ScanV2", back_populates="sources")
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': str(self.id),
            'scan_id': self.scan_id,
            'file_path': self.file_path,
            'file_size': self.file_size,
            'file_hash': self.file_hash,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class StaticFinding(Base):
    """
    Store static analysis results - replaces static_findings.json
    """
    __tablename__ = 'static_findings'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(String(255), ForeignKey('scans_v2.scan_id'), nullable=False)
    rule_id = Column(String(100), nullable=False)
    severity = Column(String(20), nullable=False)
    confidence = Column(String(20), nullable=False)
    file_path = Column(Text, nullable=False)
    line_number = Column(Integer, nullable=False)
    column_number = Column(Integer, default=0)
    function_name = Column(String(255))
    message = Column(Text, nullable=False)
    description = Column(Text)
    cwe = Column(String(20))
    cvss_score = Column(DECIMAL(3,1))
    exploitability_score = Column(DECIMAL(3,1))
    created_at = Column(TIMESTAMP, default=datetime.utcnow)
    
    # Relationships
    scan = relationship("ScanV2", back_populates="findings")
    patches = relationship("RepairPatch", back_populates="finding")
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': str(self.id),
            'scan_id': self.scan_id,
            'rule_id': self.rule_id,
            'severity': self.severity,
            'confidence': self.confidence,
            'file_path': self.file_path,
            'line_number': self.line_number,
            'column_number': self.column_number,
            'function_name': self.function_name,
            'message': self.message,
            'description': self.description,
            'cwe': self.cwe,
            'cvss_score': float(self.cvss_score) if self.cvss_score else None,
            'exploitability_score': float(self.exploitability_score) if self.exploitability_score else None,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class FuzzPlan(Base):
    """
    Store fuzz plan metadata - replaces fuzz/fuzzplan.json
    """
    __tablename__ = 'fuzz_plans'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(String(255), ForeignKey('scans_v2.scan_id'), nullable=False)
    version = Column(String(10), default='1.0')
    total_targets = Column(Integer, nullable=False, default=0)
    generated_at = Column(TIMESTAMP, default=datetime.utcnow)
    metadata_json = Column(JSONB, default={})
    
    # Relationships
    scan = relationship("ScanV2", back_populates="fuzz_plans")
    targets = relationship("FuzzTarget", back_populates="plan", cascade="all, delete-orphan")
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': str(self.id),
            'scan_id': self.scan_id,
            'version': self.version,
            'total_targets': self.total_targets,
            'generated_at': self.generated_at.isoformat() if self.generated_at else None,
            'metadata': self.metadata_json,
            'targets': [target.to_dict() for target in self.targets]
        }


class FuzzTarget(Base):
    """
    Store individual fuzz targets - replaces target entries in fuzzplan.json
    """
    __tablename__ = 'fuzz_targets'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    plan_id = Column(UUID(as_uuid=True), ForeignKey('fuzz_plans.id'), nullable=False)
    scan_id = Column(String(255), nullable=False)
    target_id = Column(String(255), nullable=False)
    function_name = Column(String(255), nullable=False)
    file_path = Column(Text, nullable=False)
    line_number = Column(Integer, nullable=False)
    bug_class = Column(String(50), nullable=False)
    priority = Column(DECIMAL(4,2), nullable=False)
    harness_type = Column(String(50), nullable=False)
    sanitizers = Column(JSON, nullable=False)
    seeds = Column(JSON)
    dictionaries = Column(JSON)
    function_signature = Column(JSON)
    created_at = Column(TIMESTAMP, default=datetime.utcnow)
    
    # Relationships
    plan = relationship("FuzzPlan", back_populates="targets")
    harnesses = relationship("HarnessFile", back_populates="target", cascade="all, delete-orphan")
    executions = relationship("FuzzExecution", back_populates="target")
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': str(self.id),
            'plan_id': str(self.plan_id),
            'scan_id': self.scan_id,
            'target_id': self.target_id,
            'function_name': self.function_name,
            'file_path': self.file_path,
            'line_number': self.line_number,
            'bug_class': self.bug_class,
            'priority': float(self.priority),
            'harness_type': self.harness_type,
            'sanitizers': self.sanitizers,
            'seeds': self.seeds,
            'dictionaries': self.dictionaries,
            'function_signature': self.function_signature,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class HarnessFile(Base):
    """
    Store harness files - replaces fuzz/harnesses/*.cc files
    """
    __tablename__ = 'harness_files'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    target_id = Column(UUID(as_uuid=True), ForeignKey('fuzz_targets.id'), nullable=False)
    scan_id = Column(String(255), nullable=False)
    filename = Column(String(255), nullable=False)
    harness_code = Column(Text, nullable=False)
    harness_type = Column(String(50), nullable=False)
    build_status = Column(String(20), default='pending')
    build_log = Column(Text)
    binary_path = Column(Text)
    created_at = Column(TIMESTAMP, default=datetime.utcnow)
    
    # Relationships
    target = relationship("FuzzTarget", back_populates="harnesses")
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': str(self.id),
            'target_id': str(self.target_id),
            'scan_id': self.scan_id,
            'filename': self.filename,
            'harness_type': self.harness_type,
            'build_status': self.build_status,
            'binary_path': self.binary_path,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class FuzzCampaign(Base):
    """
    Store fuzzing campaign results - replaces fuzz/results/campaign_results.json
    """
    __tablename__ = 'fuzz_campaigns'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(String(255), ForeignKey('scans_v2.scan_id'), nullable=False)
    runtime_minutes = Column(Integer, nullable=False)
    total_targets = Column(Integer, nullable=False)
    targets_executed = Column(Integer, default=0)
    total_executions = Column(Integer, default=0)
    total_crashes = Column(Integer, default=0)
    status = Column(String(20), default='pending')
    started_at = Column(TIMESTAMP)
    completed_at = Column(TIMESTAMP)
    total_time_seconds = Column(Integer)
    metadata_json = Column(JSONB, default={})
    
    # Relationships
    scan = relationship("ScanV2", back_populates="campaigns")
    executions = relationship("FuzzExecution", back_populates="campaign", cascade="all, delete-orphan")
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': str(self.id),
            'scan_id': self.scan_id,
            'runtime_minutes': self.runtime_minutes,
            'total_targets': self.total_targets,
            'targets_executed': self.targets_executed,
            'total_executions': self.total_executions,
            'total_crashes': self.total_crashes,
            'status': self.status,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'total_time_seconds': self.total_time_seconds,
            'metadata': self.metadata_json
        }


class FuzzExecution(Base):
    """
    Store individual target execution results
    """
    __tablename__ = 'fuzz_executions'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    campaign_id = Column(UUID(as_uuid=True), ForeignKey('fuzz_campaigns.id'), nullable=False)
    target_id = Column(UUID(as_uuid=True), ForeignKey('fuzz_targets.id'), nullable=False)
    scan_id = Column(String(255), nullable=False)
    target_name = Column(String(255), nullable=False)
    status = Column(String(20), nullable=False)
    runtime_seconds = Column(DECIMAL(8,2))
    exit_code = Column(Integer)
    executions_count = Column(Integer, default=0)
    crashes_found = Column(Integer, default=0)
    coverage_stats = Column(JSON)
    fuzzer_output = Column(Text)
    created_at = Column(TIMESTAMP, default=datetime.utcnow)
    
    # Relationships
    campaign = relationship("FuzzCampaign", back_populates="executions")
    target = relationship("FuzzTarget", back_populates="executions")
    crashes = relationship("CrashArtifact", back_populates="execution", cascade="all, delete-orphan")
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': str(self.id),
            'campaign_id': str(self.campaign_id),
            'target_id': str(self.target_id),
            'scan_id': self.scan_id,
            'target_name': self.target_name,
            'status': self.status,
            'runtime_seconds': float(self.runtime_seconds) if self.runtime_seconds else None,
            'exit_code': self.exit_code,
            'executions_count': self.executions_count,
            'crashes_found': self.crashes_found,
            'coverage_stats': self.coverage_stats,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class CrashArtifact(Base):
    """
    Store crash artifacts - replaces fuzz/crashes/* files
    """
    __tablename__ = 'crash_artifacts'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    execution_id = Column(UUID(as_uuid=True), ForeignKey('fuzz_executions.id'), nullable=False)
    scan_id = Column(String(255), nullable=False)
    filename = Column(String(255), nullable=False)
    crash_type = Column(String(50))
    file_size = Column(Integer, nullable=False)
    crash_data = Column(LargeBinary)  # Store the actual crash input
    stack_trace = Column(Text)
    sanitizer_output = Column(Text)
    severity = Column(String(20))
    exploitability = Column(String(20))
    created_at = Column(TIMESTAMP, default=datetime.utcnow)
    
    # Relationships
    execution = relationship("FuzzExecution", back_populates="crashes")
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': str(self.id),
            'execution_id': str(self.execution_id),
            'scan_id': self.scan_id,
            'filename': self.filename,
            'crash_type': self.crash_type,
            'file_size': self.file_size,
            'severity': self.severity,
            'exploitability': self.exploitability,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class RepairPatch(Base):
    """
    Store patches and repairs - replaces patches/*.patch files
    """
    __tablename__ = 'repair_patches'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(String(255), ForeignKey('scans_v2.scan_id'), nullable=False)
    finding_id = Column(UUID(as_uuid=True), ForeignKey('static_findings.id'))
    file_path = Column(Text, nullable=False)
    original_code = Column(Text, nullable=False)
    patched_code = Column(Text, nullable=False)
    patch_diff = Column(Text, nullable=False)
    repair_method = Column(String(50), nullable=False)
    confidence_score = Column(DECIMAL(3,2))
    validation_status = Column(String(20), default='pending')
    applied_at = Column(TIMESTAMP)
    created_at = Column(TIMESTAMP, default=datetime.utcnow)
    
    # Relationships
    scan = relationship("ScanV2", back_populates="patches")
    finding = relationship("StaticFinding", back_populates="patches")
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': str(self.id),
            'scan_id': self.scan_id,
            'finding_id': str(self.finding_id) if self.finding_id else None,
            'file_path': self.file_path,
            'repair_method': self.repair_method,
            'confidence_score': float(self.confidence_score) if self.confidence_score else None,
            'validation_status': self.validation_status,
            'applied_at': self.applied_at.isoformat() if self.applied_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class JobQueue(Base):
    """
    Background job queue - replaces immediate processing
    """
    __tablename__ = 'job_queue'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    job_type = Column(String(50), nullable=False)
    scan_id = Column(String(255), nullable=False)
    priority = Column(Integer, default=5)
    status = Column(String(20), default='queued')
    attempts = Column(Integer, default=0)
    max_attempts = Column(Integer, default=3)
    payload = Column(JSONB, nullable=False)
    result = Column(JSONB)
    error_message = Column(Text)
    created_at = Column(TIMESTAMP, default=datetime.utcnow)
    started_at = Column(TIMESTAMP)
    completed_at = Column(TIMESTAMP)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': str(self.id),
            'job_type': self.job_type,
            'scan_id': self.scan_id,
            'priority': self.priority,
            'status': self.status,
            'attempts': self.attempts,
            'max_attempts': self.max_attempts,
            'payload': self.payload,
            'result': self.result,
            'error_message': self.error_message,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None
        }


# Database connection and session management
class DatabaseManager:
    """
    Manages database connections and provides session factory
    """
    
    def __init__(self, database_url: str):
        self.engine = create_engine(database_url, pool_pre_ping=True, pool_recycle=3600)
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
    
    def create_tables(self):
        """Create all tables"""
        Base.metadata.create_all(bind=self.engine)
    
    def get_session(self):
        """Get database session"""
        return self.SessionLocal()
    
    def health_check(self) -> bool:
        """Check database connectivity"""
        try:
            from sqlalchemy import text
            session = self.get_session()
            session.execute(text("SELECT 1"))
            session.close()
            return True
        except Exception as e:
            print(f"Health check error: {e}")
            return False