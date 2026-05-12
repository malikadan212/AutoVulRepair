"""
Webhook Event Model - Track all webhook events for visibility
"""

from sqlalchemy import Column, String, Integer, Text, TIMESTAMP, JSON, Boolean
from sqlalchemy.dialects.postgresql import UUID, JSONB
from datetime import datetime
import uuid

from src.models.scan_v2 import Base


class WebhookEvent(Base):
    """Track all webhook events received from GitHub"""
    __tablename__ = 'webhook_events'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    delivery_id = Column(String(255), unique=True, nullable=False)  # GitHub delivery ID
    event_type = Column(String(50), nullable=False)  # push, pull_request, installation
    action = Column(String(50))  # opened, synchronize, created, etc.
    repository_full_name = Column(String(255))
    installation_id = Column(Integer)
    sender_login = Column(String(255))
    
    # Processing status
    status = Column(String(50), nullable=False, default='received')  # received, processed, skipped, failed
    scan_id = Column(String(255))  # If a scan was created
    error_message = Column(Text)
    
    # Metadata
    payload_summary = Column(JSONB, default={})  # Key info from payload
    created_at = Column(TIMESTAMP, default=datetime.utcnow)
    processed_at = Column(TIMESTAMP)
    
    def to_dict(self):
        """Convert to dictionary for API responses"""
        return {
            'id': str(self.id),
            'delivery_id': self.delivery_id,
            'event_type': self.event_type,
            'action': self.action,
            'repository': self.repository_full_name,
            'installation_id': self.installation_id,
            'sender': self.sender_login,
            'status': self.status,
            'scan_id': self.scan_id,
            'error_message': self.error_message,
            'payload_summary': self.payload_summary,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'processed_at': self.processed_at.isoformat() if self.processed_at else None
        }
