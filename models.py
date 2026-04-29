from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime

Base = declarative_base()

class LtiDeployment(Base):
    __tablename__ = "lti_deployments"

    id = Column(Integer, primary_key=True, index=True)
    issuer = Column(String, unique=True, index=True, nullable=False)  # iss claim from JWT
    client_id = Column(String, unique=True, index=True, nullable=False)  # client_id from LTI registration
    deployment_id = Column(String, unique=True, index=True, nullable=False)  # deployment_id from LTI message
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationship to LtiSessions
    sessions = relationship("LtiSession", back_populates="deployment")

class LtiSession(Base):
    __tablename__ = "lti_sessions"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String, unique=True, index=True, nullable=False)  # Generated session ID
    user_id = Column(String, index=True, nullable=False)  # User ID from LTI message
    user_email = Column(String, index=True)  # Email from LTI message
    user_name = Column(String)  # Name from LTI message
    context_id = Column(String, index=True)  # Course or context ID
    context_title = Column(String)  # Course or context title
    resource_link_id = Column(String, index=True)  # Link ID for specific resource
    roles = Column(String)  # Comma-separated roles string
    lti_deployment_id = Column(Integer, ForeignKey("lti_deployments.id"))  # Reference to LtiDeployment.id
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationship to LtiDeployment
    deployment = relationship("LtiDeployment", back_populates="sessions")

class LtiNonce(Base):
    __tablename__ = "lti_nonces"

    id = Column(Integer, primary_key=True, index=True)
    nonce = Column(String, unique=True, index=True, nullable=False)  # The nonce value from JWT
    expires_at = Column(DateTime, nullable=False)  # When this nonce expires
    used = Column(Boolean, default=False)  # Whether this nonce has been used
    created_at = Column(DateTime, default=datetime.utcnow)