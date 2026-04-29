from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import jwt
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from models import LtiDeployment, LtiSession, LtiNonce
from utils.lti import verify_lti_token
import os

class LtiService:
    def __init__(self, db: Session):
        self.db = db

    def get_or_create_lti_deployment(self, issuer: str, client_id: str, deployment_id: str) -> LtiDeployment:
        """Get existing deployment or create new one"""
        deployment = self.db.query(LtiDeployment).filter(
            LtiDeployment.issuer == issuer,
            LtiDeployment.client_id == client_id,
            LtiDeployment.deployment_id == deployment_id
        ).first()
        
        if not deployment:
            deployment = LtiDeployment(
                issuer=issuer,
                client_id=client_id,
                deployment_id=deployment_id
            )
            self.db.add(deployment)
            try:
                self.db.commit()
                self.db.refresh(deployment)
            except IntegrityError:
                self.db.rollback()
                # Try to fetch again in case of concurrent creation
                deployment = self.db.query(LtiDeployment).filter(
                    LtiDeployment.issuer == issuer,
                    LtiDeployment.client_id == client_id,
                    LtiDeployment.deployment_id == deployment_id
                ).first()
        
        return deployment

    def create_lti_session(self, lti_params: Dict[str, Any], deployment_id: int) -> LtiSession:
        """Create a new LTI session from LTI launch parameters"""
        # Extract key fields from LTI parameters
        user_id = lti_params.get('sub')  # Use sub as external_id
        user_email = lti_params.get('email')
        user_name = lti_params.get('name', lti_params.get('given_name', ''))
        context_id = lti_params.get('context_id')
        context_title = lti_params.get('context_title')
        resource_link_id = lti_params.get('resource_link_id')
        
        # Process roles - map standard IMS LTI roles to instructor/learner
        roles_claim = lti_params.get('roles', '')
        roles_list = [role.strip() for role in roles_claim.split(',')]
        simplified_roles = []
        
        for role in roles_list:
            # Match standard IMS LTI role URIs
            if any(uri in role.lower() for uri in ['instructor', 'teachingassistant']):
                if 'instructor' not in simplified_roles:
                    simplified_roles.append('instructor')
            elif 'learner' in role.lower():
                if 'learner' not in simplified_roles:
                    simplified_roles.append('learner')
        
        # Join roles with comma if we have any
        final_roles = ','.join(simplified_roles) if simplified_roles else 'learner'
        
        # Create or update session
        session = LtiSession(
            session_id=f"{user_id}_{int(datetime.utcnow().timestamp())}",
            user_id=user_id,
            user_email=user_email,
            user_name=user_name,
            context_id=context_id,
            context_title=context_title,
            resource_link_id=resource_link_id,
            roles=final_roles,
            lti_deployment_id=deployment_id
        )
        
        self.db.add(session)
        self.db.commit()
        self.db.refresh(session)
        
        return session

    def validate_and_process_lti_launch(self, id_token: str) -> Optional[LtiSession]:
        """Validate LTI token and create session if valid"""
        # Verify the LTI token using utility function
        verified_claims = verify_lti_token(id_token)
        
        if not verified_claims:
            return None
        
        # Extract required claims
        issuer = verified_claims.get('iss')
        client_id = verified_claims.get('aud') if isinstance(verified_claims.get('aud'), str) else verified_claims.get('aud')[0]
        deployment_id = verified_claims.get('https://purl.imsglobal.org/spec/lti/claim/deployment_id')
        
        # Get or create deployment
        deployment = self.get_or_create_lti_deployment(issuer, client_id, deployment_id)
        
        # Create session
        lti_session = self.create_lti_session(verified_claims, deployment.id)
        
        return lti_session

    def store_nonce(self, nonce_value: str, expires_in_seconds: int = 300) -> bool:
        """Store a nonce to prevent replay attacks"""
        try:
            # Check if nonce already exists
            existing_nonce = self.db.query(LtiNonce).filter(LtiNonce.nonce == nonce_value).first()
            
            if existing_nonce:
                # Nonce already exists, reject
                return False
            
            # Create new nonce record
            expires_at = datetime.utcnow() + timedelta(seconds=expires_in_seconds)
            nonce_record = LtiNonce(nonce=nonce_value, expires_at=expires_at)
            
            self.db.add(nonce_record)
            self.db.commit()
            
            return True
        except Exception:
            self.db.rollback()
            return False

    def mark_nonce_as_used(self, nonce_value: str) -> bool:
        """Mark a nonce as used after successful validation"""
        try:
            nonce_record = self.db.query(LtiNonce).filter(
                LtiNonce.nonce == nonce_value
            ).first()
            
            if nonce_record and not nonce_record.used and nonce_record.expires_at > datetime.utcnow():
                nonce_record.used = True
                self.db.commit()
                return True
            
            return False
        except Exception:
            self.db.rollback()
            return False

    def get_current_user_from_session(self, session_id: str):
        """Retrieve user information based on session"""
        session = self.db.query(LtiSession).filter(LtiSession.session_id == session_id).first()
        
        if not session:
            return None
        
        # Return a simple user-like object with essential attributes
        class LTIUser:
            def __init__(self, session: LtiSession):
                self.id = session.user_id
                self.email = session.user_email
                self.name = session.user_name
                self.roles = session.roles.split(',') if session.roles else []
                self.context_id = session.context_id
                self.context_title = session.context_title
        
        return LTIUser(session)