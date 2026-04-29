from datetime import datetime
import jwt
import json
from jwt.algorithms import RSAAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import os
from services.lti import LtiService
from models import LtiNonce
from sqlalchemy.orm import Session

def load_public_key():
    """Load the public key from file and return as PEM string"""
    public_key_path = os.getenv('LTI_PUBLIC_KEY_PATH', 'lti_keys/public_key.pem')
    with open(public_key_path, 'rb') as f:
        public_key_data = f.read()
    return public_key_data.decode('utf-8')

def get_jwks():
    """Return JWKS (JSON Web Key Set) containing our public key"""
    public_key_pem = load_public_key()
    
    # Load the PEM key
    public_key = serialization.load_pem_public_key(public_key_pem.encode())
    
    # Convert to JWK format
    jwk = RSAAlgorithm.to_jwk(public_key)
    
    # Add required fields
    jwk['use'] = 'sig'  # This key is for signatures
    jwk['kid'] = 'classquiz-key-1'  # Consistent kid for our key
    
    # Return JWKS
    return {
        "keys": [jwk]
    }

def verify_lti_token(id_token: str, db: Session = None) -> dict:
    """
    Verify an LTI token according to LTI 1.3 standards
    """
    try:
        # Decode header without verification to get kid
        header = jwt.get_unverified_header(id_token)
        kid = header.get('kid')
        
        # For now, we'll just use the single key since we know our kid
        # In a more complex system, we'd match the kid to the appropriate key
        public_key_pem = load_public_key()
        
        # Verify the token
        decoded_token = jwt.decode(
            id_token,
            public_key_pem,
            algorithms=["RS256"],
            options={"verify_exp": True}  # Verify expiration
        )
        
        # Validate required LTI claims
        required_claims = [
            'iss',
            'aud',
            'https://purl.imsglobal.org/spec/lti/claim/message_type',
            'https://purl.imsglobal.org/spec/lti/claim/version',
            'https://purl.imsglobal.org/spec/lti/claim/deployment_id',
            'sub'
        ]
        
        for claim in required_claims:
            if claim not in decoded_token:
                print(f"Missing required claim: {claim}")
                return None
        
        # Validate message type
        message_type = decoded_token['https://purl.imsglobal.org/spec/lti/claim/message_type']
        if message_type != 'LtiResourceLinkRequest':
            print(f"Invalid message type: {message_type}")
            return None
        
        # Validate version
        version = decoded_token['https://purl.imsglobal.org/spec/lti/claim/version']
        if version != '1.3.0':
            print(f"Invalid LTI version: {version}")
            return None
        
        # Validate audience - check if it matches our expected client ID
        aud = decoded_token['aud']
        expected_client_id = os.getenv('LTI_CLIENT_ID')
        if isinstance(aud, list):
            if expected_client_id not in aud:
                print(f"Invalid audience: {aud}")
                return None
        else:
            if aud != expected_client_id:
                print(f"Invalid audience: {aud}")
                return None
        
        # Validate issuer
        issuer = decoded_token['iss']
        expected_issuer = os.getenv('LTI_ISSUER')
        if issuer != expected_issuer:
            print(f"Invalid issuer: {issuer}, expected: {expected_issuer}")
            return None
        
        # Validate deployment ID
        deployment_id = decoded_token['https://purl.imsglobal.org/spec/lti/claim/deployment_id']
        if not deployment_id:
            print("Missing deployment ID")
            return None
        
        # Validate nonce and prevent replay attacks if DB session provided
        if db:
            nonce = decoded_token.get('nonce')
            if nonce:
                # Check if nonce has already been used
                nonce_exists = db.query(LtiNonce).filter(
                    LtiNonce.nonce == nonce,
                    LtiNonce.used == True
                ).first()
                
                if nonce_exists:
                    print("Nonce already used - possible replay attack")
                    return None
                
                # Store the nonce to prevent reuse
                lti_service = LtiService(db)
                if not lti_service.store_nonce(nonce):
                    print("Failed to store nonce or nonce already exists")
                    return None
        
        return decoded_token
        
    except jwt.ExpiredSignatureError:
        print("Token has expired")
        return None
    except jwt.InvalidTokenError as e:
        print(f"Invalid token: {str(e)}")
        return None
    except Exception as e:
        print(f"Error verifying token: {str(e)}")
        return None