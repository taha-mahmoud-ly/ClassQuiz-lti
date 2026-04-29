from fastapi import APIRouter, Request, HTTPException, Depends
from fastapi.responses import RedirectResponse
from urllib.parse import urlencode
import os
from typing import Dict, Any
from utils.lti import get_jwks, verify_lti_token
from services.lti import LtiService
from models import LtiSession
from database import get_db
from sqlalchemy.orm import Session

router = APIRouter(prefix="/lti", tags=["lti"])

@router.get("/login/")
async def lti_login(
    login_hint: str,
    target_link_uri: str,
    lti_message_hint: str = None,
    db: Session = Depends(get_db)
):
    """
    LTI 1.3 Login Initiatior endpoint
    This endpoint receives the initial login request from the platform
    and redirects to the platform's authorization endpoint.
    """
    # Get required environment variables
    client_id = os.getenv('LTI_CLIENT_ID')
    auth_login_url = os.getenv('LTI_AUTH_LOGIN_URL')  # Platform's OIDC auth URL
    redirect_uri = os.getenv('LTI_REDIRECT_URI')  # Our launch URI
    
    if not client_id or not auth_login_url or not redirect_uri:
        raise HTTPException(status_code=500, detail="Missing required LTI environment variables")
    
    # Build the authentication request
    params = {
        "response_type": "id_token",
        "response_mode": "form_post",
        "scope": "openid",
        "login_hint": login_hint,
        "client_id": client_id,
        "target_link_uri": target_link_uri,
        "redirect_uri": redirect_uri,
    }
    
    # Add lti_message_hint if present
    if lti_message_hint:
        params["lti_message_hint"] = lti_message_hint
    
    # Generate a state parameter to maintain state between login request and callback
    import secrets
    state = secrets.token_urlsafe(32)
    params["state"] = state
    
    # Redirect to the platform's authentication endpoint
    auth_url = f"{auth_login_url}?{urlencode(params)}"
    return RedirectResponse(url=auth_url)

@router.post("/launch/")
async def lti_launch(
    id_token: str,  # This will come from form post
    db: Session = Depends(get_db)
):
    """
    LTI 1.3 Launch Validator endpoint
    Validates the JWT token sent by the platform and creates a session
    """
    if not id_token:
        raise HTTPException(status_code=400, detail="ID token is required")
    
    # Verify the LTI token
    lti_service = LtiService(db)
    lti_session = lti_service.validate_and_process_lti_launch(id_token)
    
    if not lti_session:
        raise HTTPException(status_code=401, detail="Invalid LTI token")
    
    # Mark the nonce as used after successful validation
    # First decode the token to get the nonce without verification
    import jwt
    unverified_header = jwt.get_unverified_header(id_token)
    unverified_payload = jwt.decode(id_token, options={"verify_signature": False})
    nonce = unverified_payload.get('nonce')
    
    if nonce:
        lti_service.mark_nonce_as_used(nonce)
    
    # Return success response with session info
    return {
        "status": "success",
        "session_id": lti_session.session_id,
        "user_id": lti_session.user_id,
        "user_name": lti_session.user_name,
        "user_email": lti_session.user_email,
        "roles": lti_session.roles,
        "context_id": lti_session.context_id,
        "context_title": lti_session.context_title,
        "resource_link_id": lti_session.resource_link_id
    }

@router.get("/jwks")
async def jwks():
    """
    JSON Web Key Set endpoint
    Returns the public keys that platforms can use to verify signatures
    """
    return get_jwks()