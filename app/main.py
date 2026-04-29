from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from routers import lti
import os

# Create FastAPI app instance
app = FastAPI(title="ClassQuiz LTI Tool", version="1.0.0")

# Configure CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("ALLOWED_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include LTI router
app.include_router(lti.router)

@app.get("/")
def read_root():
    return {"Hello": "World"}

@app.get("/health")
def health_check():
    return {"status": "healthy"}