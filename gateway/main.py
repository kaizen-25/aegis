"""Entry point: python -m uvicorn gateway.main:app --host 127.0.0.1 --port 8000

Building the app loads and validates the policy and every scenario, so an invalid file
stops the gateway from starting.
"""
from gateway.app import create_app

app = create_app()
