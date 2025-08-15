"""
API Blueprint for MCP Server
"""

from flask import Blueprint

# Create API blueprint
api_bp = Blueprint('api', __name__)

# Import routes to register them with the blueprint
from . import signatures
from . import logs
from . import feedback
from . import health