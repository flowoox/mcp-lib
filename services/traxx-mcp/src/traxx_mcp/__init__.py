"""Independent Traxx/BeMusic MCP connector."""

__version__ = "0.3.14"

# Security boundary: ordinary Traxx API requests must never follow a server-
# controlled redirect while carrying bearer or deployment proxy/WAF headers.
# Importing the package installs the policy for every TraxxClient consumer.
from .redirect_guard import install as _install_redirect_guard  # noqa: E402

_install_redirect_guard()
