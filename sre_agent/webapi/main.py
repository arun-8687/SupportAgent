"""
uvicorn entrypoint for the web API.

Production runs `uvicorn sre_agent.webapi.main:app` (App Service, Always On)
or `python -m sre_agent.webapi`. The module-level `app` is what uvicorn's
`--workers` importer needs; `run()` is the convenience launcher.
"""
import logging

from sre_agent.config import get_settings
from sre_agent.observability import configure_telemetry
from sre_agent.webapi.app import create_app

logging.basicConfig(level=logging.INFO)
configure_telemetry()

# Importable ASGI app for `uvicorn sre_agent.webapi.main:app --workers N`.
app = create_app()


def run() -> None:
    import uvicorn

    settings = get_settings()
    uvicorn.run(
        "sre_agent.webapi.main:app",
        host=settings.webapi_host,
        port=settings.webapi_port,
        log_level="info",
    )


if __name__ == "__main__":
    run()
