"""
©AngelaMos | 2026
__init__.py
"""

from flask import Flask
from flask_cors import CORS

from app.config import settings


def create_app() -> Flask:
    """
    Application factory that
    wires up all extensions and blueprints
    """
    app = Flask(__name__)
    app.config.from_mapping(
        MONGO_URI = settings.MONGO_URI,
        MONGO_DB = settings.MONGO_DB,
        REDIS_URL = settings.REDIS_URL,
        SECRET_KEY = settings.SECRET_KEY,
        DEBUG = settings.DEBUG,
    )

    CORS(app, origins = settings.CORS_ORIGINS)

    from app.extensions import init_mongo, init_redis
    init_mongo(app)
    init_redis(app)

    from app.core.errors import register_error_handlers
    register_error_handlers(app)

    from app.core.rate_limiting import init_limiter
    init_limiter(app)

    from app.routes import register_blueprints
    register_blueprints(app)

    from app.cli import register_cli
    register_cli(app)

    from app.core.streaming import ensure_consumer_group
    ensure_consumer_group(settings.LOG_STREAM_KEY)
    ensure_consumer_group(settings.ALERT_STREAM_KEY)

    from app.models.ScenarioRun import ScenarioRun
    for orphan in ScenarioRun.get_active_runs():
        orphan.mark_stopped()

    from app.engine.correlation import start_engine
    start_engine()

    @app.get("/health")
    def health():  # type: ignore[no-untyped-def]
        return "1"

    return app
