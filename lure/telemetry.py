"""Anonymous usage statistics, so we can see how Lure is used and fix what breaks.

What is sent: the command run (demo, init, listen, test...), the Lure version,
the operating system, the Python version, the bait profile name, which alert
channels are on (yes or no only), and for each alert only its severity, service
and whether it came from the demo. Each install gets a random ID that is not
linked to you.

What is never sent: IP addresses, hostnames, usernames, bait file names or
contents, alert details, webhook URLs or email addresses.

Turn it off with LURE_NO_TELEMETRY=1 or DO_NOT_TRACK=1.
"""

import atexit
import logging
import os
import platform
import sys
import threading
import uuid

from posthog import Posthog

from . import __version__

# Retained only for compatibility with callers that patch this legacy setting.
BUILTIN_KEY = None
posthog_client = None
logger = logging.getLogger(__name__)
posthog_log_logger = logging.getLogger("lure.posthog.logs")
log_provider = None

ALLOWED = {"command", "version", "os", "python", "profile", "channels", "severity", "service", "demo", "count", "baits", "files", "retired"}
LOG_ATTRIBUTES = {"event", "command", "baits", "files"}


def _key():
    return os.environ.get("POSTHOG_PROJECT_TOKEN") or os.environ.get("LURE_POSTHOG_KEY") or BUILTIN_KEY


def _host():
    return os.environ.get("POSTHOG_HOST")


def enabled():
    if os.environ.get("LURE_NO_TELEMETRY") or os.environ.get("DO_NOT_TRACK") == "1":
        return False
    return bool(_key())


def _client():
    """Return the one PostHog client for this process, if it is configured."""
    global posthog_client
    if posthog_client is not None:
        return posthog_client

    project_token, host = _key(), _host()
    if not project_token or not host:
        if os.environ.get("LURE_ENVIRONMENT") != "production":
            missing = "POSTHOG_PROJECT_TOKEN" if not project_token else "POSTHOG_HOST"
            logger.warning(
                "%s variable required by PostHog is missing or un-configured, this causes events to be silently missed. "
                "This error stops appearing once %s is configured",
                missing,
                missing,
            )
        return None

    posthog_client = Posthog(
        project_token,
        host=host,
        enable_exception_autocapture=True,
    )
    atexit.register(posthog_client.shutdown)
    return posthog_client


def _shutdown_log_provider(provider):
    try:
        provider.shutdown()
    except Exception:
        pass


def configure_log_capture():
    """Export only purpose-written Lure lifecycle logs through OTLP."""
    global log_provider
    if log_provider is not None or not enabled():
        return

    project_token, host = _key(), _host()
    if not project_token or not host:
        return

    try:
        from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
        from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
        from opentelemetry.sdk._logs.export import BatchLogRecordProcessor

        log_provider = LoggerProvider()
        log_provider.add_log_record_processor(
            BatchLogRecordProcessor(
                OTLPLogExporter(
                    endpoint=host.rstrip("/") + "/i/v1/logs",
                    headers={"Authorization": "Bearer " + project_token},
                )
            )
        )
        posthog_log_logger.addHandler(LoggingHandler(logger_provider=log_provider))
        posthog_log_logger.setLevel(logging.INFO)
        posthog_log_logger.propagate = False
        atexit.register(_shutdown_log_provider, log_provider)
    except Exception:
        log_provider = None


def log_lifecycle(event, **attributes):
    """Emit a safe, structured lifecycle log without affecting Lure's work."""
    try:
        if log_provider is None:
            return
        extra = {"event": event}
        extra.update({key: value for key, value in attributes.items() if key in LOG_ATTRIBUTES})
        posthog_log_logger.info(event.replace("_", " "), extra=extra)
    except Exception:
        pass


def _dir():
    from .notify import config_path
    return os.path.dirname(config_path())


def install_id():
    path = os.path.join(_dir(), "telemetry-id")
    try:
        with open(path) as f:
            value = f.read().strip()
            if value:
                return value
    except OSError:
        pass
    value = str(uuid.uuid4())
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(value)
    except OSError:
        pass
    return value


def notice(out=print):
    """Say once per install that stats are on, and how to turn them off."""
    try:
        _notice(out)
    except Exception:
        pass


def _notice(out):
    if not enabled():
        return
    marker = os.path.join(_dir(), "telemetry-noticed")
    if os.path.exists(marker):
        return
    out("Lure sends anonymous usage stats (command, version, OS). Never IPs, bait names or alert contents. "
        "Turn off: set LURE_NO_TELEMETRY=1.")
    try:
        os.makedirs(os.path.dirname(marker), exist_ok=True)
        open(marker, "w").close()
    except OSError:
        pass


def payload(event, props=None):
    base = {"version": __version__, "os": platform.system(), "python": "%d.%d" % sys.version_info[:2]}
    base.update({k: v for k, v in (props or {}).items() if k in ALLOWED})
    base["$process_person_profile"] = False
    return {"api_key": _key(), "event": "lure_" + event, "distinct_id": install_id(), "properties": base}


def _post(body):
    client = _client()
    if client:
        client.capture(
            distinct_id=body["distinct_id"],
            event=body["event"],
            properties=body["properties"],
        )


def send(event, props=None, post=None, wait=False):
    """Fire and forget. Never raises and never slows Lure down."""
    try:
        if not enabled():
            if not os.environ.get("LURE_NO_TELEMETRY") and os.environ.get("DO_NOT_TRACK") != "1":
                _client()
            return
        body = payload(event, props)
    except Exception:
        return
    if post:
        def go():
            try:
                post(body)
            except Exception:
                pass
        thread = threading.Thread(target=go, daemon=True)
        thread.start()
        if wait:
            thread.join(4)
        return

    try:
        _post(body)
    except Exception:
        pass
