from __future__ import annotations
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Set, Optional
import configparser
import json
import logging
import sys
import time
from time import sleep
from functools import wraps
import signal

try:
    import ssl as _ssl
    import urllib3.util.ssl_ as _u3_ssl
    if not hasattr(_u3_ssl, "ssl"):
        _u3_ssl.ssl = _ssl
except Exception:
    pass

try:
    _THIS_FILE = Path(__file__).resolve()
    BASE_DIR = _THIS_FILE.parent
except NameError:
    BASE_DIR = Path.cwd()

SEEN_FILE = BASE_DIR / "seen_events.json"
CONFIG_FILE = BASE_DIR / "config.ini"

try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
except ImportError as exc:
    boto3 = None
    BotoCoreError = ClientError = Exception
    _BOTO_IMPORT_ERROR = exc
else:
    _BOTO_IMPORT_ERROR = None

try:
    from slack_sdk import WebClient
    from slack_sdk.errors import SlackApiError
    from slack_sdk.socket_mode import SocketModeClient
    from slack_sdk.socket_mode.request import SocketModeRequest
    from slack_sdk.socket_mode.response import SocketModeResponse
except ImportError as exc:
    WebClient = None
    SlackApiError = Exception
    SocketModeClient = SocketModeRequest = SocketModeResponse = None
    _SLACK_IMPORT_ERROR = exc
else:
    _SLACK_IMPORT_ERROR = None

try:
    import Logging_Framework as Log
    INFO_LOG = Log.setTenant(Log.getInfoLogger())
    ERROR_LOG = Log.setTenant(Log.getErrorLogger())
except Exception:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
    INFO_LOG = logging.getLogger("aws‑notifier.info")
    ERROR_LOG = logging.getLogger("aws‑notifier.error")

CFG = configparser.ConfigParser()
if not CFG.read(CONFIG_FILE):
    ERROR_LOG.warning("Missing %s – using environment defaults", CONFIG_FILE)

BOT_TOKEN = CFG.get("SLACK", "BOT_TOKEN", fallback="").strip()
APP_TOKEN = CFG.get("SLACK", "APP_TOKEN", fallback="").strip()
CHANNEL = CFG.get("SLACK", "CHANNEL", fallback="").strip()
POLL_SECONDS = CFG.getint("SLACK", "POLL_SECONDS", fallback=900)

_SLACK: Optional[WebClient] = None

def slack_client() -> WebClient:
    if WebClient is None:
        raise SystemExit(
            "slack_sdk is not installed – install slack_sdk, or run in diag/test mode only"
        )
    global _SLACK
    if _SLACK is None:
        if not BOT_TOKEN or not CHANNEL:
            raise SystemExit("Slack BOT_TOKEN and CHANNEL must be configured in config.ini")
        _SLACK = WebClient(token=BOT_TOKEN)
    return _SLACK

def load_seen() -> Set[str]:
    try:
        if SEEN_FILE.exists():
            return set(json.loads(SEEN_FILE.read_text()))
    except Exception as exc:
        ERROR_LOG.warning("Corrupted %s (%s) – starting fresh", SEEN_FILE, exc)
    return set()


def save_seen(arns: Set[str]) -> None:
    SEEN_FILE.write_text(json.dumps(sorted(arns)))

def rate_limit(calls_per_second=1):
    """Rate limiting decorator."""
    min_interval = 1.0 / calls_per_second
    last_call = [0.0]
    
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            now = time.time()
            elapsed = now - last_call[0]
            if elapsed < min_interval:
                sleep(min_interval - elapsed)
            result = func(*args, **kwargs)
            last_call[0] = time.time()
            return result
        return wrapper
    return decorator

@rate_limit(calls_per_second=0.5)  # AWS Health API has a limit of 2 calls per second
def _health_client():
    if _BOTO_IMPORT_ERROR is not None:
        raise SystemExit(
            "boto3/botocore failed to import – likely urllib3 mismatch.  "
            "Upgrade boto3/botocore or pin urllib3<2.  Error: "
            f"{_BOTO_IMPORT_ERROR}"
        )
    return boto3.client("health", region_name="us-east-1")


def fetch_upcoming_events() -> List[dict]:
    try:
        paginator = _health_client().get_paginator("describe_events")
        events: List[dict] = []
        for page in paginator.paginate(
            filter={
                "eventTypeCategories": ["scheduledChange"],
                "eventStatusCodes": ["upcoming"],
            },
            PaginationConfig={"PageSize": 100},
        ):
            events.extend(page["events"])

        if not events:
            return []

        details: List[dict] = []
        for i in range(0, len(events), 10):
            arns = [e["arn"] for e in events[i : i + 10]]
            details.extend(
                _health_client().describe_event_details(eventArns=arns)["successfulSet"]
            )
        INFO_LOG.info("Fetched %s upcoming events", len(details))
        return details
    except (BotoCoreError, ClientError) as exc:
        ERROR_LOG.error("AWS error: %s", exc)
        return []
    except Exception as exc:
        ERROR_LOG.exception("Unexpected AWS Health error: %s", exc)
        return []

def build_blocks(events: List[dict]) -> List[dict]:
    blocks: List[dict] = []
    for item in events:
        ev = item["event"]
        desc = item["eventDescription"]["latestDescription"]
        start = ev.get("startTime")
        start_str = (
            start.strftime("%Y-%m-%d %H:%M UTC") if isinstance(start, datetime) else str(start)
        )
        header = f"*{ev['service']}*: `{ev['eventTypeCode']}`"
        region = ev.get("region", "ALL")
        blocks.extend(
            [
                {"type": "section", "text": {"type": "mrkdwn", "text": header}},
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Region:* {region}"},
                        {"type": "mrkdwn", "text": f"*Starts:* {start_str}"},
                    ],
                },
                {"type": "section", "text": {"type": "mrkdwn", "text": desc}},
                {"type": "divider"},
            ]
        )
    return blocks


@rate_limit(calls_per_second=1)  # Slack API has a limit of 1 call per second
def post_blocks(blocks: List[dict], fallback: str) -> None:
    try:
        slack_client().chat_postMessage(
            channel=CHANNEL,
            text=fallback,
            blocks=blocks,
            username="AWS‑Notifier",
            icon_url=(
                "https://thumbs.dreamstime.com/z/ai-artificial-intelligence-technology-"
                "robot-cartoon-design-element-vector-illustration-eps-136666412.jpg"
            ),
        )
        INFO_LOG.info("Posted message with %s event(s)", len(blocks) // 4)
    except SlackApiError as exc:
        ERROR_LOG.error("Slack API error: %s", exc.response.get("error"))
    except Exception as exc:
        ERROR_LOG.exception("Unexpected Slack error: %s", exc)

def scan_once(seen: Optional[Set[str]] = None) -> Set[str]:
    events = fetch_upcoming_events()
    if not events:
        INFO_LOG.info("No upcoming events detected in this scan.")
        return seen or set()

    seen = seen or load_seen()
    new_events = [e for e in events if e["event"]["arn"] not in seen]
    if new_events:
        post_blocks(build_blocks(new_events), "New AWS Health scheduled‑change events detected")
        seen.update(e["event"]["arn"] for e in new_events)
        save_seen(seen)
    else:
        INFO_LOG.info("No new events since previous scan.")
    return seen

def handle_shutdown(signum, frame):
    """Handle shutdown signals gracefully."""
    INFO_LOG.info("Received shutdown signal %d - cleaning up...", signum)
    sys.exit(0)

def daemon_mode() -> None:
    INFO_LOG.info("Daemon started – polling every %s s", POLL_SECONDS)
    seen = load_seen()
    
    # Set up signal handlers
    signal.signal(signal.SIGTERM, handle_shutdown)
    signal.signal(signal.SIGINT, handle_shutdown)
    
    try:
        while True:
            seen = scan_once(seen)
            time.sleep(POLL_SECONDS)
    except KeyboardInterrupt:
        INFO_LOG.info("Daemon interrupted – exiting.")
    finally:
        INFO_LOG.info("Saving final state...")
        save_seen(seen)


def listen_mode() -> None:
    if SocketModeClient is None:
        raise SystemExit("slack_sdk.SocketMode is unavailable – install slack_sdk>=3.11")
    if not APP_TOKEN:
        raise SystemExit("APP_TOKEN must be set in config.ini for listen mode")

    client = SocketModeClient(app_token=APP_TOKEN, web_client=slack_client())

    @client.socket_mode_request_listeners.append
    def _handler(req: SocketModeRequest):
        if req.type != "events_api":
            return
        client.send_socket_mode_response(SocketModeResponse(envelope_id=req.envelope_id))
        ev = req.payload.get("event", {})
        if ev.get("type") == "app_mention" and "show" in ev.get("text", "").lower():
            events = fetch_upcoming_events()
            if not events:
                slack_client().chat_postMessage(channel=ev["channel"], thread_ts=ev.get("ts"), text="No upcoming scheduled‑change events 📭")
            else:
                slack_client().chat_postMessage(channel=ev["channel"], thread_ts=ev.get("ts"), text="Upcoming AWS Health scheduled‑change events", blocks=build_blocks(events))

    INFO_LOG.info("Socket‑Mode listener started …")
    client.connect()
    client.wait_until_ready()


def diag_mode() -> None:
    try:
        events = fetch_upcoming_events()
        print(f"DIAG OK – fetched {len(events)} upcoming event(s)")
    except Exception as exc:
        print(f"DIAG FAILURE – {exc}")
        raise

def _self_test() -> None:
    print("Running self‑tests …")
    if Path.cwd() != BASE_DIR and "__file__" not in globals():
        raise AssertionError("BASE_DIR fallback failed")

    tmp = BASE_DIR / "_tmp_seen.json"
    try:
        global SEEN_FILE
        original = SEEN_FILE
        SEEN_FILE = tmp
        data = {"arn:aws:health::event/alpha", "arn:aws:health::event/beta"}
        save_seen(data)
        assert load_seen() == data, "Persistence mismatch"
        print("Self‑tests passed ✔")
    finally:
        if tmp.exists():
            tmp.unlink()
        SEEN_FILE = original

def health_check() -> dict:
    """Return health status of the script's components."""
    status = {
        "aws_connection": False,
        "slack_connection": False,
        "config_loaded": False,
        "last_scan": None,
        "errors": []
    }
    
    try:
        # Check AWS connection
        _health_client().describe_events(maxResults=1)
        status["aws_connection"] = True
    except Exception as e:
        status["errors"].append(f"AWS Health API error: {str(e)}")
    
    try:
        # Check Slack connection
        if BOT_TOKEN and CHANNEL:
            slack_client().auth_test()
            status["slack_connection"] = True
    except Exception as e:
        status["errors"].append(f"Slack API error: {str(e)}")
    
    # Check config
    status["config_loaded"] = bool(CFG.sections())
    
    # Get last scan time from seen events file
    try:
        if SEEN_FILE.exists():
            status["last_scan"] = datetime.fromtimestamp(SEEN_FILE.stat().st_mtime).isoformat()
    except Exception as e:
        status["errors"].append(f"File system error: {str(e)}")
    
    return status

if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "once"

    if mode == "once":
        scan_once()
    elif mode == "daemon":
        daemon_mode()
    elif mode == "listen":
        listen_mode()
    elif mode == "diag":
        diag_mode()
    elif mode == "test":
        _self_test()
    elif mode == "health":
        print(json.dumps(health_check(), indent=2))
    else:
        sys.exit("Usage: aws_notifier.py [once|daemon|listen|diag|test|health]")
