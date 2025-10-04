# -*- coding: utf-8 -*-
"""
Box OAuth の /authorize, /token を仲介するミニサーバを aiohttp で実装。
起動時に rclone の box リモートの設定 (client_id 等) をローカルの仲介URLに更新します。

- GET  /authorize: クエリに device_id, redirect_uri を付与して Box の認可画面へ 302 リダイレクト
- POST /token    : フォームに device_id, redirect_uri を付与して Box のトークンエンドポイントへ転送
- GET  /         : 動作確認 (hello)
- GET  /health   : ヘルスチェック (ok)

依存: aiohttp
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import logging
import socket
import subprocess
import sys
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple

from aiohttp import ClientSession, web

# === 定数 =====================================================================

BOX_AUTHORIZE_URL = "https://account.box.com/api/oauth2/authorize"
BOX_TOKEN_URL = "https://api.box.com/oauth2/token"
FORM_CT = "application/x-www-form-urlencoded"
MAX_LOG_BYTES = 2000  # レスポンスボディのログを過度に膨らませないための上限

STATE_DIR = Path.home() / ".box_proxy"
PORT_FILE = STATE_DIR / "port"
APPLICATIONS_DIR = Path.home() / ".local/share/applications"
DESKTOP_FILE_NAME = "box-proxy-boxlogin.desktop"
DESKTOP_FILE_PATH = APPLICATIONS_DIR / DESKTOP_FILE_NAME
DEFAULT_CONFIG_PATH = Path("config.json")


# === 設定 =====================================================================

@dataclass(frozen=True)
class AppConfig:
    device_id: str
    redirect_uri: str
    client_id: str
    client_secret: str

    @staticmethod
    def from_file(path: str) -> "AppConfig":
        with open(path, "rb") as fp:
            obj = json.load(fp)
        return AppConfig(
            device_id=obj["device_id"],
            redirect_uri=obj["redirect_uri"],
            client_id=obj["client_id"],
            client_secret=obj["client_secret"],
        )


# === ユーティリティ ============================================================


def ensure_state_dir() -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)


def save_port(port: int) -> None:
    ensure_state_dir()
    PORT_FILE.write_text(f"{port}\n", encoding="utf-8")


def load_port() -> int:
    try:
        value = PORT_FILE.read_text(encoding="utf-8").strip()
    except FileNotFoundError as exc:
        raise RuntimeError("Port information not found. Run the 'serve' command first.") from exc

    if not value:
        raise RuntimeError("Port information file is empty. Run the 'serve' command again.")

    try:
        return int(value)
    except ValueError as exc:
        raise RuntimeError("Invalid port value stored. Run the 'serve' command again.") from exc


def setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s: %(message)s",
    )


def parse_qs_first(qs: str) -> Dict[str, str]:
    """
    urllib.parse.parse_qs() は各値がリストになるので、先頭要素のみ取り出す。
    例: "a=1&a=2" -> {"a": "1"}  （※元コードと同じ挙動）
    """
    parsed = urllib.parse.parse_qs(qs, keep_blank_values=True)
    return {k: v[0] for k, v in parsed.items()}


def parse_urlencoded_first(body: str) -> Dict[str, str]:
    parsed = urllib.parse.parse_qs(body, keep_blank_values=True)
    return {k: v[0] for k, v in parsed.items()}


def is_form_urlencoded(content_type: str | None) -> bool:
    if not content_type:
        return False
    return content_type.split(";", 1)[0].strip().lower() == FORM_CT


def build_redirect(base: str, params: Dict[str, str]) -> str:
    return f"{base}?{urllib.parse.urlencode(params)}"


def log_request(req: web.Request) -> None:
    logging.info(
        "method=%s path=%s query_string=%s content_type=%s",
        req.method,
        req.path,
        req.query_string,
        req.headers.get("Content-Type", ""),
    )


def shorten_bytes(b: bytes, limit: int = MAX_LOG_BYTES) -> str:
    s = b.decode(errors="replace")
    return s if len(s) <= limit else s[:limit] + "...(truncated)"


# === ハンドラ ================================================================

class OAuthProxy:
    def __init__(self, config: AppConfig):
        self.config = config

    async def authorize(self, request: web.Request) -> web.Response:
        log_request(request)
        original = parse_qs_first(request.query_string)
        logging.debug("query original: %s", json.dumps(original, ensure_ascii=False))
        modified = {
            **original,
            "device_id": self.config.device_id,
            "redirect_uri": self.config.redirect_uri,
        }
        logging.debug("query modified: %s", json.dumps(modified, ensure_ascii=False))
        location = build_redirect(BOX_AUTHORIZE_URL, modified)
        raise web.HTTPFound(location)

    async def token(self, request: web.Request) -> web.Response:
        log_request(request)
        content_type = request.headers.get("Content-Type", "")
        if not is_form_urlencoded(content_type):
            raise web.HTTPBadRequest(text="Invalid Content-Type")

        # 元実装と同じく生ボディを読み、URLエンコードを自力で解釈して先頭値のみ採用
        body_text = (await request.read()).decode("utf-8")
        params = parse_urlencoded_first(body_text)
        logging.debug("param original: %s", json.dumps(params, ensure_ascii=False))

        # 必須パラメータを追加
        params["device_id"] = self.config.device_id
        params["redirect_uri"] = self.config.redirect_uri
        logging.debug("param modified: %s", json.dumps(params, ensure_ascii=False))

        session: ClientSession = request.app["http_client"]
        try:
            # aiohttp は dict を渡すと application/x-www-form-urlencoded で送信してくれる
            async with session.post(
                BOX_TOKEN_URL,
                data=params,
                headers={"Content-Type": FORM_CT},
            ) as resp:
                status = resp.status
                content = await resp.read()
                resp_ct = resp.headers.get("Content-Type", "application/octet-stream")
        except Exception:
            logging.exception("Error making POST request to Box")
            raise web.HTTPInternalServerError(text="Internal Server Error")

        logging.info("response.status_code=%s", status)
        logging.debug("response.content=%s", shorten_bytes(content))
        return web.Response(status=status, body=content, headers={"Content-Type": resp_ct})


# === rclone 設定更新（非同期サブプロセス） ====================================

async def _run(cmd: List[str]) -> Tuple[int, bytes, bytes]:
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await proc.communicate()
    return proc.returncode, stdout, stderr


async def update_rclone_config(port: int, config: AppConfig) -> None:
    """
    rclone の設定を JSON で取得し、box タイプのセクションに対して
    client_id, client_secret, auth_url, token_url を更新する。
    """
    rc, out, err = await _run(["rclone", "config", "dump"])
    if rc != 0:
        logging.error("[error] rclone config dump failed: %s", err.decode(errors="replace").strip())
        return

    try:
        rclone_config = json.loads(out.decode())
    except json.JSONDecodeError as e:
        logging.error("[error] JSON decode error: %s", e)
        return

    # box タイプのセクション名を収集
    box_sections: List[str] = [
        name
        for name, prefs in rclone_config.items()
        if isinstance(prefs, dict) and prefs.get("type") == "box"
    ]

    # box セクションが存在しない場合、"box" または "box*" を利用
    if not box_sections:
        if "box" in rclone_config:
            candidate = "box"
        else:
            candidate = next((k for k in rclone_config.keys() if k.startswith("box")), "box")
        box_sections = [candidate]

    update_args = [
        "type",
        "box",
        "client_id",
        config.client_id,
        "client_secret",
        config.client_secret,
        "auth_url",
        f"http://127.0.0.1:{port}/authorize",
        "token_url",
        f"http://127.0.0.1:{port}/token",
    ]

    # 各 box セクションに対して rclone の設定を更新する
    for section in box_sections:
        rc, out, err = await _run(
            ["rclone", "config", "update", "--non-interactive", section, *update_args]
        )
        if rc != 0:
            logging.error("[error] rclone config update failed: %s", err.decode(errors="replace").strip())
            raise RuntimeError("rclone config update failed")

        text = out.decode()
        try:
            obj = json.loads(text)
        except json.JSONDecodeError as e:
            logging.error("[error] JSON decode error in update: %s", e)
            raise RuntimeError("rclone config update JSON decode error")

        if obj.get("Error") or rc != 0:
            logging.error("[error] %s", text)
            logging.error("[error] return code: %s", rc)
            raise RuntimeError("rclone config update error")

    # 正常終了時は None を返す（そのまま終了）


# === アプリ作成・起動 ==========================================================

async def on_startup(app: web.Application):
    app["http_client"] = ClientSession()


async def on_cleanup(app: web.Application):
    await app["http_client"].close()


def create_app(config: AppConfig) -> web.Application:
    app = web.Application()
    app["config"] = config
    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)

    proxy = OAuthProxy(config)
    app.add_routes(
        [
            web.get("/authorize", proxy.authorize),  # 405 は aiohttp が自動で返す
            web.post("/token", proxy.token),
            web.get("/", lambda req: web.Response(text="hello")),
            web.get("/health", lambda req: web.Response(text="ok")),
        ]
    )
    return app


async def serve(app: web.Application, host: str = "0.0.0.0") -> None:
    """
    ポート 0 でバインドすると実際のポートが分かりづらいので、
    先にソケットを自前でバインドしてポートを確定させる。
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((host, 0))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.listen(128)
    sock.setblocking(False)
    port = sock.getsockname()[1]
    save_port(port)
    logging.info("[info] saved port=%s to %s", port, PORT_FILE)

    runner = web.AppRunner(app)
    await runner.setup()

    # SockSite で事前に割り当てたソケットを使って起動
    site = web.SockSite(runner, sock=sock)
    await site.start()

    logging.info("[info] updating rclone config")
    await update_rclone_config(port, app["config"])
    logging.info("[info] Server running on port %s", port)

    try:
        # サーバを走らせ続ける
        await asyncio.Event().wait()
    finally:
        await runner.cleanup()


# === CLI サポート =============================================================


def build_authorize_payload(port: int, config: AppConfig) -> str:
    payload = {
        "auth_url": f"http://127.0.0.1:{port}/authorize",
        "client_id": config.client_id,
        "client_secret": config.client_secret,
        "token_url": f"http://127.0.0.1:{port}/token",
    }
    return base64.b64encode(json.dumps(payload).encode()).decode()


def parse_token_from_output(text: str) -> str:
    ptfiyrm = "Paste the following into your remote machine --->"
    ep = "<---End paste"
    start = text.find(ptfiyrm)
    end = text.rfind(ep)
    if start == -1 or end == -1 or end < start:
        raise RuntimeError("Failed to parse token information from rclone output.")

    b64_text = text[start + len(ptfiyrm) : end].strip()
    pad = (4 - (len(b64_text) % 4)) % 4
    b64_text += "=" * pad
    print(b64_text)
    return json.loads(base64.b64decode(b64_text))["token"]


def run_rclone_authorize(port: int, config: AppConfig) -> str:
    payload = build_authorize_payload(port, config)
    cmd = ["rclone", "authorize", "box", payload]
    logging.info("[info] running command: %s", " ".join(cmd))
    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        logging.error(proc.stderr.strip())
        raise RuntimeError("rclone authorize command failed")

    logging.info(proc.stdout)
    return parse_token_from_output(proc.stdout)


def create_rclone_config_entry(name: str, port: int, config: AppConfig, token_json: str) -> None:
    cmd = [
        "rclone",
        "config",
        "create",
        "--non-interactive",
        name,
        "box",
        "client_id",
        config.client_id,
        "client_secret",
        config.client_secret,
        "auth_url",
        f"http://127.0.0.1:{port}/authorize",
        "token_url",
        f"http://127.0.0.1:{port}/token",
        "token",
        token_json,
    ]
    logging.info("[info] running command: %s", " ".join(cmd[:-1] + ["<token-json>"]))
    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        logging.error(proc.stderr.strip())
        raise RuntimeError("rclone config create failed")

    logging.debug(proc.stdout)


def register_boxlogin_handler(script_path: Path) -> None:
    if sys.platform.startswith("linux"):
        APPLICATIONS_DIR.mkdir(parents=True, exist_ok=True)
        desktop_entry = """[Desktop Entry]
Version=1.0
Type=Application
Name=Box Proxy boxlogin handler
Exec={exec_path} {script} _boxlogin %u
NoDisplay=true
MimeType=x-scheme-handler/boxlogin;
""".format(exec_path=sys.executable, script=script_path)
        DESKTOP_FILE_PATH.write_text(desktop_entry, encoding="utf-8")
        logging.info("[info] registered desktop entry at %s", DESKTOP_FILE_PATH)
        try:
            subprocess.run(
                [
                    "xdg-mime",
                    "default",
                    DESKTOP_FILE_NAME,
                    "x-scheme-handler/boxlogin",
                ],
                check=True,
            )
            logging.info("[info] associated boxlogin scheme via xdg-mime")
        except FileNotFoundError:
            logging.warning("xdg-mime not found; please register the boxlogin handler manually if necessary.")
        except subprocess.CalledProcessError as exc:
            logging.warning("xdg-mime returned non-zero exit status: %s", exc)
    elif sys.platform.startswith("win"):
        try:
            import winreg
        except ImportError:
            logging.warning("winreg module not available; cannot register boxlogin handler automatically.")
            return

        command = f'"{sys.executable}" "{script_path}" _boxlogin "%1"'
        try:
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\\Classes\\boxlogin") as key:
                winreg.SetValueEx(key, None, 0, winreg.REG_SZ, "URL:boxlogin Protocol")
                winreg.SetValueEx(key, "URL Protocol", 0, winreg.REG_SZ, "")
            with winreg.CreateKey(
                winreg.HKEY_CURRENT_USER, r"Software\\Classes\\boxlogin\\shell\\open\\command"
            ) as cmd_key:
                winreg.SetValueEx(cmd_key, None, 0, winreg.REG_SZ, command)
            logging.info("[info] registered boxlogin handler in Windows registry")
        except OSError as exc:
            logging.warning("Failed to register boxlogin handler in Windows registry: %s", exc)
    else:
        logging.warning(
            "Automatic boxlogin handler registration is not supported on this platform (%s).",
            sys.platform,
        )


def command_serve(args: argparse.Namespace) -> None:
    config = AppConfig.from_file(args.config)
    app = create_app(config)
    try:
        asyncio.run(serve(app, host=args.host))
    except KeyboardInterrupt:
        logging.info("Server interrupted, shutting down.")


def command_authorize(args: argparse.Namespace) -> None:
    config = AppConfig.from_file(args.config)
    port = load_port()
    register_boxlogin_handler(Path(__file__).resolve())
    token_json = run_rclone_authorize(port, config)
    logging.info("[info] received token from rclone authorize")
    create_rclone_config_entry(args.boxentryname, port, config, token_json)
    logging.info("[info] rclone configuration updated for entry '%s'", args.boxentryname)


def command_boxlogin(args: argparse.Namespace) -> None:
    # port = load_port()
    port = 53682
    url = urllib.parse.urlparse(args.url)
    if url.scheme != "boxlogin":
        raise RuntimeError("Invalid scheme for _boxlogin handler")

    query = url.query
    target = f"http://127.0.0.1:{port}/?{query}"

    logging.info("[info] forwarding boxlogin callback to %s", target)
    request = urllib.request.Request(target, method="GET")
    with urllib.request.urlopen(request, timeout=30) as response:
        logging.info("[info] forwarded with status %s", response.status)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Box proxy utility")
    subparsers = parser.add_subparsers(dest="command")
    subparsers.required = True

    serve_parser = subparsers.add_parser("serve", help="Start the proxy server")
    serve_parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH), help="Path to config.json")
    serve_parser.add_argument("--host", default="0.0.0.0", help="Host address to bind")
    serve_parser.set_defaults(func=command_serve)

    authorize_parser = subparsers.add_parser("authorize", help="Run rclone box authorization helper")
    authorize_parser.add_argument("boxentryname", help="rclone config entry name to create")
    authorize_parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH), help="Path to config.json")
    authorize_parser.set_defaults(func=command_authorize)

    boxlogin_parser = subparsers.add_parser("_boxlogin", help="Internal handler for boxlogin scheme")
    boxlogin_parser.add_argument("url", help="boxlogin URL provided by the browser")
    boxlogin_parser.set_defaults(func=command_boxlogin)

    return parser


def main(argv: List[str] | None = None) -> None:
    setup_logging()
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except RuntimeError as exc:
        logging.error("%s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
