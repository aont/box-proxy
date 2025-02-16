import json
import sys
import urllib.parse
import urllib.request
import urllib.error
import http.client
import subprocess
import wsgiref.simple_server # make_server

# 定数
oath_client_id = "1y4ddq8mohgjyat6767yda5zca9ytxu3"
oauth_client_secret = "H7aF3eXr4KxoomlFKiFx8HRheBBlfYlo"
box_device_id_key = "box_device_id"
box_device_id_value = "7e99dafd7a5ffa309d82113cc05360e808cb679b5a8720d55769516ef2c20f3a"
redirect_uri_key = "redirect_uri"
redirect_uri_value = "boxlogin://login"

def parse_qs_flat(qs):
    """parse_qs() は各値がリストになるので、先頭要素のみ取り出す"""
    parsed = urllib.parse.parse_qs(qs)
    return {k: v[0] for k, v in parsed.items()}

def app(environ, start_response):
    method = environ.get("REQUEST_METHOD", "")
    path = environ.get("PATH_INFO", "")
    query_string = environ.get("QUERY_STRING", "")
    content_type = environ.get("CONTENT_TYPE", "")
    sys.stderr.write(f"method={method} path={path} query_string={query_string} content_type={content_type}\n")
    
    if path == "/authorize":
        if method != "GET":
            start_response("405 Method Not Allowed", [("Content-Type", "text/plain")])
            return [b"Method Not Allowed"]
        query = parse_qs_flat(query_string)
        sys.stderr.write(f"query original: {json.dumps(query)}\n")
        # 必要なパラメータを追加
        query[box_device_id_key] = box_device_id_value
        query[redirect_uri_key] = redirect_uri_value
        sys.stderr.write(f"query modified: {json.dumps(query)}\n")
        new_query = urllib.parse.urlencode(query)
        location = "https://account.box.com/api/oauth2/authorize?" + new_query
        start_response("302 Found", [("Location", location)])
        return [b""]
    
    elif path == "/token":
        if method != "POST":
            start_response("405 Method Not Allowed", [("Content-Type", "text/plain")])
            return [b"Method Not Allowed"]
        if content_type != "application/x-www-form-urlencoded":
            start_response("400 Bad Request", [("Content-Type", "text/plain")])
            return [b"Invalid Content-Type"]
        try:
            content_length = int(environ.get("CONTENT_LENGTH", "0"))
        except (ValueError, TypeError):
            content_length = 0
        body = environ["wsgi.input"].read(content_length).decode("utf-8")
        params = urllib.parse.parse_qs(body)
        params = {k: v[0] for k, v in params.items()}
        sys.stderr.write(f"param original: {json.dumps(params)}\n")
        # 必要なパラメータを追加
        params[box_device_id_key] = box_device_id_value
        params[redirect_uri_key] = redirect_uri_value
        sys.stderr.write(f"param modified: {json.dumps(params)}\n")
        
        # POST リクエスト用のデータ作成
        post_data = urllib.parse.urlencode(params).encode("utf-8")
        req = urllib.request.Request("https://api.box.com/oauth2/token", data=post_data, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        try:
            with urllib.request.urlopen(req) as resp:
                status_code = resp.getcode()
                content = resp.read()
                resp_content_type = resp.headers.get("Content-Type", "application/octet-stream")
        except urllib.error.HTTPError as e:
            status_code = e.code
            content = e.read()
            resp_content_type = e.headers.get("Content-Type", "application/octet-stream")
        except Exception as e:
            sys.stderr.write(f"Error making POST request: {e}\n")
            start_response("500 Internal Server Error", [("Content-Type", "text/plain")])
            return [b"Internal Server Error"]
        
        sys.stderr.write(f"response.status_code={status_code}\n")
        sys.stderr.write(f"response.content={content}\n")
        reason = http.client.responses.get(status_code, "")
        status_line = f"{status_code} {reason}"
        start_response(status_line, [("Content-Type", resp_content_type)])
        return [content]
    
    else:
        start_response("200 OK", [("Content-Type", "text/plain")])
        return [b"hello"]

def update_rclone_config(port):
    """
    rclone の設定を JSON で取得し、box タイプのセクションに対して
    client_id, client_secret, auth_url, token_url を更新する。
    """
    try:
        proc = subprocess.run(
            ["rclone", "config", "dump"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True
        )
    except subprocess.CalledProcessError as e:
        sys.stderr.write(f"[error] rclone config dump failed: {e.stderr.decode().strip()}\n")
        return None
    output = proc.stdout.decode().strip()
    try:
        rclone_config = json.loads(output)
    except json.JSONDecodeError as e:
        sys.stderr.write(f"[error] JSON decode error: {e}\n")
        return None

    # box タイプのセクション名を収集
    box_section_name_list = []
    for section_name, preferences in rclone_config.items():
        if isinstance(preferences, dict) and preferences.get("type") == "box":
            box_section_name_list.append(section_name)
    
    # box セクションが存在しない場合、"box" または "box*" を利用
    if not box_section_name_list:
        if "box" in rclone_config:
            box_section_name = "box"
        else:
            box_section_name = None
            for key in rclone_config.keys():
                if key.startswith("box"):
                    box_section_name = key
                    break
            if box_section_name is None:
                box_section_name = "box"
        box_section_name_list.append(box_section_name)

    rclone_config_update_args = (
        "type", "box",
        "client_id", oath_client_id,
        "client_secret", oauth_client_secret,
        "auth_url", f"http://127.0.0.1:{port}/authorize",
        "token_url", f"http://127.0.0.1:{port}/token",
    )

    # 各 box セクションに対して rclone の設定を更新する
    for box_section_name in box_section_name_list:
        try:
            proc = subprocess.run(
                tuple((
                    "rclone", "config", "update",
                    "--non-interactive", box_section_name,
                    *rclone_config_update_args,
                )),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True
            )
        except subprocess.CalledProcessError as e:
            sys.stderr.write(f"[error] rclone config update failed: {e.stderr.decode().strip()}\n")
            raise Exception("rclone config update failed")
        return_text = proc.stdout.decode()
        try:
            return_obj = json.loads(return_text)
        except json.JSONDecodeError as e:
            sys.stderr.write(f"[error] JSON decode error in update: {e}\n")
            raise Exception("rclone config update JSON decode error")
        if return_obj.get("Error") or proc.returncode != 0:
            sys.stderr.write(f"[error] {return_text}\n")
            sys.stderr.write(f"[error] return code: {proc.returncode}\n")
            raise Exception("rclone config update error")
    # 正常終了時は None を返す

def main():
    httpd = wsgiref.simple_server.make_server("0.0.0.0", 0, app)
    sys.stderr.write("[info] updating rclone config\n")
    update_rclone_config(httpd.server_port)
    sys.stderr.write(f"[info] Server running on port {httpd.server_port}\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write("Server interrupted, shutting down.\n")

if __name__ == "__main__":
    main()
