import json
import asyncio
import sys
import urllib.parse
import aiohttp.web
import aiohttp
import socket
import re
import configparser

def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        return s.getsockname()[1]

oath_client_id = ""
oauth_client_secret = ""
box_device_id_key = "box_device_id"
box_device_id_value = ""
redirect_uri_key = "redirect_uri"
redirect_uri_value = "boxlogin://login"
section_name_list = ("share", "data")

async def handle(request):
    method = request.method
    path = request.path
    path_qs = request.path_qs
    content_type = request.content_type
    sys.stderr.write(f"{method=} {path=} {path_qs=} {content_type=}\n")

    if path == "/authorize":
        assert method == "GET"
        query = dict(request.query)
        sys.stderr.write(f"query original: {json.dumps(query)}\n")
        query[box_device_id_key] = box_device_id_value
        query[redirect_uri_key] = redirect_uri_value
        sys.stderr.write(f"query modified: {json.dumps(query)}\n")
        query_string = urllib.parse.urlencode(query)
        return aiohttp.web.HTTPFound(location="https://account.box.com/api/oauth2/authorize?" + query_string)

    elif path == "/token":
        assert method == "POST"
        assert content_type == "application/x-www-form-urlencoded"
        params = dict(await request.post())
        sys.stderr.write(f"param original: {json.dumps(params)}\n")
        params[box_device_id_key] = box_device_id_value
        params[redirect_uri_key] = redirect_uri_value
        sys.stderr.write(f"param modified: {json.dumps(params)=}\n")
        async with aiohttp.ClientSession() as session:
            async with session.post("https://api.box.com/oauth2/token", data=params) as response:
                sys.stderr.write(f"{response.status=}\n")
                data = await response.content.read()
                sys.stderr.write(f"{data=}\n")
                return aiohttp.web.Response(
                    status=response.status,
                    content_type=response.content_type,
                    body=data,
                )

    else:
        return aiohttp.web.Response(content_type="text/plain", body="hello")

async def update_rclone_config(port):
    process = await asyncio.create_subprocess_exec(
        "rclone", "config", "dump",
        stdout=asyncio.subprocess.PIPE,
    )
    return_text = await process.stdout.read()
    returncode = await process.wait()

    if returncode != 0:
        sys.stderr.write(f"[error] {return_text.decode().strip()}\n")
        return None

    output = return_text.decode().strip()
    rclone_config: dict = json.loads(output)

    box_section_name_list = []
    for section_name, preferences in rclone_config.items():
        preferences: dict
        if preferences.get('type') == 'box':
            box_section_name_list.append(section_name)
    
    if len(box_section_name_list) == 0:
        box_section_name = "box"
        box_section_num = 0
        if not f"box{box_section_num}" in rclone_config:
            while True:
                box_section_name = f"box{box_section_num}"
                if box_section_name in rclone_config:
                    break
        box_section_name_list.append(box_section_name)

    
    for box_section_name in box_section_name_list:
        rclone_config_update_args = ["rclone", "config", "update", "--non-interactive"]

        rclone_config_update_args.append(box_section_name)
        
        rclone_config_update_args.append("type")
        rclone_config_update_args.append("box")

        rclone_config_update_args.append("client_id")
        rclone_config_update_args.append(oath_client_id)

        rclone_config_update_args.append("client_secret")
        rclone_config_update_args.append(oauth_client_secret)

        rclone_config_update_args.append("auth_url")
        rclone_config_update_args.append(f"http://127.0.0.1:{port}/authorize")

        rclone_config_update_args.append("token_url")
        rclone_config_update_args.append(f"http://127.0.0.1:{port}/token")

        process = await asyncio.create_subprocess_exec(
            *rclone_config_update_args,
            stdout=asyncio.subprocess.PIPE,
        )
        # stdout = (await process.communicate())[0]
        return_text = await process.stdout.read()
        return_obj = json.loads(return_text)
        returncode = await process.wait()
        if not (not return_obj.get("Error") and returncode == 0):
            sys.stderr.write(f"[error] {return_text=}\n")
            sys.stderr.write(f"[error] {returncode=}\n")
            raise Exception()

async def setup_runner():
    app = aiohttp.web.Application()
    app.router.add_route('*', '/{tail:.*}', handle)

    runner = aiohttp.web.AppRunner(app)
    await runner.setup()

    port = find_free_port()

    sys.stderr.write(f"[info] updating rclone config\n")
    await update_rclone_config(port)

    site = aiohttp.web.TCPSite(runner, "0.0.0.0", port)
    await site.start()
    sys.stderr.write(f"[info] Server running on port {port}\n")

    return runner
    
def main():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop=loop)
    runner = loop.run_until_complete(setup_runner())
    loop.run_forever()
    
if __name__ == "__main__":
    main()