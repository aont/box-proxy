import json
import asyncio
import sys
import urllib.parse
import aiohttp.web
import aiohttp

box_device_id_key = "box_device_id"
box_device_id_value = "random device id"
redirect_uri_key = "redirect_uri"
redirect_uri_value = "boxlogin://login"

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

async def setup_runner():
    app = aiohttp.web.Application()
    app.router.add_route('*', '/{tail:.*}', handle)

    runner = aiohttp.web.AppRunner(app)
    await runner.setup()

    port = 8080
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