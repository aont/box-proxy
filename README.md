# rclone box proxy
A proxy that modifies some data when connecting to Box using `rclone`.

## Usage

The `box_proxy.py` script now exposes a unified command interface with multiple sub-commands:

### 1. Start the proxy server

```
python box_proxy.py serve --config config.json
```

This command launches the proxy, remembers the dynamically assigned port under `~/.box_proxy/port`, and rewrites existing `rclone` Box entries so that they use the local proxy endpoints.

### 2. Complete the Box authorization

```
python box_proxy.py authorize <boxentryname> --config config.json
```

`boxentryname` is the name for the entry that will be written into `rclone.conf`. The command registers a handler for the `boxlogin://` scheme (on Linux systems via `xdg-mime`). On Windows the handler is added to the registry under `HKEY_CURRENT_USER\Software\Classes\boxlogin` with the following structure:

```
Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\Software\Classes\boxlogin]
@="URL:boxlogin Protocol"
"URL Protocol"=""

[HKEY_CURRENT_USER\Software\Classes\boxlogin\shell\open\command]
@="\"C:\\Path\\to\\python.exe\" \"C:\\Path\\to\\box_proxy.py\" _boxlogin \"%1\""
```

After associating the handler, the command invokes `rclone authorize box ...`, waits for the browser-based login flow to complete, parses the resulting token, and finally stores it in `rclone.conf` via `rclone config create`.

### 3. boxlogin handler

The proxy also exposes an internal sub-command that acts as the target of the `boxlogin://` scheme:

```
python box_proxy.py _boxlogin "boxlogin://login?..."
```

This forwards the authorization result to the running proxy server. The command is intended to be executed automatically by the OS after the handler registration performed in step 2.

### Legacy helper

`box_redirect.js` is kept for reference; the new `_boxlogin` command supersedes its role in most environments.
