# rclone box proxy

A proxy that modifies some data when connecting to Box using `rclone`.
- Enter the Box setup wizard from `rclone config`, proceed through all the steps using the default settings, skip browser authentication, register a dummy token, and finish the setup.
- Start the proxy `box_proxy.py`. If there is no Box configuration, it will be added; if a configuration exists, it will be partially modified to use this proxy.
- Enter the Box setup wizard again from `rclone config`, proceed through all the steps using the default settings, and complete the authentication in your browser at the end.
- After authentication is complete and a blank white screen appears, use `box_redirect.js` to send the authorization code to the HTTP server running internally in `rclone`. 
- The configuration in rclone should now be complete.  
