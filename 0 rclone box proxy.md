# rclone box proxy

`rclone` でAndroidのBoxアプリのIDを使うためのプロキシ  
Proxy for using the Android Box app ID with `rclone`  

- プロクシを起動 `box_proxy.py`  
  Start the proxy using `box_proxy.py`.  

- `rclone` にboxのclient id, client secretをセットし、oauth用のURLをこのプロクシにセット  
  Configure rclone with the Box client ID and client secret, and set the OAuth URL to this proxy.  

- boxの認証を進める  
  Proceed with Box authentication.  

- 認証が完了し、白い画面で止まったら `box_redirect.js` で、`rclone` が内部で立ち上げているHTTPサーバーにcodeを送る  
  After authentication is complete and a blank white screen appears, use `box_redirect.js` to send the authorization code to the HTTP server running internally in `rclone`.  

- rcloneで設定が完了するはず  
  The configuration in rclone should now be complete.  