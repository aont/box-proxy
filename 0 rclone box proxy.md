# rclone box proxy

`rclone` でboxに接続する際に一部データを編集するプロキシ  
A proxy that modifies some data when connecting to Box using `rclone`.

- プロクシを起動 `box_proxy.py` 。boxの設定がない場合は追加、ある場合はこのプロクシを使うように一部書き換えされる。  
  Start the proxy `box_proxy.py`. If there is no Box configuration, it will be added; if a configuration exists, it will be partially modified to use this proxy.

- `rclone config` からboxの設定ウィザードに入り、すべて既定の設定のまま進め、最後にブラウザによる認証を進める  
  Enter the Box configuration wizard from `rclone config`, proceed with all settings left as default, and finally complete the process with browser-based authentication.

- 認証が完了し、白い画面で止まったら `box_redirect.js` で、`rclone` が内部で立ち上げているHTTPサーバーにcodeを送る  
  After authentication is complete and a blank white screen appears, use `box_redirect.js` to send the authorization code to the HTTP server running internally in `rclone`.  

- rcloneで設定が完了するはず  
  The configuration in rclone should now be complete.  