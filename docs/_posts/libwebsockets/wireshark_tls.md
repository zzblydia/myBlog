背景:

使用libwebsockets作为客户端访问ASR/TTS websockets服务器, 由于使用SSL加密, tcpdump捕获的报文需要解密.


解决依据:

1. 通过wireshark官方文档TLS章节(附录链接1)知, wireshark解密TLSv1.3只能通过获取(Pre)-Master Secret方式.另外

   OpenSSL 1.1.1 and after 可以设置libssl回调函数 SSL_CTX_set_keylog_callback 获取.

   OpenSSL 1.1.0 and before 可以使用 LD_PRELOAD libsslkeylog.so 获取.

2. 由于编译libwebsockets.so时链接了静态的libssl.a和libcrypto.a, 没有链接libssl.so动态库, 所以无法通过LD_PRELOAD的方式获取(Pre)-Master Secret.

3. 通过libwebsockets github(附录链接2)知,  可以使用lws_klog_dump捕获打印(Pre)-Master Secret到环境变量SSLKEYLOGFILE设置的文件里. 但是此功能只在main分支, 不在发布分支里.


操作步骤:
echo "export SSLKEYLOGFILE=/opt/tls.keys" 

cat /proc/pid/environ  | tr '\0' '\n' | grep SSLKEYLOGFILE

tcpdump -s 0 -i any '(src port 8001 || dst port 8001)' -w /opt/tts.pcap

下载/opt/tls.keys和/opt/tts.pcap到本地


处理结果:

1.使用wireshark打开tts.pcap, 并过滤tls报文.

2.点击wireshark---编辑---首选项---协议---TCP---选中Reassemble out-of-order segments, 点击确定

3.点击wiershark---编辑---首选项---协议---TLS(Protocol name is SSL before Wireshark 3.0.)---(Pre)-Master-Secret选中tls.keys, 点击确定

即可正常解密.


附录:

链接1: https://wiki.wireshark.org/TLS#tls-decryption

链接2: https://github.com/warmcat/libwebsockets/issues/3087
