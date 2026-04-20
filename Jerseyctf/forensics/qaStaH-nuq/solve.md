filter http:

Frame 316: Packet, 193 bytes on wire (1544 bits), 193 bytes captured (1544 bits)
Raw packet data
Internet Protocol Version 4, Src: 172.166.1.12, Dst: 10.5.0.5
Transmission Control Protocol, Src Port: 80, Dst Port: 1234, Seq: 1, Ack: 1, Len: 153
Hypertext Transfer Protocol
    HTTP/1.1 200 OK\r\n
        Response Version: HTTP/1.1
        Status Code: 200
        [Status Code Description: OK]
        Response Phrase: OK
    Content-Type: text/plain\r\n
    Content-Length: 36\r\n
    Content-Disposition: attachment; filename=flag.txt\r\n
    \r\n
    File Data: 36 bytes
Line-based text data: text/plain (1 lines)
    amN0ZntBdHRhY2tfVGhlX0VudGVycHJpc2V9


base64 encode: amN0ZntBdHRhY2tfVGhlX0VudGVycHJpc2V9
base64 decode: jctf{Attack_The_Enterprise}
