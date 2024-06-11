# huaxin

* **16xtotext**: A tool to convert hexadecimal and string.
* **router_program**: A service program that simulates routeros.


问题说明  
1.之前写的代码是基于M2协议的，使用winbox客户端连接不上。对其进行重新分析（仅分析了报文，未进行实现）。  
　目前基于报文和winbox_server.py服务的分析，winbox的协议位一个字节的length，一个字节的handle，M2协议的字节序列  
　|length|handle|m2 binary seq|  
　handle说明  
　　0x06 : 登录  
　　0x02 : 获取list,index  
2.之前的代码可以使用参考代码中的8291_honeypot进行登录验证。  
3.之前的代码可以使用cleaner_wrasse进行获取index文件。  
4.使用 go run cmd/main.go -h 查看帮助信息  
　　-c 指定配置文件  
　　-l 指定监听ip  
　　-p 指定监听端口  
5.操作日志记录在当前执行路径下的run.log文件中。  
