package main

import (
	"flag"

	"net"
	"os"
	"router/internal/app"
	"router/internal/log"
)

func init() {
	log.InitLog()
}

func main() {
	addr, configPath := parseCommandLine()
	// 监听指定端口
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Slog.Error("监听失败:", "err", err.Error())
		os.Exit(1)
	}
	defer listener.Close()
	log.Slog.Info("服务器已启动，正在监听 : ", "addr", addr)

	// 接受客户端连接
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Slog.Error("接受连接失败:", "err", err.Error())
			os.Exit(1)
		}

		// 处理客户端请求
		go handleClient(conn, configPath)
	}
}

// 处理客户端请求
func handleClient(conn net.Conn, path string) {
	defer conn.Close()
	td := app.NewTransmissionData(conn, path)
	for {
		if !td.HandlerProcess() {
			break
		}
	}
}

func parseCommandLine() (string, string) {
	ip := flag.String("l", "127.0.0.1", "listen ip")
	port := flag.String("p", "8291", "port")
	configPath := flag.String("c", "", "config file path")
	flag.Parse()
	return *ip + ":" + *port, *configPath
}
