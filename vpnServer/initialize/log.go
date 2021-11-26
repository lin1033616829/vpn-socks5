package initialize

import (
	"fmt"
	"log"
	"os"
)

func InitLog() {
	fmt.Println("当前log输出到了文件中，server.log中")

	logFile, err := os.OpenFile("./vpnServer/server.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Println("open log file failed, err:", err)
		return
	}

	log.SetOutput(logFile)
	log.SetPrefix("[server]")
	log.SetFlags(log.Lshortfile | log.Lmicroseconds | log.Ldate)
}