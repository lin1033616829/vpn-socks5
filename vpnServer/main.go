package main

import (
	"fmt"
	"log"
	"myVpn/vpnServer/initialize"
	"myVpn/vpnServer/service"
	"net"
)

func main() {
	initialize.InitLog()

	server, err := net.Listen("tcp", ":7080")
	if err != nil {
		fmt.Printf("Listen failed: %v\n", err)
		return
	}


	for {
		client, err := server.Accept()
		if err != nil {
			log.Printf("Accept failed: %v", err)
			continue
		}

		go service.Process(client)
	}
}



