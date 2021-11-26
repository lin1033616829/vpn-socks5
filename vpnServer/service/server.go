package service

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
)

func Process(client net.Conn) {
	log.Println(fmt.Sprintf("有请求进来 %v", client))

	if err := socks5Auth(client); err != nil {
		log.Println("auth error:", err)
		client.Close()
		return
	}

	target, err := socks5Connect(client)
	if err != nil {
		log.Println("connect error:", err)
		client.Close()
		return
	}

	log.Println(fmt.Sprintf("target = [%v]", target))

	Socks5Forward(client, target)
}


func socks5Auth(client net.Conn) (err error) {
	buf := make([]byte, 256)

	log.Println("开始进行权限认证")

	// 读取 VER 和 NMETHODS
	n, err := io.ReadFull(client, buf[:2])
	if n != 2 {
		return errors.New("reading header: " + err.Error())
	}

	log.Println(fmt.Sprintf("读取到n=[%v]个字节", n))
	log.Println(fmt.Sprintf("读取到buf， 包含了VER 和 NMETHODS  %v", buf[:n]))

	ver, nMethods := int(buf[0]), int(buf[1])
	if ver != 5 {
		return errors.New("invalid version")
	}

	log.Println(fmt.Sprintf("ver = [%v], nMethods = [%v]", ver, nMethods))

	// 读取 METHODS 列表
	n, err = io.ReadFull(client, buf[:nMethods])
	if n != nMethods {
		return errors.New("reading methods: " + err.Error())
	}

	log.Println(fmt.Sprintf("读取到methods列表 [%v]", buf[:n]))

	//无需认证
	log.Println("没有做任何认证方式")
	n, err = client.Write([]byte{0x05, 0x00})
	if n != 2 || err != nil {
		return errors.New("write rsp err: " + err.Error())
	}

	return nil
}

func socks5Connect(client net.Conn) (net.Conn, error) {
	buf := make([]byte, 256)

	log.Println("开始尝试连接到vpn服务器")

	n, err := io.ReadFull(client, buf[:4])
	if n != 4 {
		return nil, errors.New("read header: " + err.Error())
	}

	log.Println(fmt.Sprintf("读取到4个字节 buf=[%v]", buf[:4]))

	ver, cmd, _, atyp := buf[0], buf[1], buf[2], buf[3]
	if ver != 5 || cmd != 1 {
		return nil, errors.New("invalid ver/cmd")
	}

	log.Println(fmt.Sprintf("ver = [%v] cmd = [%v] _, atyp = [%v]", ver, cmd, atyp))
	log.Println("开始判断 atyp 类型， 查看对方的连接方式")

	addr := ""
	switch atyp {
	case 1:
		n, err = io.ReadFull(client, buf[:4])
		if n != 4 {
			return nil, errors.New("invalid IPv4: " + err.Error())
		}
		log.Println("Ipv4连接方式")
		addr = fmt.Sprintf("%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3])
		break
	case 3:
		n, err = io.ReadFull(client, buf[:1])
		if n != 1 {
			return nil, errors.New("invalid hostname: " + err.Error())
		}
		addrLen := int(buf[0])

		n, err = io.ReadFull(client, buf[:addrLen])
		if n != addrLen {
			return nil, errors.New("invalid hostname: " + err.Error())
		}
		addr = string(buf[:addrLen])
		log.Println("hostname 连接方式")
		break
	case 4:
		return nil, errors.New("IPv6: no supported yet")
	default:
		return nil, errors.New("invalid atyp")
	}

	log.Println(fmt.Sprintf("addr = [%v]", addr))
	n, err = io.ReadFull(client, buf[:2])
	if n != 2 {
		return nil, errors.New("read port: " + err.Error())
	}
	port := binary.BigEndian.Uint16(buf[:2])

	log.Println(fmt.Sprintf("port = [%v]", port))

	destAddrPort := fmt.Sprintf("%s:%d", addr, port)
	log.Println(fmt.Sprintf("destAddrPort = [%v]", destAddrPort))
	dest, err := net.Dial("tcp", destAddrPort)
	if err != nil {
		log.Println(fmt.Sprintf("net.Dial err %v", err))
		return nil, errors.New("dial dst: " + err.Error())
	}

	//VER 	05 socks5
	//REP	状态码，0x00=成功，0x01=未知错误，……
	//RSV 	依然是没卵用的 RESERVED
	//ATYP 	地址类型 这里写了个固定的 Ipv4
	//BND.ADDR 服务器和DST创建连接用的地址
	//BND.PORT 服务器和DST创建连接用的端口

	// ATYP = 0x01 表示 IPv4，所以需要填充 6 个 0 —— 4 for ADDR, 2 for PORT。
	n, err = client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	if err != nil {
		dest.Close()
		return nil, errors.New("write rsp: " + err.Error())
	}


	return dest, nil
}

func Socks5Forward(client, target net.Conn) {
	forward := func(src, dest net.Conn) {
		defer src.Close()
		defer dest.Close()
		defer func() {
			log.Println("该连接处理完毕，已关闭")
		}()

		io.Copy(src, dest)
	}
	go forward(client, target)
	go forward(target, client)
}