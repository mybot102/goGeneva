package main

import (
	"context"
	"github.com/florianl/go-nfqueue"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"log"
	"net"
	"regexp"
	"strings"
	"time"
)

func packetHandle(queueNum int) {
	// 配置 nfqueue
	config := nfqueue.Config{
		NfQueue:      uint16(queueNum),
		MaxPacketLen: 0xFFFF,
		MaxQueueLen:  0xFF,
		Copymode:     nfqueue.NfQnlCopyPacket,
		WriteTimeout: 15 * time.Millisecond,
	}

	// 打开 nfqueue 套接字
	nf, err := nfqueue.Open(&config)
	if err != nil {
		log.Printf("无法打开 nfqueue 套接字: %v\n", err)
		return
	}
	defer nf.Close()

	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()

	fn := func(a nfqueue.Attribute) int {
		id := *a.PacketID
		var srcIP, dstIP net.IP
		log.Printf("处理数据包 [%03d]\n", id)

		// 解析数据包
		packet := gopacket.NewPacket(*a.Payload, layers.LayerTypeIPv4, gopacket.Default)

		// 获取 IP 层信息
		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			srcIP = ip.SrcIP
			dstIP = ip.DstIP
			log.Printf("源 IP: %15s > 目标 IP: %-15s\n", srcIP, dstIP)
		}

		// 处理 TCP 层
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			ports := strings.Split(Port, ",")
			reg := regexp.MustCompile(`\d+`)
			sport := reg.FindString(tcp.SrcPort.String())

			log.Printf("源端口: %s, 目标端口: %s\n", tcp.SrcPort, tcp.DstPort)
			log.Printf("TCP 标志: SYN=%v, ACK=%v, PSH=%v, FIN=%v, RST=%v\n",
				tcp.SYN, tcp.ACK, tcp.PSH, tcp.FIN, tcp.RST)
			log.Printf("原始窗口大小: %d\n", tcp.Window)

			var matchedPort bool = false
			for _, port := range ports {
				if port == sport {
					matchedPort = true
					log.Printf("匹配到监听端口: %s\n", port)
					break
				}
			}

			if matchedPort {
				var ok1 bool = SaEnable && tcp.SYN && tcp.ACK
				var ok2 bool = AEnable && tcp.ACK && !tcp.PSH && !tcp.FIN && !tcp.SYN && !tcp.RST
				var ok3 bool = PaEnable && tcp.PSH && tcp.ACK
				var ok4 bool = FaEnable && tcp.FIN && tcp.ACK
				var windowSize uint16

				if ok1 || ok2 || ok3 || ok4 {
					if ok1 {
						windowSize = WindowSa
						log.Println("处理 SYN-ACK 包")
					}
					if ok2 {
						windowSize = WindowA
						log.Println("处理纯 ACK 包")
					}
					if ok3 {
						windowSize = WindowPa
						log.Println("处理 PSH-ACK 包")
					}
					if ok4 {
						windowSize = WindowFa
						log.Println("处理 FIN-ACK 包")
					}

					// 修改窗口大小
					packet.TransportLayer().(*layers.TCP).Window = windowSize
					err := packet.TransportLayer().(*layers.TCP).SetNetworkLayerForChecksum(packet.NetworkLayer())
					if err != nil {
						log.Fatalf("设置网络层校验和时出错: %v", err)
					}

					// 序列化修改后的数据包
					buffer := gopacket.NewSerializeBuffer()
					options := gopacket.SerializeOptions{
						ComputeChecksums: true,
						FixLengths:       true,
					}
					if err := gopacket.SerializePacket(buffer, options, packet); err != nil {
						log.Fatalf("序列化数据包时出错: %v", err)
					}
					packetBytes := buffer.Bytes()

					log.Printf("设置 TCP 窗口大小为 %d\n", windowSize)

					// 设置修改后的数据包
					err = nf.SetVerdictModPacket(id, nfqueue.NfAccept, packetBytes)
					if err != nil {
						log.Fatalf("设置修改后的数据包时出错: %v", err)
					}
					log.Println("成功修改并重新注入数据包")
					return 0
				}

				log.Println("数据包不需要修改，直接放行")
				err := nf.SetVerdict(id, nfqueue.NfAccept)
				if err != nil {
					log.Fatalf("设置未修改的数据包时出错: %v", err)
				}
				return 0
			}

			log.Println("端口不匹配，直接放行数据包")
			err := nf.SetVerdict(id, nfqueue.NfAccept)
			if err != nil {
				log.Fatalf("设置未修改的数据包时出错: %v", err)
			}
			return 0
		}

		log.Println("非 TCP 数据包，直接放行")
		err := nf.SetVerdict(id, nfqueue.NfAccept)
		if err != nil {
			log.Fatalf("设置非 TCP 数据包时出错: %v", err)
		}
		return 0
	}

	// 注册函数以监听 nfqueue
	err = nf.RegisterWithErrorFunc(ctx, fn, func(e error) int {
		if e != nil {
			log.Printf("注册错误处理函数时出错: %v\n", e)
		}
		return 0
	})
	if err != nil {
		log.Printf("注册处理函数时出错: %v\n", err)
		return
	}

	log.Println("开始监听网络数据包...")
	<-ctx.Done()
}
