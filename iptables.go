package main

import (
	"log"
	"os"

	"github.com/coreos/go-iptables/iptables"
)

func SetIptable(sport string) {
	ipt, err := iptables.New()
	if err != nil {
		log.Printf("创建 iptables 对象失败: %v", err)
		os.Exit(1)
	}

	// 清空 OUTPUT 链
	err = ipt.ClearChain("filter", "OUTPUT")
	if err != nil {
		log.Printf("清空 OUTPUT 链失败: %v", err)
		os.Exit(1)
	}
	log.Println("已清空 OUTPUT 链")

	rules := [][]string{
		{"-p", "tcp", "-m", "multiport", "--sport", sport, "--tcp-flags", "SYN,RST,ACK,FIN,PSH", "SYN,ACK", "-j", "NFQUEUE", "--queue-balance", "1000:1127"},
		{"-p", "tcp", "-m", "multiport", "--sport", sport, "--tcp-flags", "SYN,RST,ACK,FIN,PSH", "ACK", "-j", "NFQUEUE", "--queue-balance", "2000:2127"},
		{"-p", "tcp", "-m", "multiport", "--sport", sport, "--tcp-flags", "SYN,RST,ACK,FIN,PSH", "PSH,ACK", "-j", "NFQUEUE", "--queue-balance", "3000:3127"},
		{"-p", "tcp", "-m", "multiport", "--sport", sport, "--tcp-flags", "SYN,RST,ACK,FIN,PSH", "FIN,ACK", "-j", "NFQUEUE", "--queue-balance", "4000:4127"},
	}

	for _, rule := range rules {
		err := ipt.AppendUnique("filter", "OUTPUT", rule...)
		if err != nil {
			log.Printf("添加规则失败: %v", err)
		} else {
			log.Printf("成功添加规则: %v", rule)
		}
	}
}

func UnsetIptable(sport string) {
	ipt, err := iptables.New()
	if err != nil {
		log.Printf("创建 iptables 对象失败: %v", err)
		os.Exit(1)
	}

	rules := [][]string{
		{"-p", "tcp", "-m", "multiport", "--sport", sport, "--tcp-flags", "SYN,RST,ACK,FIN,PSH", "SYN,ACK", "-j", "NFQUEUE", "--queue-balance", "1000:1127"},
		{"-p", "tcp", "-m", "multiport", "--sport", sport, "--tcp-flags", "SYN,RST,ACK,FIN,PSH", "ACK", "-j", "NFQUEUE", "--queue-balance", "2000:2127"},
		{"-p", "tcp", "-m", "multiport", "--sport", sport, "--tcp-flags", "SYN,RST,ACK,FIN,PSH", "PSH,ACK", "-j", "NFQUEUE", "--queue-balance", "3000:3127"},
		{"-p", "tcp", "-m", "multiport", "--sport", sport, "--tcp-flags", "SYN,RST,ACK,FIN,PSH", "FIN,ACK", "-j", "NFQUEUE", "--queue-balance", "4000:4127"},
	}

	for _, rule := range rules {
		err := ipt.Delete("filter", "OUTPUT", rule...)
		if err != nil {
			log.Printf("删除规则失败: %v, 错误: %v", rule, err)
		} else {
			log.Printf("成功删除规则: %v", rule)
		}
	}
}
