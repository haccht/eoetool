package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"

	. "github.com/haccht/eoetool/eoe"
)

func main() {
	var (
		iface string
	)

	flag.StringVar(&iface, "I", "eth0", "Name of interface to wait for packet")
	flag.Parse()

	handle, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		if eoeLayer := packet.Layer(LayerTypeEoE); eoeLayer != nil {
			fmt.Println(packet)
			fmt.Println("EoE layer decoded.")
		}

		if ecpLayer := packet.Layer(LayerTypeECP); ecpLayer != nil {
			fmt.Println(packet)
			fmt.Println("ECP layer decoded.")
		}
	}
}
