package main

import (
	"log"
	"net"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/haccht/eoetool"

	flags "github.com/jessevdk/go-flags"
)

const (
	snapshotLen int32 = 68
	promiscuous bool  = true
)

type options struct {
	IFace     string `short:"I" long:"iface" description:"Interface name" required:"true"`
	DstEoEMAC string `long:"eoe-da" description:"EoE destination address" default:"0F:0E:CC:00:00:FE"`
	SrcEoEMAC string `long:"eoe-sa" description:"EoE source address" default:"0E:30:00:00:00:00"`
	VlanID    uint   `short:"v" long:"vid" description:"VLAN ID" default:"0"`
	EoeTTL    uint   `short:"T" long:"ttl" description:"EoE time to live" default:"255"`
	EoeEID    uint   `short:"d" long:"domain" description:"EoE domain ID" default:"0"`
	DstMAC    string `long:"da" description:"Destination address" default:"00:00:00:00:00:01"`
	SrcMAC    string `long:"sa" description:"Source address" default:"00:00:00:00:00:02"`
}

func newEthernet(dstMAC, srcMAC string, layerType uint16) *layers.Ethernet {
	var err error

	ethernet := &layers.Ethernet{}
	ethernet.EthernetType = layers.EthernetType(layerType)

	if ethernet.DstMAC, err = net.ParseMAC(dstMAC); err != nil {
		log.Fatal(err)
	}

	if ethernet.SrcMAC, err = net.ParseMAC(srcMAC); err != nil {
		log.Fatal(err)
	}

	return ethernet
}

func main() {
	opts := &options{}
	if _, err := flags.Parse(opts); err != nil {
		os.Exit(1)
	}

	buffer := gopacket.NewSerializeBuffer()
	option := gopacket.SerializeOptions{}
	gopacket.SerializeLayers(
		buffer,
		option,
		newEthernet(opts.DstEoEMAC, opts.SrcEoEMAC, 0x8100),
		&layers.Dot1Q{VLANIdentifier: uint16(opts.VlanID), Type: eoe.EthernetTypeEoE},
		&eoe.EoE{TimeToLive: uint8(opts.EoeTTL), ExtendedID: uint8(opts.EoeEID)},
		newEthernet(opts.DstMAC, opts.SrcMAC, 0x88b8),
		gopacket.Payload(nil),
	)

	handle, err := pcap.OpenLive(opts.IFace, snapshotLen, promiscuous, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	err = handle.WritePacketData(buffer.Bytes())
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Complete.")
}
