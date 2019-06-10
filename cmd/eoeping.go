package main

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"reflect"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/haccht/eoetool"

	flags "github.com/jessevdk/go-flags"
)

const (
	programName string = "EoEPing by haccht"
	snapshotLen int32  = 68
	promiscuous bool   = true
)

type options struct {
	IFace     string `short:"I" long:"iface" description:"Interface name to send requests" required:"true"`
	Timeout   int    `short:"t" long:"timeout" description:"Time in sec to wait for response" default:"3"`
	Interval  int    `short:"i" long:"interval" description:"Time in msec to wait for next request" default:"1000"`
	Count     int    `short:"c" long:"count" description:"Number of requests to send" default:"4"`
	EoEDstMAC string `long:"eoe-da" description:"EoE destination address" required:"true"`
	EoESrcMAC string `long:"eoe-sa" description:"EoE source address" default:"0e:30:00:00:00:00"`
	VlanID    uint   `short:"v" long:"vid" description:"VLAN ID" default:"0"`
	EoETTL    uint   `short:"T" long:"ttl" description:"EoE time to live" default:"255"`
	EoEEID    uint   `short:"d" long:"domain" description:"EoE domain ID" default:"0"`
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

func eoePingRequest(msg, seq uint16, opts *options) ([]byte, error) {
	dstMAC, err := net.ParseMAC(opts.EoEDstMAC)
	if err != nil {
		return nil, err
	}

	srcMAC, err := net.ParseMAC(opts.EoESrcMAC)
	if err != nil {
		return nil, err
	}

	if opts.VlanID > 0xFFF {
		err := fmt.Errorf("vlan ID %v out of range", opts.VlanID)
		return nil, err
	}

	buffer := gopacket.NewSerializeBuffer()
	option := gopacket.SerializeOptions{}
	gopacket.SerializeLayers(
		buffer, option,
		&layers.Ethernet{
			DstMAC:       dstMAC,
			SrcMAC:       srcMAC,
			EthernetType: 0x8100,
		},
		&layers.Dot1Q{
			VLANIdentifier: uint16(opts.VlanID),
			Type:           eoe.EthernetTypeECP,
		},
		&eoe.ECP{
			TimeToLive: uint8(opts.EoETTL),
			ExtendedID: uint8(opts.EoEEID),
			SubType:    3,
			Version:    1,
			OpCode:     1,
			SubCode:    1,
			MessageID:  uint16(msg),
			Sequence:   uint16(seq),
			ReplyID:    layers.EthernetBroadcast,
			ChassisID:  programName,
		},
	)

	return buffer.Bytes(), nil
}

func main() {
	opts := &options{}
	if _, err := flags.Parse(opts); err != nil {
		os.Exit(1)
	}

	handle, err := pcap.OpenLive(opts.IFace, snapshotLen, promiscuous, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	ecpPackets := make(chan *eoe.ECP)
	go func() {
		dstMAC, _ := net.ParseMAC(opts.EoEDstMAC)
		srcMAC, _ := net.ParseMAC(opts.EoESrcMAC)

		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			ethLayer := packet.Layer(layers.LayerTypeEthernet)
			ecpLayer := packet.Layer(eoe.LayerTypeECP)
			if ethLayer != nil && ecpLayer != nil {
				eth, _ := ethLayer.(*layers.Ethernet)
				if reflect.DeepEqual(eth.DstMAC, srcMAC) && reflect.DeepEqual(eth.SrcMAC, dstMAC) {
					ecp, _ := ecpLayer.(*eoe.ECP)
					ecpPackets <- ecp
				}
			}
		}
	}()

	for seq := 0; seq < opts.Count; seq++ {
		if seq != 0 {
			time.Sleep(time.Duration(opts.Interval) * time.Millisecond)
		}

		messageID := uint16(rand.Intn(65536))
		reqPacket, err := eoePingRequest(messageID, uint16(seq), opts)
		if err != nil {
			log.Fatal(err)
		}

		start := time.Now()
		if err := handle.WritePacketData(reqPacket); err != nil {
			log.Fatal(err)
		}

	NEXT_PING:
		for {
			select {
			case ecp := <-ecpPackets:
				if ecp.SubType == 3 && ecp.Version == 1 && ecp.OpCode == 1 && ecp.SubCode == 2 && ecp.Sequence == uint16(seq) && ecp.MessageID == messageID {
					rtt := float64(time.Since(start).Nanoseconds()) / 1000000
					log.Printf(" 68 bytes from %s : eoe_seq=%d ttl=%d time=%.3f ms\n", ecp.ReplyID.String(), ecp.Sequence, ecp.TimeToLive, rtt)
					break NEXT_PING
				}
			case <-time.After(time.Duration(opts.Timeout) * time.Second):
				log.Printf(" ERROR: Request timed out.\n")
				break NEXT_PING
			}
		}
	}
}
