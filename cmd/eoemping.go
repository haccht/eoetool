package main

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"reflect"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/haccht/eoetool"

	flags "github.com/jessevdk/go-flags"
)

const (
	programName string = "multicast eoeping program"
	snapshotLen int32  = 68
	promiscuous bool   = true
)

/*
  The echo request file is a toml formatted list.
  Example:

  [[node]]
  name = "sir03-aes-101"
  addr = "0e:33:13:8a:10:00"
  vlan = [100,101,102,103,104,105]

  [[node]]
  name = "sir03-aes-102"
  addr = "0e:33:13:8a:20:00"
  vlan = [100,101,102,103,104,105]
*/

type options struct {
	File       string `short:"f" long:"file" description:"Echo request target list file" required:"true"`
	IFace      string `short:"I" long:"iface" description:"Interface name to send requests" required:"true"`
	Timeout    int    `short:"t" long:"timeout" description:"Time in sec to wait for response" default:"1"`
	Interval   int    `short:"i" long:"interval" description:"Time in msec to wait for next request" default:"100"`
	EoEDstMAC  string `long:"eoe-da" description:"EoE destination address" default:"0f:0e:cc:00:00:00"`
	EoESrcMAC  string `long:"eoe-sa" description:"EoE source address" default:"0e:30:00:00:00:00"`
	EoEReplyID string `long:"reply-id" description:"EoE reply address" default:"ff:ff:ff:ff:ff:ff"`
	EoETTL     uint   `short:"T" long:"ttl" description:"EoE time to live" default:"25"`
	EoEEID     uint   `short:"d" long:"domain" description:"EoE domain ID" default:"0"`
}

type Config struct {
	Node []NodeConfig
}

type NodeConfig struct {
	Name string
	Addr string
	Vlan []uint16
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

func ecpEchoRequestPacket(dstMAC, srcMAC, replyID net.HardwareAddr, ttl, eid uint8, vlanID, messageID, sequence uint16) []byte {
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
			VLANIdentifier: vlanID,
			Type:           eoe.EthernetTypeECP,
		},
		&eoe.ECP{
			TimeToLive: ttl,
			ExtendedID: eid,
			SubType:    3,
			Version:    1,
			OpCode:     1,
			SubCode:    1,
			MessageID:  messageID,
			Sequence:   sequence,
			ReplyID:    replyID,
			ChassisID:  programName,
		},
	)

	return buffer.Bytes()
}

func ecpEchoReplyPackets(ctx context.Context, handle *pcap.Handle, srcMAC net.HardwareAddr, eid uint8, vlanID uint16) <-chan *eoe.ECP {
	ecpEchoReplies := make(chan *eoe.ECP)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	go func() {
		for {
			select {
			case packet := <-packetSource.Packets():
				ethLayer := packet.Layer(layers.LayerTypeEthernet)
				d1qLayer := packet.Layer(layers.LayerTypeDot1Q)
				ecpLayer := packet.Layer(eoe.LayerTypeECP)
				if ethLayer != nil && d1qLayer != nil && ecpLayer != nil {
					eth, _ := ethLayer.(*layers.Ethernet)
					d1q, _ := d1qLayer.(*layers.Dot1Q)
					ecp, _ := ecpLayer.(*eoe.ECP)
					if reflect.DeepEqual(eth.DstMAC, srcMAC) && d1q.VLANIdentifier == vlanID && ecp.ExtendedID == eid &&
						ecp.SubType == 3 && ecp.Version == 1 && ecp.OpCode == 1 && ecp.SubCode == 2 {
						ecpEchoReplies <- ecp
					}
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	return ecpEchoReplies
}

func main() {
	opts := &options{}
	if _, err := flags.Parse(opts); err != nil {
		os.Exit(1)
	}

	var c Config
	_, err := toml.DecodeFile(opts.File, &c)
	if err != nil {
		log.Fatal(err)
	}

	target := make(map[uint16][]NodeConfig)
	for _, node := range c.Node {
		for _, vlan := range node.Vlan {
			nodes := target[vlan]
			target[vlan] = append(nodes, node)
		}
	}

	dstMAC, err := net.ParseMAC(opts.EoEDstMAC)
	if err != nil {
		log.Fatal(err)
	}

	srcMAC, err := net.ParseMAC(opts.EoESrcMAC)
	if err != nil {
		log.Fatal(err)
	}

	replyID, err := net.ParseMAC(opts.EoEReplyID)
	if err != nil {
		log.Fatal(err)
	}

	handle, err := pcap.OpenLive(opts.IFace, snapshotLen, promiscuous, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	for vlan, nodes := range target {
		ctx := context.Background()
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()

		ecpEchoReplies := ecpEchoReplyPackets(ctx, handle, srcMAC, opts.EoEEID, vlan)

		messageID := uint16(rand.Intn(65536))
		reqPacket, err := eoePingRequest(messageID, uint16(seq), opts)
		if err != nil {
			log.Fatal(err)
		}

		start := time.Now()
		if err := handle.WritePacketData(reqPacket); err != nil {
			log.Fatal(err)
		}

		func() {
			for {
				select {
				case ecp := <-ecpEchoReplies:
					if ecp.MessageID == messageID && ecp.Sequence == seq {
						rtt := float64(time.Since(start).Nanoseconds()) / 1000000
						log.Printf(" 68 bytes from %s : eoe_seq=%d ttl=%d time=%.3f ms\n", ecp.ReplyID.String(), ecp.Sequence, ecp.TimeToLive, rtt)
						return
					}
				case <-time.After(time.Duration(opts.Timeout) * time.Second):
					log.Printf(" ERROR: Request timed out.\n")
					return
				}
			}
		}()
	}
}
