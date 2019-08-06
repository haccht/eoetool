package main

import (
	"context"
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
	EoETTL     uint8  `short:"T" long:"ttl" description:"EoE time to live" default:"25"`
	EoEEID     uint8  `short:"d" long:"domain" description:"EoE domain ID" default:"0"`
}

type Config struct {
	Node []NodeConfig
}

type NodeConfig struct {
	Name string
	Addr string
	Vlan []uint16
}

func (nc NodeConfig) HardwareAddr() (net.HardwareAddr, error) {
	return net.ParseMAC(nc.Addr)
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

func ecpEchoReplyPackets(ctx context.Context, handle *pcap.Handle, srcMAC net.HardwareAddr, eid uint8, vlanID uint16) <-chan gopacket.Packet {
	ecpEchoReplies := make(chan gopacket.Packet)
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
						ecpEchoReplies <- packet
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

	vlanToNodes := make(map[uint16][]NodeConfig)
	for _, node := range c.Node {
		for _, vlanID := range node.Vlan {
			nodes := vlanToNodes[vlanID]
			vlanToNodes[vlanID] = append(nodes, node)
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

	for vlanID, nodes := range vlanToNodes {
		ctx := context.Background()
		ctx, cancel := context.WithCancel(ctx)

		nodesNG := make([]NodeConfig, len(nodes))
		ecpEchoReplies := ecpEchoReplyPackets(ctx, handle, srcMAC, opts.EoEEID, vlanID)

		start := time.Now()
		messageID := uint16(rand.Intn(65536))
		sequence := uint16(rand.Intn(65536))
		reqPacket := ecpEchoRequestPacket(dstMAC, srcMAC, replyID, opts.EoETTL, opts.EoEEID, vlanID, messageID, sequence)
		if err := handle.WritePacketData(reqPacket); err != nil {
			log.Fatal(err)
		}

		func() {
			for {
				select {
				case packet := <-ecpEchoReplies:
					ethLayer := packet.Layer(layers.LayerTypeEthernet)
					ecpLayer := packet.Layer(eoe.LayerTypeECP)
					eth, _ := ethLayer.(*layers.Ethernet)
					ecp, _ := ecpLayer.(*eoe.ECP)

					if ecp.MessageID == messageID && ecp.Sequence == sequence {
						for _, n := range nodes {
							hwAddr, err := n.HardwareAddr()
							if err == nil && reflect.DeepEqual(hwAddr, eth.SrcMAC) {
								nodesNG = append(nodesNG, n)
								rtt := float64(time.Since(start).Nanoseconds()) / 1000000
								log.Printf(" %d bytes from %s(%s) : vid=%d.%d ttl=%d time=%.3f ms\n", snapshotLen, n.Name, n.Addr, opts.EoEEID, vlanID, ecp.TimeToLive, rtt)
								break
							}
						}

						return
					}
				case <-time.After(time.Duration(opts.Timeout) * time.Second):
					cancel()
					return
				}
			}
		}()

		for _, n := range nodesNG {
			log.Printf(" ERROR: Request timed out - %s(%s) : vid=%d.%d", n.Name, n.Addr, opts.EoEEID, vlanID)
		}
	}
}
