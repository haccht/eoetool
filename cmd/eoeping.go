package main

import (
	"context"
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
	programName string = "eoeping program"
	snapshotLen int32  = 68
	promiscuous bool   = true
)

type options struct {
	IFace      string `short:"I" long:"iface" description:"Interface name to send requests" required:"true"`
	Timeout    uint16 `short:"t" long:"timeout" description:"Time in sec to wait for response" default:"3"`
	Interval   uint16 `short:"i" long:"interval" description:"Time in msec to wait for next request" default:"1000"`
	Count      uint16 `short:"c" long:"count" description:"Number of requests to send" default:"4"`
	VlanID     uint16 `short:"v" long:"vid" description:"VLAN ID" default:"0"`
	EoEDstMAC  string `long:"eoe-da" description:"EoE destination address" required:"true"`
	EoESrcMAC  string `long:"eoe-sa" description:"EoE source address" default:"0e:30:00:00:00:00"`
	EoEReplyID string `long:"reply-id" description:"EoE reply address" default:"ff:ff:ff:ff:ff:ff"`
	EoETTL     uint8  `short:"T" long:"ttl" description:"EoE time to live" default:"255"`
	EoEEID     uint8  `short:"d" long:"domain" description:"EoE domain ID" default:"0"`
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

func ecpEchoReplyPackets(ctx context.Context, handle *pcap.Handle, srcMAC net.HardwareAddr) <-chan gopacket.Packet {
	ecpEchoReplies := make(chan gopacket.Packet)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	go func() {
		for {
			select {
			case packet := <-packetSource.Packets():
				ethLayer := packet.Layer(layers.LayerTypeEthernet)
				ecpLayer := packet.Layer(eoe.LayerTypeECP)
				if ethLayer != nil && ecpLayer != nil {
					eth, _ := ethLayer.(*layers.Ethernet)
					ecp, _ := ecpLayer.(*eoe.ECP)
					if reflect.DeepEqual(eth.DstMAC, srcMAC) &&
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

	if opts.VlanID > 0xFFF {
		log.Fatalf("vlan ID %v out of range", opts.VlanID)
	}

	handle, err := pcap.OpenLive(opts.IFace, snapshotLen, promiscuous, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	ecpEchoReplies := ecpEchoReplyPackets(ctx, handle, srcMAC)
	for seq := uint16(0); seq < opts.Count; seq++ {
		if seq != 0 {
			time.Sleep(time.Duration(opts.Interval) * time.Millisecond)
		}

		start := time.Now()
		messageID := uint16(rand.Intn(65536))
		reqPacket := ecpEchoRequestPacket(dstMAC, srcMAC, replyID, opts.EoETTL, opts.EoEEID, opts.VlanID, messageID, seq)
		if err := handle.WritePacketData(reqPacket); err != nil {
			log.Fatal(err)
		}

		func() {
			for {
				select {
				case packet := <-ecpEchoReplies:
					eth, _ := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
					d1q, _ := packet.Layer(layers.LayerTypeDot1Q).(*layers.Dot1Q)
					ecp, _ := packet.Layer(eoe.LayerTypeECP).(*eoe.ECP)
					if d1q.VLANIdentifier == opts.VlanID && ecp.ExtendedID == opts.EoEEID && ecp.MessageID == messageID && ecp.Sequence == seq {
						rtt := float64(time.Since(start).Nanoseconds()) / 1000000
						log.Printf(" %d bytes from %s : eoe_seq=%d ttl=%d time=%.3f ms\n", snapshotLen, eth.SrcMAC.String(), ecp.Sequence, ecp.TimeToLive, rtt)
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
