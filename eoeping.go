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

	. "github.com/haccht/eoetool/eoe"
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

func buildRequest(msg, seq uint16, opts *options) ([]byte, error) {
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
			Type:           EthernetTypeECP,
		},
		&ECP{
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

func init() {
	rand.Seed(time.Now().UnixNano())
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

	ecpReplyPackets := make(chan *ECP)
	go func() {
		dstMAC, _ := net.ParseMAC(opts.EoEDstMAC)
		srcMAC, _ := net.ParseMAC(opts.EoESrcMAC)

		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
			if ethernetLayer == nil {
				continue
			}

			ecpLayer := packet.Layer(LayerTypeECP)
			if ecpLayer == nil {
				continue
			}

			eth, _ := ethernetLayer.(*layers.Ethernet)
			ecp, _ := ecpLayer.(*ECP)

			if reflect.DeepEqual(eth.DstMAC, srcMAC) && reflect.DeepEqual(eth.SrcMAC, dstMAC) &&
				ecp.SubType == 3 && ecp.Version == 1 && ecp.OpCode == 1 && ecp.SubCode == 2 {
				ecpReplyPackets <- ecp
			}
		}
	}()

	for seq := 0; seq < opts.Count; seq++ {
		if seq != 0 {
			time.Sleep(time.Duration(opts.Interval) * time.Millisecond)
		}

		messageID := uint16(rand.Intn(65536))

		res := make(chan *ECP)
		req, err := buildRequest(messageID, uint16(seq), opts)
		if err != nil {
			log.Fatal(err)
		}

		done := make(chan bool)
		go func() {
			for {
				select {
				case ecp := <-ecpReplyPackets:
					if ecp.Sequence == uint16(seq) && ecp.MessageID == messageID {
						res <- ecp
					}
				case <-done:
					return
				}
			}
		}()

		startTime := time.Now()
		if err := handle.WritePacketData(req); err != nil {
			log.Fatal(err)
		}

		select {
		case ecp := <-res:
			rtt := float64(time.Since(startTime).Nanoseconds()) / 1000000
			log.Printf(" 68 bytes from %s : eoe_seq=%d ttl=%d time=%.3f ms\n", ecp.ReplyID.String(), ecp.Sequence, ecp.TimeToLive, rtt)
		case <-time.After(time.Duration(opts.Timeout) * time.Second):
			log.Printf(" ERROR: Request timed out.\n")
		}

		done <- true
	}

	close(ecpReplyPackets)
}
