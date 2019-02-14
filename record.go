package main

import (
	"flag"
	"fmt"
	"log"
	"reflect"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	. "github.com/haccht/eoetool/eoe"
	influx "github.com/influxdata/influxdb1-client/v2"
)

const (
	INFLUXDB_URL      = "http://localhost:8086"
	INFLUXDB_DATABASE = "EoENetwork"
	INFLUXDB_SERIES   = "BUM"
)

func packetToPoint(packet gopacket.Packet) *influx.Point {
	tags := map[string]string{}
	packetLayers := packet.Layers()

	if false ||
		packetLayers[0].LayerType() != layers.LayerTypeEthernet ||
		packetLayers[1].LayerType() != layers.LayerTypeDot1Q ||
		packetLayers[2].LayerType() != LayerTypeEoE ||
		packetLayers[3].LayerType() != layers.LayerTypeEthernet {
		return nil
	}

	stag, _ := packetLayers[1].(*layers.Dot1Q)
	tags["pvid"] = fmt.Sprint(stag.VLANIdentifier)

	ethernet, _ := packetLayers[3].(*layers.Ethernet)
	switch {
	case reflect.DeepEqual(ethernet.DstMAC, layers.EthernetBroadcast):
		tags["type"] = "broadcast"
	case ethernet.DstMAC[0]&0x01 == 1: //I/G bit
		tags["type"] = "multicast"
	default:
		tags["type"] = "unicast"
	}

	// 18 (Ethernet) + 4 (Dot1Q) + 2 (EoE) = 24 Bytes
	length := packet.Metadata().Length - 24
	switch {
	case length < 128:
		tags["length"] = "64-127"
	case length < 256:
		tags["length"] = "128-255"
	case length < 512:
		tags["length"] = "256-511"
	case length < 1024:
		tags["length"] = "512-1023"
	case length < 1519:
		tags["length"] = "1024-1518"
	default:
		tags["length"] = "1519-"
	}

	var protocol gopacket.LayerType

	cvid := []string{}
	for i := 3; i < len(packetLayers); i++ {
		protocol = packetLayers[i].LayerType()

		switch protocol {
		case layers.LayerTypeDot1Q:
			ctag, _ := packetLayers[i].(*layers.Dot1Q)
			cvid = append(cvid, fmt.Sprint(ctag.VLANIdentifier))
		case gopacket.LayerTypePayload, gopacket.LayerTypeDecodeFailure:
			protocol = packetLayers[i-1].LayerType()
			break
		}
	}

	tags["cvid"] = strings.Join(cvid, ":")
	tags["protocol"] = fmt.Sprint(protocol)

	timestamp := packet.Metadata().Timestamp
	fields := map[string]interface{}{"event": 1}
	pt, _ := influx.NewPoint(INFLUXDB_SERIES, tags, fields, timestamp)

	return pt
}

func openInfluxDB(url, database string) (influx.Client, error) {
	client, err := influx.NewHTTPClient(influx.HTTPConfig{Addr: url})
	if err != nil {
		return nil, err
	}

	q := influx.NewQuery(fmt.Sprintf("CREATE DATABASE %s", database), "", "")
	if _, err := client.Query(q); err != nil {
		return nil, err
	}

	return client, nil
}

func main() {
	var iface string

	flag.StringVar(&iface, "I", "eth0", "Name of interface to wait for packet")
	flag.Parse()

	pcapHandle, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer pcapHandle.Close()

	influxdb, err := openInfluxDB(INFLUXDB_URL, INFLUXDB_DATABASE)
	if err != nil {
		log.Fatal(err)
	}
	defer influxdb.Close()

	tick := time.NewTicker(5 * time.Second)
	packetSource := gopacket.NewPacketSource(pcapHandle, pcapHandle.LinkType())

	points := []*influx.Point{}
	for {
		select {
		case packet := <-packetSource.Packets():
			if point := packetToPoint(packet); point != nil {
				points = append(points, point)
			}
		case <-tick.C:
			bp, _ := influx.NewBatchPoints(influx.BatchPointsConfig{
				Database:  INFLUXDB_DATABASE,
				Precision: "s",
			})
			bp.AddPoints(points)

			size := len(points)
			points = points[:0]

			if err = influxdb.Write(bp); err != nil {
				log.Printf("Could not write points to InfluxDB: %s", err.Error())
			} else {
				log.Printf("Dump %d points to InfluxDB.", size)
			}
		}
	}
}
