package eoe

import (
	"encoding/binary"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	EthernetTypeEoE = layers.EthernetType(0xe0e0)
	EthernetTypeECP = layers.EthernetType(0xe0ec)
)

var (
	LayerTypeEoE = gopacket.RegisterLayerType(
		2001,
		gopacket.LayerTypeMetadata{
			Name:    "EoE",
			Decoder: gopacket.DecodeFunc(decodeEoE),
		})
	LayerTypeECP = gopacket.RegisterLayerType(
		2002,
		gopacket.LayerTypeMetadata{
			Name:    "ECP",
			Decoder: gopacket.DecodeFunc(decodeECP),
		})
)

func init() {
	layers.EthernetTypeMetadata[EthernetTypeEoE] = layers.EnumMetadata{
		Name:       "EoE",
		DecodeWith: gopacket.DecodeFunc(decodeEoE),
		LayerType:  LayerTypeEoE}
	layers.EthernetTypeMetadata[EthernetTypeECP] = layers.EnumMetadata{
		Name:       "ECP",
		DecodeWith: gopacket.DecodeFunc(decodeECP),
		LayerType:  LayerTypeECP}
}

type EoE struct {
	layers.BaseLayer
	TimeToLive uint8
	ExtendedID uint8
}

func decodeEoE(data []byte, p gopacket.PacketBuilder) error {
	eoe := &EoE{}
	err := eoe.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}

	p.AddLayer(eoe)
	return p.NextDecoder(layers.LayerTypeEthernet)
}

func (eoe *EoE) CanDecode() gopacket.LayerClass {
	return LayerTypeEoE
}

func (eoe *EoE) LayerType() gopacket.LayerType {
	return LayerTypeEoE
}

func (eoe *EoE) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	eoe.TimeToLive = uint8(data[0])
	eoe.ExtendedID = uint8(data[1])
	eoe.BaseLayer = layers.BaseLayer{Contents: data[:2], Payload: data[2:]}
	return nil
}

func (eoe *EoE) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	bytes, err := b.PrependBytes(2)
	if err != nil {
		return err
	}

	bytes[0] = eoe.TimeToLive
	bytes[1] = eoe.ExtendedID
	return nil
}

type ECP struct {
	layers.BaseLayer
	TimeToLive uint8
	ExtendedID uint8
	SubType    uint8
	Version    uint8
	OpCode     uint8
	SubCode    uint8
	MessageID  uint16
	Sequence   uint16
	ReplyID    net.HardwareAddr
	ChassisID  string
	Slot       uint8
	Port       uint8
}

func decodeECP(data []byte, p gopacket.PacketBuilder) error {
	ecp := &ECP{}
	err := ecp.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}

	p.AddLayer(ecp)
	p.SetApplicationLayer(ecp)
	return nil
}

func (ecp *ECP) CanDecode() gopacket.LayerClass {
	return LayerTypeECP
}

func (ecp *ECP) LayerType() gopacket.LayerType {
	return LayerTypeECP
}

func (ecp *ECP) Payload() []byte {
	return nil
}

func (ecp *ECP) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	ecp.TimeToLive = uint8(data[0])
	ecp.ExtendedID = uint8(data[1])
	ecp.SubType = uint8(data[2])
	ecp.Version = uint8(data[3])
	ecp.OpCode = uint8(data[4])
	ecp.SubCode = uint8(data[5])
	ecp.MessageID = binary.BigEndian.Uint16(data[6:8])
	ecp.Sequence = binary.BigEndian.Uint16(data[8:10])
	ecp.ReplyID = net.HardwareAddr(data[10:16])
	ecp.ChassisID = string(data[16:48])
	ecp.Slot = uint8(data[48])
	ecp.Port = uint8(data[49])
	ecp.BaseLayer = layers.BaseLayer{Contents: data[:50], Payload: nil}
	return nil
}

func (ecp *ECP) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	bytes, err := b.PrependBytes(50)
	if err != nil {
		return err
	}

	bytes[0] = ecp.TimeToLive
	bytes[1] = ecp.ExtendedID
	bytes[2] = ecp.SubType
	bytes[3] = ecp.Version
	bytes[4] = ecp.OpCode
	bytes[5] = ecp.SubCode
	binary.BigEndian.PutUint16(bytes[6:], ecp.MessageID)
	binary.BigEndian.PutUint16(bytes[8:], ecp.Sequence)
	copy(bytes[10:], ecp.ReplyID)
	copy(bytes[16:], []byte(ecp.ChassisID))
	bytes[48] = ecp.Slot
	bytes[49] = ecp.Port
	return nil
}
