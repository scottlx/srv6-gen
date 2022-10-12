package srv6

import (
	"encoding/binary"
	"errors"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"net"
)

type Srv6Layer struct {
	layers.BaseLayer
	NextHeader uint8
	Length     uint8
	Type       uint8
	Left       uint8
	LastEntry  uint8
	Flags      uint8
	Tag        uint16
	Address    []net.IP
}

var Srv6LayerType = gopacket.RegisterLayerType(
	2001,
	gopacket.LayerTypeMetadata{
		Name:    "Srv6LayerType",
		Decoder: gopacket.DecodeFunc(decodeSrv6Layer),
	},
)

func (l *Srv6Layer) LayerType() gopacket.LayerType {
	return Srv6LayerType
}

func (i *Srv6Layer) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 8 {
		df.SetTruncated()
		return errors.New("SRV6 layer less then 8 bytes for SRV6 packet")
	}
	i.NextHeader = data[0]
	i.Length = data[1]
	i.Type = data[2]
	i.Left = data[3]
	i.LastEntry = data[4]
	i.Flags = data[5]
	i.Tag = binary.BigEndian.Uint16(data[6:8])

	for j := 0; j < int(i.Length/2); j++ {
		startBit := 8 + 16*j
		endBit := 24 + 16*j
		var addr []byte
		for k := endBit; k >= startBit; k-- {
			addr = append(addr, data[k])
		}
		i.Address = append(i.Address, addr)
	}
	i.BaseLayer = layers.BaseLayer{
		Contents: data[:8],
		Payload:  data[8:],
	}
	return nil
}

func (i *Srv6Layer) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	l := int(i.Length)*8 + 8
	bytes, err := b.PrependBytes(l)
	if err != nil {
		return err
	}
	bytes[0] = i.NextHeader
	bytes[1] = i.Length
	bytes[2] = i.Type
	bytes[3] = i.Left
	bytes[4] = i.LastEntry
	bytes[5] = i.Flags
	binary.BigEndian.PutUint16(bytes[6:], i.Tag)

	for i2, address := range i.Address {
		lsb := binary.BigEndian.Uint64(address[:8])
		msb := binary.BigEndian.Uint64(address[8:])
		binary.BigEndian.PutUint64(bytes[8+16*i2:], lsb)
		binary.BigEndian.PutUint64(bytes[16+16*i2:], msb)
	}
	return nil
}

func (i *Srv6Layer) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// Custom decode function. We can name it whatever we want
// but it should have the same arguments and return value
// When the layer is registered we tell it to use this decode function
func decodeSrv6Layer(data []byte, p gopacket.PacketBuilder) error {
	i := &Srv6Layer{}
	err := i.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(i)
	next := i.NextLayerType()
	if next == gopacket.LayerTypeZero {
		return nil
	}
	return p.NextDecoder(next)
}
