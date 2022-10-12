package apn6

import (
	"encoding/binary"
	"errors"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type Apn6Layer struct {
	layers.BaseLayer
	NextHeader    uint8
	Length        uint8
	OptionType    uint8
	OptionDataLen uint8

	ApnIdType   uint8
	Flags       uint8
	ApnParaType uint16
	ApnId       uint64
}

var Apn6LayerType = gopacket.RegisterLayerType(
	2002,
	gopacket.LayerTypeMetadata{
		Name:    "Apn6LayerType",
		Decoder: gopacket.DecodeFunc(decodeApn6Layer),
	},
)

func (l *Apn6Layer) LayerType() gopacket.LayerType {
	return Apn6LayerType
}

func (i *Apn6Layer) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 8 {
		df.SetTruncated()
		return errors.New("SRV6 layer less then 8 bytes for SRV6 packet")
	}
	i.NextHeader = data[0]
	i.Length = data[1]
	i.OptionType = data[2]
	i.OptionDataLen = data[3]

	i.ApnIdType = data[4]
	i.Flags = data[5]
	i.ApnParaType = binary.BigEndian.Uint16(data[6:8])

	i.ApnId = binary.BigEndian.Uint64(data[8:])

	return nil
}

func (i *Apn6Layer) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	l := int(i.Length)*8 + 8
	bytes, err := b.PrependBytes(l)
	if err != nil {
		return err
	}
	bytes[0] = i.NextHeader
	bytes[1] = i.Length
	bytes[2] = i.OptionType
	bytes[3] = i.OptionDataLen
	bytes[4] = i.ApnIdType
	bytes[5] = i.Flags
	binary.BigEndian.PutUint16(bytes[6:], i.ApnParaType)
	binary.BigEndian.PutUint64(bytes[8:], i.ApnId)

	return nil
}

func (i *Apn6Layer) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

func decodeApn6Layer(data []byte, p gopacket.PacketBuilder) error {
	i := &Apn6Layer{}
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
