package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
	"os"
	"srv6-gen/apn6"
	"srv6-gen/conf"
	"srv6-gen/srv6"
	"time"
)

var (
	device       string        = "vpp1host"
	snapshot_len int32         = 1024
	promiscuous  bool          = false
	timeout      time.Duration = 30 * time.Second
	handle       *pcap.Handle
	buffer       gopacket.SerializeBuffer
	options      gopacket.SerializeOptions
)

const (
	ethNextIpv6  = 0x86dd
	IcmpRequest  = 0x0800
	ProtocalIcmp = 1
	Ip6NextSrv6  = 43
	Ip6NextDoh   = 60
	Ip6NextIpv4  = 4
	IcmpLen      = 8
	Ip4Len       = 20
)

func main() {
	path := os.Args[1]
	cfg, err := conf.LoadConfig(path)
	if err != nil {
		log.Fatal(err)
	}
	// Open device
	handle, err = pcap.OpenLive(cfg.Device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	var pktLayer []gopacket.SerializableLayer

	pktLayer = AppendEthHeader(cfg, pktLayer)

	pktLayer = AppendIp6Header(cfg, pktLayer)

	pktLayer = AppendSrHeader(cfg, pktLayer)

	pktLayer = AppendIp4Header(cfg, pktLayer)
	pktLayer = AppendIcmpHeader(cfg, pktLayer)

	pktLayer = append(pktLayer, gopacket.Payload(cfg.PayLoad))

	// Create the packet with the layers
	buffer = gopacket.NewSerializeBuffer()
	options.ComputeChecksums = true

	gopacket.SerializeLayers(buffer, options,
		pktLayer...,
	)
	outgoingPacket := buffer.Bytes()
	// Send our packet
	err = handle.WritePacketData(outgoingPacket)
	if err != nil {
		log.Fatal(err)
	}
}

func AppendEthHeader(cfg *conf.Config, pktLayer []gopacket.SerializableLayer) []gopacket.SerializableLayer {
	srcMac, err := net.ParseMAC(cfg.L2Src)
	if err != nil {
		log.Fatal(err)
	}
	dstMac, err := net.ParseMAC(cfg.L2Dst)
	if err != nil {
		log.Fatal(err)
	}
	ethernetLayer := &layers.Ethernet{
		SrcMAC:       srcMac,
		DstMAC:       dstMac,
		EthernetType: ethNextIpv6,
	}
	return append(pktLayer, ethernetLayer)
}

func AppendIp6Header(cfg *conf.Config, pktLayer []gopacket.SerializableLayer) []gopacket.SerializableLayer {
	srv6HeaderLength := 8 + 16*len(cfg.SrhAddresses)
	var apn6HeaderLength int
	if cfg.EncapApn6 {
		apn6HeaderLength = 16
	}
	ipv6Layer := &layers.IPv6{
		Version:      6,
		TrafficClass: 0,
		FlowLabel:    0xf141,
		Length:       uint16(Ip4Len + IcmpLen + len(cfg.PayLoad) + srv6HeaderLength + apn6HeaderLength),
		NextHeader:   Ip6NextSrv6,
		HopLimit:     62,
		SrcIP:        net.ParseIP(cfg.UnderlayV6Src),
		DstIP:        net.ParseIP(cfg.UnderlayV6Dst),
	}
	return append(pktLayer, ipv6Layer)
}

func AppendIp4Header(cfg *conf.Config, pktLayer []gopacket.SerializableLayer) []gopacket.SerializableLayer {
	ipLayer := &layers.IPv4{
		Version:    4,
		IHL:        5,
		TOS:        0,
		Length:     uint16(Ip4Len + IcmpLen + len(cfg.PayLoad)),
		Id:         0,
		Flags:      0,
		FragOffset: 0,
		TTL:        254,
		Protocol:   ProtocalIcmp,
		SrcIP:      net.ParseIP(cfg.OverlayV4Src),
		DstIP:      net.ParseIP(cfg.OverlayV4Dst),
	}
	return append(pktLayer, ipLayer)
}

func AppendIcmpHeader(cfg *conf.Config, pktLayer []gopacket.SerializableLayer) []gopacket.SerializableLayer {
	icmpLayer := &layers.ICMPv4{
		TypeCode: IcmpRequest,
		Id:       0x7cf5,
		Seq:      0x0100,
	}
	return append(pktLayer, icmpLayer)
}

func AppendSrHeader(cfg *conf.Config, pktLayer []gopacket.SerializableLayer) []gopacket.SerializableLayer {
	var dohLayer *apn6.Apn6Layer
	var srv6Layer *srv6.Srv6Layer

	var srhAddr []net.IP
	for _, address := range cfg.SrhAddresses {
		srhAddr = append(srhAddr, net.ParseIP(address))
	}

	if cfg.EncapApn6 {
		dohLayer = &apn6.Apn6Layer{
			NextHeader:    Ip6NextIpv4,
			Length:        1,
			OptionType:    0x13,
			OptionDataLen: 12,
			ApnIdType:     0,
			Flags:         0,
			ApnParaType:   0,
			ApnId:         0x1234567812345678,
		}
		srv6Layer = &srv6.Srv6Layer{
			NextHeader: Ip6NextDoh,
			Length:     uint8(2 * len(cfg.SrhAddresses)),
			Type:       4,
			Left:       1,
			LastEntry:  2,
			Flags:      0,
			Tag:        0,
			Address:    srhAddr,
		}
		pktLayer = append(pktLayer, srv6Layer)
		pktLayer = append(pktLayer, dohLayer)

	} else {
		srv6Layer = &srv6.Srv6Layer{
			NextHeader: Ip6NextIpv4,
			Length:     uint8(2 * len(cfg.SrhAddresses)),
			Type:       4,
			Left:       1,
			LastEntry:  2,
			Flags:      0,
			Tag:        0,
			Address:    srhAddr,
		}
		pktLayer = append(pktLayer, srv6Layer)
	}

	return pktLayer
}
