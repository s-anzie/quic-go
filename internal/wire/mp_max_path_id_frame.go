package wire

import (
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"
)

type MaxPathIDFrame struct {
	MaxPathID uint64
}

func parseMaxPathIDFrame(b []byte, _ protocol.Version) (*MaxPathIDFrame, int, error) {
	f := &MaxPathIDFrame{}
	maxPathID, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	f.MaxPathID = maxPathID
	return f, l, nil
}

func (f *MaxPathIDFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	typ := uint64(maxPathIDFrameType)
	b = quicvarint.Append(b, typ)
	b = quicvarint.Append(b, f.MaxPathID)
	return b, nil
}

func (f *MaxPathIDFrame) Length(_ protocol.Version) protocol.ByteCount {
	return 1 + protocol.ByteCount(quicvarint.Len(f.MaxPathID))
}