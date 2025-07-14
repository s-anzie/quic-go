package wire

import (
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"
)

type PathRetireConnectionIDFrame struct {
	PathID         uint64
	SequenceNumber uint64
}

func parsePathRetireConnectionIDFrame(b []byte, _ protocol.Version) (*PathRetireConnectionIDFrame, int, error) {
	f := &PathRetireConnectionIDFrame{}
	pathID, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	b = b[l:]
	f.PathID = pathID

	seq, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	f.SequenceNumber = seq
	return f, l, nil
}

func (f *PathRetireConnectionIDFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	typ := uint64(pathRetireConnectionIDFrameType)
	b = quicvarint.Append(b, typ)
	b = quicvarint.Append(b, f.PathID)
	b = quicvarint.Append(b, f.SequenceNumber)
	return b, nil
}

func (f *PathRetireConnectionIDFrame) Length(protocol.Version) protocol.ByteCount {
	return 1 + protocol.ByteCount(quicvarint.Len(f.PathID)+quicvarint.Len(f.SequenceNumber))
}