package wire

import (
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"
)

type PathStatusAvailableFrame struct {
	PathID uint64
}

func parsePathStatusAvailableFrame(b []byte, _ protocol.Version) (*PathStatusAvailableFrame, int, error) {
	f := &PathStatusAvailableFrame{}
	pathID, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	f.PathID = pathID
	return f, l, nil
}

func (f *PathStatusAvailableFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	typ := uint64(pathStatusAvailableFrameType)
	b = quicvarint.Append(b, typ)
	b = quicvarint.Append(b, f.PathID)
	return b, nil
}

func (f *PathStatusAvailableFrame) Length(_ protocol.Version) protocol.ByteCount {
	return 1 + protocol.ByteCount(quicvarint.Len(f.PathID))
}