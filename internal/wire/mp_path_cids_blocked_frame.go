package wire

import (
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"
)

type PathCIDsBlockedFrame struct {
	MaxPathCIDs uint64
}

func parsePathCIDsBlockedFrame(b []byte, _ protocol.Version) (*PathCIDsBlockedFrame, int, error) {
	f := &PathCIDsBlockedFrame{}
	maxPathCIDs, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	f.MaxPathCIDs = maxPathCIDs
	return f, l, nil
}

func (f *PathCIDsBlockedFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	typ := uint64(pathCIDsBlockedFrameType)
	b = quicvarint.Append(b, typ)
	b = quicvarint.Append(b, f.MaxPathCIDs)
	return b, nil
}

func (f *PathCIDsBlockedFrame) Length(_ protocol.Version) protocol.ByteCount {
	return 1 + protocol.ByteCount(quicvarint.Len(f.MaxPathCIDs))
}