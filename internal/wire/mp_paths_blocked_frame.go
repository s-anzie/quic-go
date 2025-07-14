package wire

import (
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"
)

type PathsBlockedFrame struct {
	MaxPaths uint64
}

func parsePathsBlockedFrame(b []byte, _ protocol.Version) (*PathsBlockedFrame, int, error) {
	f := &PathsBlockedFrame{}
	maxPaths, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	f.MaxPaths = maxPaths
	return f, l, nil
}

func (f *PathsBlockedFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	typ := uint64(pathsBlockedFrameType)
	b = quicvarint.Append(b, typ)
	b = quicvarint.Append(b, f.MaxPaths)
	return b, nil
}

func (f *PathsBlockedFrame) Length(_ protocol.Version) protocol.ByteCount {
	return 1 + protocol.ByteCount(quicvarint.Len(f.MaxPaths))
}