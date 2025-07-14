package wire

import (
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"
)

type PathStatusBackupFrame struct {
	PathID uint64
}

func parsePathStatusBackupFrame(b []byte, _ protocol.Version) (*PathStatusBackupFrame, int, error) {
	f := &PathStatusBackupFrame{}
	pathID, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	f.PathID = pathID
	return f, l, nil
}

func (f *PathStatusBackupFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	typ := uint64(pathStatusBackupFrameType)
	b = quicvarint.Append(b, typ)
	b = quicvarint.Append(b, f.PathID)
	return b, nil
}

func (f *PathStatusBackupFrame) Length(_ protocol.Version) protocol.ByteCount {
	return 1 + protocol.ByteCount(quicvarint.Len(f.PathID))
}