package wire

import (
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"
)

type PathAckFrame struct {
	PathID uint64
	AckFrame
}

func parsePathAckFrame(frame *PathAckFrame, b []byte, ackDelayExponent uint8) (*PathAckFrame, int, error) {
	pathID, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	b = b[l:]
	frame.PathID = pathID
	ackLen, err := parseAckFrame(&frame.AckFrame, b, 0, ackDelayExponent, 0)
	if err != nil {
		return nil, 0, err
	}
	return frame, l + ackLen, nil
}

func (f *PathAckFrame) Append(b []byte, v protocol.Version) ([]byte, error) {
	typ := uint64(pathAckFrameType)
	b = quicvarint.Append(b, typ)
	b = quicvarint.Append(b, f.PathID)
	return f.AckFrame.Append(b, v)
}

func (f *PathAckFrame) Length(v protocol.Version) protocol.ByteCount {
	return protocol.ByteCount(quicvarint.Len(f.PathID)) + f.AckFrame.Length(v)
}
