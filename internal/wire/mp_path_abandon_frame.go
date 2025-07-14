package wire

import (
	"io"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"
)

type PathAbandonFrame struct {
	PathID       uint64
	ErrorCode    uint64
	ReasonPhrase string
}

func parsePathAbandonFrame(b []byte, _ protocol.Version) (*PathAbandonFrame, int, error) {
	startLen := len(b)
	f := &PathAbandonFrame{}
	pathID, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	b = b[l:]
	f.PathID = pathID

	ec, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	b = b[l:]
	f.ErrorCode = ec

	reasonPhraseLen, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	b = b[l:]
	if int(reasonPhraseLen) > len(b) {
		return nil, 0, io.EOF
	}

	reasonPhrase := make([]byte, reasonPhraseLen)
	copy(reasonPhrase, b)
	f.ReasonPhrase = string(reasonPhrase)
	return f, startLen - len(b) + int(reasonPhraseLen), nil
}

func (f *PathAbandonFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	typ := uint64(pathAbandonFrameType)
	b = quicvarint.Append(b, typ)
	b = quicvarint.Append(b, f.PathID)
	b = quicvarint.Append(b, f.ErrorCode)
	b = quicvarint.Append(b, uint64(len(f.ReasonPhrase)))
	b = append(b, []byte(f.ReasonPhrase)...)
	return b, nil
}

func (f *PathAbandonFrame) Length(_ protocol.Version) protocol.ByteCount {
	return protocol.ByteCount(quicvarint.Len(f.PathID)+quicvarint.Len(f.ErrorCode)+quicvarint.Len(uint64(len(f.ReasonPhrase)))) + protocol.ByteCount(len(f.ReasonPhrase))
}