package wire

import (
	"errors"
	"fmt"
	"io"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"
)

type PathNewConnectionIDFrame struct {
	PathID              uint64
	SequenceNumber      uint64
	RetirePriorTo       uint64
	ConnectionID        protocol.ConnectionID
	StatelessResetToken protocol.StatelessResetToken
}

func parsePathNewConnectionIDFrame(b []byte, _ protocol.Version) (*PathNewConnectionIDFrame, int, error) {
	startLen := len(b)
	f := &PathNewConnectionIDFrame{}
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
	b = b[l:]
	f.SequenceNumber = seq

	ret, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	b = b[l:]
	f.RetirePriorTo = ret

	if ret > seq {
		return nil, 0, fmt.Errorf("error Retire Prior To value (%d) larger than Sequence Number (%d)", ret, seq)
	}
	if len(b) == 0 {
		return nil, 0, io.EOF
	}
	connIDLen := int(b[0])
	b = b[1:]
	if connIDLen == 0 {
		return nil, 0, errors.New("invalid zero-length connection ID")
	}
	if connIDLen > protocol.MaxConnIDLen {
		return nil, 0, protocol.ErrInvalidConnectionIDLen
	}
	if len(b) < connIDLen {
		return nil, 0, io.EOF
	}
	f.ConnectionID = protocol.ParseConnectionID(b[:connIDLen])
	b = b[connIDLen:]
	if len(b) < len(f.StatelessResetToken) {
		return nil, 0, io.EOF
	}
	copy(f.StatelessResetToken[:], b)
	return f, startLen - len(b) + len(f.StatelessResetToken), nil
}

func (f *PathNewConnectionIDFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	typ := uint64(pathNewConnectionIDFrameType)
	b = quicvarint.Append(b, typ)
	b = quicvarint.Append(b, f.PathID)
	b = quicvarint.Append(b, f.SequenceNumber)
	b = quicvarint.Append(b, f.RetirePriorTo)
	connIDLen := f.ConnectionID.Len()
	if connIDLen > protocol.MaxConnIDLen {
		return nil, fmt.Errorf("invalid connection ID length: %d", connIDLen)
	}
	b = append(b, uint8(connIDLen))
	b = append(b, f.ConnectionID.Bytes()...)
	b = append(b, f.StatelessResetToken[:]...)
	return b, nil
}

func (f *PathNewConnectionIDFrame) Length(protocol.Version) protocol.ByteCount {
	return 1 + protocol.ByteCount(quicvarint.Len(f.PathID)+quicvarint.Len(f.SequenceNumber)+quicvarint.Len(f.RetirePriorTo)+1+f.ConnectionID.Len()) + 16
}
