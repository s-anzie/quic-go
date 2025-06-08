package quic

import (
	"context"
	"crypto/rand"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
)

// Path IDs are now uint64, managed by multipathManager.
const invalidPathID = ^uint64(0) // Max uint64 as an invalid marker

var (
	// ErrPathClosed is returned when trying to switch to a path that has been closed.
	ErrPathClosed = errors.New("path closed")
	// ErrPathNotValidated is returned when trying to use a path before path probing has completed.
	ErrPathNotValidated = errors.New("path not yet validated")
)

var errPathDoesNotExist = errors.New("path does not exist")

// Path is a network path.
type Path struct {
	id          uint64 // Use uint64 for path ID
	pathManager *pathManagerOutgoing
	tr          *Transport
	initialRTT  time.Duration

	enablePath func()
	validated  atomic.Bool
	abandon    chan struct{}
}

func (p *Path) Probe(ctx context.Context) error {
	path := p.pathManager.addPath(p, p.enablePath)

	p.pathManager.enqueueProbe(p)
	nextProbeDur := p.initialRTT
	var timer *time.Timer
	var timerChan <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-path.Validated():
			p.validated.Store(true)
			return nil
		case <-timerChan:
			p.pathManager.enqueueProbe(p)
		case <-path.ProbeSent():
		case <-p.abandon:
			return ErrPathClosed
		}

		if timer != nil {
			timer.Stop()
		}
		timer = time.NewTimer(nextProbeDur)
		timerChan = timer.C
		nextProbeDur *= 2 // exponential backoff
	}
}

// Switch switches the QUIC connection to this path.
// It immediately stops sending on the old path, and sends on this new path.
func (p *Path) Switch() error {
	if err := p.pathManager.switchToPath(p.id); err != nil {
		switch {
		case errors.Is(err, ErrPathNotValidated):
			return err
		case errors.Is(err, errPathDoesNotExist) && !p.validated.Load():
			select {
			case <-p.abandon:
				return ErrPathClosed
			default:
				return ErrPathNotValidated
			}
		default:
			return ErrPathClosed
		}
	}
	return nil
}

// Close abandons a path.
// It is not possible to close the path that’s currently active.
// After closing, it is not possible to probe this path again.
func (p *Path) Close() error {
	select {
	case <-p.abandon:
		return nil
	default:
	}

	if err := p.pathManager.removePath(p.id); err != nil {
		return err
	}
	close(p.abandon)
	return nil
}

type pathOutgoing struct {
	id             uint64 // The uint64 ID assigned by multipathManager
	pathChallenges [][8]byte // length is implicitly limited by exponential backoff
	tr             *Transport
	isValidated    bool
	probeSent      chan struct{} // receives when a PATH_CHALLENGE is sent
	validated      chan struct{} // closed when the path the corresponding PATH_RESPONSE is received
	enablePath     func()
}

func (p *pathOutgoing) ProbeSent() <-chan struct{} { return p.probeSent }
func (p *pathOutgoing) Validated() <-chan struct{} { return p.validated }

type pathManagerOutgoing struct {
	getConnID             func(id uint64) (_ protocol.ConnectionID, ok bool)
	retireConnID          func(id uint64)
	scheduleSending       func()
	pathValidatedCallback func(pathID uint64) // Callback to signal path validation

	mx             sync.Mutex
	activePath     uint64
	pathsToProbe   []uint64
	paths          map[uint64]*pathOutgoing
	pathToSwitchTo *pathOutgoing
}

func newPathManagerOutgoing(
	getConnID func(id uint64) (_ protocol.ConnectionID, ok bool),
	retireConnID func(id uint64),
	scheduleSending func(),
	pathValidatedCallback func(pathID uint64),
) *pathManagerOutgoing {
	return &pathManagerOutgoing{
		activePath:            0, // Path ID 0 is the primary path
		getConnID:             getConnID,
		retireConnID:          retireConnID,
		scheduleSending:       scheduleSending,
		paths:                 make(map[uint64]*pathOutgoing, 4),
		pathValidatedCallback: pathValidatedCallback,
	}
}

func (pm *pathManagerOutgoing) addPath(pArg *Path, enablePath func()) *pathOutgoing {
	pm.mx.Lock()
	defer pm.mx.Unlock()

	// path might already exist, and just being re-probed
	if existingPath, ok := pm.paths[pArg.id]; ok {
		existingPath.validated = make(chan struct{})
		return existingPath
	}

	path := &pathOutgoing{
		id:         pArg.id, // Store the uint64 ID
		tr:         pArg.tr,
		probeSent:  make(chan struct{}, 1),
		validated:  make(chan struct{}),
		enablePath: enablePath,
	}
	pm.paths[pArg.id] = path
	return path
}

func (pm *pathManagerOutgoing) enqueueProbe(p *Path) {
	pm.mx.Lock()
	pm.pathsToProbe = append(pm.pathsToProbe, p.id)
	pm.mx.Unlock()
	pm.scheduleSending()
}

func (pm *pathManagerOutgoing) removePath(id uint64) error {
	if err := pm.removePathImpl(id); err != nil {
		return err
	}
	pm.scheduleSending()
	return nil
}

func (pm *pathManagerOutgoing) removePathImpl(id uint64) error {
	pm.mx.Lock()
	defer pm.mx.Unlock()

	if id == pm.activePath {
		return errors.New("cannot close active path")
	}
	p, ok := pm.paths[id]
	if !ok {
		return nil
	}
	if len(p.pathChallenges) > 0 {
		pm.retireConnID(id)
	}
	delete(pm.paths, id)
	return nil
}

func (pm *pathManagerOutgoing) switchToPath(id uint64) error {
	pm.mx.Lock()
	defer pm.mx.Unlock()

	p, ok := pm.paths[id]
	if !ok {
		return errPathDoesNotExist
	}
	if !p.isValidated {
		return ErrPathNotValidated
	}
	pm.pathToSwitchTo = p
	pm.activePath = id
	return nil
}

func (pm *pathManagerOutgoing) NewPath(t *Transport, idToUse uint64, initialRTT time.Duration, enablePath func()) *Path {
	pm.mx.Lock()
	defer pm.mx.Unlock()

	return &Path{
		pathManager: pm,
		id:          idToUse,
		tr:          t,
		enablePath:  enablePath,
		initialRTT:  initialRTT,
		abandon:     make(chan struct{}),
	}
}

// NextPathToProbe is called by the connection to get the next path to probe.
func (pm *pathManagerOutgoing) NextPathToProbe(getPathCtx func(pathIDForPathObject uint64) *path) (_ protocol.ConnectionID, _ ackhandler.Frame, _ *Transport, _ *path, hasPath bool) {
	pm.mx.Lock()
	defer pm.mx.Unlock()

	var p *pathOutgoing
	id := invalidPathID
	var pathInfoForPN *path // This is the *quic.path from connection.go's mpManager

	originalPathsToProbe := pm.pathsToProbe
	var remainingPathsToProbe []uint64

	for _, pID := range originalPathsToProbe {
		var ok bool
		p, ok = pm.paths[pID]
		if ok {
			pathInfoForPN = getPathCtx(pID)
			if pathInfoForPN == nil {
				// Corresponding quic.path doesn't exist in mpManager or has no pnSpace,
				// cannot generate packet number for probe. Keep it in pathsToProbe for later.
				remainingPathsToProbe = append(remainingPathsToProbe, pID)
				p = nil
				id = invalidPathID
				continue
			}
			id = pID // id is now confirmed to be valid and has a context
			// Remove current pID from remaining, as it's being processed
		} else {
			// if the path doesn't exist in the map, it might have been abandoned
			// Do not add to remainingPathsToProbe
		}
		if id != invalidPathID { // Found a valid path to probe
			break
		}
	}
	// Update pm.pathsToProbe to only contain paths that were not processed or skipped this round
	if id != invalidPathID && len(pm.pathsToProbe) > 0 { // if a path was selected, remove it from original list
		var newPathsToProbe []uint64
		for _, pID := range pm.pathsToProbe {
			if pID != id {
				newPathsToProbe = append(newPathsToProbe, pID)
			}
		}
		pm.pathsToProbe = newPathsToProbe
	} else { // if no path was selected or list was empty, use remaining (which might be same as original or subset)
		pm.pathsToProbe = remainingPathsToProbe
	}


	if id == invalidPathID {
		return protocol.ConnectionID{}, ackhandler.Frame{}, nil, nil, false
	}

	connID, ok := pm.getConnID(id)
	if !ok {
		// This path is problematic, remove from pathsToProbe for next attempt
		var newPathsToProbe []uint64
		for _, pID := range pm.pathsToProbe {
			if pID != id {
				newPathsToProbe = append(newPathsToProbe, pID)
			}
		}
		pm.pathsToProbe = newPathsToProbe
		return protocol.ConnectionID{}, ackhandler.Frame{}, nil, nil, false
	}

	var b [8]byte
	_, _ = rand.Read(b[:])
	p.pathChallenges = append(p.pathChallenges, b)

	select {
	case p.probeSent <- struct{}{}:
	default:
	}
	p.enablePath() // This was already here, for the *pathOutgoing's transport
	// The actual *quic.path (pathInfoForPN) is used for PN, not for its transport.
	frame := ackhandler.Frame{
		Frame:   &wire.PathChallengeFrame{Data: b},
		Handler: (*pathManagerOutgoingAckHandler)(pm),
	}
	return connID, frame, p.tr, pathInfoForPN, true // Return the *quic.path context
}

func (pm *pathManagerOutgoing) HandlePathResponseFrame(f *wire.PathResponseFrame) {
	pm.mx.Lock()
	defer pm.mx.Unlock()

	for pathID_map_key, pathDetails_map_value := range pm.paths {
		if slices.Contains(pathDetails_map_value.pathChallenges, f.Data) {
			// path validated
			if !pathDetails_map_value.isValidated {
				pathDetails_map_value.isValidated = true
				pathDetails_map_value.pathChallenges = nil // Clear challenges once validated
				close(pathDetails_map_value.validated)
				if pm.pathValidatedCallback != nil {
					pm.pathValidatedCallback(pathDetails_map_value.id)
				}
			}
			break
		}
	}
}

func (pm *pathManagerOutgoing) ShouldSwitchPath() (*Transport, bool) {
	pm.mx.Lock()
	defer pm.mx.Unlock()

	if pm.pathToSwitchTo == nil {
		return nil, false
	}
	p := pm.pathToSwitchTo
	pm.pathToSwitchTo = nil
	return p.tr, true
}

type pathManagerOutgoingAckHandler pathManagerOutgoing

var _ ackhandler.FrameHandler = &pathManagerOutgoingAckHandler{}

// OnAcked is called when the PATH_CHALLENGE is acked.
// This doesn't validate the path, only receiving the PATH_RESPONSE does.
func (pm *pathManagerOutgoingAckHandler) OnAcked(wire.Frame) {}

func (pm *pathManagerOutgoingAckHandler) OnLost(wire.Frame) {}
