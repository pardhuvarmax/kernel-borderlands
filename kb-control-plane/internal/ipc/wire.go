package ipc

import (
    "encoding/binary"
    "fmt"
    "io"
    "math"
    "net"
    "os"
)

const (
    WireMagic          uint16 = 0x4B42
    WireVersion        uint8  = 3
    WireMsgProcessState   uint8 = 1
    WireMsgZoneTransition uint8 = 2
    DefaultSocketPath           = "/run/kb/kbd.sock"
    DimCount                    = 6
)
func GetSocketPath() string {
    if p := os.Getenv("KB_SOCKET_PATH"); p != ""{
        return p
    }
    return DefaultSocketPath
}

type KBZone uint32
const (
    ZoneSafe        KBZone = 0
    ZoneSuspicious  KBZone = 1
    ZoneBorderlands KBZone = 2
)
func (z KBZone) String() string {
    switch z {
    case ZoneSafe:        return "SAFE"
    case ZoneSuspicious:  return "SUSPICIOUS"
    case ZoneBorderlands: return "BORDERLANDS"
    default:              return "UNKNOWN"
    }
}

var DimNames   = [DimCount]string{"process","syscall","privilege","file","network","memory"}
var DimWeights = [DimCount]float64{0.20,0.25,0.20,0.10,0.10,0.15}

type ProcessStateMsg struct {
    PID                     uint32
    PPID                    uint32
    UID                     uint32
    Comm                    string
    StartTimeNs             uint64
    LastUpdatedNs           uint64
    DimScore                [DimCount]float64
    CompositeScore          float64
    EMAScore                float64
    SyscallEntropyLifetime  float64  // advisory only — do NOT use for zone decisions
    Zone                    KBZone
    EventCount              uint32
}

type ZoneTransitionMsg struct {
    PID          uint32
    StartTimeNs  uint64  // PID-reuse guard — verify before enforcing
    FromZone     KBZone
    ToZone       KBZone
    Score        float64
    TsNs         uint64
}

type MessageHandler interface {
    OnProcessState(msg *ProcessStateMsg)
    OnZoneTransition(msg *ZoneTransitionMsg)
}

func readFloat64(buf []byte, off int) (float64, int) {
    bits := binary.LittleEndian.Uint64(buf[off:])
    return math.Float64frombits(bits), off + 8
}

// Wire sizes below are derived from the actual C struct layout in
// kb_bridge.c (verified via sizeof(), not hand-counted from a doc —
// hand-counting is exactly how these numbers drifted last time).
// Both include the 4-byte header, since buf here is the full frame
// payload (header + body), not just the body.
//
//   kb_wire_process_state:   128 bytes  (was miscounted as 130)
//   kb_wire_zone_transition:  40 bytes
func parseProcessState(buf []byte) (*ProcessStateMsg, error) {
    const expected = 128 
    if len(buf) < expected {
        return nil, fmt.Errorf("process state: want %d bytes got %d", expected, len(buf))
    }
    off := 4 // skip header (magic+version+msg_type already validated)
    msg := &ProcessStateMsg{}

    msg.PID  = binary.LittleEndian.Uint32(buf[off:]); off += 4
    msg.PPID = binary.LittleEndian.Uint32(buf[off:]); off += 4
    msg.UID  = binary.LittleEndian.Uint32(buf[off:]); off += 4

    raw := buf[off : off+16]; off += 16
    for i, b := range raw { if b == 0 { raw = raw[:i]; break } }
    msg.Comm = string(raw)

    msg.StartTimeNs   = binary.LittleEndian.Uint64(buf[off:]); off += 8
    msg.LastUpdatedNs = binary.LittleEndian.Uint64(buf[off:]); off += 8

    for i := 0; i < DimCount; i++ {
        msg.DimScore[i], off = readFloat64(buf, off)
    }
    msg.CompositeScore,         off = readFloat64(buf, off)
    msg.EMAScore,               off = readFloat64(buf, off)
    msg.SyscallEntropyLifetime, off = readFloat64(buf, off)

    msg.Zone       = KBZone(binary.LittleEndian.Uint32(buf[off:])); off += 4
    msg.EventCount = binary.LittleEndian.Uint32(buf[off:])
    return msg, nil
}

func parseZoneTransition(buf []byte) (*ZoneTransitionMsg, error) {
    const expected = 40
    if len(buf) < expected {
        return nil, fmt.Errorf("zone transition: want %d bytes got %d", expected, len(buf))
    }
    off := 4
    msg := &ZoneTransitionMsg{}
    msg.PID         = binary.LittleEndian.Uint32(buf[off:]); off += 4
    msg.StartTimeNs = binary.LittleEndian.Uint64(buf[off:]); off += 8
    msg.FromZone    = KBZone(binary.LittleEndian.Uint32(buf[off:])); off += 4
    msg.ToZone      = KBZone(binary.LittleEndian.Uint32(buf[off:])); off += 4
    msg.Score,      off = readFloat64(buf, off)
    msg.TsNs        = binary.LittleEndian.Uint64(buf[off:])
    return msg, nil
}

type Reader struct{ conn net.Conn; handler MessageHandler }

func NewReader(conn net.Conn, h MessageHandler) *Reader { return &Reader{conn, h} }

func (r *Reader) ReadLoop() error {
    for {
        var length uint32
        if err := binary.Read(r.conn, binary.LittleEndian, &length); err != nil {
            return err
        }
        if length == 0 || length > 65536 {
            return fmt.Errorf("invalid frame length %d", length)
        }
        buf := make([]byte, length)
        if _, err := io.ReadFull(r.conn, buf); err != nil { return err }
        if len(buf) < 4 { continue }

        magic   := binary.LittleEndian.Uint16(buf[0:2])
        version := buf[2]
        msgType := buf[3]

        if magic != WireMagic {
            continue // not KB frame
        }
        if version != WireVersion {
            return fmt.Errorf("wire version mismatch: got %d want %d", version, WireVersion)
        }

        switch msgType {
        case WireMsgProcessState:
            if msg, err := parseProcessState(buf); err == nil {
                r.handler.OnProcessState(msg)
            }
        case WireMsgZoneTransition:
            if msg, err := parseZoneTransition(buf); err == nil {
                r.handler.OnZoneTransition(msg)
            }
        }
    }
}