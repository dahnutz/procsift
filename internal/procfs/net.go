package procfs

import (
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/dahnutz/procsift/internal/model"
)

// TCP and UDP state numbers from include/net/tcp_states.h.
var protoStates = map[int]string{
	1:  "ESTABLISHED",
	2:  "SYN_SENT",
	3:  "SYN_RECV",
	4:  "FIN_WAIT1",
	5:  "FIN_WAIT2",
	6:  "TIME_WAIT",
	7:  "CLOSE",
	8:  "CLOSE_WAIT",
	9:  "LAST_ACK",
	10: "LISTEN",
	11: "CLOSING",
}

// ParsePacket reads /proc/net/packet, whose columns differ from TCP and raw.
// It also counts rows that cannot be parsed so the collector can report gaps.
func ParsePacket(text string) ([]model.Socket, int) {
	var out []model.Socket
	malformed := 0
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] == "sk" {
			continue
		}
		if len(f) < 9 {
			malformed++
			continue
		}
		kind, e1 := strconv.Atoi(f[2])
		protocol, e2 := strconv.ParseUint(f[3], 16, 16)
		iface, e3 := strconv.Atoi(f[4])
		uid, e4 := strconv.Atoi(f[7])
		inode, e5 := strconv.ParseUint(f[8], 10, 64)
		if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil {
			malformed++
			continue
		}
		out = append(out, model.Socket{
			Proto: "packet", Local: fmt.Sprintf("iface=%d", iface),
			State: fmt.Sprintf("type=%d protocol=0x%04x", kind, protocol),
			UID:   uid, Inode: inode,
		})
	}
	return out, malformed
}

// ParseNet reads /proc/net/tcp, tcp6, udp, or udp6. proto is stored on each row.
func ParseNet(proto, text string) []model.Socket {
	var out []model.Socket
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 10 {
			continue
		}
		if strings.Contains(f[0], "sl") || strings.Contains(line, "local_address") {
			continue
		}
		stateID, err := strconv.ParseInt(f[3], 16, 32)
		if err != nil {
			continue
		}
		uid, _ := strconv.Atoi(f[7])
		inode, err := strconv.ParseUint(f[9], 10, 64)
		if err != nil {
			continue
		}
		name := protoStates[int(stateID)]
		if name == "" {
			name = f[3]
		}
		out = append(out, model.Socket{
			Proto:   proto,
			Local:   formatEndpoint(f[1]),
			Remote:  formatEndpoint(f[2]),
			State:   name,
			StateID: int(stateID),
			UID:     uid,
			Inode:   inode,
		})
	}
	return out
}

func formatEndpoint(raw string) string {
	ipHex, portHex, ok := strings.Cut(raw, ":")
	if !ok {
		return raw
	}
	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return raw
	}
	ip := decodeProcIP(ipHex)
	if ip == "" {
		return raw
	}
	return ip + ":" + strconv.FormatUint(port, 10)
}

func decodeProcIP(ipHex string) string {
	b, err := hex.DecodeString(ipHex)
	if err != nil {
		return ""
	}
	switch len(b) {
	case 4:
		// /proc prints IPv4 little-endian.
		return net.IPv4(b[3], b[2], b[1], b[0]).String()
	case 16:
		ip := make(net.IP, 16)
		for i := 0; i < 16; i += 4 {
			ip[i] = b[i+3]
			ip[i+1] = b[i+2]
			ip[i+2] = b[i+1]
			ip[i+3] = b[i]
		}
		return ip.String()
	default:
		return ""
	}
}
