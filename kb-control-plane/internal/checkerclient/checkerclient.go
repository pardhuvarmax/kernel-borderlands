// Package checkerclient dials kb-checker's diagnostic UDS socket
// (/run/kb/kbc.sock, ipc.SocketCheckerDiag) and asks it whether it
// considers itself healthy. kb-checker is the one that knows this — its
// self-assessment (JIT signature audits, heartbeat liveness) lives entirely
// in its own process, so kbd has no way to compute it and has to ask.
package checkerclient

import (
	"context"
	"fmt"
	"net"
	"time"

	checkerpb "github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/proto/checker"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// GetStatus dials socketPath (a kb-checker UDS gRPC socket) and returns
// its self-reported health. Callers should treat any error as "offline" —
// kb-checker not being reachable is itself an unhealthy signal, not
// something to propagate as a request failure.
func GetStatus(ctx context.Context, socketPath string, timeout time.Duration) (*checkerpb.StatusResponse, error) {
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := grpc.DialContext(dialCtx, "unix:"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketPath)
		}),
		grpc.WithBlock(),
	)
	if err != nil {
		return nil, fmt.Errorf("dial kb-checker at %s: %w", socketPath, err)
	}
	defer conn.Close()

	client := checkerpb.NewCheckerStatusClient(conn)
	callCtx, callCancel := context.WithTimeout(ctx, timeout)
	defer callCancel()

	resp, err := client.GetStatus(callCtx, &checkerpb.StatusRequest{})
	if err != nil {
		return nil, fmt.Errorf("kb-checker GetStatus: %w", err)
	}
	return resp, nil
}
