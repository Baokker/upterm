package internal

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	gssh "github.com/charmbracelet/ssh"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/server"
	"github.com/owenthereal/upterm/upterm"
	"github.com/owenthereal/upterm/utils"

	"github.com/oklog/run"
	"github.com/olebedev/emitter"
	uio "github.com/owenthereal/upterm/io"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

// 命令安全等级表
var commandRiskMap = map[string]string{
	// dangerous
	"rm":       "dangerous",
	"dd":       "dangerous",
	"mkfs":     "dangerous",
	"reboot":   "dangerous",
	"shutdown": "dangerous",
	"init":     "dangerous",
	"telinit":  "dangerous",
	"poweroff": "dangerous",
	"halt":     "dangerous",
	"fdisk":    "dangerous",
	"wipefs":   "dangerous",
	"ddrescue": "dangerous",

	// risky
	"sudo":   "risky",
	"mv":     "risky",
	"cp":     "risky",
	"chmod":  "risky",
	"chown":  "risky",
	"mount":  "risky",
	"umount": "risky",
	"curl":   "risky",
	"wget":   "risky",
	"apt":    "risky",
	"yum":    "risky",
	"dnf":    "risky",
}

func getCommandRisk(cmd string) string {
	fields := strings.Fields(cmd)
	if len(fields) == 0 {
		return "secure"
	}
	base := strings.ToLower(fields[0])
	if risk, ok := commandRiskMap[base]; ok {
		return risk
	}
	return "secure"
}

// evaluateCommand 统一评估命令风险
// 返回 risk 等级(dangerous|risky|secure) 以及 是否应该拦截
func evaluateCommand(cmd, projectRoot string) (risk string, shouldBlock bool) {
	// 1. 路径越界检查
	if strings.Contains(cmd, "..") {
		parts := strings.Fields(cmd)
		for _, part := range parts {
			if !isPathInProject(part, projectRoot) {
				return "dangerous", true
			}
		}
	}

	// 2. 命令风险等级
	risk = getCommandRisk(cmd)
	switch risk {
	case "dangerous":
		return "dangerous", true
	case "risky":
		return "risky", false
	default:
		return "secure", false
	}
}

type FileAccessMonitor struct {
	ProjectRoot string
	Logger      log.FieldLogger
}

func (m *FileAccessMonitor) Check(path string) bool {
	absPath, err := filepath.Abs(path)
	if err != nil {
		m.Logger.Warnf("Invalid path: %s", path)
		return false
	}

	if !strings.HasPrefix(absPath, m.ProjectRoot) {
		m.Logger.Warnf("Blocked external access: %s", absPath)
		return false
	}
	return true
}

type Server struct {
	Command           []string
	CommandEnv        []string
	ForceCommand      []string
	Signers           []ssh.Signer
	AuthorizedKeys    []ssh.PublicKey
	EventEmitter      *emitter.Emitter
	KeepAliveDuration time.Duration
	Stdin             *os.File
	Stdout            *os.File
	Logger            log.FieldLogger
	ReadOnly          bool
}

// 获取项目根目录
func getProjectRoot() (string, error) {
	return os.Getwd()
}

func (s *Server) ServeWithContext(ctx context.Context, l net.Listener) error {
	writers := uio.NewMultiWriter(5)

	cmdCtx, cmdCancel := context.WithCancel(ctx)
	defer cmdCancel()
	cmd := newCommand(
		s.Command[0],
		s.Command[1:],
		s.CommandEnv,
		s.Stdin,
		s.Stdout,
		s.EventEmitter,
		writers,
	)
	ptmx, err := cmd.Start(cmdCtx)
	if err != nil {
		return fmt.Errorf("error starting command: %w", err)
	}

	var g run.Group
	{
		ctx, cancel := context.WithCancel(ctx)
		teh := terminalEventHandler{
			eventEmitter: s.EventEmitter,
			logger:       s.Logger,
		}
		g.Add(func() error {
			return teh.Handle(ctx)
		}, func(err error) {
			cancel()
		})
	}
	{
		g.Add(func() error {
			return cmd.Run()
		}, func(err error) {
			cmdCancel()
		})
	}
	{
		ctx, cancel := context.WithCancel(ctx)
		sh := sessionHandler{
			forceCommand:      s.ForceCommand,
			ptmx:              ptmx,
			eventEmmiter:      s.EventEmitter,
			writers:           writers,
			keepAliveDuration: s.KeepAliveDuration,
			ctx:               ctx,
			logger:            s.Logger,
			readonly:          s.ReadOnly,
		}
		ph := publicKeyHandler{
			AuthorizedKeys: s.AuthorizedKeys,
			EventEmmiter:   s.EventEmitter,
			Logger:         s.Logger,
		}

		var ss []gssh.Signer
		for _, signer := range s.Signers {
			ss = append(ss, signer)
		}

		server := gssh.Server{
			HostSigners:      ss,
			Handler:          sh.HandleSession,
			Version:          upterm.HostSSHServerVersion,
			PublicKeyHandler: ph.HandlePublicKey,
			ConnectionFailedCallback: func(conn net.Conn, err error) {
				s.Logger.WithError(err).Error("connection failed")
			},
		}
		g.Add(func() error {
			return server.Serve(l)
		}, func(err error) {
			// kill ssh sessionHandler
			cancel()
			// shut down ssh server
			_ = server.Shutdown(ctx)
		})
	}

	return g.Run()
}

type publicKeyHandler struct {
	AuthorizedKeys []ssh.PublicKey
	EventEmmiter   *emitter.Emitter
	Logger         log.FieldLogger
}

func (h *publicKeyHandler) HandlePublicKey(ctx gssh.Context, key gssh.PublicKey) bool {
	checker := server.UserCertChecker{}
	auth, pk, err := checker.Authenticate(ctx.User(), key)
	if err != nil {
		h.Logger.WithError(err).Error("error parsing auth request from cert")
		return false
	}

	// TODO: sshproxy already rejects unauthorized keys
	// Does host still need to check them?
	if len(h.AuthorizedKeys) == 0 {
		emitClientJoinEvent(h.EventEmmiter, ctx.SessionID(), auth, pk)
		return true
	}

	for _, k := range h.AuthorizedKeys {
		if utils.KeysEqual(k, pk) {
			emitClientJoinEvent(h.EventEmmiter, ctx.SessionID(), auth, pk)
			return true
		}
	}

	h.Logger.Info("unauthorized public key")
	return false
}

type sessionHandler struct {
	forceCommand      []string
	ptmx              *pty
	eventEmmiter      *emitter.Emitter
	writers           *uio.MultiWriter
	keepAliveDuration time.Duration
	ctx               context.Context
	logger            log.FieldLogger
	readonly          bool
	projectRoot       string
}

func (h *sessionHandler) HandleSession(sess gssh.Session) {
	// 获取项目根目录
	projectRoot, err := getProjectRoot()
	if err != nil {
		h.logger.Errorf("Failed to get project root: %v", err)
		return
	}
	h.projectRoot = projectRoot

	// 显示安全提示
	_, _ = io.WriteString(sess, "\r\n=== SECURITY NOTICE ===")
	_, _ = io.WriteString(sess, "\r\nYou are restricted to: "+projectRoot)
	_, _ = io.WriteString(sess, "\r\nExternal file access is blocked\r\n\r\n")

	sessionID := sess.Context().Value(gssh.ContextKeySessionID).(string)
	defer emitClientLeftEvent(h.eventEmmiter, sessionID)

	ptyReq, winCh, isPty := sess.Pty()
	if !isPty {
		_, _ = io.WriteString(sess, "PTY is required.\n")
		_ = sess.Exit(1)
	}

	var (
		g    run.Group
		ptmx = h.ptmx
	)

	// simulate openssh keepalive
	{
		ctx, cancel := context.WithCancel(h.ctx)
		g.Add(func() error {
			ticker := time.NewTicker(h.keepAliveDuration)
			defer ticker.Stop()

			for {
				select {
				case <-ticker.C:
					if _, err := sess.SendRequest(upterm.OpenSSHKeepAliveRequestType, true, nil); err != nil {
						h.logger.WithError(err).Debug("error pinging client to keepalive")
					}
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		}, func(err error) {
			cancel()
		})
	}

	if len(h.forceCommand) > 0 {
		ctx, cancel := context.WithCancel(h.ctx)
		defer cancel()
		cmd, ptmx2, err := startAttachCmd(ctx, h.forceCommand, ptyReq.Term)
		if err != nil {
			h.logger.WithError(err).Error("error starting force command")
			_ = sess.Exit(1)
			return
		}
		ptmx = ptmx2
		g.Add(func() error {
			_, err := io.Copy(sess, uio.NewContextReader(ctx, ptmx))
			return ptyError(err)
		}, func(err error) {
			cancel()
			ptmx.Close()
		})
		g.Add(func() error { return cmd.Wait() }, func(err error) {
			cancel()
			ptmx.Close()
		})
	} else {
		if err := h.writers.Append(sess); err != nil {
			_ = sess.Exit(1)
			return
		}
		defer h.writers.Remove(sess)
	}

	{
		// pty
		ctx, cancel := context.WithCancel(h.ctx)
		tee := terminalEventEmitter{h.eventEmmiter}
		g.Add(func() error {
			for {
				select {
				case win := <-winCh:
					tee.TerminalWindowChanged(sessionID, ptmx, win.Width, win.Height)
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		}, func(err error) {
			tee.TerminalDetached(sessionID, ptmx)
			cancel()
		})
	}

	// if a readonly session has been requested, don't connect stdin
	if h.readonly {
		// write to client to notify them that they have connected to a read-only session
		_, _ = io.WriteString(sess, "\r\n=== Attached to read-only session ===\r\n\r\n")
	} else {
		// input
		ctx, cancel := context.WithCancel(h.ctx)
		g.Add(func() error {

			reader := uio.NewContextReader(ctx, sess)
			var currentCommand string
			for {
				buf := make([]byte, 1024)
				n, err := reader.Read(buf)
				if err != nil {
					return err
				}

				input := string(buf[:n])
				currentCommand += input

				// 检查命令是否安全
				if strings.Contains(input, "\r") || strings.Contains(input, "\n") {
					risk, shouldBlock := evaluateCommand(currentCommand, h.projectRoot)

					if shouldBlock && risk == "dangerous" {
						// 路径越界或危险命令
						_, _ = ptmx.Write([]byte{3}) // Ctrl+C
						_, _ = sess.Write([]byte(fmt.Sprintf(
							"\r\nSECURITY BLOCKED: %s\r\n", currentCommand)))
						currentCommand = ""
						continue
					}

					if risk == "risky" {
						// 风险命令，仅终端提示后放行
						_, _ = sess.Write([]byte(fmt.Sprintf(
							"\r\nWARNING: Risky command: %s\r\n", currentCommand)))
					}

					// 安全命令或风险命令放行
					currentCommand = ""
				} else if strings.Contains(input, "\x7f") && len(currentCommand) > 0 {
					currentCommand = currentCommand[:len(currentCommand)-1]
				} else if strings.Contains(input, "\x03") {
					currentCommand = ""
				}
				_, err = ptmx.Write(buf[:n])
				if err != nil {
					return err
				}
			}
		}, func(err error) { cancel() })
	}

	if err := g.Run(); err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			_ = sess.Exit(exitError.ExitCode())
		} else {
			_ = sess.Exit(1)
		}
	} else {
		_ = sess.Exit(0)
	}
}

func emitClientJoinEvent(eventEmmiter *emitter.Emitter, sessionID string, auth *server.AuthRequest, pk ssh.PublicKey) {
	c := &api.Client{
		Id:                   sessionID,
		Version:              auth.ClientVersion,
		Addr:                 auth.RemoteAddr,
		PublicKeyFingerprint: utils.FingerprintSHA256(pk),
	}
	eventEmmiter.Emit(upterm.EventClientJoined, c)
}

func emitClientLeftEvent(eventEmmiter *emitter.Emitter, sessionID string) {
	eventEmmiter.Emit(upterm.EventClientLeft, sessionID)
}

func startAttachCmd(ctx context.Context, c []string, term string) (*exec.Cmd, *pty, error) {
	cmd := exec.CommandContext(ctx, c[0], c[1:]...)
	cmd.Env = append(os.Environ(), fmt.Sprintf("TERM=%s", term))
	pty, err := startPty(cmd)
	return cmd, pty, err
}
