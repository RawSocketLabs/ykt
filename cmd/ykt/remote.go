package main

// Native SSH client for host-collect / host-install --apply.
// Auth comes from the operator's running ssh-agent (which is where the
// daily YubiKey-backed key lives anyway); host keys verify against
// ~/.ssh/known_hosts — including our own @cert-authority lines.

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

func sshConnect(dest string) (*ssh.Client, error) { return dialSSH(dest, false) }

// sshConnectTOFU is sshConnect with trust-on-first-use: an unknown host key is
// shown to the operator for confirmation and then pinned to known_hosts. Used
// by host-collect, whose whole job is onboarding brand-new hosts.
func sshConnectTOFU(dest string) (*ssh.Client, error) { return dialSSH(dest, true) }

func dialSSH(dest string, tofu bool) (*ssh.Client, error) {
	user := os.Getenv("USER")
	host := dest
	if i := strings.Index(dest, "@"); i >= 0 {
		user, host = dest[:i], dest[i+1:]
	}
	if !strings.Contains(host, ":") {
		host += ":22"
	}

	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return nil, fmt.Errorf("SSH_AUTH_SOCK not set — start ssh-agent and load your key: ssh-add -K (resident) or ssh-add ~/.ssh/" + dailyKeyName)
	}
	conn, err := net.Dial("unix", sock)
	if err != nil {
		return nil, fmt.Errorf("connecting to ssh-agent: %w", err)
	}
	ag := agent.NewClient(conn)
	if signers, _ := ag.Signers(); len(signers) == 0 {
		return nil, fmt.Errorf("ssh-agent holds no identities — load your key first: ssh-add -K (resident) or ssh-add ~/.ssh/" + dailyKeyName)
	}

	home, _ := os.UserHomeDir()
	khPath := filepath.Join(home, ".ssh", "known_hosts")
	if tofu { // ensure the file exists so knownhosts.New doesn't error
		if _, err := os.Stat(khPath); os.IsNotExist(err) {
			_ = os.MkdirAll(filepath.Dir(khPath), 0o700)
			_ = os.WriteFile(khPath, nil, 0o644)
		}
	}
	known, err := knownhosts.New(khPath)
	if err != nil {
		return nil, fmt.Errorf("loading %s: %w", khPath, err)
	}

	hostKeyCB := known
	if tofu {
		hostKeyCB = tofuHostKeyCallback(known, khPath)
	}

	cfg := &ssh.ClientConfig{
		User:              user,
		Auth:              []ssh.AuthMethod{ssh.PublicKeysCallback(ag.Signers)},
		HostKeyCallback:   hostKeyCB,
		HostKeyAlgorithms: preferredHostKeyAlgos(),
	}
	return ssh.Dial("tcp", host, cfg)
}

// tofuHostKeyCallback trusts a known host key normally; for a genuinely
// unknown host it shows the fingerprint, asks the operator, and pins it. A
// key that MISMATCHES a pinned entry is always rejected (possible MITM).
func tofuHostKeyCallback(known ssh.HostKeyCallback, khPath string) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := known(hostname, remote, key)
		if err == nil {
			return nil
		}
		var ke *knownhosts.KeyError
		if !errors.As(err, &ke) || len(ke.Want) > 0 {
			return err // real mismatch (pinned key differs) — never auto-trust
		}
		warn("first contact with %s — host key is not yet known", hostname)
		say("  %s %s", key.Type(), ssh.FingerprintSHA256(key))
		if !confirm("  Trust and pin this host key?") {
			return fmt.Errorf("host key for %s not trusted by operator", hostname)
		}
		line := knownhosts.Line([]string{knownhosts.Normalize(hostname)}, key)
		f, ferr := os.OpenFile(khPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if ferr != nil {
			return ferr
		}
		defer f.Close()
		_, werr := f.WriteString(line + "\n")
		return werr
	}
}

func preferredHostKeyAlgos() []string {
	return []string{
		ssh.CertAlgoED25519v01, ssh.CertAlgoECDSA256v01,
		ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoRSASHA256,
	}
}

// remoteRun executes one command, returning combined output.
func remoteRun(c *ssh.Client, cmd string) (string, error) {
	sess, err := c.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	var buf bytes.Buffer
	sess.Stdout, sess.Stderr = &buf, &buf
	err = sess.Run(cmd)
	return buf.String(), err
}

// remoteWriteFile streams content to a root-owned path via sudo tee — no
// sftp subsystem or scp binary needed.
func remoteWriteFile(c *ssh.Client, path string, content []byte, mode string) error {
	sess, err := c.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	sess.Stdin = bytes.NewReader(content)
	var buf bytes.Buffer
	sess.Stdout, sess.Stderr = &buf, &buf
	cmd := fmt.Sprintf("sudo install -m %s /dev/stdin %s", mode, shellQuote(path))
	if err := sess.Run(cmd); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(buf.String()))
	}
	return nil
}

// remoteReadFile reads a (world-readable) remote file.
func remoteReadFile(c *ssh.Client, path string) ([]byte, error) {
	out, err := remoteRun(c, "cat "+shellQuote(path))
	if err != nil {
		return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(out))
	}
	return []byte(out), nil
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
