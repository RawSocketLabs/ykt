package main

// Native YubiKey PIV operations via go-piv (no ykman, no OpenSC, no PKCS#11).
// Only pcscd needs to be running.

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-piv/piv-go/v2/piv"
)

// pivKey is the slice of *piv.YubiKey behavior ykt uses. Widening the concrete
// type to this interface lets tests substitute a software backend (fakePIV) for
// the hardware, exercising the genesis/enroll/sign/stash orchestration without a
// YubiKey. *piv.YubiKey satisfies it directly, so the production path is
// unchanged — this is a type-widening, not a logic change.
type pivKey interface {
	Close() error
	Version() piv.Version
	Serial() (uint32, error)
	Retries() (int, error)
	Reset() error
	SetManagementKey(oldKey, newKey []byte) error
	SetPIN(oldPIN, newPIN string) error
	SetPUK(oldPUK, newPUK string) error
	VerifyPIN(pin string) error
	Metadata(pin string) (*piv.Metadata, error)
	SetMetadata(key []byte, m *piv.Metadata) error
	GenerateKey(key []byte, slot piv.Slot, opts piv.Key) (crypto.PublicKey, error)
	PrivateKey(slot piv.Slot, public crypto.PublicKey, auth piv.KeyAuth) (crypto.PrivateKey, error)
	Attest(slot piv.Slot) (*x509.Certificate, error)
	AttestationCertificate() (*x509.Certificate, error)
	Certificate(slot piv.Slot) (*x509.Certificate, error)
	SetCertificate(key []byte, slot piv.Slot, cert *x509.Certificate) error
}

// slotByName maps registry slot strings ("82".."95", "9a", "9c", "9d", "9e").
func slotByName(name string) (piv.Slot, error) {
	switch strings.ToLower(name) {
	case "9a":
		return piv.SlotAuthentication, nil
	case "9c":
		return piv.SlotSignature, nil
	case "9d":
		return piv.SlotKeyManagement, nil
	case "9e":
		return piv.SlotCardAuthentication, nil
	}
	n, err := strconv.ParseUint(name, 16, 32)
	if err != nil {
		return piv.Slot{}, fmt.Errorf("bad slot %q", name)
	}
	s, ok := piv.RetiredKeyManagementSlot(uint32(n))
	if !ok {
		return piv.Slot{}, fmt.Errorf("%q is not a retired key management slot", name)
	}
	return s, nil
}

func slotHint(name string) string {
	switch strings.ToLower(name) {
	case "9a":
		return "standard slot 9a (PIV Authentication)"
	case "9c":
		return "standard slot 9c (Digital Signature)"
	case "9d":
		return "standard slot 9d (Key Management)"
	case "9e":
		return "standard slot 9e (Card Authentication)"
	}
	n, _ := strconv.ParseUint(name, 16, 32)
	return fmt.Sprintf("retired slot %s (a.k.a. \"Retired KEY MAN %d\")", name, n-0x82+1)
}

// listYubiKeys returns "serial -> card name" for every connected YubiKey.
func listYubiKeys() (map[uint32]string, error) {
	cards, err := piv.Cards()
	if err != nil {
		return nil, fmt.Errorf("pcscd unreachable? %w", err)
	}
	out := map[uint32]string{}
	for _, card := range cards {
		if !strings.Contains(strings.ToLower(card), "yubikey") {
			continue
		}
		yk, err := piv.Open(card)
		if err != nil {
			warn("cannot open %q: %v", card, err)
			warn("(another process holding the card? gpg-agent/scdaemon and browser smartcard support are the usual suspects)")
			continue
		}
		serial, err := yk.Serial()
		yk.Close()
		if err != nil {
			warn("cannot read serial of %q: %v", card, err)
			continue
		}
		out[serial] = card
	}
	return out, nil
}

// pickYubiKey selects the YubiKey to operate on.
//   - expected != "" (and not "unset"): the registry knows which serial this
//     anchor is — verify it's connected and confirm once. No typing.
//   - one key connected: confirm it. Several: type the serial (the guard
//     that keeps an anchor operation off a daily-carry key).
//
// pickYubiKeyHook lets tests substitute a fake device (and skip enumeration).
// nil in production.
var pickYubiKeyHook func(expected string) (pivKey, uint32)

func pickYubiKey(expected string) (pivKey, uint32) {
	if pickYubiKeyHook != nil {
		return pickYubiKeyHook(expected)
	}
	head("YubiKey selection")
	if dryRun {
		// Honor the contract: --dry-run touches no hardware. Don't enumerate or
		// open any card; return the expected serial (if any) as a placeholder.
		note("dry-run: not touching any YubiKey")
		var chosen uint32
		if expected != "" && expected != "unset" {
			if n, err := strconv.ParseUint(expected, 10, 32); err == nil {
				chosen = uint32(n)
			}
		}
		return nil, chosen
	}
	keys, err := listYubiKeys()
	if err != nil || len(keys) == 0 {
		if dryRun {
			note("dry-run: no YubiKey available — using a placeholder")
			keys = map[uint32]string{0: "(dry-run placeholder)"}
		} else if err != nil {
			fatal("listing YubiKeys: %v", err)
		} else {
			fatal("no YubiKey detected over PC/SC — plugged in? PIV/CCID enabled?\n  check: ykman info   enable: ykman config usb --enable PIV (then replug)")
		}
	}
	var chosen uint32
	switch {
	case expected != "" && expected != "unset":
		want, err := strconv.ParseUint(expected, 10, 32)
		if err != nil {
			fatal("registry has a malformed yubikey_serial %q", expected)
		}
		if _, ok := keys[uint32(want)]; !ok && !dryRun {
			say("Connected: %v", keyList(keys))
			fatal("expected YubiKey serial %s (from registry) is NOT connected — wrong key inserted?", expected)
		}
		good("found expected YubiKey serial %s (matches registry)", expected)
		if !dryRun && !confirm("Proceed with this key?") {
			fatal("aborted")
		}
		chosen = uint32(want)
	case len(keys) == 1:
		for s := range keys {
			chosen = s
		}
		say("One YubiKey connected: serial %d (%s)", chosen, keys[chosen])
		if !dryRun && !confirm("Use this key?") {
			fatal("aborted")
		}
	default:
		say("Connected YubiKeys:")
		for serial, card := range keys {
			say("  serial %-10d %s", serial, card)
		}
		warn("Multiple keys — make sure you pick the right one.")
		typed := prompt("Type the SERIAL of the YubiKey to use: ")
		n, err := strconv.ParseUint(typed, 10, 32)
		if err != nil {
			fatal("that is not a serial number")
		}
		if _, ok := keys[uint32(n)]; !ok {
			fatal("serial %s is not among the connected keys", typed)
		}
		chosen = uint32(n)
	}
	if dryRun {
		return nil, chosen
	}
	yk, err := piv.Open(keys[chosen])
	if err != nil {
		fatal("opening YubiKey: %v", err)
	}
	return yk, chosen
}

// presentQuiet reports whether a YubiKey with the serial is connected,
// without warning on transient open failures (used while polling).
func presentQuiet(serial uint32) bool {
	cards, err := piv.Cards()
	if err != nil {
		return false
	}
	for _, card := range cards {
		if !strings.Contains(strings.ToLower(card), "yubikey") {
			continue
		}
		yk, err := piv.Open(card)
		if err != nil {
			continue
		}
		s, err := yk.Serial()
		yk.Close()
		if err == nil && s == serial {
			return true
		}
	}
	return false
}

// waitForReplug walks the operator through unplug → replug, returning the
// moment the key is detected again — so a follow-up command lands inside
// the YubiKey's 5-second post-insertion window.
func waitForReplug(serial uint32) {
	fmt.Println(colorize(cYlw, fmt.Sprintf("  👉 UNPLUG the YubiKey (serial %d) now…", serial)))
	for presentQuiet(serial) {
		time.Sleep(300 * time.Millisecond)
	}
	good("removed")
	fmt.Println(colorize(cYlw, "  👉 PLUG IT BACK IN…"))
	for !presentQuiet(serial) {
		time.Sleep(300 * time.Millisecond)
	}
	good("detected — continuing immediately")
}

// openBySerial (re)opens a YubiKey after a replug, retrying while PC/SC
// re-enumerates the reader.
func openBySerial(serial uint32) pivKey {
	for i := 0; i < 20; i++ {
		if keys, err := listYubiKeys(); err == nil {
			if card, ok := keys[serial]; ok {
				if yk, err := piv.Open(card); err == nil {
					return yk
				}
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	fatal("YubiKey serial %d did not come back after replug — re-insert and re-run", serial)
	return nil
}

func keyList(keys map[uint32]string) []uint32 {
	out := make([]uint32, 0, len(keys))
	for s := range keys {
		out = append(out, s)
	}
	return out
}

// pivPreflight verifies the card is workable BEFORE any input is gathered:
// firmware version reported, PIN counter not blocked.
func pivPreflight(yk pivKey) {
	if yk == nil { // dry-run
		return
	}
	v := yk.Version()
	r, err := yk.Retries()
	if err != nil {
		fatal("reading PIN retry counter: %v", err)
	}
	if r == 0 {
		fatal("this key's PIV PIN is BLOCKED (0 retries left). Fix first:\n  ykman piv access unblock-pin   (needs PUK)\n  or: ykman piv reset            (wipes the PIV applet)")
	}
	good("preflight: firmware %d.%d.%d · PIN retries left %d", v.Major, v.Minor, v.Patch, r)
}

// verifyPINOnce validates the PIN immediately so a typo surfaces here — with
// the retry count — instead of blocking the card mid-operation.
func verifyPINOnce(yk pivKey, pin string) {
	if yk == nil {
		return
	}
	if err := yk.VerifyPIN(pin); err != nil {
		r, _ := yk.Retries()
		fatal("PIN rejected (%v) — %d retries remain. Re-run when sure; do NOT guess.", err, r)
	}
	good("PIN verified")
}

// mgmtKey resolves the management key: PIN-protected metadata (our standard,
// set during init ca) with a fallback to the factory default for a
// brand-new key.
func mgmtKey(yk pivKey, pin string) []byte {
	if m, err := yk.Metadata(pin); err == nil && m.ManagementKey != nil {
		return *m.ManagementKey
	}
	note("no PIN-protected management key found — assuming factory default (new YubiKey)")
	return piv.DefaultManagementKey
}

func generateOnDevice(yk pivKey, key []byte, slotName string) (crypto.PublicKey, error) {
	slot, err := slotByName(slotName)
	if err != nil {
		return nil, err
	}
	return yk.GenerateKey(key, slot, piv.Key{
		Algorithm:   piv.AlgorithmEC256,
		PINPolicy:   piv.PINPolicyOnce,
		TouchPolicy: piv.TouchPolicyCached,
	})
}

// pivSigner returns a crypto.Signer backed by a key living in a slot.
func pivSigner(yk pivKey, slotName string, pub crypto.PublicKey, pin string) (crypto.Signer, error) {
	slot, err := slotByName(slotName)
	if err != nil {
		return nil, err
	}
	// PINPolicyOnce matches how init ca generates every key; setting it
	// explicitly avoids an attestation-cert lookup inside the signing path.
	priv, err := yk.PrivateKey(slot, pub, piv.KeyAuth{PIN: pin, PINPolicy: piv.PINPolicyOnce})
	if err != nil {
		return nil, err
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("slot %s key does not implement crypto.Signer", slotName)
	}
	return signer, nil
}

// slotPublicKey loads the public key for a slot from the certificate object.
func slotPublicKey(yk pivKey, slotName string) (crypto.PublicKey, error) {
	slot, err := slotByName(slotName)
	if err != nil {
		return nil, err
	}
	cert, err := yk.Certificate(slot)
	if err != nil {
		return nil, fmt.Errorf("no certificate object in slot %s (anchor not initialized?): %w", slotName, err)
	}
	return cert.PublicKey, nil
}

func attest(yk pivKey, slotName string) (*x509.Certificate, error) {
	slot, err := slotByName(slotName)
	if err != nil {
		return nil, err
	}
	return yk.Attest(slot)
}

func setSlotCertificate(yk pivKey, key []byte, slotName string, cert *x509.Certificate) error {
	slot, err := slotByName(slotName)
	if err != nil {
		return err
	}
	return yk.SetCertificate(key, slot, cert)
}

// slotCertificate reads a slot's certificate object (no PIN/touch needed).
func slotCertificate(yk pivKey, slotName string) (*x509.Certificate, error) {
	slot, err := slotByName(slotName)
	if err != nil {
		return nil, err
	}
	return yk.Certificate(slot)
}

// stashOnCard wraps payload in an X.509 carrier and stores it in slotName on
// the daily key, so `ykt setup key` can recover it elsewhere. Honors dry-run.
func stashOnCard(yk pivKey, mk []byte, slotName, label string, payload []byte) error {
	if dryRun {
		return nil
	}
	cert, err := buildCarrier(label, payload)
	if err != nil {
		return err
	}
	return setSlotCertificate(yk, mk, slotName, cert)
}

// ---------------------------------------------------------------- pem io

func writePEM(path, blockType string, der []byte) error {
	return writeFileAtomic(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o644)
}

func writeCertPEM(path string, cert *x509.Certificate) error {
	return writePEM(path, "CERTIFICATE", cert.Raw)
}

func writePubPEM(path string, pub crypto.PublicKey) error {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return err
	}
	return writePEM(path, "PUBLIC KEY", der)
}
