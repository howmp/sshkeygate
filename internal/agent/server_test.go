package agent

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/sshkeygate/sshkeygate/internal/auditlog"
	"github.com/sshkeygate/sshkeygate/internal/keystore"
	"github.com/sshkeygate/sshkeygate/internal/policy"
	"github.com/sshkeygate/sshkeygate/internal/vault"
)

// Protocol opcodes, from PROTOCOL.agent.
const (
	agentFailure         = 5
	agentSuccess         = 6
	agentcRequestIdentit = 11
	agentIdentitiesReply = 12
	agentcSignRequest    = 13
	agentSignResponse    = 14
)

type fakestore map[string][]byte

func (f fakestore) Get(k string) ([]byte, error) {
	v, ok := f[k]
	if !ok {
		return nil, errors.New("not found")
	}
	return v, nil
}

func (f fakestore) Set(k string, v []byte) error { f[k] = v; return nil }

const (
	ed25519BlobB64 = "AAAAC3NzaC1lZDI1NTE5AAAAIJpJCF84JbHwr2jeCbNr70aRpphDIeHzQ06vRWL0BVHv"
	testKeyName    = "test-ed25519"
)

func fixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "sshkey", "testdata", "id_ed25519_bwagent"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return b
}

type fixtureSet struct {
	srv    *Server
	keys   *keystore.Store
	pol    *policy.Engine
	vault  *vault.Vault
	blob   []byte
	signer ssh.Signer
}

func newFixture(t *testing.T, importKey bool) *fixtureSet {
	t.Helper()
	v, err := vault.Open(t.TempDir(), fakestore{})
	if err != nil {
		t.Fatalf("vault.Open: %v", err)
	}
	if err := v.Create("correct horse battery"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	keys := keystore.New(v)
	if err := keys.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	pol := policy.New(v)
	log, err := auditlog.Open(filepath.Join(t.TempDir(), "agent.log"))
	if err != nil {
		t.Fatalf("auditlog.Open: %v", err)
	}
	f := &fixtureSet{srv: New(keys, pol, log), keys: keys, pol: pol, vault: v}
	if importKey {
		key, _, err := keys.Import(fixture(t), testKeyName, "", keystore.SourceManual)
		if err != nil {
			t.Fatalf("Import: %v", err)
		}
		f.blob = key.Blob
	}
	return f
}

// roundTrip runs one request over an in-memory connection and returns the
// response frame body.
func roundTrip(t *testing.T, srv *Server, peer Peer, request []byte) []byte {
	t.Helper()
	clientSide, serverSide := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Serve(serverSide, peer)
	}()

	frame := make([]byte, 4+len(request))
	binary.BigEndian.PutUint32(frame, uint32(len(request)))
	copy(frame[4:], request)
	if _, err := clientSide.Write(frame); err != nil {
		t.Fatalf("write request: %v", err)
	}

	respHeader := make([]byte, 4)
	if err := readFull(clientSide, respHeader); err != nil {
		t.Fatalf("read length: %v", err)
	}
	size := binary.BigEndian.Uint32(respHeader)
	body := make([]byte, size)
	if err := readFull(clientSide, body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	clientSide.Close()
	<-done
	return body
}

func readFull(r io.Reader, buf []byte) error {
	_, err := io.ReadFull(r, buf)
	return err
}

func TestIdentitiesResponse(t *testing.T) {
	f := newFixture(t, true)
	resp := roundTrip(t, f.srv, Peer{}, []byte{agentcRequestIdentit})

	if resp[0] != agentIdentitiesReply {
		t.Fatalf("message type = %d, want %d", resp[0], agentIdentitiesReply)
	}
	if got := binary.BigEndian.Uint32(resp[1:5]); got != 1 {
		t.Fatalf("numKeys = %d, want 1", got)
	}
	blobLen := binary.BigEndian.Uint32(resp[5:9])
	blob := resp[9 : 9+blobLen]
	if got := base64.StdEncoding.EncodeToString(blob); got != ed25519BlobB64 {
		t.Errorf("key blob = %q\nwant %q", got, ed25519BlobB64)
	}
	commentOff := 9 + blobLen
	commentLen := binary.BigEndian.Uint32(resp[commentOff : commentOff+4])
	comment := string(resp[commentOff+4 : commentOff+4+commentLen])
	if comment != testKeyName {
		t.Errorf("comment = %q, want %q", comment, testKeyName)
	}
}

func TestIdentitiesFailsWhenLocked(t *testing.T) {
	f := newFixture(t, true)
	f.vault.Lock()
	f.keys.Clear()
	resp := roundTrip(t, f.srv, Peer{}, []byte{agentcRequestIdentit})
	if resp[0] != agentFailure {
		t.Errorf("message type = %d, want agentFailure while locked", resp[0])
	}
}

func TestTruncatedSignRequestFails(t *testing.T) {
	f := newFixture(t, true)
	resp := roundTrip(t, f.srv, Peer{}, []byte{agentcSignRequest})
	if !bytes.Equal(resp, []byte{agentFailure}) {
		t.Errorf("response = %v, want [5]", resp)
	}
}

func TestUnknownOpcodeFails(t *testing.T) {
	f := newFixture(t, true)
	resp := roundTrip(t, f.srv, Peer{}, []byte{0x7f})
	if resp[0] != agentFailure {
		t.Errorf("message type = %d, want agentFailure", resp[0])
	}
}

func TestOversizedFrameClosesConnection(t *testing.T) {
	f := newFixture(t, true)
	clientSide, serverSide := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = f.srv.Serve(serverSide, Peer{})
	}()
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, 8*1024*1024)
	if _, err := clientSide.Write(header); err != nil {
		t.Fatalf("write header: %v", err)
	}
	_ = clientSide.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if _, err := clientSide.Read(buf); err == nil {
		t.Error("connection stayed open after an oversized frame")
	}
	clientSide.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after the oversized frame")
	}
}

func TestSignRefusedWhileLocked(t *testing.T) {
	f := newFixture(t, true)
	f.vault.Lock()
	f.keys.Clear()
	req := signRequest(t, f.blob, []byte("data"))
	resp := roundTrip(t, f.srv, Peer{}, req)
	if resp[0] != agentFailure {
		t.Errorf("message type = %d, want agentFailure", resp[0])
	}
}

func TestSignUnknownKeyFails(t *testing.T) {
	f := newFixture(t, true)
	other := make([]byte, len(f.blob))
	copy(other, f.blob)
	other[len(other)-1] ^= 0xff
	resp := roundTrip(t, f.srv, Peer{}, signRequest(t, other, []byte("data")))
	if resp[0] != agentFailure {
		t.Errorf("message type = %d, want agentFailure for an unknown key", resp[0])
	}
}

func TestSignWithoutApprovalFails(t *testing.T) {
	f := newFixture(t, true)
	// No confirmation callback installed: the request is denied.
	resp := roundTrip(t, f.srv, Peer{}, signRequest(t, f.blob, []byte("data")))
	if resp[0] != agentFailure {
		t.Errorf("message type = %d, want agentFailure without a confirmation UI", resp[0])
	}
}

func TestSignAfterApproval(t *testing.T) {
	f := newFixture(t, true)
	f.srv.SetConfirm(func(p *Pending) { go p.Resolve(AllowOnce) })

	data := []byte("data-to-sign")
	resp := roundTrip(t, f.srv, Peer{PID: 1234}, signRequest(t, f.blob, data))
	if resp[0] != agentSignResponse {
		t.Fatalf("message type = %d, want %d", resp[0], agentSignResponse)
	}
	sig, err := parseSignature(resp[1:])
	if err != nil {
		t.Fatalf("parse signature: %v", err)
	}
	pub, err := ssh.ParsePublicKey(f.blob)
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	if err := pub.Verify(data, sig); err != nil {
		t.Errorf("signature does not verify: %v", err)
	}
}

func TestConcurrentSignRequestsAllAnswered(t *testing.T) {
	f := newFixture(t, true)
	f.srv.SetConfirm(func(p *Pending) {
		go p.Resolve(AllowOnce)
	})

	var wg sync.WaitGroup
	results := make([]byte, 3)
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp := roundTrip(t, f.srv, Peer{PID: 1}, signRequest(t, f.blob, []byte("data")))
			results[i] = resp[0]
		}(i)
	}
	wg.Wait()
	for i, msgType := range results {
		if msgType != agentSignResponse {
			t.Errorf("request %d answered with %d, want a signature", i, msgType)
		}
	}
}

func TestDenyBlocksSignature(t *testing.T) {
	f := newFixture(t, true)
	f.srv.SetConfirm(func(p *Pending) { go p.Resolve(Deny) })
	resp := roundTrip(t, f.srv, Peer{PID: 9}, signRequest(t, f.blob, []byte("data")))
	if resp[0] != agentFailure {
		t.Errorf("message type = %d, want agentFailure after deny", resp[0])
	}
}

func TestTrustedProgramSkipsThePrompt(t *testing.T) {
	f := newFixture(t, true)
	exe := filepath.Join(t.TempDir(), "ssh.exe")
	if err := os.WriteFile(exe, []byte("binary"), 0o700); err != nil {
		t.Fatalf("write executable: %v", err)
	}
	if err := f.pol.TrustProgram(exe); err != nil {
		t.Fatalf("TrustProgram: %v", err)
	}

	f.srv.SetConfirm(func(p *Pending) { t.Error("prompted for a trusted program") })
	resp := roundTrip(t, f.srv, Peer{PID: 5, Path: exe}, signRequest(t, f.blob, []byte("data")))
	if resp[0] != agentSignResponse {
		t.Errorf("message type = %d, want a signature", resp[0])
	}
}

func TestKeyManagementIsRefused(t *testing.T) {
	f := newFixture(t, true)
	clientSide, serverSide := net.Pipe()
	go func() { _ = f.srv.Serve(serverSide, Peer{}) }()
	client := agent.NewClient(clientSide)

	if err := client.RemoveAll(); err == nil {
		t.Error("RemoveAll succeeded, want an error")
	}
	if err := client.Lock([]byte("x")); err == nil {
		t.Error("Lock succeeded, want an error")
	}
	clientSide.Close()
}

// signRequest builds a sign request frame body.
func signRequest(t *testing.T, blob, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	buf.WriteByte(agentcSignRequest)
	writeString(&buf, blob)
	writeString(&buf, data)
	buf.Write([]byte{0, 0, 0, 0}) // flags
	return buf.Bytes()
}

func writeString(buf *bytes.Buffer, b []byte) {
	lenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBytes, uint32(len(b)))
	buf.Write(lenBytes)
	buf.Write(b)
}

// parseSignature reads a sign response body after the message type. The body
// is one SSH string holding the marshaled signature.
func parseSignature(body []byte) (*ssh.Signature, error) {
	var raw struct {
		Blob []byte
	}
	if err := ssh.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	var sig ssh.Signature
	if err := ssh.Unmarshal(raw.Blob, &sig); err != nil {
		return nil, err
	}
	return &sig, nil
}
