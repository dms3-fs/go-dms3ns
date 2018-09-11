package dms3ns

import (
	"fmt"
	"testing"
	"time"

	u "github.com/dms3-fs/go-fs-util"
	ci "github.com/dms3-p2p/go-p2p-crypto"
	peer "github.com/dms3-p2p/go-p2p-peer"
)

func TestEmbedPublicKey(t *testing.T) {

	sr := u.NewTimeSeededRand()
	priv, pub, err := ci.GenerateKeyPairWithReader(ci.RSA, 1024, sr)
	if err != nil {
		t.Fatal(err)
	}

	pid, err := peer.IDFromPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}

	e, err := Create(priv, []byte("/a/b"), 0, time.Now().Add(1*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := EmbedPublicKey(pub, e); err != nil {
		t.Fatal(err)
	}
	embeddedPk, err := ci.UnmarshalPublicKey(e.PubKey)
	if err != nil {
		t.Fatal(err)
	}
	embeddedPid, err := peer.IDFromPublicKey(embeddedPk)
	if err != nil {
		t.Fatal(err)
	}
	if embeddedPid != pid {
		t.Fatalf("pid mismatch: %s != %s", pid, embeddedPid)
	}
}

func ExampleCreate() {
	// Generate a private key to sign the DMS3NS record with. Most of the time,
	// however, you'll want to retrieve an already-existing key from DMS3FS using
	// go-dms3-fs/core/coreapi CoreAPI.KeyAPI() interface.
	privateKey, _, err := ci.GenerateKeyPair(ci.RSA, 2048)
	if err != nil {
		panic(err)
	}

	// Create an DMS3NS record that expires in one hour and points to the DMS3FS address
	// /dms3fs/Qme1knMqwt1hKZbc1BmQFmnm9f36nyQGwXxPGVpVJ9rMK5
	dms3nsRecord, err := Create(privateKey, []byte("/dms3fs/Qme1knMqwt1hKZbc1BmQFmnm9f36nyQGwXxPGVpVJ9rMK5"), 0, time.Now().Add(1*time.Hour))
	if err != nil {
		panic(err)
	}

	fmt.Println(dms3nsRecord)
}
