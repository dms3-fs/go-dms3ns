package examples

import (
	"time"

	pb "github.com/dms3-fs/go-dms3ns/pb"

	dms3ns "github.com/dms3-fs/go-dms3ns"
	crypto "github.com/dms3-p2p/go-p2p-crypto"
)

// CreateEntryWithEmbed shows how you can create an DMS3NS entry
// and embed it with a public key. For ed25519 keys this is not needed
// so attempting to embed with an ed25519 key, will not actually embed the key
func CreateEntryWithEmbed(dms3fsPath string, publicKey crypto.PubKey, privateKey crypto.PrivKey) (*pb.Dms3NsEntry, error) {
	dms3fsPathByte := []byte(dms3fsPath)
	eol := time.Now().Add(time.Hour * 48)
	entry, err := dms3ns.Create(privateKey, dms3fsPathByte, 1, eol)
	if err != nil {
		return nil, err
	}
	err = dms3ns.EmbedPublicKey(publicKey, entry)
	if err != nil {
		return nil, err
	}
	return entry, nil
}
