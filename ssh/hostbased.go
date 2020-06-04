package ssh

import (
	"io"
)

type hostbasedAuthMsg struct {
	User       string `sshtype:"50"`
	Service    string
	Method     string
	Algoname   string
	PubKey     []byte
	ClientHost string
	ClientUser string
	// Sig is tagged with "rest" so Marshal will exclude it during
	// validateKey
	Sig []byte `ssh:"rest"`
}

// buildDataSignedForHostBasedAuth returns the data that is signed in order to prove
// possession of a private key. See RFC 4252, section 7.
func buildDataSignedForHostBasedAuth(sessionID []byte, req userAuthRequestMsg, algo, pubKey []byte, clientHost string, clientUser string) []byte {
	data := struct {
		Session    []byte
		Type       byte
		User       string
		Service    string
		Method     string
		Algo       []byte
		PubKey     []byte
		ClientHost string
		ClientUser string
	}{
		sessionID,
		msgUserAuthRequest,
		req.User,
		req.Service,
		req.Method,
		algo,
		pubKey,
		clientHost,
		clientUser,
	}
	return Marshal(data)
}

// hostBasedCallback is an AuthMethod that uses a set of key
// pairs for authentication.
type hostBasedCallback func() ([]Signer, string, string, error)

func (cb hostBasedCallback) method() string {
	return "hostbased"
}

func (cb hostBasedCallback) auth(session []byte, user string, c packetConn, rand io.Reader) (authResult, []string, error) {
	signers, clientHost, clientUser, err := cb()
	if err != nil {
		return authFailure, nil, err
	}
	var methods []string
	for _, signer := range signers {
		pub := signer.PublicKey()
		pubKey := pub.Marshal()
		sign, err := signer.Sign(rand, buildDataSignedForHostBasedAuth(session, userAuthRequestMsg{
			User:    user,
			Service: serviceSSH,
			Method:  cb.method(),
		}, []byte(pub.Type()), pubKey, clientHost, clientUser))
		if err != nil {
			return authFailure, nil, err
		}

		// manually wrap the serialized signature in a string
		s := Marshal(sign)
		sig := make([]byte, stringLength(len(s)))
		marshalString(sig, s)
		msg := hostbasedAuthMsg{
			User:       user,
			Service:    serviceSSH,
			Method:     cb.method(),
			Algoname:   pub.Type(),
			PubKey:     pubKey,
			ClientHost: clientHost,
			ClientUser: clientUser,
			Sig:        sig,
		}
		p := Marshal(&msg)
		if err := c.writePacket(p); err != nil {
			return authFailure, nil, err
		}
		var success authResult
		success, methods, err = handleAuthResponse(c)
		if err != nil {
			return authFailure, nil, err
		}

		if success == authSuccess {
			return success, methods, err
		}
	}

	return authFailure, methods, nil
}

// HostBased returns an AuthMethod that uses the given key
// pairs.
func HostBased(clientHost string, clientUser string, signers ...Signer) AuthMethod {
	return hostBasedCallback(func() ([]Signer, string, string, error) { return signers, clientHost, clientUser, nil })
}

// HostBasedCallback returns an AuthMethod that runs the given
// function to obtain a list of key pairs.
func HostBasedCallback(getSigners func() (signers []Signer, clientHost string, clientUser string, err error)) AuthMethod {
	return hostBasedCallback(getSigners)
}
