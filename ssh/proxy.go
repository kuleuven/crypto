// This file is implemented with reference to tg123/sshpiper.
// Ref: https://github.com/tg123/sshpiper/blob/master/vendor/golang.org/x/crypto/ssh/sshpiper.go
// Thanks to @tg123

package ssh

import (
	"errors"
	"fmt"
	"net"
)

type userFile string

var (
	userAuthorizedKeysFile userFile = "authorized_keys"
	userPrivateKeyFile     userFile = "id_rsa"
)

type AuthType int

type AuthRequestMsg interface {
	GetUser() string
	GetService() string
	GetMethod() string
	GetPayload() []byte
}

func (msg *userAuthRequestMsg) GetUser() string {
	return msg.User
}

func (msg *userAuthRequestMsg) GetService() string {
	return msg.Service
}

func (msg *userAuthRequestMsg) GetMethod() string {
	return msg.Method
}

func (msg *userAuthRequestMsg) GetPayload() []byte {
	return msg.Payload
}

type ProxyConfig struct {
	ServerConfig         *ServerConfig
	UpstreamCallback     func(AuthRequestMsg) (net.Conn, error)
	ClientConfigCallback func(AuthRequestMsg) (*ClientConfig, error)
}

type proxyConn struct {
	serverConfig *ServerConfig
	clientConfig *ClientConfig
	Upstream     *connection
	Downstream   *connection
}

func NewProxyConn(conn net.Conn, config *ProxyConfig) (pConn *proxyConn, err error) {
	d, err := newDownstreamConn(conn, config.ServerConfig)
	if err != nil {
		return nil, err
	}
	defer func() {
		if pConn == nil {
			d.Close()
		}
	}()

	authRequestMsg, err := d.getAuthRequestMsg()
	if err != nil {
		return nil, err
	}

	clientConfig, err := config.ClientConfigCallback(authRequestMsg)
	if err != nil {
		return nil, err
	}

	upConn, err := config.UpstreamCallback(authRequestMsg)
	if err != nil {
		return nil, err
	}

	u, err := newUpstreamConn(upConn, clientConfig)
	if err != nil {
		return nil, err
	}
	defer func() {
		if pConn == nil {
			u.Close()
		}
	}()

	pConn = &proxyConn{
		serverConfig: config.ServerConfig,
		clientConfig: clientConfig,
		Upstream:     u,
		Downstream:   d,
	}

	if err = pConn.authenticateProxyConn(authRequestMsg); err != nil {
		return nil, err
	}

	return pConn, nil
}

func (p *proxyConn) handleAuthMsg(msg *userAuthRequestMsg) (*userAuthRequestMsg, error) {
	username := msg.User
	switch msg.Method {
	case "publickey":
		downStreamPublicKey, isQuery, sig, err := parsePublicKeyMsg(msg)
		if err != nil {
			break
		}

		if isQuery {
			if err := p.sendOKMsg(downStreamPublicKey); err != nil {
				return nil, err
			}
			return nil, nil
		}

		// Validate the downstream ssh key
		_, err = p.serverConfig.PublicKeyCallback(p.Downstream, downStreamPublicKey)
		if err != nil {
			return noneAuthMsg(username), nil
		}

		// Verify the downstream signature
		ok, err := p.verifySignature(msg, downStreamPublicKey, sig)
		if err != nil || !ok {
			break
		}

		// Get the upstream authMethod
		for _, authMethod := range p.clientConfig.Auth {
			f, ok := authMethod.(publicKeyCallback)
			if !ok {
				break
			}

			signers, err := f()
			if err != nil || len(signers) == 0 {
				break
			}

			for _, signer := range signers {
				msg, err = p.signAgain(p.clientConfig.User, msg, signer)
				if err != nil {
					break
				}
				return msg, nil
			}
		}

	case "password":
		// In the case of password authentication,
		// since authentication is left up to the upstream server,
		// it suffices to flow the packet as it is.
		return msg, nil

	default:
		return msg, nil
	}

	err := p.sendFailureMsg(msg.Method)
	return nil, err
}

func (p *proxyConn) sendOKMsg(key PublicKey) error {
	okMsg := userAuthPubKeyOkMsg{
		Algo:   key.Type(),
		PubKey: key.Marshal(),
	}

	return p.Downstream.transport.writePacket(Marshal(&okMsg))
}

func (p *proxyConn) sendFailureMsg(method string) error {
	var failureMsg userAuthFailureMsg
	failureMsg.Methods = append(failureMsg.Methods, method)

	return p.Downstream.transport.writePacket(Marshal(&failureMsg))
}

func (p *proxyConn) verifySignature(msg *userAuthRequestMsg, publicKey PublicKey, sig *Signature) (bool, error) {
	if !isAcceptableAlgo(sig.Format) {
		return false, fmt.Errorf("ssh: algorithm %q not accepted", sig.Format)
	}
	signedData := buildDataSignedForAuth(p.Downstream.transport.getSessionID(), *msg, []byte(publicKey.Type()), publicKey.Marshal())

	if err := publicKey.Verify(signedData, sig); err != nil {
		return false, nil
	}

	return true, nil
}

func (p *proxyConn) signAgain(user string, msg *userAuthRequestMsg, signer Signer) (*userAuthRequestMsg, error) {
	rand := p.Upstream.transport.config.Rand
	sessionID := p.Upstream.transport.getSessionID()
	upStreamPublicKey := signer.PublicKey()
	upStreamPublicKeyData := upStreamPublicKey.Marshal()

	sign, err := signer.Sign(rand, buildDataSignedForAuth(sessionID, userAuthRequestMsg{
		User:    user,
		Service: serviceSSH,
		Method:  "publickey",
	}, []byte(upStreamPublicKey.Type()), upStreamPublicKeyData))
	if err != nil {
		return nil, err
	}

	// manually wrap the serialized signature in a string
	s := Marshal(sign)
	sig := make([]byte, stringLength(len(s)))
	marshalString(sig, s)

	publicKeyMsg := &publickeyAuthMsg{
		User:     user,
		Service:  serviceSSH,
		Method:   "publickey",
		HasSig:   true,
		Algoname: upStreamPublicKey.Type(),
		PubKey:   upStreamPublicKeyData,
		Sig:      sig,
	}

	Unmarshal(Marshal(publicKeyMsg), msg)

	return msg, nil
}

func (p *proxyConn) Wait() error {
	c := make(chan error)

	go func() {
		c <- piping(p.Upstream.transport, p.Downstream.transport)
	}()

	go func() {
		c <- piping(p.Downstream.transport, p.Upstream.transport)
	}()

	defer p.Close()
	return <-c
}

func (p *proxyConn) Close() {
	p.Upstream.transport.Close()
	p.Downstream.transport.Close()
}

func (p *proxyConn) checkBridgeAuthWithNoBanner(packet []byte) (bool, error) {
	err := p.Upstream.transport.writePacket(packet)
	if err != nil {
		return false, err
	}

	for {
		packet, err := p.Upstream.transport.readPacket()
		if err != nil {
			return false, err
		}

		msgType := packet[0]

		if err = p.Downstream.transport.writePacket(packet); err != nil {
			return false, err
		}

		switch msgType {
		case msgUserAuthSuccess:
			return true, nil
		case msgUserAuthBanner:
			continue
		case msgUserAuthFailure:
		default:
		}

		return false, nil
	}
}

func (p *proxyConn) authenticateProxyConn(initUserAuthMsg *userAuthRequestMsg) error {
	err := p.Upstream.sendAuthReq()
	if err != nil {
		return err
	}

	userAuthMsg := initUserAuthMsg
	for {
		userAuthMsg, err = p.handleAuthMsg(userAuthMsg)
		if err != nil {
			fmt.Println(err)
		}

		if userAuthMsg != nil {
			isSuccess, err := p.checkBridgeAuthWithNoBanner(Marshal(userAuthMsg))
			if err != nil {
				return err
			}
			if isSuccess {
				return nil
			}
		}

		var packet []byte

		for {
			// Read next msg after a failure
			if packet, err = p.Downstream.transport.readPacket(); err != nil {
				return err
			}

			if packet[0] == msgUserAuthRequest {
				break
			}

			return errors.New("auth request msg can be acceptable")
		}

		var userAuthReq userAuthRequestMsg

		if err = Unmarshal(packet, &userAuthReq); err != nil {
			return err
		}

		userAuthMsg = &userAuthReq
	}
}

func parsePublicKeyMsg(userAuthReq *userAuthRequestMsg) (PublicKey, bool, *Signature, error) {
	if userAuthReq.Method != "publickey" {
		return nil, false, nil, fmt.Errorf("not a publickey auth msg")
	}

	payload := userAuthReq.Payload
	if len(payload) < 1 {
		return nil, false, nil, parseError(msgUserAuthRequest)
	}
	isQuery := payload[0] == 0
	payload = payload[1:]
	algoBytes, payload, ok := parseString(payload)
	if !ok {
		return nil, false, nil, parseError(msgUserAuthRequest)
	}
	algo := string(algoBytes)
	if !isAcceptableAlgo(algo) {
		return nil, false, nil, fmt.Errorf("ssh: algorithm %q not accepted", algo)
	}

	pubKeyData, payload, ok := parseString(payload)
	if !ok {
		return nil, false, nil, parseError(msgUserAuthRequest)
	}

	publicKey, err := ParsePublicKey(pubKeyData)
	if err != nil {
		return nil, false, nil, err
	}

	var sig *Signature
	if !isQuery {
		sig, payload, ok = parseSignature(payload)
		if !ok || len(payload) > 0 {
			return nil, false, nil, parseError(msgUserAuthRequest)
		}
	}

	return publicKey, isQuery, sig, nil
}

func piping(dst, src packetConn) error {
	for {
		p, err := src.readPacket()
		if err != nil {
			return err
		}

		if err := dst.writePacket(p); err != nil {
			return err
		}
	}
}

func noneAuthMsg(user string) *userAuthRequestMsg {
	return &userAuthRequestMsg{
		User:    user,
		Service: serviceSSH,
		Method:  "none",
	}
}

func newDownstreamConn(c net.Conn, config *ServerConfig) (*connection, error) {
	fullConf := *config
	fullConf.SetDefaults()

	conn := &connection{
		sshConn: sshConn{conn: c},
	}

	_, err := conn.serverHandshakeWithNoAuth(&fullConf)
	if err != nil {
		c.Close()
		return nil, err
	}

	return conn, nil
}

func newUpstreamConn(c net.Conn, config *ClientConfig) (*connection, error) {
	fullConf := *config
	fullConf.SetDefaults()

	conn := &connection{
		sshConn: sshConn{conn: c},
	}

	if err := conn.clientHandshakeWithNoAuth(c.RemoteAddr().String(), &fullConf); err != nil {
		c.Close()
		return nil, err
	}

	return conn, nil
}

func (c *connection) sendAuthReq() error {
	if err := c.transport.writePacket(Marshal(&serviceRequestMsg{serviceUserAuth})); err != nil {
		return err
	}

	packet, err := c.transport.readPacket()
	if err != nil {
		return err
	}
	var serviceAccept serviceAcceptMsg
	return Unmarshal(packet, &serviceAccept)
}

func (c *connection) getAuthRequestMsg() (*userAuthRequestMsg, error) {
	var userAuthReq userAuthRequestMsg

	if packet, err := c.transport.readPacket(); err != nil {
		return nil, err
	} else if err = Unmarshal(packet, &userAuthReq); err != nil {
		return nil, err
	}

	if userAuthReq.Service != serviceSSH {
		return nil, errors.New("ssh: client attempted to negotiate for unknown service: " + userAuthReq.Service)
	}
	c.user = userAuthReq.User

	return &userAuthReq, nil
}

func (c *connection) clientHandshakeWithNoAuth(dialAddress string, config *ClientConfig) error {
	c.clientVersion = []byte(packageVersion)
	if config.ClientVersion != "" {
		c.clientVersion = []byte(config.ClientVersion)
	}

	var err error
	c.serverVersion, err = exchangeVersions(c.sshConn.conn, c.clientVersion)
	if err != nil {
		return err
	}

	c.transport = newClientTransport(
		newTransport(c.sshConn.conn, config.Rand, true /* is client */),
		c.clientVersion, c.serverVersion, config, dialAddress, c.sshConn.RemoteAddr())

	if err := c.transport.waitSession(); err != nil {
		return err
	}

	c.sessionID = c.transport.getSessionID()
	return nil
}

func (c *connection) serverHandshakeWithNoAuth(config *ServerConfig) (*Permissions, error) {
	if len(config.hostKeys) == 0 {
		return nil, errors.New("ssh: server has no host keys")
	}

	var err error
	if config.ServerVersion != "" {
		c.serverVersion = []byte(config.ServerVersion)
	} else {
		c.serverVersion = []byte("SSH-2.0-sshr")
	}
	c.clientVersion, err = exchangeVersions(c.sshConn.conn, c.serverVersion)
	if err != nil {
		return nil, err
	}

	tr := newTransport(c.sshConn.conn, config.Rand, false /* not client */)
	c.transport = newServerTransport(tr, c.clientVersion, c.serverVersion, config)

	if err := c.transport.waitSession(); err != nil {
		return nil, err

	}
	c.sessionID = c.transport.getSessionID()

	var packet []byte
	if packet, err = c.transport.readPacket(); err != nil {
		return nil, err
	}

	var serviceRequest serviceRequestMsg
	if err = Unmarshal(packet, &serviceRequest); err != nil {
		return nil, err
	}
	if serviceRequest.Service != serviceUserAuth {
		return nil, errors.New("ssh: requested service '" + serviceRequest.Service + "' before authenticating")
	}
	serviceAccept := serviceAcceptMsg{
		Service: serviceUserAuth,
	}
	if err := c.transport.writePacket(Marshal(&serviceAccept)); err != nil {
		return nil, err
	}

	return nil, nil
}
