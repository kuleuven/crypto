// This file is implemented with reference to tg123/sshpiper.
// Ref: https://github.com/tg123/sshpiper/blob/master/vendor/golang.org/x/crypto/ssh/sshpiper.go
// Thanks to @tg123

package ssh

import (
	"errors"
	"fmt"
	"io"
	"net"
)

type userFile string

var (
	userAuthorizedKeysFile userFile = "authorized_keys"
	userPrivateKeyFile     userFile = "id_rsa"
)

// A AuthRequestMsg exposes userAuthRequestMsg
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

// ProxyConfig represents configuration of a ssh proxy
type ProxyConfig struct {
	// ServerConfig represents the server configuration of the proxy, that is the configuration exposed to clients
	// Note that only PublicKeyCallback is used, other authentication methods are passed through to the backend
	ServerConfig *ServerConfig
	// UpstreamCallback is used to find the client configuration when connection to the backend hosts
	// The ClientConfig can either be public key authentication or hostbased authentication, other methods are ignored
	UpstreamCallback func(AuthRequestMsg) (net.Conn, *ClientConfig, error)
	// LimitAuthMethod indicates whether other authentication methods than public key authentication is allowed
	// Set to true to only accept public key authentication, and to false to pass through other methods to the backend
	// Note that hostbased authentication on the frontend is always ignored
	LimitAuthMethod bool
}

// A ProxyConn represents a ssh proxy
type ProxyConn interface {
	Wait() error
	Close()
	UpstreamConn() ConnMetadata
	DownstreamConn() ConnMetadata
}

// Implementation of ProxyConn
type proxyConn struct {
	*ProxyConfig
	serverConfig *ServerConfig
	clientConfig *ClientConfig
	Upstream     *connection
	Downstream   *connection
}

// NewProxyConn returns a new ProxyConn
func NewProxyConn(conn net.Conn, config *ProxyConfig) (ProxyConn, error) {
	var pConn *proxyConn

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

	upConn, clientConfig, err := config.UpstreamCallback(authRequestMsg)
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
		ProxyConfig:  config,
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

// Handle client authentication, intercepts publickey messages
// Returns userAuthRequestMsg to be sent to the upstream server
func (p *proxyConn) handleAuthMsg(msg *userAuthRequestMsg, cache *pubKeyCache) (*userAuthRequestMsg, error) {
	username := msg.User

	var authErr error

	switch msg.Method {
	case "none":
		if p.LimitAuthMethod {
			err := p.sendFailureMsg("publickey")
			return nil, err
		}

		return msg, nil

	case "publickey":
		downStreamPublicKey, isQuery, algo, pubKeyData, payload, err := parsePublicKeyMsg(msg)
		if err != nil {
			return nil, err
		}

		// Retrieve PublicKeyCallback output
		candidate, ok := cache.get(username, pubKeyData)
		if !ok {
			candidate.user = username
			candidate.pubKeyData = pubKeyData
			candidate.perms, candidate.result = p.serverConfig.PublicKeyCallback(p.Downstream, downStreamPublicKey)
			if candidate.result == nil && candidate.perms != nil && candidate.perms.CriticalOptions != nil && candidate.perms.CriticalOptions[sourceAddressCriticalOption] != "" {
				candidate.result = checkSourceAddress(
					p.Downstream.RemoteAddr(),
					candidate.perms.CriticalOptions[sourceAddressCriticalOption])
			}
			cache.add(candidate)
		}

		// Validate the downstream ssh key
		if candidate.result != nil {
			// Invalid public key, redirect as 'none'
			if p.LimitAuthMethod {
				authErr = candidate.result
				break
			}

			return noneAuthMsg(username), nil
		}

		var sig *Signature

		if isQuery {
			if len(payload) > 0 {
				return nil, parseError(msgUserAuthRequest)
			}

			if err := p.sendOKMsg(algo, pubKeyData); err != nil {
				return nil, err
			}
			return nil, nil
		} else {
			var ok bool
			sig, payload, ok = parseSignature(payload)
			if !ok || len(payload) > 0 {
				return nil, parseError(msgUserAuthRequest)
			}
		}

		// Verify the downstream signature
		ok, err = p.verifySignature(msg, downStreamPublicKey, sig)
		if err != nil || !ok {
			authErr = err
			break
		}

		// Get the upstream authMethod
		for _, authMethod := range p.clientConfig.Auth {
			if f, ok := authMethod.(publicKeyCallback); ok {
				signers, err := f()
				if err != nil || len(signers) == 0 {
					authErr = err
					break
				}

				for _, signer := range signers {
					msg, err = p.signAgain(p.clientConfig.User, msg, signer)
					if err != nil {
						authErr = err
						break
					}
					return msg, nil
				}
			}

			if f, ok := authMethod.(hostBasedCallback); ok {
				signers, clientHost, clientUser, err := f()
				if err != nil || len(signers) == 0 {
					authErr = err
					break
				}

				for _, signer := range signers {
					msg, err = p.signAgainHostBased(p.clientConfig.User, msg, signer, clientHost, clientUser)
					if err != nil {
						authErr = err
						break
					}
					return msg, nil
				}
			}

			break
		}

	case "hostbased":
		// Hostbased authentication is not supported, redirect as 'none'
		if p.LimitAuthMethod {
			authErr = fmt.Errorf("ssh: method %q not accepted", msg.Method)
			break
		}

		return noneAuthMsg(username), nil

	case "password":
	default:
		// In the case of password authentication or others,
		// since authentication is left up to the upstream server,
		// it suffices to flow the packet as it is.
		if p.LimitAuthMethod {
			authErr = fmt.Errorf("ssh: method %q not accepted", msg.Method)
			break
		}

		return msg, nil
	}

	if p.ServerConfig.AuthLogCallback != nil {
		p.ServerConfig.AuthLogCallback(p.Downstream, msg.Method, authErr)
	}

	// Some error occurred, or a wrong authentication method was used
	if p.LimitAuthMethod {
		err := p.sendFailureMsg("publickey")
		return nil, err
	}

	err := p.sendFailureMsg(msg.Method)
	return nil, err
}

func (p *proxyConn) sendOKMsg(algo string, pubkeyData []byte) error {
	okMsg := userAuthPubKeyOkMsg{
		Algo:   algo,
		PubKey: pubkeyData,
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

func (p *proxyConn) signAgainHostBased(user string, msg *userAuthRequestMsg, signer Signer, clientHost string, clientUser string) (*userAuthRequestMsg, error) {
	rand := p.Upstream.transport.config.Rand
	sessionID := p.Upstream.transport.getSessionID()
	upStreamPublicKey := signer.PublicKey()
	upStreamPublicKeyData := upStreamPublicKey.Marshal()

	sign, err := signer.Sign(rand, buildDataSignedForHostBasedAuth(sessionID, userAuthRequestMsg{
		User:    user,
		Service: serviceSSH,
		Method:  "hostbased",
	}, []byte(upStreamPublicKey.Type()), upStreamPublicKeyData, clientHost, clientUser))
	if err != nil {
		return nil, err
	}

	// manually wrap the serialized signature in a string
	s := Marshal(sign)
	sig := make([]byte, stringLength(len(s)))
	marshalString(sig, s)

	publicKeyMsg := &hostbasedAuthMsg{
		User:       user,
		Service:    serviceSSH,
		Method:     "hostbased",
		Algoname:   upStreamPublicKey.Type(),
		PubKey:     upStreamPublicKeyData,
		ClientHost: clientHost,
		ClientUser: clientUser,
		Sig:        sig,
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

	//defer p.Close()
	return <-c
}

func (p *proxyConn) Close() {
	p.Upstream.transport.Close()
	p.Downstream.transport.Close()
}

func (p *proxyConn) UpstreamConn() ConnMetadata {
	return p.Upstream
}

func (p *proxyConn) DownstreamConn() ConnMetadata {
	return p.Downstream
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

		// If LimitAuthMethod is set, do not expose the methods of the backend
		if msgType == msgUserAuthFailure && p.LimitAuthMethod {
			err := p.sendFailureMsg("publickey")
			return false, err
		}

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

	var cache pubKeyCache

	userAuthMsg := initUserAuthMsg
	for {
		userAuthMsg, err = p.handleAuthMsg(userAuthMsg, &cache)
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

func parsePublicKeyMsg(userAuthReq *userAuthRequestMsg) (PublicKey, bool, string, []byte, []byte, error) {
	if userAuthReq.Method != "publickey" {
		return nil, false, "", nil, nil, fmt.Errorf("not a publickey auth msg")
	}

	payload := userAuthReq.Payload
	if len(payload) < 1 {
		return nil, false, "", nil, nil, parseError(msgUserAuthRequest)
	}
	isQuery := payload[0] == 0
	payload = payload[1:]
	algoBytes, payload, ok := parseString(payload)
	if !ok {
		return nil, false, "", nil, nil, parseError(msgUserAuthRequest)
	}
	algo := string(algoBytes)
	if !isAcceptableAlgo(algo) {
		return nil, false, "", nil, nil, fmt.Errorf("ssh: algorithm %q not accepted", algo)
	}

	pubKeyData, payload, ok := parseString(payload)
	if !ok {
		return nil, false, "", nil, nil, parseError(msgUserAuthRequest)
	}

	publicKey, err := ParsePublicKey(pubKeyData)
	if err != nil {
		return nil, false, "", nil, nil, err
	}

	return publicKey, isQuery, algo, pubKeyData, payload, nil
}

func piping(dst, src packetConn) error {
	defer dst.Close()

	for {
		p, err := src.readPacket()
		if err == io.EOF {
			return nil
		} else if err != nil {
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
