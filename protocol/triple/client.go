/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package triple

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"
)

import (
	"github.com/dubbogo/gost/log/logger"

	"github.com/dustin/go-humanize"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"golang.org/x/net/http2"
)

import (
	"dubbo.apache.org/dubbo-go/v3/common"
	"dubbo.apache.org/dubbo-go/v3/common/constant"
	"dubbo.apache.org/dubbo-go/v3/global"
	tri "dubbo.apache.org/dubbo-go/v3/protocol/triple/triple_protocol"
	dubbotls "dubbo.apache.org/dubbo-go/v3/tls"
)

const (
	httpPrefix  string = "http://"
	httpsPrefix string = "https://"
)

// clientManager wraps triple clients and is responsible for find concrete triple client to invoke
// callUnary, callClientStream, callServerStream, callBidiStream.
// A Reference has a clientManager.
type clientManager struct {
	isIDL bool
	// triple_protocol clients, key is method name
	triClients map[string]*tri.Client
}

// TODO: code a triple client between clientManager and triple_protocol client
// TODO: write a NewClient for triple client

func (cm *clientManager) getClient(method string) (*tri.Client, error) {
	triClient, ok := cm.triClients[method]
	if !ok {
		return nil, fmt.Errorf("missing triple client for method: %s", method)
	}
	return triClient, nil
}

func (cm *clientManager) callUnary(ctx context.Context, method string, req, resp any) error {
	triClient, err := cm.getClient(method)
	if err != nil {
		return err
	}
	triReq := tri.NewRequest(req)
	triResp := tri.NewResponse(resp)
	if err := triClient.CallUnary(ctx, triReq, triResp); err != nil {
		return err
	}
	return nil
}

func (cm *clientManager) callClientStream(ctx context.Context, method string) (any, error) {
	triClient, err := cm.getClient(method)
	if err != nil {
		return nil, err
	}
	stream, err := triClient.CallClientStream(ctx)
	if err != nil {
		return nil, err
	}
	return stream, nil
}

func (cm *clientManager) callServerStream(ctx context.Context, method string, req any) (any, error) {
	triClient, err := cm.getClient(method)
	if err != nil {
		return nil, err
	}
	triReq := tri.NewRequest(req)
	stream, err := triClient.CallServerStream(ctx, triReq)
	if err != nil {
		return nil, err
	}
	return stream, nil
}

func (cm *clientManager) callBidiStream(ctx context.Context, method string) (any, error) {
	triClient, err := cm.getClient(method)
	if err != nil {
		return nil, err
	}
	stream, err := triClient.CallBidiStream(ctx)
	if err != nil {
		return nil, err
	}
	return stream, nil
}

func (cm *clientManager) close() error {
	// There is no need to release resources right now.
	// But we leave this function here for future use.
	return nil
}

// newClientManager extracts configurations from url and builds clientManager
func newClientManager(url *common.URL) (*clientManager, error) {
	var cliOpts []tri.ClientOption
	var isIDL bool

	// set serialization
	serialization := url.GetParam(constant.SerializationKey, constant.ProtobufSerialization)
	switch serialization {
	case constant.ProtobufSerialization:
		isIDL = true
	case constant.JSONSerialization:
		isIDL = true
		cliOpts = append(cliOpts, tri.WithProtoJSON())
	case constant.Hessian2Serialization:
		cliOpts = append(cliOpts, tri.WithHessian2())
	case constant.MsgpackSerialization:
		cliOpts = append(cliOpts, tri.WithMsgPack())
	default:
		panic(fmt.Sprintf("Unsupported serialization: %s", serialization))
	}

	// set timeout
	timeout := url.GetParamDuration(constant.TimeoutKey, "")
	cliOpts = append(cliOpts, tri.WithTimeout(timeout))

	// set service group and version
	group := url.GetParam(constant.GroupKey, "")
	version := url.GetParam(constant.VersionKey, "")
	cliOpts = append(cliOpts, tri.WithGroup(group), tri.WithVersion(version))

	// todo(DMwangnima): support opentracing

	// handle tls
	var (
		tlsFlag bool
		tlsConf *global.TLSConfig
		cfg     *tls.Config
		err     error
	)

	tlsConfRaw, ok := url.GetAttribute(constant.TLSConfigKey)
	if ok {
		tlsConf, ok = tlsConfRaw.(*global.TLSConfig)
		if !ok {
			return nil, errors.New("TRIPLE clientManager initialized the TLSConfig configuration failed")
		}
	}
	if dubbotls.IsClientTLSValid(tlsConf) {
		cfg, err = dubbotls.GetClientTlSConfig(tlsConf)
		if err != nil {
			return nil, err
		}
		if cfg != nil {
			logger.Infof("TRIPLE clientManager initialized the TLSConfig configuration")
			tlsFlag = true
		}
	}

	var tripleConf *global.TripleConfig

	tripleConfRaw, ok := url.GetAttribute(constant.TripleConfigKey)
	if ok {
		tripleConf = tripleConfRaw.(*global.TripleConfig)
	}

	// handle keepalive options
	cliKeepAliveOpts, keepAliveInterval, keepAliveTimeout, genKeepAliveOptsErr := genKeepAliveOptions(url, tripleConf)
	if genKeepAliveOptsErr != nil {
		logger.Errorf("genKeepAliveOpts err: %v", genKeepAliveOptsErr)
		return nil, genKeepAliveOptsErr
	}
	cliOpts = append(cliOpts, cliKeepAliveOpts...)

	// handle http transport of triple protocol
	var transport http.RoundTripper

	var callProtocol string
	if tripleConf != nil && tripleConf.Http3 != nil && tripleConf.Http3.Enable {
		callProtocol = constant.CallHTTP2AndHTTP3
	} else {
		// HTTP default type is HTTP/2.
		callProtocol = constant.CallHTTP2
	}

	switch callProtocol {
	// This case might be for backward compatibility,
	// it's not useful for the Triple protocol, HTTP/1 lacks trailer functionality.
	// Triple protocol only supports HTTP/2 and HTTP/3.
	case constant.CallHTTP:
		transport = &http.Transport{
			TLSClientConfig: cfg,
		}
		cliOpts = append(cliOpts, tri.WithTriple())
	case constant.CallHTTP2:
		// TODO: Enrich the http2 transport config for triple protocol.
		if tlsFlag {
			transport = &http2.Transport{
				TLSClientConfig: cfg,
				ReadIdleTimeout: keepAliveInterval,
				PingTimeout:     keepAliveTimeout,
			}
		} else {
			transport = &http2.Transport{
				DialTLSContext: func(_ context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
					return net.Dial(network, addr)
				},
				AllowHTTP:       true,
				ReadIdleTimeout: keepAliveInterval,
				PingTimeout:     keepAliveTimeout,
			}
		}
	case constant.CallHTTP3:
		if !tlsFlag {
			return nil, fmt.Errorf("TRIPLE http3 client must have TLS config, but TLS config is nil")
		}

		// TODO: Enrich the http3 transport config for triple protocol.
		transport = &http3.Transport{
			TLSClientConfig: cfg,
			QUICConfig: &quic.Config{
				// ref: https://quic-go.net/docs/quic/connection/#keeping-a-connection-alive
				KeepAlivePeriod: keepAliveInterval,
				// ref: https://quic-go.net/docs/quic/connection/#idle-timeout
				MaxIdleTimeout: keepAliveTimeout,
			},
		}

		logger.Infof("Triple http3 client transport init successfully")
	case constant.CallHTTP2AndHTTP3:
		if !tlsFlag {
			return nil, fmt.Errorf("TRIPLE HTTP/2 and HTTP/3 client must have TLS config, but TLS config is nil")
		}

		// Create a dual transport that can handle both HTTP/2 and HTTP/3
		transport = newDualTransport(cfg, keepAliveInterval, keepAliveTimeout)
		logger.Infof("Triple HTTP/2 and HTTP/3 client transport init successfully")
	default:
		return nil, fmt.Errorf("unsupported http protocol: %s", callProtocol)
	}

	httpClient := &http.Client{
		Transport: transport,
	}

	var baseTriURL string
	baseTriURL = strings.TrimPrefix(url.Location, httpPrefix)
	baseTriURL = strings.TrimPrefix(baseTriURL, httpsPrefix)
	if tlsFlag {
		baseTriURL = httpsPrefix + baseTriURL
	} else {
		baseTriURL = httpPrefix + baseTriURL
	}

	triClients := make(map[string]*tri.Client)

	if len(url.Methods) != 0 {
		for _, method := range url.Methods {
			triURL, err := joinPath(baseTriURL, url.Interface(), method)
			if err != nil {
				return nil, fmt.Errorf("JoinPath failed for base %s, interface %s, method %s", baseTriURL, url.Interface(), method)
			}
			triClient := tri.NewClient(httpClient, triURL, cliOpts...)
			triClients[method] = triClient
		}
	} else {
		// This branch is for the non-IDL mode, where we pass in the service solely
		// for the purpose of using reflection to obtain all methods of the service.
		// There might be potential for optimization in this area later on.
		service, ok := url.GetAttribute(constant.RpcServiceKey)
		if !ok {
			return nil, fmt.Errorf("triple clientmanager can't get methods")
		}

		serviceType := reflect.TypeOf(service)
		for i := range serviceType.NumMethod() {
			methodName := serviceType.Method(i).Name
			triURL, err := joinPath(baseTriURL, url.Interface(), methodName)
			if err != nil {
				return nil, fmt.Errorf("JoinPath failed for base %s, interface %s, method %s", baseTriURL, url.Interface(), methodName)
			}
			triClient := tri.NewClient(httpClient, triURL, cliOpts...)
			triClients[methodName] = triClient
		}
	}

	return &clientManager{
		isIDL:      isIDL,
		triClients: triClients,
	}, nil
}

func genKeepAliveOptions(url *common.URL, tripleConf *global.TripleConfig) ([]tri.ClientOption, time.Duration, time.Duration, error) {
	var cliKeepAliveOpts []tri.ClientOption

	// set max send and recv msg size
	maxCallRecvMsgSize := constant.DefaultMaxCallRecvMsgSize
	if recvMsgSize, err := humanize.ParseBytes(url.GetParam(constant.MaxCallRecvMsgSize, "")); err == nil && recvMsgSize > 0 {
		maxCallRecvMsgSize = int(recvMsgSize)
	}
	cliKeepAliveOpts = append(cliKeepAliveOpts, tri.WithReadMaxBytes(maxCallRecvMsgSize))
	maxCallSendMsgSize := constant.DefaultMaxCallSendMsgSize
	if sendMsgSize, err := humanize.ParseBytes(url.GetParam(constant.MaxCallSendMsgSize, "")); err == nil && sendMsgSize > 0 {
		maxCallSendMsgSize = int(sendMsgSize)
	}
	cliKeepAliveOpts = append(cliKeepAliveOpts, tri.WithSendMaxBytes(maxCallSendMsgSize))

	// set keepalive interval and keepalive timeout
	// Deprecated：use tripleconfig
	// TODO: remove KeepAliveInterval and KeepAliveInterval in version 4.0.0
	keepAliveInterval := url.GetParamDuration(constant.KeepAliveInterval, constant.DefaultKeepAliveInterval)
	keepAliveTimeout := url.GetParamDuration(constant.KeepAliveTimeout, constant.DefaultKeepAliveTimeout)

	if tripleConf == nil {
		return cliKeepAliveOpts, keepAliveInterval, keepAliveTimeout, nil
	}

	var parseErr error

	if tripleConf.KeepAliveInterval != "" {
		keepAliveInterval, parseErr = time.ParseDuration(tripleConf.KeepAliveInterval)
		if parseErr != nil {
			return nil, 0, 0, parseErr
		}
	}
	if tripleConf.KeepAliveTimeout != "" {
		keepAliveTimeout, parseErr = time.ParseDuration(tripleConf.KeepAliveTimeout)
		if parseErr != nil {
			return nil, 0, 0, parseErr
		}
	}

	return cliKeepAliveOpts, keepAliveInterval, keepAliveTimeout, nil
}

// dualTransport is a transport that can handle both HTTP/2 and HTTP/3
// It uses HTTP Alternative Services (Alt-Svc) for protocol negotiation
type dualTransport struct {
	http2Transport *http2.Transport
	http3Transport *http3.Transport
	// Cache for alternative services to avoid repeated lookups
	altSvcCache *tri.AltSvcCache
}

// newDualTransport creates a new dual transport that supports both HTTP/2 and HTTP/3
func newDualTransport(tlsConfig *tls.Config, keepAliveInterval, keepAliveTimeout time.Duration) http.RoundTripper {
	http2Transport := &http2.Transport{
		TLSClientConfig: tlsConfig,
		ReadIdleTimeout: keepAliveInterval,
		PingTimeout:     keepAliveTimeout,
	}

	http3Transport := &http3.Transport{
		TLSClientConfig: tlsConfig,
		QUICConfig: &quic.Config{
			KeepAlivePeriod: keepAliveInterval,
			MaxIdleTimeout:  keepAliveTimeout,
		},
	}

	return &dualTransport{
		http2Transport: http2Transport,
		http3Transport: http3Transport,
		altSvcCache:    tri.NewAltSvcCache(),
	}
}

// RoundTrip implements http.RoundTripper interface with HTTP Alternative Services support
func (dt *dualTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Check if we have cached alternative service information
	cachedAltSvc := dt.altSvcCache.Get(req.URL.Host)

	// If we have valid cached alt-svc info and it's for HTTP/3, try HTTP/3 first
	// Check if the cached information is still valid (not expired)
	if cachedAltSvc != nil && cachedAltSvc.Protocol == "h3" {
		logger.Debugf("Using cached HTTP/3 alternative service for %s", req.URL.String())
		resp, err := dt.http3Transport.RoundTrip(req)
		if err == nil {
			// Update alt-svc cache from response headers
			dt.altSvcCache.UpdateFromHeaders(req.URL.Host, resp.Header)
			return resp, nil
		}
		logger.Debugf("Cached HTTP/3 request failed to %s, falling back to HTTP/2: %v", req.URL.String(), err)
	}

	// Start with HTTP/2 to get alternative service information
	logger.Debugf("Making initial HTTP/2 request to %s to discover alternative services", req.URL.String())
	resp, err := dt.http2Transport.RoundTrip(req)
	if err != nil {
		logger.Errorf("HTTP/2 request failed to %s: %v", req.URL.String(), err)
		return nil, err
	}

	// Check for alternative services in the response
	dt.altSvcCache.UpdateFromHeaders(req.URL.Host, resp.Header)

	// If the response indicates HTTP/3 is available, try HTTP/3 for future requests
	if altSvc := dt.altSvcCache.Get(req.URL.Host); altSvc != nil && altSvc.Protocol == "h3" {
		logger.Debugf("Server %s supports HTTP/3, will use HTTP/3 for future requests", req.URL.Host)
	}

	return resp, nil
}
var (
	ErrPoolClosed = errors.New("tri client pool is closed")
	ErrTimeout    = errors.New("tri client pool get timeout")
)

type TriClientPool struct {
	clients     chan *tri.Client
	factory     func() *tri.Client
	mu          sync.Mutex
	maxSize     int
	curSize     int
	closed      bool
	getTimeouts int // recent timeout count, used to trigger expansion

	fallback	*tri.Client
}

func NewTriClientPool(maxSize int, factory func() *tri.Client) *TriClientPool {
	pool := &TriClientPool{
		clients: make(chan *tri.Client, maxSize),
		factory: factory,
		maxSize: maxSize,
	}
	go pool.autoScaler()
	return pool
}

// TriClient Get method
// timeout means how long to wait for an available client.
// TriClientPool keeps a fallback client pointer. If Get() times out,
// and the pool cannot expand at that moment, the pool will return fallback.
// This ensures there is at least one usable client.
// Get tries a non-blocking receive first. If that fails, it tries to expand.
// If expansion is not allowed, it waits for a client up to timeout.
// After timeout, if still no client, Get() returns ErrTimeout with fallback.
func (p *TriClientPool) Get(timeout time.Duration) (*tri.Client, error) {
	select {
	case cli := <-p.clients:
		return cli, nil
	default:
	}

	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, ErrPoolClosed
	}
	// try to expand
	if p.curSize < p.maxSize {
		p.curSize++
		p.mu.Unlock()
		cli := p.factory()
		return cli, nil
	}
	p.mu.Unlock()

	select {
	case cli, ok := <-p.clients:
		if !ok {
			return nil, ErrPoolClosed
		}
		return cli, nil
	case <-time.After(timeout):
		p.recordTimeout()
		p.mu.Lock()
		if p.fallback == nil {
			p.fallback = p.factory()
		}
		p.mu.Unlock()
		return p.fallback, ErrTimeout
	}
}

// TriClient Put method
// Put tries to put a tri.Client back into the pool.
// If it fails, Put will drop the client and notify the pool.
// Dropping a client is part of shrinking.
func (p *TriClientPool) Put(c *tri.Client) {
	if c == nil {
		return
	}

	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if closed {
		return
	}

	select {
	case p.clients <- c:
	default:
		p.mu.Lock()
		p.curSize--
		p.mu.Unlock()
	}
}

// close removes all clients from the channel and then closes it.
func (p *TriClientPool) Close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true

	for len(p.clients) > 0 {
		<-p.clients
		p.curSize--
	}

	close(p.clients)
	p.mu.Unlock()
}

func (p *TriClientPool) MaxSize() int {
	return p.maxSize
}

func (p *TriClientPool) Closed() bool {
	return p.closed
}

// autoScaler is the main worker that adjusts pool size.
// It checks regularly whether pool should expand or shrink.
// If the timeout count is high, autoScaler tends to expand.
// If the idle client count is often high, autoScaler tends to shrink.
func (p *TriClientPool) autoScaler() {
	ticker := time.NewTicker(700 * time.Millisecond)
	defer ticker.Stop()
	consecutiveHighIdle := 0

	for range ticker.C {
		if p.Closed() {
			return
		}

		p.mu.Lock()
		curSize := p.curSize
		idle := len(p.clients)
		timeouts := p.getTimeouts
		p.getTimeouts = 0
		p.mu.Unlock()

		needExpand := checkExpand(curSize, idle, timeouts)
		if needExpand != 0 {
			p.expand(needExpand)
			consecutiveHighIdle = 0
			continue
		}

		needShrink := checkShrink(curSize, idle, &consecutiveHighIdle)
		if needShrink != 0 {
			p.shrink(needShrink)
		}
	}
}

// expand creates n more clients
func (p *TriClientPool) expand(n int) {
	for i := 0; i < n; i++ {
		p.mu.Lock()
		if p.curSize >= p.maxSize {
			p.mu.Unlock()
			return
		}
		p.curSize++
		p.mu.Unlock()

		cli := p.factory()
		p.Put(cli)
	}
}

// shrink removes n clients
func (p *TriClientPool) shrink(n int) {
	for i := 0; i < n; i++ {
		select {
		case <-p.clients:
			p.mu.Lock()
			p.curSize--
			p.mu.Unlock()
		default:
			return
		}
	}
}

// record timeout count
func (p *TriClientPool) recordTimeout() {
	p.mu.Lock()
	p.getTimeouts++
	p.mu.Unlock()
}

// compute expansion size
// expansion size is based on timeout count: 2 ^ timeouts
// if idle clients are less than 20% of total, treat as busy and expand slightly
func checkExpand(curSize, idle, timeouts int) int {
	if timeouts > 0 {
		expand := 1 << timeouts
		if expand > 16 {
			expand = 16
		}
		return expand
	}

	if idle < curSize / 5 {
		return 1
	}

	return 0
}

// if more than 60% of clients are idle, increase highIdleStreak
// highIdleStreak records how often idle rate is high
// if highIdleStreak >= 10, shrink pool to 1/8
func checkShrink(curSize int, idle int, highIdleStreak *int) int {
	if idle > curSize*6/10 {
		*highIdleStreak++
		if *highIdleStreak >= 10 {
			shrink := curSize / 8
			if shrink < 1 {
				shrink = 1
			}
			*highIdleStreak = 0
			return shrink
		}
		return 0
	}

	*highIdleStreak = 0
	return 0
}
