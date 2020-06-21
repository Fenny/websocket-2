// Copyright 2013 The Gorilla WebSocket Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package websocket

import (
	"bytes"
	"fmt"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/gofiber/fiber"
)

var strPermessageDeflate = []byte("permessage-deflate")

var poolWriteBuffer = sync.Pool{
	New: func() interface{} {
		var buf []byte
		return buf
	},
}

// Handler receives a websocket connection after the handshake has been
// completed. This must be provided.
type Handler func(*Conn)

// Upgrader specifies parameters for upgrading an HTTP connection to a
// WebSocket connection.
type Config struct {
	// HandshakeTimeout specifies the duration for the handshake to complete.
	HandshakeTimeout time.Duration

	// ReadBufferSize and WriteBufferSize specify I/O buffer sizes in bytes. If a buffer
	// size is zero, then buffers allocated by the HTTP server are used. The
	// I/O buffer sizes do not limit the size of the messages that can be sent
	// or received.
	ReadBufferSize, WriteBufferSize int

	// WriteBufferPool is a pool of buffers for write operations. If the value
	// is not set, then write buffers are allocated to the connection for the
	// lifetime of the connection.
	//
	// A pool is most useful when the application has a modest volume of writes
	// across a large number of connections.
	//
	// Applications should use a single pool for each unique value of
	// WriteBufferSize.
	WriteBufferPool BufferPool

	// Subprotocols specifies the server's supported protocols in order of
	// preference. If this field is not nil, then the Upgrade method negotiates a
	// subprotocol by selecting the first match in this list with a protocol
	// requested by the client. If there's no match, then no protocol is
	// negotiated (the Sec-Websocket-Protocol header is not included in the
	// handshake response).
	Subprotocols []string

	// CheckOrigin returns true if the request Origin header is acceptable. If
	// CheckOrigin is nil, then a safe default is used: return false if the
	// Origin request header is present and the origin host is not equal to
	// request Host header.
	//
	// A CheckOrigin function should carefully validate the request origin to
	// prevent cross-site request forgery.
	CheckOrigin func(ctx *fiber.Ctx) bool

	// EnableCompression specify if the server should attempt to negotiate per
	// message compression (RFC 7692). Setting this value to true does not
	// guarantee that compression will be supported. Currently only "no context
	// takeover" modes are supported.
	EnableCompression bool
}

func (u *Upgrader) responseError(ctx *fiber.Ctx, status int, reason string) error {
	err := fiber.NewError(status, reason)
	ctx.Fasthttp.Response.Header.Set("Sec-Websocket-Version", "13")
	ctx.Next(err)
	return err
}

// checkSameOrigin returns true if the origin is not set or is equal to the request host.
func checkSameOrigin(ctx *fiber.Ctx) bool {
	origin := ctx.Fasthttp.Request.Header.Peek("Origin")
	if len(origin) == 0 {
		return true
	}
	u, err := url.Parse(GetString(origin))
	if err != nil {
		return false
	}
	return equalASCIIFold(u.Host, GetString(ctx.Fasthttp.Host()))
}

func (u *Upgrader) selectSubprotocol(ctx *fiber.Ctx) []byte {
	if u.Subprotocols != nil {
		clientProtocols := parseDataHeader(ctx.Fasthttp.Request.Header.Peek("Sec-Websocket-Protocol"))

		for _, serverProtocol := range u.Subprotocols {
			for _, clientProtocol := range clientProtocols {
				if GetString(clientProtocol) == serverProtocol {
					return clientProtocol
				}
			}
		}
	} else if ctx.Fasthttp.Response.Header.Len() > 0 {
		return ctx.Fasthttp.Response.Header.Peek("Sec-Websocket-Protocol")
	}

	return nil
}

func (u *Upgrader) isCompressionEnable(ctx *fiber.Ctx) bool {
	extensions := parseDataHeader(ctx.Fasthttp.Request.Header.Peek("Sec-WebSocket-Extensions"))

	// Negotiate PMCE
	if u.EnableCompression {
		for _, ext := range extensions {
			if bytes.HasPrefix(ext, strPermessageDeflate) {
				return true
			}
		}
	}

	return false
}

const badHandshake = "websocket: the client is not using the websocket protocol: "

// Upgrade upgrades the HTTP server connection to the WebSocket protocol.
//
// The responseHeader is included in the response to the client's upgrade
// request. Use the responseHeader to specify cookies (Set-Cookie) and the
// application negotiated subprotocol (Sec-WebSocket-Protocol).
//
// If the upgrade fails, then Upgrade replies to the client with an HTTP error
// response.
func (u *Upgrader) Upgrade(ctx *fiber.Ctx, handler Handler) error {
	if !ctx.Fasthttp.IsGet() {
		return u.responseError(ctx, fiber.StatusMethodNotAllowed, fmt.Sprintf("%s request method is not GET", badHandshake))
	}

	if !tokenContainsValue(GetString(ctx.Fasthttp.Request.Header.Peek("Connection")), "Upgrade") {
		return u.responseError(ctx, fiber.StatusBadRequest, fmt.Sprintf("%s 'upgrade' token not found in 'Connection' header", badHandshake))
	}

	if !tokenContainsValue(GetString(ctx.Fasthttp.Request.Header.Peek("Upgrade")), "Websocket") {
		return u.responseError(ctx, fiber.StatusBadRequest, fmt.Sprintf("%s 'websocket' token not found in 'Upgrade' header", badHandshake))
	}

	if !tokenContainsValue(GetString(ctx.Fasthttp.Request.Header.Peek("Sec-Websocket-Version")), "13") {
		return u.responseError(ctx, fiber.StatusBadRequest, "websocket: unsupported version: 13 not found in 'Sec-Websocket-Version' header")
	}

	if len(ctx.Fasthttp.Response.Header.Peek("Sec-Websocket-Extensions")) > 0 {
		return u.responseError(ctx, fiber.StatusInternalServerError, "websocket: application specific 'Sec-WebSocket-Extensions' headers are unsupported")
	}

	checkOrigin := u.CheckOrigin
	if checkOrigin == nil {
		checkOrigin = checkSameOrigin
	}
	if !checkOrigin(ctx) {
		return u.responseError(ctx, fiber.StatusForbidden, "websocket: request origin not allowed by FiberUpgrader.CheckOrigin")
	}

	challengeKey := ctx.Fasthttp.Request.Header.Peek("Sec-Websocket-Key")
	if len(challengeKey) == 0 {
		return u.responseError(ctx, fiber.StatusBadRequest, "websocket: not a websocket handshake: `Sec-WebSocket-Key' header is missing or blank")
	}

	subprotocol := u.selectSubprotocol(ctx)
	compress := u.isCompressionEnable(ctx)

	ctx.Fasthttp.SetStatusCode(fiber.StatusSwitchingProtocols)
	ctx.Fasthttp.Response.Header.Set("Upgrade", "websocket")
	ctx.Fasthttp.Response.Header.Set("Connection", "Upgrade")
	ctx.Fasthttp.Response.Header.Set("Sec-WebSocket-Accept", computeAcceptKeyBytes(challengeKey))
	if compress {
		ctx.Fasthttp.Response.Header.Set("Sec-WebSocket-Extensions", "permessage-deflate; server_no_context_takeover; client_no_context_takeover")
	}
	if subprotocol != nil {
		ctx.Fasthttp.Response.Header.SetBytesV("Sec-WebSocket-Protocol", subprotocol)
	}

	ctx.Fasthttp.Hijack(func(netConn net.Conn) {
		// var br *bufio.Reader  // Always nil
		writeBuf := poolWriteBuffer.Get().([]byte)

		c := newConn(netConn, true, u.ReadBufferSize, u.WriteBufferSize, u.WriteBufferPool, nil, writeBuf)
		if subprotocol != nil {
			c.subprotocol = GetString(subprotocol)
		}

		if compress {
			c.newCompressionWriter = compressNoContextTakeover
			c.newDecompressionReader = decompressNoContextTakeover
		}

		// Clear deadlines set by HTTP server.
		netConn.SetDeadline(time.Time{})

		handler(c)

		writeBuf = writeBuf[0:0]
		poolWriteBuffer.Put(writeBuf)
	})

	return nil
}

// IsWebSocketUpgrade returns true if the client requested upgrade to the
// WebSocket protocol.
func IsWebSocketUpgrade(ctx *fiber.Ctx) bool {
	return tokenContainsValue(GetString(ctx.Fasthttp.Request.Header.Peek("Connection")), "Upgrade") &&
		tokenContainsValue(GetString(ctx.Fasthttp.Request.Header.Peek("Upgrade")), "Websocket")
}
