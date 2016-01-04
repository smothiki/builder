package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

	"github.com/kr/pty"
	"golang.org/x/crypto/ssh"
)

func main() {

	// In the latest version of crypto/ssh (after Go 1.3), the SSH server type has been removed
	// in favour of an SSH connection type. A ssh.ServerConn is created by passing an existing
	// net.Conn and a ssh.ServerConfig to ssh.NewServerConn, in effect, upgrading the net.Conn
	// into an ssh.ServerConn

	config := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			perm := &ssh.Permissions{Extensions: map[string]string{
				"pubkey": string(key.Marshal()),
			}}
			return perm, nil
		},
	}

	// closer := make(chan interface{}, 1)
	// You can generate a keypair with 'ssh-keygen -t rsa'
	privateBytes, err := ioutil.ReadFile("~/.ssh/deis")
	if err != nil {
		log.Fatal("Failed to load private key (~/.ssh/deis)")
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatal("Failed to parse private key")
	}

	config.AddHostKey(private)

	// Once a ServerConfig has been configured, connections can be accepted.
	listener, err := net.Listen("tcp", "0.0.0.0:2200")
	if err != nil {
		log.Fatalf("Failed to listen on 2200 (%s)", err)
	}
	closer := make(chan interface{}, 1)
	listen(listener, config, closer)
	}
}

func listen(l net.Listener, conf *ssh.ServerConfig, closer chan interface{}) error {
	defer l.Close()

	// FIXME: Since Accept blocks, closer may not be checked often enough.
	for {
		log.Info(cxt, "Checking closer.")
		if len(closer) > 0 {
			<-closer
			log.Info(cxt, "Shutting down SSHD listener.")
			return nil
		}
		conn, err := l.Accept()
		if err != nil {
			log.Warnf(cxt, "Error during Accept: %s", err)
			// We shouldn't kill the listener because of an error.
			return err
		}

			go handleConn(conn, conf)
	}
}

// handleConn handles an individual client connection.
//
// It manages the connection, but passes channels on to `answer()`.
func handleConn(conn net.Conn, conf *ssh.ServerConfig) {
	defer conn.Close()
	log.Info(s.c, "Accepted connection.")
	_, chans, reqs, err := ssh.NewServerConn(conn, conf)
	if err != nil {
		// Handshake failure.
		log.Errf(s.c, "Failed handshake: %s (%v)", err, conn)
		return
	}

	// Discard global requests. We're only concerned with channels.
	go ssh.DiscardRequests(reqs)

	condata := sshConnection(conn)

	// Now we handle the channels.
	for incoming := range chans {
		log.Infof(s.c, "Channel type: %s\n", incoming.ChannelType())
		if incoming.ChannelType() != "session" {
			incoming.Reject(ssh.UnknownChannelType, "Unknown channel type")
		}

		channel, req, err := incoming.Accept()
		if err != nil {
			// Should close request and move on.
			panic(err)
		}
		go answer(channel, req, condata)
	}
	conn.Close()
}

// sshConnection generates the SSH_CONNECTION environment variable.
//
// This is untested on UNIX sockets.
func sshConnection(conn net.Conn) string {
	remote := conn.RemoteAddr().String()
	local := conn.LocalAddr().String()
	rhost, rport, _ := net.SplitHostPort(remote)
	lhost, lport, _ := net.SplitHostPort(local)

	return fmt.Sprintf("%s %d %s %d", rhost, rport, lhost, lport)
}

func sendExitStatus(status uint32, channel ssh.Channel) error {
	exit := struct{ Status uint32 }{uint32(0)}
	_, err := channel.SendRequest("exit-status", false, ssh.Marshal(exit))
	return err
}

// answer handles answering requests and channel requests
//
// Currently, an exec must be either "ping", "git-receive-pack" or
// "git-upload-pack". Anything else will result in a failure response. Right
// now, we leave the channel open on failure because it is unclear what the
// correct behavior for a failed exec is.
//
// Support for setting environment variables via `env` has been disabled.
func answer(channel ssh.Channel, requests <-chan *ssh.Request, sshConn string) error {
	defer channel.Close()

	// Answer all the requests on this connection.
	for req := range requests {
		ok := false

		// I think that ideally what we want to do here is pass this on to
		// the Cookoo router and let it handle each Type on its own.
		switch req.Type {
		case "env":
			o := &EnvVar{}
			ssh.Unmarshal(req.Payload, o)
			fmt.Printf("Key='%s', Value='%s'\n", o.Name, o.Value)
			req.Reply(true, nil)
		case "exec":
			clean := cleanExec(req.Payload)
			parts := strings.SplitN(clean, " ", 2)


			// TODO: Should we unset the context value 'cookoo.Router'?
			// We need a shallow copy of the context to avoid race conditions.


			// Only allow commands that we know about.
			switch parts[0] {
			case "git-receive-pack", "git-upload-pack":
				if len(parts) < 2 {
					log.Warn(s.c, "Expected two-part command.\n")
					req.Reply(ok, nil)
					break
				}
				req.Reply(true, nil) // We processed. Yay.
				sshd.Fingerprint(key)

				// sshGitReceive := cxt.Get("route.sshd.sshGitReceive", "sshGitReceive").(string)
				// err := router.HandleRequest(sshGitReceive, cxt, true)
				// var xs uint32
				if err != nil {
					log.Errf(s.c, "Failed git receive: %v", err)
					xs = 1
				}
				sendExitStatus(xs, channel)
				return nil
			default:
				log.Warnf(s.c, "Illegal command is '%s'\n", clean)
				req.Reply(false, nil)
				return nil
			}

			if err := sendExitStatus(0, channel); err != nil {
				log.Errf(s.c, "Failed to write exit status: %s", err)
			}
			return nil
		default:
			// We simply ignore all of the other cases and leave the
			// channel open to take additional requests.
			log.Infof(s.c, "Received request of type %s\n", req.Type)
			req.Reply(false, nil)
		}
	}

	return nil
}
