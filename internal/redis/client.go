package redis

import (
	"sync"
	"time"

	"github.com/gomodule/redigo/redis"
)

const (
	backoffInit = 100 * time.Millisecond
	backoffMax  = 5 * time.Second
)

// Redis is the interface of the Redis client.
type Redis interface {
	Do(commandName string, args ...interface{}) (reply interface{}, err error)
	Send(commandName string, args ...interface{}) error
	Flush() error
	Close() error
}

// Conn is the redis resilient connection.
type Conn struct {
	conn     Redis
	redisURL string
	redisPWD string
	redisDB  int

	notifyErr chan struct{}
	quit      chan struct{}
	backoff   time.Duration

	// the mutex is used with the Cond as a rendezvous point for
	// the goroutines waiting for a valid connection.
	mu   *sync.Mutex
	cond *sync.Cond
}

// NewResilientConn returns a connection that automatically recover from failures.
func NewResilientConn(url, pwd string, db int) (*Conn, error) {
	var mu = &sync.Mutex{}
	var cond = sync.NewCond(mu)

	var redisConn redis.Conn
	{
		var err error
		redisConn, err = redis.Dial("tcp", url, redis.DialDatabase(db), redis.DialPassword(pwd))
		if err != nil {
			return nil, err
		}
	}

	var conn = &Conn{
		conn:      redisConn,
		redisURL:  url,
		redisDB:   db,
		redisPWD:  pwd,
		mu:        mu,
		cond:      cond,
		notifyErr: make(chan struct{}),
		quit:      make(chan struct{}),
		backoff:   backoffInit,
	}

	go func() {
		var recovery = false
		var t = time.NewTimer(backoffInit)
	loop:
		for {
			if recovery {
				// recovery mode: try periodically to reconnect, until it succeeds.
				select {
				case <-t.C:
				case <-conn.quit:
					break loop
				}
				var redisConn, err = redis.Dial("tcp", conn.redisURL, redis.DialDatabase(conn.redisDB), redis.DialPassword(conn.redisPWD))
				conn.updateBackoff()
				conn.resetTimer(t, conn.backoff)

				if err == nil {
					// Connection successful: recover, stop timer, and quit recovery mode (wait for next error)
					recovery = false
					conn.recover(redisConn)
				}
			} else {
				// wait a goroutines signaling an error
				select {
				case <-conn.notifyErr:
				case <-conn.quit:
					break loop
				}

				recovery = true
				conn.resetTimer(t, conn.backoff)
			}
		}
	}()

	return conn, nil
}

func (c *Conn) Do(commandName string, args ...interface{}) (interface{}, error) {
	var reply interface{}
	var err error
	for {
		c.mu.Lock()
		reply, err = c.conn.Do(commandName, args...)

		if err == nil {
			c.mu.Unlock()
			break
		}

		// signal an error in a non-blocking way
		select {
		case c.notifyErr <- struct{}{}:
		default:
		}

		// rdv point, we wait on the signal that a new connection was successfully created
		c.cond.Wait()
		c.mu.Unlock()
	}

	return reply, err
}

func (c *Conn) Send(commandName string, args ...interface{}) error {
	var err error
	for {
		c.mu.Lock()
		err = c.conn.Send(commandName, args...)

		if err == nil {
			c.mu.Unlock()
			break
		}

		// signal an error in a non-blocking way
		select {
		case c.notifyErr <- struct{}{}:
		default:
		}

		// rdv point, we wait on the signal that a new connection was successfully created
		c.cond.Wait()
		c.mu.Unlock()
	}

	return err
}

func (c *Conn) Flush() error {
	return c.conn.Flush()
}

// Close terminates the goroutine that recover lost connections.
func (c *Conn) Close() error {
	c.quit <- struct{}{}
	return c.conn.Close()
}

func (c *Conn) recover(new Redis) {
	// update connection
	c.conn = new

	// reset backoff time
	c.backoff = backoffInit

	// wake goroutines that are waiting on the successfull connection
	c.cond.Broadcast()

	// Empty error channel, there may be other goroutines signaling the same connection failure.
	for len(c.notifyErr) > 0 {
		<-c.notifyErr
	}
}

// update the backoff time. A linear backoff limited to backoff max is used.
func (c *Conn) updateBackoff() {
	if c.backoff < backoffMax {
		c.backoff = c.backoff + backoffInit
	}
}

func (c *Conn) resetTimer(t *time.Timer, d time.Duration) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
	t.Reset(d)
}
