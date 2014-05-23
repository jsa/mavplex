from collections import namedtuple
import logging
import socket
import sqlite3
import sys
import threading
import time
import signal
import struct


SOURCE_TYPE = namedtuple('SourceType', ('AIR', 'GCS'))(1, 2)

_running = False


class Plexer(object):
    def __init__(self):
        self.lock = threading.RLock()
        self.out_queues = {}

    def closed(self, addr):
        with self:
            self.out_queues.pop(addr, None)

    def recv(self, data, *args):
        with self:
            for queue in self.out_queues.itervalues():
                queue.append((data,) + args)

    def pop_buffer(self, addr):
        with self:
            b = self.out_queues.setdefault(addr)
            if b:
                self.out_queues[addr] = []
                return b
            else:
                return []

    def __enter__(self):
        self.lock.acquire()

    def __exit__(self, *args):
        self.lock.release()


def init_db(db_path):
    db = sqlite3.connect(db_path,
                         isolation_level=None) # autocommit
    if not any(table == "packets" for (table,) in
               db.execute("SELECT name FROM SQLITE_MASTER")):
        db.execute("CREATE TABLE packets"
                   " (id INTEGER PRIMARY KEY ASC,"
                   "  timestamp INTEGER NOT NULL,"
                   "  source_type INTEGER NOT NULL,"
                   "  source_address TEXT NOT NULL,"
                   "  data BLOB NOT NULL)")
    return db

def forever(fn):
    def wrapper(*args):
        t = threading.current_thread()
        logging.debug("%s: started" % t.name)
        while True:
            try:
                fn(*args)
                break
            except Exception, e:
                logging.exception(e)
                logging.error("Exception in thread %s" % t.name)
                break
        logging.debug("%s: finished" % t.name)
    return wrapper

def conf_socket(s):
    s.setblocking(1)
    s.settimeout(.1)

def conf_connection(c):
    conf_socket(c)

    c.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    c.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)

    c.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2048)
    c.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2048)
    c.setsockopt(socket.SOL_SOCKET, socket.SO_SNDLOWAT, 1)
    c.setsockopt(socket.SOL_SOCKET, socket.SO_RCVLOWAT, 1)
    c.setsockopt(socket.SOL_SOCKET, socket.SO_SNDTIMEO, struct.pack("ll", 5, 0))
    c.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, struct.pack("ll", 5, 0))

@forever
def pipe(addr, conn, inbound, outbound):
    t = threading.current_thread()

    def recvsend():
        try:
            data = conn.recv(4096)
        except socket.timeout:
            pass
        else:
            if data:
                inbound.recv(data, addr)
        outbuf = outbound.pop_buffer(addr)
        if outbuf:
            conn.send("".join(x[0] for x in outbuf))

    while _running:
        try:
            recvsend()
        except socket.error, e:
            logging.exception(e)
            logging.warn("%s: socket error, closing" % t.name)
            break

    try:
        conn.close()
    except socket.error:
        pass

    outbound.closed(addr)

@forever
def accept(port, inbound, outbound):
    t = threading.current_thread()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conf_socket(sock)
    sock.bind(("0.0.0.0", port))
    sock.listen(5)
    logging.debug("%s: listening at %d" % (t.name, port))

    while _running:
        try:
            conn, addr = sock.accept()
        except socket.timeout:
            pass
        else:
            conf_connection(conn)
            p = threading.Thread(target=pipe,
                                 name="%s(%r)" % (t.name, addr[0]),
                                 args=[addr, conn, inbound, outbound])
            p.daemon = True
            p.start()

    try:
        sock.shutdown(socket.SHUT_RDWR)
    except socket.error:
        pass

def term_handler(signum, framee):
    logging.debug("Terminating by %s" % signum)
    global _running
    _running = False

def main(db_path, air_port, gcs_port):
    global _running
    _running = True

    db = init_db(db_path)
    signal.signal(signal.SIGTERM, term_handler)
    signal.signal(signal.SIGINT, term_handler)

    airplex, gcsplex = Plexer(), Plexer()

    # initialize buffers
    airplex.pop_buffer('db')
    gcsplex.pop_buffer('db')

    t = threading.Thread(target=accept, name="air_accept",
                         args=[air_port, airplex, gcsplex])
    t.daemon = True
    t.start()

    t = threading.Thread(target=accept, name="gcs_accept",
                         args=[gcs_port, gcsplex, airplex])
    t.daemon = True
    t.start()

    while _running:
        time.sleep(.1)
        for st, plex in [(SOURCE_TYPE.AIR, airplex),
                         (SOURCE_TYPE.GCS, gcsplex)]:
            queue = plex.pop_buffer('db')
            if queue:
                db.executemany("INSERT INTO packets (timestamp, source_type, source_address, data) VALUES (?, ?, ?, ?)",
                               [(int(time.time()), st, addr, data)
                                for data, (addr, port) in queue])

    db.close()

if __name__ == '__main__':
    if len(sys.argv) < 4:
        print >> sys.stderr, "Usage: %s <sqlite3 db> <air port> <gcs port>" % sys.argv[0]
        sys.exit(1)
    logging.basicConfig(level=logging.DEBUG)
    main(sys.argv[1], *map(int, sys.argv[2:]))
    sys.exit(0)