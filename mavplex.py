from collections import namedtuple
import logging
import signal
import socket
import sqlite3
import struct
import sys
import threading
import time


SOURCE_TYPE = namedtuple('SourceType', ('AIR', 'GCS'))(1, 2)

_running = False


class Perplex(object):
    def __init__(self):
        self.lock = threading.RLock()
        self.out_queues = {}

    def closed(self, addr):
        with self:
            self.out_queues.pop(addr, None)

    def recv(self, data, *args):
        now = time.time()
        with self:
            for queue in self.out_queues.itervalues():
                queue.append((data, now) + args)

    def pop_queue(self, addr):
        with self:
            b = self.out_queues.setdefault(addr, [])
            if b:
                self.out_queues[addr] = []
            return b

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
                   "  timestamp STRING NOT NULL,"
                   "  source_type INTEGER NOT NULL,"
                   "  source_address TEXT NOT NULL,"
                   "  data BLOB NOT NULL)")
    return db

def stayin_alive(fn):
    def wrapper(*args):
        t = threading.current_thread()
        logging.debug("%s: started" % t.name)
        while True:
            try:
                fn(*args)
                break
            except Exception, e:
                logging.exception(e)
                logging.error("%s: restarting on exception" % t.name)
                time.sleep(1)
        logging.debug("%s: finished" % t.name)
    return wrapper

def conf_socket(s):
    s.setblocking(1)
    s.settimeout(.1)

    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

def conf_connection(c):
    c.setblocking(1)
    c.settimeout(.01) # <= 10ms latency

    c.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1) # doge is keep-alive
    c.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)

    # unsure about this in relation to recv buffer...
    c.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2**13)
    c.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**13)
    c.setsockopt(socket.SOL_SOCKET, socket.SO_SNDLOWAT, 1)
    c.setsockopt(socket.SOL_SOCKET, socket.SO_RCVLOWAT, 1)
    c.setsockopt(socket.SOL_SOCKET, socket.SO_SNDTIMEO, struct.pack("ll", 5, 0))
    c.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, struct.pack("ll", 5, 0))

@stayin_alive
def pipe(addr, conn, inbound, outbound):
    t = threading.current_thread()
    buf = bytearray(2**16)

    def sum(args):
        """Built-in version sucks. :p"""
        return reduce(lambda x, y: x + y, args)

    def so_internet():
        try:
            size = conn.recv_into(buf)
        except socket.timeout:
            pass
        else:
            if size:
                inbound.recv(buf[:size], addr)
        queue = outbound.pop_queue(addr)
        if queue:
            conn.send(sum(x[0] for x in queue))

    while _running:
        try:
            so_internet()
        except socket.error, e:
            logging.info(e, exc_info=1)
            logging.info("%s: socket error, closing" % t.name)
            break

    try:
        conn.close()
    except socket.error:
        pass

    outbound.closed(addr)

@stayin_alive
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
        sock.close()
        logging.debug("%s: socket closed" % t.name)
    except socket.error, e:
        logging.debug(e, exc_info=1)
        logging.debug("%s: socket.close exception" % t.name)

def fml(signum, framee):
    logging.debug("Terminating by %s" % signum)
    global _running
    _running = False

def main(db_path, air_port, gcs_port):
    global _running
    _running = True

    db = init_db(db_path)
    signal.signal(signal.SIGTERM, fml)
    signal.signal(signal.SIGINT, fml)

    airplex, gcsplex = Perplex(), Perplex()

    # initialize buffers
    airplex.pop_queue('db')
    gcsplex.pop_queue('db')

    t_air = threading.Thread(target=accept, name="air_accept",
                             args=[air_port, airplex, gcsplex])
    t_air.daemon = True
    t_air.start()

    t_gcs = threading.Thread(target=accept, name="gcs_accept",
                             args=[gcs_port, gcsplex, airplex])
    t_gcs.daemon = True
    t_gcs.start()

    def flush_db():
        for source, plex in [(SOURCE_TYPE.AIR, airplex),
                             (SOURCE_TYPE.GCS, gcsplex)]:
            queue = plex.pop_queue('db')
            if queue:
                try:
                    db.executemany("INSERT INTO packets (timestamp, source_type, source_address, data) VALUES (?, ?, ?, ?)",
                                   [(ts, source, "%s:%d" % addr, str(buf))
                                    for buf, ts, addr in queue])
                except sqlite3.Error, e:
                    logging.warn(e, exc_info=1)
                    logging.warn("Database write failed")

    while _running:
        time.sleep(.1)
        flush_db()

    logging.debug("Shutting down...")
    t_air.join()
    t_gcs.join()
    flush_db()
    db.close()
    logging.debug("Clean shutdown")


if __name__ == '__main__':
    if len(sys.argv) < 4:
        print >> sys.stderr, "Usage: %s <sqlite3 db> <air port> <gcs port>" % sys.argv[0]
        sys.exit(1)
    logging.basicConfig(level=logging.DEBUG)
    main(sys.argv[1], *map(int, sys.argv[2:]))
    sys.exit(0)
