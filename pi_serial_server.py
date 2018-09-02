#!/usr/bin/env python

"""
Simple Serial to Network (TCP/IP) re-director aka Serial Server for use with Raspberry Pi.
Forwards data between a COM port and a TCP port, in both directions.

"""

__version__ = "1.0"

import sys
import time
import threading
import argparse
import socket
import logging
from logging.handlers import RotatingFileHandler

try:
    import serial
except ImportError:
    print "Running serial_tcp_redirect requires pyserial"
    sys.exit(1)


class SerialServer:
    """
    The serial server.

    :param port: (string) optional name of the serial/COM port to use (default /dev/ttyUSB0)
    :param baudrate: (integer) communication rate of the serial port (default 9600)
    :param rtscts: (Boolean) use Ready To Send / Clear To Send flow control on serial port
    :param xonxoff: (Boolean) use XON/XOFF flow control on serial port
    :param dsrdtr: (Boolean) use Data Se
    :param timeout: (integer) seconds
    :param writeTimeout: (integer)
    :param tcp_port: (integer) the TCP port to listen for remote connections (default 9001)

    """
    def __init__(self, port, baudrate=9600,
                 rtscts=False, xonxoff=False, dsrdtr=False,
                 timeout=1, writeTimeout=1,
                 tcp_port=9001):
        self.tcp_port = tcp_port
        self.socket = None
        self.conn = None
        self.thread_write = None
        self.thread_read = None
        self.ip_read_size = 1024
        self.alive = False
        # Set up the serial connection
        self.ser = serial.Serial()
        self.ser.port = port
        self.ser.baudrate = baudrate
        self.ser.timeout = timeout
        self.ser.writeTimeout=writeTimeout
        self.ser.xonxoff = xonxoff
        self.ser.rtscts = rtscts
        self.ser.dsrdtr = dsrdtr

    def start(self):
        """Opens the serial port and TCP listener to being forwarding data."""
        self.alive = True
        try:
            self.ser.open()
            print("Serial connection open on {port}".format(port=self.ser.port))
        except serial.SerialException, e:
            print "Could not open serial {port} - {error}".format(port=self.ser.port, error=e)
            sys.exit(1)
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.bind(('', self.tcp_port))
            host = socket.gethostbyname(socket.gethostname())
            self.socket.listen(1)
            print("Listening on {host}:{port}".format(host=host, port=self.tcp_port))
            self.conn, addr = self.socket.accept()
            print("TCP connection from {addr}".format(addr=addr))
        except socket.error, e:
            print("Could not open socket: {error}".format(error=e))
            self.socket = None
            raise
        # start redirecting from tcp/ip to serial
        self.thread_write = threading.Thread(target=self._writer, name='_writer')
        self.thread_write.setDaemon(True)
        self.thread_write.start()
        self.thread_read = threading.Thread(target=self._reader, name='_reader')
        self.thread_read.setDaemon(True)
        self.thread_read.start()

    def _reader(self):
        """loop forever and copy serial->socket"""
        print("Waiting for serial data on {port}".format(port=self.ser.port))
        while self.alive:
            data = self.ser.read_until()
            if data:
                print("Serial data received: {data}".format(data=data))
                if self.conn:
                    try:
                        self.conn.sendall(data)
                    except socket.error, e:
                        print("Socket error: {error}".format(error=e))
                        break
                else:
                    print("No TCP connection active, dropping data.")
        print("Terminating from _reader.")
        self._terminate()

    def _writer(self):
        """loop forever and copy socket->serial"""
        while self.alive:
            try:
                data = self.conn.recv(self.ip_read_size)
                if not data:
                    break
                else:
                    print("Received TCP socket data {data}".format(data=data))
                    self.ser.write(data)
            except socket.error, e:
                print("Socket error: {error}".format(error=e))
                break
        print("Terminating from _writer.")
        self._terminate()

    def stop(self):
        """Stop forwarding data and shut the server down."""
        self.alive = False

    def _terminate(self):
        """Clean up."""
        if self.thread_write:
            self.thread_write.join()
        if self.thread_read:
            self.thread_read.join()
        if self.conn:
            self.conn.close()
        if self.socket:
            self.socket.close()
            self.socket = None
        if self.ser.is_open:
            self.ser.close()


def init_log(logfile=None, file_size=5, debug=False):
    """
    Initializes logging to file and console.

    :param logfile: the name of the file
    :param file_size: the max size of the file in megabytes, before wrapping occurs
    :param debug: Boolean to enable verbose logging
    :return: ``log`` object

    """
    # TODO: move into imported module
    if debug:
        log_lvl = logging.DEBUG
    else:
        log_lvl = logging.INFO
    log_formatter = logging.Formatter(fmt='%(asctime)s.%(msecs)03d,(%(threadName)-10s),' \
                                          '[%(levelname)s],%(funcName)s(%(lineno)d),%(message)s',
                                      datefmt='%Y-%m-%d %H:%M:%S')
    log_formatter.converter = time.gmtime
    if logfile is not None:
        log_object = logging.getLogger(logfile)
        log_handler = RotatingFileHandler(logfile, mode='a', maxBytes=file_size * 1024 * 1024,
                                          backupCount=2, encoding=None, delay=0)
        log_handler.setFormatter(log_formatter)
        log_object.addHandler(log_handler)
    else:
        log_object = logging.getLogger("temp_log")
    log_object.setLevel(log_lvl)
    console = logging.StreamHandler()
    console.setFormatter(log_formatter)
    console.setLevel(log_lvl)
    log_object.addHandler(console)
    return log_object


def parse_args(argv):
    """
    Parses the command line arguments.

    :param argv: An array containing the command line arguments
    :returns: A dictionary containing the command line arguments and their values

    """
    parser = argparse.ArgumentParser(description="Converts TCP/IP to serial.")

    # parser.add_argument('-l', '--log', dest='logfile', type=str, default='pi_serial_server.log',
    #                     help="the log file name with optional extension (default extension .log)")
    #
    # parser.add_argument('-s', '--logsize', dest='log_size', type=int, default=5,
    #                     help="the maximum log file size, in MB (default 5 MB)")
    #

    parser.add_argument('-p', '--port', dest='port', default='/dev/ttyUSB0',
                        help="name of the serial port (default /dev/ttyUSB0)")

    parser.add_argument('-b', '--baud', dest='baud', default='9600',
                        help="baud rate (default 9600)")

    parser.add_argument('-r', '--rtscts', dest='rts_cts', action='store_true',
                        help="use RTS/CTS flow control (default disabled)")

    parser.add_argument('-x', '--xonxoff', dest='xon_xoff', action='store_true',
                        help="use XON/XOFF flow control (default disabled)")

    parser.add_argument('-t', '--tcp', dest='tcp_port', default='9001',
                        help="TCP/IP Host port (default 9001)")

    return vars(parser.parse_args(args=argv[1:]))


def main():
    # parse command line options
    user_options = parse_args(sys.argv)
    if user_options['baud'] not in ('2400', '4800', '9600', '19200', '38400', '57600', '115200'):
        print("Invalid baud rate, using 9600 (default).")
        user_options['baud'] = 9600
    else:
        user_options['baud'] = int(user_options['baud'])
    # TODO: validate serial port exists

    try:
        user_options['tcp_port'] = int(user_options['tcp_port'])
        # TODO: validate port range
    except ValueError:
        # raise ValueError, "TCP port must be a valid integer number in the range (X..Y)"
        print("Invalid TCP port, using 9001 (default)")
        user_options['tcp_port'] = 9001

    server = SerialServer(port=user_options['port'], baudrate=user_options['baud'],
                          rtscts=user_options['rts_cts'], xonxoff=user_options['xon_xoff'],
                          timeout=1, writeTimeout=0,
                          tcp_port=user_options['tcp_port'])

    try:
        print "***** RPi Serial <--> TCP/IP port server (type Ctrl-C / BREAK to quit) *****"
        server.start()
        while True:
            pass

    except KeyboardInterrupt:
        print("Execution halted by user.")

    except Exception, e:
        print("Error {error}".format(error=e))

    finally:
        server.stop()


if __name__ == '__main__':
    main()
