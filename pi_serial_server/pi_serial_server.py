#!/usr/bin/env python

"""
Simple Serial to Network (TCP/IP) re-director aka Serial Server for use with Raspberry Pi.
Forwards data between a local COM port and a remote TCP (client) port, in both directions.

Runs from Command Line Interface.

Supports optional logging to a file with (UTC) timestamped details and verbose debug output.

.. note::
    You may need to increase read/write timeouts on the attached serial device to accommodate
    network delays.

.. tip::
    Windows Users can use a virtual serial port driver like `HW Group Virtual Serial Port
    <https://www.hw-group.com/software/hw-vsp3-virtual-serial-port>`_

"""

__version__ = "1.0"

import sys
import time
import threading
import argparse
import socket
import logging
from logging.handlers import RotatingFileHandler
import binascii
import string

try:
    # TODO: requires pySerial version 3.0 or higher
    import serial
    import serial.tools.list_ports
except ImportError:
    print "Running serial_tcp_redirect requires pyserial"
    sys.exit(1)


class SerialServer:
    """
    The serial server.

    .. _pySerial: https://pyserial.readthedocs.io

    :param port: (string) optional name of the serial/COM port to use (default /dev/ttyUSB0)
    :param baudrate: (integer) communication rate of the serial port (default 9600)
    :param bytesize: (enum) see pySerial_
    :param parity: (enum) see pySerial_
    :param stopbits: (enum) see pySerial_
    :param rtscts: (Boolean) use Request To Send / Clear To Send flow control on serial port
    :param xonxoff: (Boolean) use XON / XOFF flow control on serial port
    :param dsrdtr: (Boolean) use Data Set Ready / Data Terminal Ready flow control on serial port
    :param timeout: (float) seconds
    :param write_timeout: (float) seconds
    :param inter_byte_timeout: (float) seconds or None (default)
    :param tcp_port: (integer) the TCP port to listen for remote connections (default 9001)
    :param log: optional logging object

    """
    def __init__(self, port, baudrate=9600,
                 bytesize=serial.EIGHTBITS, parity=serial.PARITY_NONE, stopbits=serial.STOPBITS_ONE,
                 rtscts=False, xonxoff=False, dsrdtr=False,
                 timeout=1, write_timeout=1, inter_byte_timeout=None,
                 tcp_port=9001,
                 log=None):
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
        self.ser.bytesize = bytesize
        self.ser.parity = parity
        self.ser.stopbits = stopbits
        self.ser.timeout = timeout
        self.ser.write_timeout = write_timeout
        self.ser.inter_byte_timeout = inter_byte_timeout
        self.ser.xonxoff = xonxoff
        self.ser.rtscts = rtscts
        self.ser.dsrdtr = dsrdtr
        # logging
        if log is not None:
            self.log = log
        else:
            self.log = get_log_wrap()

    def start(self):
        """
        Opens the serial port and TCP listener to begin forwarding data.
        Waits until a TCP client connects on the specified port, before creating a read and write thread.
        """
        self.alive = True
        try:
            self.ser.open()
            self.log.info("Serial connection open on {port}".format(port=self.ser.port))
            if self.ser.inter_byte_timeout is not None:
                self.log.debug("  Serial inter-byte timeout {ibt} seconds".format(ibt=self.ser.inter_byte_timeout))
        except serial.SerialException, e:
            self.log.error("Could not open serial {port} - {error}".format(port=self.ser.port, error=e))
            sys.exit(1)
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.bind(('', self.tcp_port))
            host = socket.gethostbyname(socket.gethostname())
            self.socket.listen(1)
            self.log.info("Listening on {host}:{port}".format(host=host, port=self.tcp_port))
            self.conn, addr = self.socket.accept()
            self.log.info("TCP connection from {addr}".format(addr=addr))
        except socket.error, e:
            self.log.error("Could not open socket: {error}".format(error=e))
            self.socket = None
            raise
        # start redirecting from tcp/ip to serial
        self.thread_write = threading.Thread(target=self._writer, name='_writer')
        self.thread_write.setDaemon(True)
        self.thread_write.start()
        self.thread_read = threading.Thread(target=self._reader, name='_reader')
        self.thread_read.setDaemon(True)
        self.thread_read.start()

    def _printable(self, data):
        """
        Returns a printable string either ASCII text if all readable, or a hex string.

        :param data: (bytes) to make printable
        :return: printable string

        """
        printable = ''
        all_printable = True
        for b in data:
            if b in string.printable and all_printable:
                printable += str(b)
            else:
                if all_printable:
                    all_printable = False
                    if len(printable) > 0:
                        self.log.debug("Must replace {num} chars from {s}".format(num=len(printable)/2, s=printable))
                        non_printable = ''
                        for c in printable:
                            non_printable += c.encode('hex')
                        printable = non_printable
                printable += binascii.hexlify(b)
        if all_printable and printable[len(printable) - 1] == '\n':
            printable = printable.replace('\n', '')
        else:
            printable = printable.replace('\n', '0a')
        return printable

    def _reader(self):
        """loop forever and copy serial->socket"""
        self.log.debug("Waiting for serial data on {port}".format(port=self.ser.port))
        self.ser.reset_input_buffer()
        while self.alive:
            data = self.ser.read_until()
            if self.ser.in_waiting > 0:
                data += self.ser.read(self.ser.in_waiting)
            if data:
                self.log.debug("Serial data received: {data}".format(data=self._printable(data)))
                if self.conn:
                    try:
                        self.conn.sendall(data)
                    except socket.error, e:
                        self.log.error("Socket error: {error}".format(error=e))
                        break
                else:
                    self.log.warning("No TCP connection active, dropping data.")
        self.log.debug("Terminating from _reader.")
        self._terminate()

    def _writer(self):
        """loop forever and copy socket->serial"""
        self.ser.reset_output_buffer()
        while self.alive:
            try:
                data = self.conn.recv(self.ip_read_size)
                if not data:
                    break
                else:
                    self.log.debug("Received TCP socket data {data}".format(data=self._printable(data)))
                    self.ser.write(data)
            except socket.error, e:
                self.log.error("Socket error: {error}".format(error=e))
                break
        self.log.debug("Terminating from _writer.")
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


def validate_serial_port(target, log):
    """
    Validates a given serial port as available on the host.

    :param target: (string) the target port name e.g. '/dev/ttyUSB0'
    :param log: a logger object for debug/info logging
    :return: (Boolean) validity

    """
    found = False
    ser_ports = [tuple(port) for port in list(serial.tools.list_ports.comports())]
    for port in ser_ports:
        if 'USB VID:PID=0403:6001' in port[2] and target == port[0]:
            log.info("Using serial FTDI FT232 (RS485/RS422/RS232) on {port}".format(port=port[0]))
            found = True
        elif 'USB VID:PID=067B:2303' in port[2] and target == port[0]:
            log.info("Using serial Prolific PL2303 (RS232) on {port}".format(port=port[0]))
            found = True
        elif target == port[0]:
            usb_id = str(port[2])
            log.info("Using serial vendor/device {id} on {port}".format(id=usb_id, port=port[0]))
            found = True
    return found


def get_log_wrap(filename=None, filesize=5, debug=False):
    """
    Initializes logging to file and console.

    :param filename: (string) the name of the file (None will just use a temporary log in memory)
    :param filesize: (int) the max size of the file in megabytes, before wrapping occurs
    :param debug: (Boolean) enables verbose logging
    :return: logger object with custom formatting and handlers for console and file

    """
    if debug:
        log_lvl = logging.DEBUG
    else:
        log_lvl = logging.INFO
    log_formatter = logging.Formatter(fmt='%(asctime)s.%(msecs)03d,(%(threadName)-10s),'
                                               '[%(levelname)s],%(funcName)s(%(lineno)d),%(message)s',
                                           datefmt='%Y-%m-%d %H:%M:%S')
    log_formatter.converter = time.gmtime
    if filename is not None:
        log_object = logging.getLogger(filename)
        log_handler = RotatingFileHandler(filename, mode='a', maxBytes=filesize * 1024 * 1024,
                                          backupCount=2, encoding=None, delay=0)
        log_handler.setFormatter(log_formatter)
        log_object.addHandler(log_handler)
    else:
        log_object = logging.getLogger("pi_serial_server")
    log_object.setLevel(log_lvl)
    console = logging.StreamHandler()
    console.setFormatter(log_formatter)
    console.setLevel(log_lvl)
    log_object.addHandler(console)
    return log_object


def get_parser():
    """
    Creates the command line arguments.

    :returns: An argparse.ArgumentParser

    """
    parser = argparse.ArgumentParser(description="Converts TCP/IP to serial.")

    parser.add_argument('--tcp', default=9001, type=int, choices=range(1024, 65535),
                        help="TCP/IP host port to listen on (``int`` default 9001)", metavar="{1024..65535}")

    parser.add_argument('-p', '--port', default='/dev/ttyUSB0',
                        help="name of the serial port (``string`` default /dev/ttyUSB0)")

    parser.add_argument('-b', '--baud', default=9600, type=int,
                        choices=[2400, 4800, 9600, 19200, 38400, 57600, 115200],
                        help="baud rate (``int`` default 9600)", metavar="{2400..115200}")

    parser.add_argument('--rtscts', action='store_true',
                        help="use RTS/CTS flow control (default disabled)")

    parser.add_argument('--xonxoff', action='store_true',
                        help="use XON/XOFF flow control (default disabled)")

    parser.add_argument('--dsrdtr', action='store_true',
                        help="use DSR/DTR flow control (default disabled)")

    parser.add_argument('-t', '--timeout', default=1.0, type=float, choices=range(0, 60),
                        help="serial read/write timeouts (``float`` default 1.0 seconds)", metavar="{0..60}")

    parser.add_argument('--logfile', dest='filename', default=None,
                        help="an output log file name (optional ``string``)")

    parser.add_argument('--logsize', dest='filesize', type=int, default=5,
                        help="the maximum log file size, in MB (``int`` default 5 MB)")

    parser.add_argument('--debug', action='store_true',
                        help="enable verbose debug logging")

    return parser


def main():
    """Gets user inputs and starts the server until keyboard interrupt"""
    parser = get_parser()
    user_options = parser.parse_args()

    # logger setup
    if user_options.filename is not None and user_options.filename.split('.')[1] != '.log':
        user_options.filename = user_options.filename + '.log'
    log = get_log_wrap(filename=user_options.filename, filesize=user_options.filesize,
                       debug=user_options.debug)

    log.info("***** Starting: RPi Serial <--> TCP/IP port server (type Ctrl-C / BREAK to quit) *****")
    # log.debug("PySerial version {version}".format(version=serial.__version__))

    if not validate_serial_port(user_options.port, log):
        log.error("No available serial port matching {port}".format(port=user_options.port))
        sys.exit(1)
    if serial.__version__ < 3.0:
        log.error("Please update pySerial module from {version} to 3.0 or higher (e.g. pip install pyserial --upgrade)"
                  .format(version=serial.__version__))
        sys.exit(1)

    # TODO: allow for settings other than 8N1 with inter_byte_timeout ``None``
    server = SerialServer(port=user_options.port, baudrate=user_options.baud,
                          rtscts=user_options.rtscts, xonxoff=user_options.xonxoff,
                          timeout=user_options.timeout, write_timeout=user_options.timeout,
                          tcp_port=user_options.tcp,
                          log=log)

    try:
        server.start()
        while True:
            pass

    except KeyboardInterrupt:
        log.info("Execution halted by user.")

    except Exception, e:
        log.error("Error {error}".format(error=e))

    finally:
        server.stop()


if __name__ == '__main__':
    main()
