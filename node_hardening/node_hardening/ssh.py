""" SSH helpers using paramiko library.
"""

import os
import paramiko
import socket
import sys
import time
import traceback
from functools import wraps

CONNECT_TIMEOUT = 20   # seconds


class TimeoutException(Exception):
    pass


class SSHConnection(object):

    def __init__(self, *args, **kwargs):
        self.client = SshClient(*args, **kwargs)

    def __enter__(self):
        self.client.connect()
        return self.client

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.client.close()


def retry_if_fail(retries, interval=10):

    s = lambda x: "%s%s" % (x, {1: 'st', 2: 'nd', 3: 'rd'}.get(x, 'th'))

    def decorator(func):
        @wraps(func)
        def wrapper(ssh, *args, **kwargs):
            def _run(count):
                try:
                    return func(ssh, *args, **kwargs)
                except paramiko.SSHException as err:
                    if ("SSH session not active" in str(err) or
                        "Error reading SSH protocol banner" in str(err) or \
                        "Authentication failed" in str(err)) \
                            and count < retries:
                        count += 1
                        ssh.log(str(err))
                        ssh.log('Retrying to run "%s" for the %s time.' %
                                (func.__name__, s(count)))
                        time.sleep(interval)
                        ssh.close()
                        return _run(count)
                    else:
                        exc_type, exc_val, exc_tb = sys.exc_info()
                        tb = ''.join(traceback.format_tb(exc_tb))\
                             if exc_tb else ''
                        ssh.log(tb)
                        ssh.log("%s: %s\n" % (exc_type.__name__, exc_val))
                        raise err
            return _run(0)
        return wrapper
    return decorator


class SshClient(object):
    """ This class implements basic features of paramiko library in order to
    run remote commands.
    """

    def __init__(self, host, user, password=None, port=22, via_host=None,
                 via_user=None, via_password=None, via_port=22):
        """ This constructor requires the connection arguments.
        >>> SshClient("host", "user")
        <SshClient host 22>
        >>> p = "some_password"
        >>> client = SshClient("host2", "user2", p, port=24)
        >>> client
        <SshClient host2 24>
        >>> client.password == p
        True
        >>> client._ssh is None
        True
        """
        self.host = host
        self.user = user
        self.password = password
        self.port = port
        self.via_host = via_host
        self.via_user = via_user
        self.via_password = via_password
        self.via_port = via_port
        self._ssh = None
        self.transport = None

    def __str__(self):
        """ Retrieves the str informal representation of this object.
        >>> client = SshClient("host", "user")
        >>> str(client)
        '<SshClient host 22>'
        """
        return "<%s %s %s>" % (self.__class__.__name__, self.host, self.port)

    def __repr__(self):
        """ Retrieves the official representation of this object.
        >>> client = SshClient("host", "user")
        >>> repr(client)
        '<SshClient host 22>'
        """
        return self.__str__()

    def log(self, msg, log_type='info'):
        """ Uses NasLogger.instance to log messages. The log_type must be one
        of those self.log_types.
        """
        if log_type != 'debug':
            print "%s: %s" % (log_type, msg)

    def debug(self, msg):
        """ Just a small helper for debug messages.
        """
        self.log(msg, 'debug')

    @property
    def ssh(self):
        """ Gets the paramiko SshClient object connected.
        """
        if self._ssh is not None:
            if not self.is_connected():
                self.debug("connection lost to NAS server, will "
                           "try again now")
                self.connect()
            return self._ssh
        self.connect()
        return self._ssh

    @retry_if_fail(5)
    def connect(self):
        """ Builds the paramiko.SshClient object, sets
        the system keys, the missing host key (for .ssh/know_host file) and try
        to establish the SSH connection.
        """
        if self._ssh is not None:
            return
        if self.via_host:
            t0 = paramiko.Transport(self.via_host)
            t0.start_client()
            t0.auth_password(self.via_user, self.via_password)
            # setup forwarding from 127.0.0.1:<free_random_port> to |host|
            channel = t0.open_channel('direct-tcpip', (self.host,
                                                       self.port),
                                      ('127.0.0.1', 0))
            self.transport = paramiko.Transport(channel)
            self.transport.start_client()
            self.transport.auth_password(self.user,
                                         self.password)
        else:
            self._ssh = paramiko.SSHClient()
            self._ssh.load_system_host_keys()
            self._ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.debug("connecting to the NAS server")
            self._ssh.connect(self.host, self.port, self.user, self.password,
                              timeout=CONNECT_TIMEOUT)
            self.debug("connection to the NAS server has been established.")

    def is_connected(self):
        """ Checks the SSH connectivity.
        """
        transport = self._ssh.get_transport() if self._ssh else None
        return bool(transport and transport.is_active())

    def _via_run(self, cmd, su=None, expects=None):
        """ Executes a command using self.transport object to open a channel
        inside the "via_host" machine.
        """
        if self.transport is None:
            self.connect()
        ch = self.transport.open_session()
        ch.set_combine_stderr(True)
        if su:
            ch.get_pty()
            cmd = cmd.replace('$', '\$')
            cmd = 'su -c "%s"' % cmd
        ch.exec_command(cmd)
        if su:
            time.sleep(2)
            buf = ''
            while ch.recv_ready():
                resp = ch.recv(1024)
                if resp:
                    buf += resp
            time.sleep(1)
            ch.send('%s\n' % su)
        buf = ''
        while ch.recv_ready():
            resp = ch.recv(1024)
            if resp:
                buf += resp
        if expects:
            time.sleep(1)
            for exp in expects:
                time.sleep(1)
                ch.send('%s\n' % exp)
        status = ch.recv_exit_status()
        buf = ''
        while ch.recv_ready():
            time.sleep(0.5)
            resp = ch.recv(1024)
            if resp:
                buf += resp
        if status == 0:
            out = ["%s\n" % i for i in buf.splitlines()]
            err = ""
        else:
            out = ""
            err = ["%s\n" % i for i in buf.splitlines()]
        return status, out, err

    def _normal_run(self, cmd, timeout=None, su=None, expects=None):
        """ Uses the paramiko SSHClient to execute a cmd.
        """
        ssh_kwargs = dict(get_pty=True)
        if su:
            cmd = cmd.replace('$', '\$')
            cmd = 'su -c "%s"' % cmd
        stdin, stdout, stderr = self.ssh.exec_command(cmd,
                                     timeout=timeout, **ssh_kwargs)
        if su:
            time.sleep(1)
            stdin.write('%s\n' % su)
            stdin.flush()
        if expects:
            for exp in expects:
                time.sleep(1)
                stdin.write('%s\n' % exp)
                stdin.flush()
        self.debug("the paramiko exec_command ran successfully (%s)"
                   % cmd)
        out = stdout.readlines()
        self.debug("paramiko stdout.readlines() ran successfully (%s)"
                   % cmd)
        err = stderr.readlines()
        self.debug("paramiko stderr.readlines() ran successfully (%s)"
                   % cmd)
        # IMPORTANT: the exit status must be caught after reading the
        # stdout and stderr, since the timeout exception will be only
        # raised by reading those buffers. Paramiko may hangs while
        # executing recv_exit_status before reading the buffers.
        status = stdout.channel.recv_exit_status()
        if status != 0:
            self.debug("paramiko status: %s (%s)" % (status, cmd))
            err = out + err
            out = []
        return status, out, err

    @retry_if_fail(5)
    def run(self, cmd, timeout=None, su=None, expects=None):
        """ Uses paramiko SshClient object to execute commands remotely and
        retrieves the correspond standard output and standard error.
        """
        self.debug("running (%s)" % cmd)
        try:
            if self.via_host:
                status, out, err = self._via_run(cmd, su, expects)
            else:
                status, out, err = self._normal_run(cmd, timeout, su, expects)
        except socket.timeout as err:
            raise TimeoutException("A timeout of %s seconds "
                                   "occurred after trying to execute"
                                   "the following command remotely "
                                   "through SSH: \"%s\". Error: %s" % (
                                   timeout, cmd, str(err)))
        self.debug("ran (%s)" % cmd)
        return status, "".join(out), "".join(err)

    def close(self):
        """ Closes the ssh connection properly.
        """
        self.debug("closing ssh")
        if self._ssh is not None:
            self._ssh.close()
        self._ssh = None
        self.debug("closed ssh")


class SshScpClient(SshClient):

    def __init__(self, *args, **kwargs):
        super(SshScpClient, self).__init__(*args, **kwargs)
        self._sftp = None

    @property
    def sftp(self):
        if self._sftp is not None:
            return self._sftp
        self.connect()
        return self._sftp

    def connect(self):
        super(SshScpClient, self).connect()
        if self._sftp is not None:
            return
        t = paramiko.Transport((self.host, self.port))
        t.connect(username=self.user, password=self.password)
        self._sftp = paramiko.SFTPClient.from_transport(t)

    def get(self, path):
        self.sftp.get(path)

    def put(self, source, dest):
        self.debug("Put %s to %s" % (source, dest))
        if not os.path.isfile(source):
            raise Exception("%s not found" % source)
        self.sftp.put(source, dest)
        self.debug("Put %s to %s: SUCCESS!" % (source, dest))

    def close(self):
        super(SshScpClient, self).close()
        self.debug("closing sftp")
        self.sftp.close()
        self._sftp = None
        self.debug("closed sftp")
