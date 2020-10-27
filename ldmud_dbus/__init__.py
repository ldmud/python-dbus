import ldmud, ldmud_asyncio, asyncio, sys, os, configparser, urllib.parse, struct, enum, collections, re, traceback

re_busname = re.compile("^(:[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)+|[A-Za-z_-][A-Za-z0-9_-]*(\.[A-Za-z_-][A-Za-z0-9_-]*)+)$")
re_interface = re.compile("^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+$")
re_member = re.compile("^[A-Za-z_][A-Za-z0-9_]*$")
re_path = re.compile("^/([A-Za-z0-9_]+(/[A-Za-z0-9_]+)*)?$")

config = configparser.ConfigParser()
config['dbus'] = {}
config.read(os.path.expanduser('~/.ldmud-efuns'))
dbusconfig = config['dbus']

listeners = {}  # rule string: (DBusSignaRule, [Callbacks])
objects = {}    # object path: (LDMud object, {interface name: prefix})

# Classes to hint at the right signature for variants
class DBusObjectPath(str):
    pass

class DBusSignature(str):
    pass

class DBusUint32(int):
    pass

class DBusException(Exception):
    """
    Exception that captures the error name as well as a message for
    use in a D-Bus answer.
    """
    def __init__(self, name, msg):
        Exception.__init__(self, msg)
        self.name = name
        self.msg = msg

class DBusMessage:
    """
    A D-Bus message.
    """

    class MessageType(enum.IntEnum):
        INVALID       = 0
        METHOD_CALL   = 1
        METHOD_RETURN = 2
        ERROR         = 3
        SIGNAL        = 4

    class Flags(enum.IntFlag):
        NO_REPLY_EXPECTED               = 1
        NO_AUTO_START                   = 2
        ALLOW_INTERACTIVE_AUTHORIZATION = 4

    class HeaderField(enum.IntEnum):
        INVALID      = 0
        PATH         = 1
        INTERFACE    = 2
        MEMBER       = 3
        ERROR_NAME   = 4
        REPLY_SERIAL = 5
        DESTINATION  = 6
        SENDER       = 7
        SIGNATURE    = 8
        UNIX_FDS     = 9

    @staticmethod
    def check_signature(signature):
        """
        Checks whether the given signature is valid.
        Raises an exception if not.
        """
        idx = 0
        while idx < len(signature):
            idx = DBusConnection.skip_signature(signature, idx)

    @staticmethod
    def check_name(value, name, regexp):
        """
        Checks a name against a regular expression.
        Raises an exception if it doesn't match.
        """
        if len(value) > 255:
            raise ValueError(name + " is too long")
        if not regexp.fullmatch(value):
            raise ValueError("invalid " + name)

    def __init__(self, msg_type, *, path = None, interface = None, member = None, error_name = None, reply_serial = None, destination = None, signature = None, data = None):
        """
        Initializes the message and validates its arguments.
        """
        self.msg_type = msg_type
        self.header = collections.OrderedDict()
        self.data = data
        self.flags = 0

        if path:
            self.check_name(path, "object path", re_path)
            self.header[DBusMessage.HeaderField.PATH]         = DBusObjectPath(path)
        if interface:
            self.check_name(interface, "interface name", re_interface)
            self.header[DBusMessage.HeaderField.INTERFACE]    = interface
        if member:
            self.check_name(member, "member name", re_member)
            self.header[DBusMessage.HeaderField.MEMBER]       = member
        if error_name:
            self.check_name(error_name, "error name", re_interface)
            self.header[DBusMessage.HeaderField.ERROR_NAME]   = error_name
        if reply_serial:
            self.header[DBusMessage.HeaderField.REPLY_SERIAL] = DBusUint32(reply_serial)
        if destination:
            self.check_name(destination, "bus name", re_busname)
            self.header[DBusMessage.HeaderField.DESTINATION]  = destination
        if signature:
            if len(signature) > 255:
                raise ValueError("signature is too long")
            self.check_signature(signature)
            self.header[DBusMessage.HeaderField.SIGNATURE]    = DBusSignature(signature)

class DBusMethodCall(DBusMessage):
    """
    A D-Bus message representing a method call.
    """
    def __init__(self, destination, path, interface, method, signature, args):
        DBusMessage.__init__(self, DBusMessage.MessageType.METHOD_CALL, destination = destination, path = path, interface = interface, member = method, signature = signature, data = args)

class DBusMethodResult(DBusMessage):
    """
    A D-Bus message representing a method call result.
    """
    def __init__(self, destination, serial, signature, result):
        DBusMessage.__init__(self, DBusMessage.MessageType.METHOD_RETURN, destination = destination, reply_serial = serial, signature=signature, data = result)

class DBusErrorMessage(DBusMessage):
    """
    A D-Bus message representing an error message.
    """
    def __init__(self, destination, serial, error_name, msg):
        DBusMessage.__init__(self, DBusMessage.MessageType.ERROR, destination = destination, reply_serial = serial, error_name = error_name, signature='s', data = [msg])

class DBusSignal(DBusMessage):
    """
    A D-Bus message representing a signal.
    """
    def __init__(self, path, interface, signal, signature, args):
        DBusMessage.__init__(self, DBusMessage.MessageType.SIGNAL, path = path, interface = interface, member = signal, signature = signature, data = args)

class DBusSignalRule:
    """
    A match rule for receiving signals.
    """
    def __init__(self, bus, path, interface, signal):
        self.rule = collections.OrderedDict(type='signal')
        if bus:
            DBusMessage.check_name(bus, "bus name", re_busname)
            self.rule['sender'] = bus
        if path:
            DBusMessage.check_name(path, "object path", re_path)
            self.rule['path'] = path
        if interface:
            DBusMessage.check_name(interface, "interface name", re_interface)
            self.rule['interface'] = interface
        if signal:
            DBusMessage.check_name(signal, "signal name", re_member)
            self.rule['member'] = signal

    def get_str(self):
        """
        Return a string suitable for the AddMatch() method.
        The same DBusSignalRule parameters will always yield the same string.
        """
        return ",".join("%s='%s'" % entry for entry in self.rule.items())

    def matches(self, msg):
        """
        Returns True if the rule matches the given message.
        """
        def mismatch(name, field):
            value = self.rule.get(name)
            return value and msg.header.get(field) != value

        if mismatch('sender', DBusMessage.HeaderField.SENDER):
            return False
        if mismatch('path', DBusMessage.HeaderField.PATH):
            return False
        if mismatch('interface', DBusMessage.HeaderField.INTERFACE):
            return False
        if mismatch('member', DBusMessage.HeaderField.MEMBER):
            return False
        return True

class DBusConnection:
    """
    A single D-Bus connection.

    This class handles marshalling and unmarshalling D-Bus messages.
    Incoming messages will be dispatched according to the module variables
    listeners and objects.
    """

    class PythonTypes:
        """
        Types used for unmarshalling D-Bus message headers.
        """
        Struct = tuple
        Array = list
        Dict = collections.OrderedDict

    class LDMudTypes:
        """
        Types used for unmarshalling D-Bus message payloads..
        """
        Struct = ldmud.Array
        Array = ldmud.Array
        Dict = ldmud.Mapping

    def __init__(self, address = 'session'):
        self.address = address
        self.reader = self.writer = None
        self.serial = 0
        self.callbacks = {}
        self.consumer_task = None

    async def get_address(self):
        """
        Determine the socket to connect to.
        """
        if self.address == 'system':
            return os.environ.get('DBUS_SYSTEM_BUS_ADDRESS','unix:path=/var/run/dbus/system_bus_socket')
        elif self.address == 'session':
            addr = os.environ.get('DBUS_SESSION_BUS_ADDRESS')
            if addr:
                return addr
            raise ValueError('could not determine session bus address')
        else:
            return self.address

    async def connect(self):
        """
        Establish the D-Bus connection.
        """
        addrstr = await self.get_address()
        error = ConnectionError("missing address")

        # The address may contain multiple endpoints, separated by semicolon.
        for addr in addrstr.split(';'):
            try:
                # Format: "transport:option=value,option=value,..."
                if ':' not in addr:
                    raise ValueError("invalid address format")
                transport, optionsstr = addr.split(':', 1)

                options = {}
                for optionstr in optionsstr.split(','):
                    if '=' not in optionstr:
                        raise ValueError("invalid address format")
                    key, value = optionstr.split('=', 1)
                    options[key] = urllib.parse.unquote(value)

                if transport == 'unix':
                    if 'path' in options:
                        self.reader, self.writer = await asyncio.open_unix_connection(options['path'])
                    elif 'abstract' in options:
                        self.reader, self.writer = await asyncio.open_unix_connection('\0' + options['abstract'])
                    else:
                        raise ConnectionError("unknown unix transport specification")
                elif transport == 'tcp':
                    self.reader, self.writer = await asyncio.open_connection(options.get('host', ''), int(options.get('port', '0')))
                else:
                    raise ConnectionError("unknown transport '%s'" % (transport,))
                error = None
                break
            except ex:
                if error is None:
                    error = ex

        if error is not None:
            raise error

        # Before we are allowed to send D-Bus messages we must do authentification.
        await self.do_authentification()

        self.consumer_task =  asyncio.get_event_loop().create_task(self.consumer())

    async def do_authentification(self):
        """
        Handle authentification. Currently only 'AUTH EXTERNAL' is supported.
        """
        self.writer.write(b'\0AUTH EXTERNAL ' + str(os.getuid()).encode('ASCII').hex().encode('ASCII') + b'\r\n')
        await self.writer.drain()

        response = await self.reader.readline()
        if not response.startswith(b'OK '):
            raise ConnectionRefusedError('authentication rejected: ' + response.decode('ASCII'))

        self.writer.write(b'BEGIN\r\n')

    async def close(self):
        """
        Close the connection.
        """
        self.writer.close()
        await self.writer.wait_closed()
        await self.consumer_task

    async def consumer(self):
        """
        This thread processes all incoming messages.
        """
        while not self.reader.at_eof():
            try:
                msg = await self.read_message()
                if msg is None:
                    return
                await self.process_message(msg)
            except:
                traceback.print_exc()

    async def process_message(self, msg):
        """
        Dispatch a single message.
        """
        if msg.msg_type == DBusMessage.MessageType.METHOD_RETURN:
            serial = msg.header.get(DBusMessage.HeaderField.REPLY_SERIAL, 0)
            cb = self.callbacks.pop(serial, None)
            if cb:
                await cb(msg)
        elif msg.msg_type == DBusMessage.MessageType.ERROR:
            serial = msg.header.get(DBusMessage.HeaderField.REPLY_SERIAL, 0)
            cb = self.callbacks.pop(serial, None)
            if cb:
                await cb(msg)
        elif msg.msg_type == DBusMessage.MessageType.SIGNAL:
            for key, (rule,cbs) in listeners.items():
                if rule.matches(msg):
                    for cb in cbs:
                        cb(*msg.data)
        elif msg.msg_type == DBusMessage.MessageType.METHOD_CALL:
            try:
                path = msg.header.get(DBusMessage.HeaderField.PATH)
                if path not in objects:
                    raise DBusException("org.freedesktop.DBus.Error.UnknownObject", "Path not found.")

                interface = msg.header.get(DBusMessage.HeaderField.INTERFACE)
                if interface not in objects[path][1]:
                    raise DBusException("org.freedesktop.DBus.Error.UnknownInterface", "Interface not found.")

                ob = objects[path][0]
                lfunname =  objects[path][1][interface] + msg.header.get(DBusMessage.HeaderField.MEMBER, "")
                if not ob:
                    raise DBusException("org.freedesktop.DBus.Error.UnknownObject", "Object has vanished.")
                if isinstance(ob, str):
                    ob = ldmud.Object(ob)
                lfun = getattr(ob.functions, lfunname, None)
                if not lfun:
                    raise DBusException("org.freedesktop.DBus.Error.UnknownMethod", "Method not found.")
                result = lfun(*msg.data)

                if not (msg.flags & DBusMessage.Flags.NO_REPLY_EXPECTED):
                    self.send_message(print_error_callback, DBusMethodResult(msg.header.get(DBusMessage.HeaderField.SENDER), msg.serial, self.get_signature(result), [result]))
            except DBusException as ex:
                if not (msg.flags & DBusMessage.Flags.NO_REPLY_EXPECTED):
                    self.send_message(print_error_callback, DBusErrorMessage(msg.header.get(DBusMessage.HeaderField.SENDER), msg.serial, ex.name, ex.msg))
            except Exception as ex:
                if not (msg.flags & DBusMessage.Flags.NO_REPLY_EXPECTED):
                    self.send_message(print_error_callback, DBusErrorMessage(msg.header.get(DBusMessage.HeaderField.SENDER), msg.serial, "org.freedesktop.DBus.Error.Failed", repr(ex)))

    async def read_message(self):
        """
        Read a single message from the connection.
        """
        endianness = await self.reader.read(1)
        if not endianness:
            return None

        hdr = await self.read_block(1, endianness, "yyyuua(yv)", DBusConnection.PythonTypes, 8)
        fields = dict(hdr[5])
        body = await self.read_block(0, endianness, fields.get(DBusMessage.HeaderField.SIGNATURE, ''), DBusConnection.LDMudTypes, 1)

        msg = DBusMessage(hdr[0])
        msg.header = collections.OrderedDict(hdr[5])
        msg.flags = hdr[1]
        msg.serial = hdr[4]
        msg.data = body

        return msg

    @staticmethod
    def skip_signature(signature, idx):
        """
        Skip a single element in the signature and return
        the index of the next element.
        """
        breaks = []
        while True:
            if signature[idx] in "ybnqiuxtdsogv":
                idx += 1
            elif signature[idx] == 'a':
                idx += 1
                if idx >= len(signature):
                    raise ValueError("unexpected end in signature")
                continue
            elif signature[idx] == '(':
                breaks.append(')')
                idx += 1
            elif signature[idx] == '{':
                breaks.append('}')
                idx += 1
            elif breaks and signature[idx] == breaks[-1]:
                breaks.pop()
                idx += 1
            else:
                raise ValueError("unsupported type '%s'" % (signature[idx],))

            if not breaks:
                return idx
            if idx >= len(signature):
                raise ValueError("unexpected end in signature")

    @staticmethod
    def get_signature(value):
        """
        Guess the signature for a given value.
        """
        if isinstance(value, DBusUint32):
            return "u"
        elif isinstance(value, int):
            return "x"
        elif isinstance(value, float):
            return "d"
        elif isinstance(value, DBusObjectPath):
            return 'o'
        elif isinstance(value, DBusSignature):
            return 'g'
        elif isinstance(value, str):
            return "s"
        elif isinstance(value, bytes):
            return "ay"
        elif isinstance(value, (tuple, list, ldmud.Array)):
            return "av"
        elif isinstance(value, (dict, ldmud.Mapping)):
            keysig = set()
            for key in value:
                keysig.add(DBusConnection.get_signature(key))
            if keysig.difference(("x", "d", "o", "g", "s",)):
                raise RuntimeError("Dictionary must only contain basic key types")
            if len(keysig) > 1:
                raise RuntimeError("Dictionary must only contain a single key type")
            if keysig:
                return "a{" + keysig.pop() + "v}"
            return "a{sv}"
        else:
            raise RuntimeError("Can't serialize type: %s" % (value.__class__,))

    async def read_block(self, pos, endiannes, signature, types, finalpadding):
        """
        Read a block of values according to the given signatures.
        """
        async def read(size):
            nonlocal pos
            pos += size
            return await self.reader.readexactly(size)

        async def pad(size):
            nonlocal pos
            await read(size - 1 - (pos - 1) % size)

        async def read_byte(sigidx):
            return sigidx, (await read(1))[0]

        async def read_boolean(sigidx):
            sigidx, val = await read_int32(sigidx)
            return sigidx, val != 0

        def read_packed(fmt, size):
            if endiannes == b'l':
                fmt = "<" + fmt
            else:
                fmt = ">" + fmt

            async def read_fun(sigidx):
                await pad(size)
                return sigidx, struct.unpack(fmt, await read(size))[0]

            return read_fun

        read_int32 = read_packed("i", 4)

        async def read_string(sigidx):
            sigidx, size = await read_int32(sigidx)
            buf = await read(size)
            await read(1)
            return sigidx, buf.decode('UTF-8')

        async def read_object_path(sigidx):
            sigidx, val = await read_string(sigidx)
            return sigidx, DBusObjectPath(val)

        async def read_signature(sigidx):
            sigidx, size = await read_byte(sigidx)
            buf = await read(size)
            await read(1)
            return sigidx, DBusSignature(buf.decode('UTF-8'))

        async def read_array(sigidx):
            _, size = await read_int32(sigidx)

            # Check whether we need better padding
            if sigidx >= len(signature):
                raise ValueError("array without element type in signature")

            if signature[sigidx] in "xtd{":
                await pad(8)

            # Our end position
            finalpos = pos + size

            if signature[sigidx] == '{':
                # Special handling for dictionaries
                result = {}
                while pos < finalpos:
                    await pad(8)

                    nidx, key = await read_value(sigidx+1)
                    nidx, value = await read_value(nidx)
                    if nidx >= len(signature):
                        raise ValueError("unexpected end in signature")
                    if signature[nidx] != '}':
                        raise ValueError("too many elements in dict entry")
                    result[key] = value
                result = types.Dict(result)
            elif signature[sigidx] == 'y':
                # We restore to bytes instead of a list of bytes.
                result = await read(size)
            else:
                result = []
                while pos < finalpos:
                    _, value = await read_value(sigidx)
                    result.append(value)
                result = types.Array(result)

            sigidx = self.skip_signature(signature, sigidx)
            return sigidx, result

        async def read_struct(sigidx):
            await pad(8)
            sigidx, values = await read_values(sigidx)
            if sigidx >= len(signature):
                raise ValueError("unexpected end in signature")
            if signature[sigidx] != ')':
                raise ValueError("too few values for signature")
            return sigidx + 1, types.Struct(values)

        async def read_variant(sigidx):
            nonlocal signature

            _, sig = await read_signature(sigidx)
            oldsig = signature
            signature = sig
            _, val = await read_value(0)
            signature = oldsig

            return sigidx, val

        unmarshaller = {
            'y': read_byte,
            'b': read_boolean,
            'n': read_packed("h", 2),
            'q': read_packed("H", 2),
            'i': read_packed("i", 4),
            'u': read_packed("I", 4),
            'x': read_packed("q", 8),
            't': read_packed("Q", 8),
            'd': read_packed("d", 8),
            's': read_string,
            'o': read_object_path,
            'g': read_signature,
            'a': read_array,
            '(': read_struct,
            'v': read_variant,
        }

        async def read_value(sigidx):
            if sigidx >= len(signature) or signature[sigidx] == ')':
                raise ValueError("unexpected end in signature")

            m = unmarshaller.get(signature[sigidx])
            if m:
                return await m(sigidx + 1)
            else:
                raise ValueError("unsupported type '%s'" % (signature[sigidx],))

        async def read_values(sigidx):
            result = []
            while sigidx < len(signature) and signature[sigidx] not in ")}":
                sigidx, value = await read_value(sigidx)
                result.append(value)
            return sigidx, result

        sigidx, values = await read_values(0)

        await pad(finalpadding)

        return values

    def build_block(self, signature, values):
        """
        Generate a block of values according to the signature.
        """
        buf = bytearray()

        def pad(size):
            nonlocal buf
            buf += bytes(size - 1 - (len(buf) - 1) % size)

        def add_byte(sigidx, value):
            buf.append(value)
            return sigidx

        def add_boolean(sigidx, value):
            add_int32(sigidx, value and 1 or 0)
            return sigidx

        def add_packed(fmt, padding):
            def add_fun(sigidx, value):
                pad(padding)
                buf.extend(struct.pack("<" + fmt, value))
                return sigidx
            return add_fun

        add_int32 = add_packed("i", 4)

        def add_string(sigidx, value):
            b = value.encode('UTF-8')
            add_int32(sigidx, len(b))
            buf.extend(b)
            buf.append(0)
            return sigidx

        def add_object_path(sigidx, value):
            return add_string(sigidx, value)

        def add_signature(sigidx, value):
            b = value.encode('UTF-8')
            buf.append(len(b))
            buf.extend(b)
            buf.append(0)
            return sigidx

        def add_array(sigidx, value):
            pad(4)

            # Remember where to put the final length
            lenpos = len(buf)
            buf.extend(bytes(4))

            # Check whether we need better padding
            if sigidx >= len(signature):
                raise ValueError("array without element type in signature")

            if signature[sigidx] in "xtd{":
                pad(8)

            startpos = len(buf)
            if signature[sigidx] == '{':
                # Special handling for dictionaries
                for key, value in value.items():
                    pad(8)
                    nidx = add_value(sigidx+1, key)
                    nidx = add_value(nidx, value)
                    if nidx >= len(signature):
                        raise ValueError("unexpected end in signature")
                    if signature[nidx] != '}':
                        raise ValueError("too many elements in dict entry")
            else:
                for element in value:
                    add_value(sigidx, element)

            sigidx = self.skip_signature(signature, sigidx)

            buf[lenpos:lenpos+4] = struct.pack("<I", len(buf) - startpos)
            return sigidx

        def add_struct(sigidx, value):
            pad(8)
            sigidx = add_values(sigidx, value)
            if sigidx >= len(signature):
                raise ValueError("unexpected end in signature")
            if signature[sigidx] != ')':
                raise ValueError("too few values for signature")
            return sigidx + 1

        def add_variant(sigidx, value):
            nonlocal signature

            sig = self.get_signature(value)
            add_signature(sigidx, sig)

            oldsig = signature
            signature = sig
            add_value(0, value)
            signature = oldsig

            return sigidx

        marshaller = {
            'y': add_byte,
            'b': add_boolean,
            'n': add_packed("h", 2),
            'q': add_packed("H", 2),
            'i': add_packed("i", 4),
            'u': add_packed("I", 4),
            'x': add_packed("q", 8),
            't': add_packed("Q", 8),
            'd': add_packed("d", 8),
            's': add_string,
            'o': add_object_path,
            'g': add_signature,
            'a': add_array,
            '(': add_struct,
            'v': add_variant,
        }

        def add_value(sigidx, value):
            if sigidx >= len(signature) or signature[sigidx] == ')':
                raise ValueError("too many values for signature")

            m = marshaller.get(signature[sigidx])
            if m:
                return m(sigidx + 1, value)
            else:
                raise ValueError("unsupported type '%s'" % (signature[sigidx],))

        def add_values(sigidx, values):
            for value in values:
                sigidx = add_value(sigidx, value)
            return sigidx

        sigidx = add_values(0, values)
        return buf

    def send_message(self, cb, msg):
        """
        Send the D-Bus message over the connection.
        """
        self.serial += 1
        self.callbacks[self.serial] = cb

        hdr = self.build_block("yyyyuua(yv)", (ord(b'l'), msg.msg_type, msg.flags, 1, 0, self.serial, msg.header.items()))
        hdr += bytes(7 - (len(hdr) - 1) % 8)
        body = self.build_block(msg.header.get(DBusMessage.HeaderField.SIGNATURE, ''), msg.data)
        hdr[4:8] = struct.pack("<I", len(body))
        self.writer.write(hdr)
        self.writer.write(body)

    def active(self):
        """
        Return True if the connection is still open.
        """
        return not self.reader.at_eof()

async def print_error_callback(msg):
    """
    Callback that will print any errors and ignore all other messages.
    """
    if msg.msg_type == DBusMessage.MessageType.ERROR:
        print(msg.header[DBusMessage.HeaderField.ERROR_NAME], *msg.data)

connection = None
async def get_connection():
    """
    Return the current connection, create a new one if necessary.
    """
    global connection
    if connection is not None and connection.active():
        return connection

    conn = DBusConnection(address = dbusconfig.get('bus', 'session'))
    await conn.connect()

    # First message needs to be the Hello call.
    conn.send_message(print_error_callback, DBusMethodCall('org.freedesktop.DBus', '/org/freedesktop/DBus', 'org.freedesktop.DBus', 'Hello', "", []))

    name = dbusconfig.get('name', None)
    if name:
        conn.send_message(print_error_callback, DBusMethodCall('org.freedesktop.DBus', '/org/freedesktop/DBus', 'org.freedesktop.DBus', 'RequestName', "su", [name, 3]))

    for keys in sorted(listeners):
        conn.send_message(print_error_callback, DBusMethodCall('org.freedesktop.DBus', '/org/freedesktop/DBus', 'org.freedesktop.DBus', 'AddMatch', "s", [keys]))

    if not conn.active():
        raise ConnectionResetError("dbus connection closed unexpectedly")
    connection = conn
    return conn

def check_privilege(name, *args):
    """
    Calls master->privilege_violation(). Returns True if it is allowed.
    """
    res = ldmud.get_master().functions.privilege_violation(name, ldmud.efuns.this_object(), *args)
    if res > 0:
        return True
    if res == 0:
        return False
    raise PermissionError("insufficient privileges")

def efun_dbus_call_method(callback: ldmud.Closure, bus: str, path: str, interface: str, method: str, signature: str, *args) -> None:
    """
    SYNOPSIS
            void dbus_call_method(closure callback, string bus, string path, string interface, string method, string signature, mixed args...)

    DESCRIPTION
            Call the method on dbus, specified by the destination connection <bus>,
            object <path> and interface <interface>. The method's dbus signature
            can optionally be given. If it's 0, then it will be determined by the
            arguments.

            After a successful call the callback closure is executed with 0 as
            the first argument and the method's result as the following arguments.

            If there is an error in the call, the callback is called with
            the error type as the first argument and error information as the
            following arguments.

    SEE ALSO
            dbus_register_signal_listener(E), dbus_unregister_signal_listener(E),
            dbus_publish_object(E), dbus_emit_signal(E)
    """
    if not bus:
        raise ValueError("missing bus name")
    if not path:
        raise ValueError("missing path name")
    if not method:
        raise ValueError("missing method name")
    if not signature:
        signature = "".join(DBusConnection.get_signature(value) for value in args)

    msg = DBusMethodCall(bus, path, interface, method, signature, args)

    if check_privilege("dbus_call_method", bus, path, interface):
        asyncio.run(do_efun_dbus_call_method(callback, msg))

async def do_efun_dbus_call_method(callback, msg):
    async def cb(msg):
        if msg.msg_type == DBusMessage.MessageType.METHOD_RETURN:
            callback(0, *msg.data)
        elif msg.msg_type == DBusMessage.MessageType.ERROR:
            callback(msg.header[DBusMessage.HeaderField.ERROR_NAME], *msg.data)

    try:
        conn = await get_connection()
        conn.send_message(cb, msg)
    except Exception as ex:
        import traceback
        traceback.print_exc()
        callback("Exception", str(ex))

def efun_dbus_register_signal_listener(callback: ldmud.Closure, bus: str, path: str, interface: str, signal: str) -> None:
    """
    SYNOPSIS
            void dbus_register_signal_listener(closure callback, string bus, string path, string interface, string signal)

    DESCRIPTION
            The given closure will be called whenever the specified signal is
            received with the signal's values as the arguments.

    SEE ALSO
            dbus_unregister_signal_listener(E), dbus_call_method(E),
            dbus_publish_object(E), dbus_emit_signal(E)
    """
    rule = DBusSignalRule(bus, path, interface, signal)

    if check_privilege("dbus_register_signal_listener", bus, path, interface):
        rule_str = rule.get_str()

        if not rule_str in listeners:
            listeners[rule_str] = (rule, [ callback ])
            asyncio.run(do_efun_dbus_register_signal_listener(rule_str))
        else:
            listeners[rule_str][1].append(callback)

async def do_efun_dbus_register_signal_listener(rulestr):
    conn = await get_connection()
    conn.send_message(print_error_callback, DBusMethodCall('org.freedesktop.DBus', '/org/freedesktop/DBus', 'org.freedesktop.DBus', 'AddMatch', "s", [rulestr]))

def efun_dbus_unregister_signal_listener(callback: ldmud.Closure, bus: str, path: str, interface: str, signal: str) -> None:
    """
    SYNOPSIS
            void dbus_unregister_signal_listener(closure callback, string bus, string path, string interface, string signal)

    DESCRIPTION
            Removes a given signal callback. The arguments must be the same as
            given to the dbus_register_signal_listener efun.

    SEE ALSO
            dbus_register_signal_listener(E), dbus_call_method(E),
            dbus_publish_object(E), dbus_emit_signal(E)
    """
    rule = DBusSignalRule(bus, path, interface, signal)

    if check_privilege("dbus_unregister_signal_listener", bus, path, interface):
        rule_str = rule.get_str()

        if rule_str in listeners and callback in listeners[rule_str][1]:
            listeners[rule_str][1].remove(callback)

def efun_dbus_publish_object(ob: (ldmud.Object, str), path: str, interfaces: (str, ldmud.Array, ldmud.Mapping)) -> None:
    """
    SYNOPSIS
            void dbus_publish_object(object|string ob, string path, string|string*|mapping interfaces)

    DESCRIPTION
            Makes the given object available for calls from dbus. The target object
            can be specified with an object pointer, then it will only be callable
            as long as it exists, or as a object name, then it will be loaded when
            called.

            <path> denotes the dbus path to be used when calling its functions.
            The corresponding interfaces can be either specified as a single string
            (then only one interface), string array or a mapping from interface name
            to function name prefix. The function name prefix will be prepended to
            every method name in a call to find the corresponding lfun.

            If the same path was already published, that old registration will be
            discarded. If <ob> is 0, then no new object will be registered instead.

    NOTES
            This efun won't make the functions available for introspection.
            To offer introspection the object must implement the
            "org.freedesktop.DBus.Introspectable" interace itself.

            The signature of every function result will be determined upon its
            values and cannot be specified explicitely.

    SEE ALSO
            dbus_call_method(E), dbus_emit_signal(E),
            dbus_register_signal_listener(E), dbus_unregister_signal_listener(E),
    """
    if not path:
        raise ValueError("missing path name")
    DBusMessage.check_name(path, "object path", re_path)

    if not interfaces:
        raise ValueError("missing interface name")
    elif isinstance(interfaces, str):
        ints = {interfaces: ""}
    elif isinstance(interfaces, ldmud.Array):
        ints = {}
        for i in interfaces:
            ints[i] = ""
    else:
        ints = dict(interfaces)

    for i in ints:
        if not isinstance(i, str):
            raise ValueError("invalid interface name")
        DBusMessage.check_name(i, "interface name", re_interface)

    if check_privilege("dbus_publish_object", ob, path, interfaces):
        if not ob:
            if path in objects:
                del objects[path]
        else:
            objects[path] = (ob, ints)

    asyncio.run(get_connection())

def efun_dbus_emit_signal(interface: str, name: str, signature: str, *args) -> None:
    """
    SYNOPSIS
            void dbus_emit_signal(string interface, string name, string signature, mixed args...)

    DESCRIPTION
            Emits the given signal.

            Signals can only be emitted by published objects. If the signature
            was not given then it will be determined by the values.

    SEE ALSO
            dbus_publish_object(E), dbus_call_method(E),
            dbus_register_signal_listener(E), dbus_unregister_signal_listener(E),
    """
    if not interface:
        raise ValueError("missing interface name")
    if not name:
        raise ValueError("missing signal name")
    if not signature:
        signature = "".join(DBusConnection.get_signature(value) for value in args)

    ob = ldmud.efuns.this_object()
    obs = (ob, ob.name)
    path = None

    for published_path, (published_ob, published_interfaces) in objects.items():
        if published_ob in obs:
            path = published_path
            break

    if not path:
        raise RuntimeError("signal not from a published object")

    msg = DBusSignal(path, interface, name, signature, args)

    if check_privilege("dbus_emit_signal", 0, path, interface):
        asyncio.run(do_efun_dbus_emit_signal(msg))

async def do_efun_dbus_emit_signal(msg):
    conn = await get_connection()
    conn.send_message(print_error_callback, msg)

async def do_on_reload():
    # Close our connection.
    if connection is not None:
        await connection.close()

    # Wait for the new module to be loaded.
    await asyncio.sleep(0.1)
    newmodule = sys.modules[__name__]
    newlisteners = newmodule.listeners
    newobjects = newmodule.objects

    # Transfer all listeners to the new module.
    if newlisteners is not listeners:
        for key, value in listeners.items():
            if not value[1]:
                pass
            elif key in newlisteners:
                newlisteners[key][1].extend(value[1])
            else:
                newlisteners[key] = value

    # Transfer all published objects to the new module.
    if newobjects is not objects:
        for key, value in objects.items():
            if key not in newobjects:
                newobjects[key] = value

    # Open a connection if needed.
    if (len(newlisteners) or len(newobjects)) and newmodule.connection is None:
        await newmodule.get_connection()

def on_reload():
    """
    Called when the module is replaced by a newer one.
    """
    asyncio.run(do_on_reload())

def register():
    """
    Register all efuns.
    """
    ldmud.register_efun("dbus_call_method", efun_dbus_call_method)
    ldmud.register_efun("dbus_register_signal_listener", efun_dbus_register_signal_listener)
    ldmud.register_efun("dbus_unregister_signal_listener", efun_dbus_unregister_signal_listener)
    ldmud.register_efun("dbus_publish_object", efun_dbus_publish_object)
    ldmud.register_efun("dbus_emit_signal", efun_dbus_emit_signal)
