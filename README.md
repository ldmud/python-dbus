# Python D-Bus package for LDMud

These are python efuns for LDMud 3.6.2 and later for communicating over D-Bus.
It offers a very simple interface to do and receive method calls and signals.
This module doesn't offer any support for introspection. Support for
introspection can be implemented on the LPC side by providing the
`org.freedesktop.DBus.Introspectable` interface.

This package contains the following efuns:
 * `void dbus_call_method(closure callback, string bus, string path, string interface, string method, string signature, mixed args...)`
 * `void dbus_register_signal_listener(closure callback, string bus, string path, string interface, string signal)`
 * `void dbus_unregister_signal_listener(closure callback, string bus, string path, string interface, string signal)`
 * `void dbus_publish_object(object|string ob, string path, string|string*|mapping interfaces)`
 * `void dbus_emit_signal(string interface, string name, string signature, mixed args...)`

All efuns are privileged, each call is checked with `master->privilege_violation()`.

This package supports the following LDMud types and their D-Bus counterparts.
The first entry in the D-Bus column is the type chosen when no signature is specified.

LDMud     | D-Bus                                                                                                      | Notes
--------- | ---------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------
`int`     | `x` (INT64), `t` (UINT64), `i` (INT32), `u` (UINT32), `n` (INT16), `q` (UINT16), `y` (BYTE), `b` (BOOLEAN) |
`float`   | `d` (DOUBLE)                                                                                               |
`string`  | `s` (STRING), `o` (OBJECT_PATH), `g` (SIGNATURE)                                                           |
`bytes`   | `ay` (ARRAY of BYTES)                                                                                      |
`mixed*`  | `av` (ARRAY of VARIANT), `r` (STRUCT)                                                                      |
`mapping` | `a{?v}` (ARRAY of DICT_ENTRY)                                                                              | The key type is determined by looking at the mapping and must be int, float or string.

## Usage

### Prerequisites

This package also needs the [ldmud-asyncio](https://github.com/ldmud/python-asyncio) package.

### Install from the python package index

The efun package can be downloaded from the python package index:

```
pip3 install --user ldmud-dbus
```

### Build & install the package yourself

You can build the package yourself.

First clone the repository
```
git clone https://github.com/ldmud/python-dbus.git
```

Install the package
```
cd python-dbus
python3 setup.py install --user
```

### Automatically load the modules at startup

Use [startup.py](https://github.com/ldmud/python-efuns/blob/master/startup.py) as the Python startup script for LDMud.
It will automatically detect the installed python efuns and load them.

You can deactivate single efuns with a configfile `.ldmud-efuns`
in your home directory, with the following contents
```
[efuns]
name_of_the_efun = off
```

### Manually load the modules at startup

Add the following lines to your startup script:
```
import ldmud_dbus

ldmud_dbus.register()
```

## Configuration
The configuration file `.ldmud-efuns` in your home directrory might specify the bus and connection name to use.

```
[dbus]
# The bus might be 'session', 'system' or an address like 'unix:path=/var/run/dbus/system_bus_socket'.
# Default is 'session'.
bus = session
# The connection name must be composed of at least two elements consisting of alphanumeric characters
# and separated by a period character. Default is none.
name = net.ldmud.mud
```

## Examples

### Notification

This package is intended to be used with a separate D-Bus daemon used for communicating with MUD specific tools.
But if you'll connect to your session daemon, then you could show some notifications:

```
dbus_call_method(
    function void(string error, varargs mixed* result)
    {
        // This is called with the result (notification id).
    },
    "org.freedesktop.Notifications", "/org/freedesktop/Notifications", "org.freedesktop.Notifications", "Notify", "sisssasa{sv}i",
    "LDMud", 0, "dialog-information", "Greetings!", "This is a message from your running LDMud.", ({}), ([]), 5000);
```

### Outside call

Create an object to be called from the outside:

```
void create()
{
    // This call can also by made by another object, for example at MUD startup.
    // It routes external calls for "/my/object" to this object.
    // The "my.mud.interface" interface will be implemented by the dbus_* functions.
    dbus_publish_object(object_name(), "/my/object", ([ "my.mud.interface": "dbus_"]));
}

void dbus_message(string str)
{
    shout(str);
}

string dbus_get_version()
{
    return __VERSION__;
}
```

You can test that with the `dbus-send` utility:
```
dbus-send --session --type=method_call --print-reply --dest=net.ldmud.mud "/my/object" my.mud.interface.message string:'Hello, World!'
dbus-send --session --type=method_call --print-reply --dest=net.ldmud.mud "/my/object" my.mud.interface.get_version
```

Have fun!
