import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="ldmud-dbus",
    version="0.0.1",
    author="LDMud Team",
    author_email="ldmud-dev@UNItopia.DE",
    description="Python dbus package for LDMud",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ldmud/python-dbus",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.5',
    install_requires=[
        'ldmud-asyncio',
    ],
    entry_points={
        'ldmud_efun': [
            'dbus_call_method                = ldmud_dbus:efun_dbus_call_method',
            'dbus_register_signal_listener   = ldmud_dbus:efun_dbus_register_signal_listener',
            'dbus_unregister_signal_listener = ldmud_dbus:efun_dbus_unregister_signal_listener',
            'dbus_publish_object             = ldmud_dbus:efun_dbus_publish_object',
            'dbus_emit_signal                = ldmud_dbus:efun_dbus_emit_signal',
        ]
    },
    zip_safe=False,
)
