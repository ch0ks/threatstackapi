================================
Threat Stack Command Line Tool
================================

The purpose of this script is to connect to the Threat Stack infrastructure and be able to manipulate the information contained.

Usage
-----

.. code-block:: sh

    usage: tscli.py [-h]

    Threat Stack Command Line Tool.

    optional arguments:
      -h, --help            show this help message and exit



Quick Start
-----------
First, install the library and set a default region:

.. code-block:: sh

    $ pip install configparser unirest

Set up the profiles and default regions (in e.g. ``~/.threatstack/config``):

.. code-block:: ini

    [default]
    key = 9b243b293c3ae9d2f9302b7bb4563e0feaf33e70

Then, from a command prompt:

.. code-block:: sh

    $ ./tscli.py


