================================
Threat Stack Command Line Tool
================================

This command line tool allows the user to connect to a Threat Stack account and retrieve the information contained
within an account. It is important to note that this script was not created  or is supported by Threat Stack.
Use under your own risk.

Usage
-----

.. code-block:: sh

    usage: tscli.py [-h] [-g] [-i] [-p] [-o] [-l] [-d]
    
    Threat Stack Command Line Tool.
    
    optional arguments:
      -h, --help            show this help message and exit
      -g, --list-agents     lists all the agents in the organization
      -i, --list-alerts     lists all the agents in the organization
      -p, --list-policies   lists all the agents in the organization
      -o, --list-organizations
                            lists all the agents in the organization
      -l, --list-logs       lists all the agents in the organization
      -d, --dump-policies   dumps all the policies in the organization into
                            individual md files

Quick Start
-----------
First, install the libraries and set a default account:

.. code-block:: sh

    $ pip install configparser unirest urlib

Set up the config file with the authentication token in ``~/.threatstack/config``:

.. code-block:: ini

    [default]
    key = 9b243b293c3ae9d2f9302b7bb4563e0feaf33e70

Then, from a command prompt:

.. code-block:: sh

    $ ./tscli.py -h

