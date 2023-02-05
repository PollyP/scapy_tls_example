# scapy_tls_example

This example script connects to a HTTPS server while generating a NSS keys file, and sniffs the
resulting traffic using Scapy. Then the sniffed traffic is turned into Scapy TLS layers while
applying the NSS keys to decrypt the traffic. This example code works with TLS 1.2 only.

# requirements

This code requires a recent version of Python3 and Scapy 2.5 or greater. You can get Scapy
at https://scapy.net/. Documentation for Scapy is here: https://scapy.readthedocs.io/en/latest.

# useful references

Much of the example code comes from the "Decrypt Manually" section of https://github.com/secdev/scapy/blob/master/doc/notebooks/tls/notebook3_tls_compromised.ipynb.

# setting up the HTTPS server

I tested against a local HTTPS server; details (and thanks) to this gist: https://gist.github.com/dergachev/7028596.

# license

This example code is released under the terms of the MIT license. Copyright 2023 P.S. Powledge
