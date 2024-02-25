# SiteScan
A Python script for Linux-based preliminary web application penetration testing scanning. **(19 May 2023)**

3rd year university project (CMP320) for a security-related script. Outputs results as a .txt file basic-formatted report/digest.

Functions as a small suite of data-gathering and security schema analysis tools, in fulfilment of some steps of the OWASP Web Security Testing Guide.
Performs collection, identification, and basic investigation/analysis of the following:

- Code comments
- Cookie usage
- Data entry points
- Default files
- Encryption usage
- HTTP Header information
- Information leakage
- Server technologies
- Storage directory information
- Website structure

Testing in Kali Linux with Python 3.10, combining tools: cURL, Dirb, Nikto, SSLScan, wget, and WhatWeb. See PDF for more (and detailed) information.

...

This is a long script in desperate need of a change from a procedural to an object-oriented coding paradigm. Many things could be improved, added, tidied up, etc. etc. The "documentation" is just the report I had to submit for this module, but it contains pretty much all the useful information.
