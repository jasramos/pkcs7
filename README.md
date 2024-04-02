This project provides an implementation for parsing PKCS#7 signed and enveloped messages. It is a fork of the [fullsailor/pkcs7](https://github.com/fullsailor/pkcs7) project, designed to improve parsing capabilities.

## Features
In this fork, we focus on the implementation of two specific functions:

- Parse(): For parsing PKCS#7 messages.
- DegenerateCertificate(): For creating a signed data structure containing only the provided certificate or certificate chain.

## Motivation
The primary goal of creating this fork was to address a limitation in the original fullsailor/pkcs7 package, specifically its inability to handle empty objects of indefinite length. This enhancement aims to provide a more robust solution for applications requiring the parsing of PKCS#7 messages, including those with such objects.