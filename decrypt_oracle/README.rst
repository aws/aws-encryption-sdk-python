####################################
aws-encryption-sdk-decryption-oracle
####################################


This project provides a REST API to be used as a decryption oracle to verify
that ciphertext can be successfully decrypted by the AWS Encryption SDK for Python.

The API is deployed on Amazon API Gateway and backed by AWS Lambda.

API v0
======

**Path**

``/v0/decrypt``

**Request**

* **Method**: POST
* **Body**: Raw ciphertext bytes
* **Headers**:

  * **Content-Type**: ``application/octet-stream``
  * **Accept**: ``application/octet-stream``

**Response**

* 200 response code with the raw plaintext bytes as the body
* 400 response code with whatever error code was encountered as the body

Development
===========

Building
********

The Lambda package must be built on an Amazon Linux platform as close as possible to the AWS
Lambda environment.


To build the Lambda package, run: ``tox -e chalice -- package {TARGET DIR}``

Deployment
**********

This API is built using Chalice and can be deployed independently of any other infrastructure.

To build and deploy the API, run: ``tox -e chalice -- deploy``
