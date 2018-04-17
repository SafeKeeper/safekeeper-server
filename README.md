SafeKeeper - Protecting Web passwords using Trusted Execution Environments
==========================================================================

Introduction
------------

SafeKeeper is a server-side technology for protecting password databases. SafeKeeper's server-side password protection service is a drop-in replacement for standard password hashing functions. It computes a cipher-based message authentication code (CMAC) on passwords before they are stored in the
database. An adversary must obtain the CMAC key in order to perform offline guessing attacks against a stolen password database. SafeKeeper generates and protects this key within a Trusted Execution Environment, realized using Intel's Software Guard Extensions (SGX) technology.


Building instructions
---------------------

### Prerequisites

- Install SGX SDK:
  * Download and install [Intel SGX SDK for Linux](https://github.com/01org/linux-sgx)
  * Set the SGX-SDK variable in the Makefile to the location of your SGX SDK
  * Set the SIGNING-KEY variable in the Makefile to point to an enclave signing key. If needed, generate a signing key following Intel's [OpenSSL Examples](https://software.intel.com/en-us/node/708948)

- Build the 3rd party and SafeKeeper libraries
  * Clone [safekeeper-libs](https://github.com/SafeKeeper/safekeeper-libs)
  * Set the TOP-DIR variable in the `safekeeper-libs/Makefile` to the location of your SGX SDK *cloned repository*. Note that it is referenced from Makefiles in `lib_tke` and `lib_uke`, so if using relative paths, add one level of `../`.
  * Build libraries by running `make`.

### Building SafeKeeper service

  * Make sure that the Makefile libdir variable points to the right directory (`safekeeper-libs`), and the paths to the 3rd party libraries are correct.
  * Run `make`. This will generate objects under ``build`` directory and safekeeper executable. The enclave will be put under ``build/enclave``.
  * To test the build run `./testing_app`. There is no need to build the PHP extension for that.

Installation
------------

Run `./safekeeper`. Note that the in order to deploy SafeKeeper in production,
the safekeeper server should be running as a service. Details on how to do it
depend on the particular Linux distribution.
By default, the server listens on port 7000 at localhost.
It is possible to pass the port to the server at command line.

In order for the Remote Attestation to work, fill in the SPID obtained from Intel in
safekeeper.cpp

PHP Extension
-------------

- To build the PHP extension:
  * Install `php-dev` package of your Linux distribution. It is necessary to build PHP-CPP library. Refer to its README file for more details.
  * From the safekeeper-libs repo, run `git submodule init` and `git submodule update` that will fetch PHP-CPP library from its GitHub repository at [PHP-CPP](https://github.com/CopernicaMarketingSoftware/PHP-CPP)
  * In the php_cpp directory, build the PHP-CPP library and install it.
  * In the safekeeper-server repo, run `make php`. The PHP extension will be at ``build/php/safekeeper.so``.

- To install the PHP extension

  * Run
```
    $ sudo make install
```

It will copy the extension and the enclave library to the PHP
extensions directory (on Ubuntu 16.04 with PHP version 7.0 it is
`/usr/lib/php/20151012/`, the following instructions assume the same OS and PHP version).

  * To enable the extension, copy ``src/php/safekeeper.ini`` to
`/etc/php/7.0/mods-available`. Depending on the way PHP is run, enable the
extension by creating a corresponding symlink under
`/etc/php/7.0/(cgi)/conf.d`. For example, to have the extension available on
the command-line PHP server:

```
  $ sudo ln -s /etc/php/7.0/mods-available/safekeeper.ini /etc/php/7.0/cli/conf.d/30-safekeeper.ini 
```

  * Install WordPress for PHP (e.g. on Ubuntu run `sudo apt-get install wordpress`) and locate the wordpress root directory (e.g. /usr/share/wordpress on Ubuntu). This contains your wp-includes directory.

  * Ensure your PHP include path includes the wordpress root directory e.g. by editing the include_path variable in /etc/php/7.0/cli/php.ini.

  * In the wp-includes directory, rename class-phpass.php to class-phpass-original.php.

  * Copy class-phpass.php from safekeeper-server/src/php into the wp-includes directory.

  * The PHP extension connects to default port 7000 of SafeKeeper service.
If the port is to be changed, edit ``src/php/php_module.cpp``.
Specifying the port in the PHP extension configuration file is a desirable feature.

  * Test the setup:

```
  $ php -f tests/perf.php
```

If the setup was successful, it will output how long it took to CMAC 1,000
passwords with SGX and without SGX.

