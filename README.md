# logactiond
>Logactiond can trigger actions based on logfile contents. It's basically a
very lightweight alternative to fail2ban (written in C instead of Python) which
can handle heavy load without using significant resources itself.

At the moment in only supports observing logfiles via inotify and a polling
backend. Goal is to support additional methods (systemd etc.) and platofrms
(kqueue) as well. Right now, the code  should be considered alpha quality code
and I don't suggest that you use it on production system. logactiond itself
can't do too much harm but as it very likely will run iptables and the like,
there's definitely potential for stuff to go wrong.

## Installing / Getting started

A simple ./configure; make; make install should do. For more elaborate
instructions, see the standard GNU INSTALL file.

logactiond will require libsystemd to make use of systemd, libsodium
(https://doc.libsodium.org) to encrypt its communication. Optionally the tests
will require the check package (https://libcheck.github.io/check/)

### Initial Configuration

logactiond is looking for it's configuration by default in
"$(syconfdir)/logationd/logactiond.cfg". The default installation will create
an example config file plus additional files subdirectories "actions.d",
"rules.d" and "sources.d" which will be included by the main configuration
file. But ultimately the configuration file setup will be up to you.

As of now, there's no extended documentation of the configuration file syntax.
but the provided default configuration file should give a good indication of
all available options.

## Developing

To get get started, do the usual:

```shell
git clone https://github.com/claude42/logactiond
cd logationd
./bootstrap
```
You'll need the standard GNU build system. If you plan to rebuild libconfig's
.l or .y files, you'll need flex and bison as well.

logactiond uses libconfig (https://hyperrealm.com/libconfig/libconfig.html)
to parse the config file. It's included in the libconfig sub directory and
will be linked statically in case you system doesn't have libconfig installed.

## Contributing

If you'd like to contribute, please fork the repository and use a feature
branch. Pull requests are warmly welcome.

There's quite a bit that's still missing. Among others and in no particular
order:
* man pages or other form of documentation
* rules and actions - currently there's only a minimal example set

## Features

TODO



## Links

- Github repository: https://github.com/claude42/logactiond
- Issue tracker: https://github.com/claude42/logactiond/issues
- Project homepage: https://logactiond.org/
- For anything else, you can reach me at kw@aw.net
- logactiond uses libconfig for parsing its config file. More information on
  libconfig can be found at https://hyperrealm.com/libconfig/libconfig.html


## Licensing

The code in this project is licensed under the GNU GENERAL PUBLIC LICENSE
Version 3. 

logactiond uses code taken from libconfig which is has been originally
licensed under the GNU Lesser General Public License Version 2.1.
