# logactiond
> Trigger actions based on logfile contents

Logactiond started as a clone of fail2ban. What I observed was that under
heavey load of brute force or DOS attacks, fail2ban seemed to be unable to
immediately block incoming attacks. Instead, 1000s of logfile entries
accumulated before fail2ban started detecting them. Which it then tried to
work of one by one every second it woke up.

In addition my feeling was that fail2ban generally consumes more resources
then I would like to spend on the task of getting rid of brute force attacks.

Logactiond tries to be a lightweight daemon. At the moment in only supports
observing logfiles via inotify only so is limited to Linux. Goal is to support
additional backends (e.g. systemd, simple polling for all other cases).

Right now, this should be considered alpha quality code and I don't suggest
that you use it on production system. logactiond itself can't do too much harm
but as it very likely will run iptables and the like, there's definitely
potential for stuff to go wrong.

## Installing / Getting started

A simple ./configure; make; make install should do. For more elaborate
instructions, see the standard GNU INSTALL file.

As mentioned, the code in its current form depends on inotify, thus will only
compile on Linux.

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
* any kind of tests

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
