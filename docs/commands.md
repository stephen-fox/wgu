# Commands

wgu supports several commands which are documented below.

## `help`

In addition to the `-h` argument, `help` provides configuration syntax
descriptions and examples via standard output. It is recommended to
pipe it to a program like `less` to make it searchable:

```console
$ wgu help
$ wgu help | less
```

## `version`

Writes the version number to standard output and exits.

Example:

```console
$ wgu version
v0.0.8
```

## `genconf`

Generates an example configuration file and a private key file in the
user's home directory under `.wgu/` followed by writing the public key
to standard output.

Example:

```console
$ wgu genconf
z9yJgu9cvwbygPzuUtzcmkuB2K2nxA6viKj1kUDj4Ug=
```

If a different directory is desired, simply specify it as an argument.
If the directory does not already exist, wgu will create it for you:

```console
$ wgu genconf /usr/local/etc/wgu
z9yJgu9cvwbygPzuUtzcmkuB2K2nxA6viKj1kUDj4Ug=
```

## `genkey`

Generates a new WireGuard private key and writes it to standard output.

Example:

```console
$ wgu genkey
<private-key-plaintext>
```

## `pubkey`

Reads a private key from standard input and writes the corresponding
public key to standard output.

Example:

```console
$ wgu pubkey < example-private-key-file
z9yJgu9cvwbygPzuUtzcmkuB2K2nxA6viKj1kUDj4Ug=
```

## `pubkeyconf`

Reads a configuration file from a path or standard input, parses the
private key from the file, and writes the corresponding public key to
standard output.

Example:

```console
$ wgu pubkeyconf < example-config-file
z9yJgu9cvwbygPzuUtzcmkuB2K2nxA6viKj1kUDj4Ug=
$ # Or read from the default config file path:
$ wgu pubkeyconf
M2njNIDzUKZHa8z55V0u4pb5BJSikUZcmBQkRH06Zg8=
```

## `pubkeyaddr`

Note: This is for use with the `automatic address planning mode` feature.

Generates an IPv6 address for the given WireGuard public key.

Example:

```console
$ wgu pubkeyaddr < another-peers-public-key
483b:9c67:9217:d415:774d:480:f642:1e5c
```

## `up`

Creates the WireGuard tunnel(s) using the specified configuration.
Defaults to using the configuration file at `~/.wgu/wgu.conf` if
no configuration file is specified.

Example:

```console
$ # The following line uses the configuration file at ~/.wgu/wgu.conf:
$ wgu up
$ # The following line uses a configuration file named "wgu.conf"
$ # in the current working directory:
$ wgu up wgu.conf
```
