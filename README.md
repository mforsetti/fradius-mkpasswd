# fradius-mkpasswd

## About
Password hash generator for [FreeRADIUS](https://freeradius.org/)<sup>1</sup> PAP authentication, probably compatible
with OpenLDAP's slapd<sup>2</sup> password.

## Requirement
- Python 2.6+ for module methods.
- Python 2.7+<sup>3</sup> for command line interface.

## Installation and Usage
This script provided as-is, without any package management. You can use it as a command line script, or a module in your
own script.

### Command Line Interface
Running this script without any arguments will cause it to ask you for a password, and create a FreeRADIUS
```Password-With-Header``` control attribute with ```cleartext``` hashing algorithm. Using ```-h``` or ```--help```
argument will display available argument options for the script. This section will describe it with more detail.

```usage: fradius_mkpasswd.py [-h] [-a ALGORITHM] [-b] [-s [SALT]] [-v] [PASSWORD]```

#### Argument switches:
- ```-h```, ```--help```
   
   (_Optional_, _Informational_) Displays help message and exit.
- ```-v```, ```--version```

   (_Optional_, _Informational_) Displays script name and version, and exit.
- ```-a ALGORITHM```, ```--algorithm ALGORITHM```

   (_Optional_, _Functional_) Supplies a hashing algorithm. If none supplied, ```cleartext``` is used. Be warned that
   ```cleartext``` does not hash any supplied password. Use ```--help``` argument to see available (and salt-able)
   algorithms.
   Examples:
   - Hash a password without a salt with ```md5``` algorithm
      ```
      $ python fradius_mkpasswd.py -a md5 hunter2000
      Password-With-Header := {md5}O5bnlzl24vE/X+MgvAecVA==
      ```
   
   - Hash a password with a automatically generated salt with ```sha224``` algorithm
      ```
      $ python fradius_mkpasswd.py -s -a sha224 hunter2000
      Password-With-Header := {ssha224}lJCFsgQRCFZLL6nbJmqSAa/SPLuVKMloMXVHFx8Snv456lEW
      ```
   
- ```-b```, ```--bare```

   (_Optional_, _Functional_) Remove attribute key from generated hash.
   - Without _bare_:
      ```
      $ python fradius_mkpasswd.py hunter2000
      *** W: SaltWarning: `cleartext' algorithm does not support salt string.
      Password-With-Header := {cleartext}hunter2000
      ```
   
   - With _bare_:
      ```
      $ python fradius_mkpasswd.py -b hunter2000
      *** W: SaltWarning: `cleartext' algorithm does not support salt string.
      {cleartext}hunter2000
      ```
   
- ```-s [SALT]```, ```--salt [SALT]```

   (_Optional_, _Functional_) Add salt to hashing algorithm. If no salt string is specified, a random salt string is
   generated. If salt string is specified and goes through salt checks, the salt string is used. Use ```--help``` argument to see available (and salt-able) algorithms.
   
   ```crypt``` algorithm always salted. OpenSSL-dependent algorithm prepends a letter 's' to the header as a sign that
   the hash is salted.
   
   Examples:
   - Without salt
      ```
      $ python fradius_mkpasswd.py -a md5 hunter2000
      Password-With-Header := {md5}O5bnlzl24vE/X+MgvAecVA==
      ```
   - Automatically generated salt
      ```
      $ python fradius_mkpasswd.py -s -a md5 hunter2000
      Password-With-Header := {smd5}m6wIR28elyJBYLRRDZm0M7Wfl9ChMYm1
      ```
   - Manually supplied salt
      ```
      $ python fradius_mkpasswd.py -s thisisthesalt123 -a md5 hunter2000
      Password-With-Header := {smd5}m1Rdb2aYoS72U62OojKDfHRoaXNpc3RoZXNhbHQxMjM=
      ```
- ```[PASSWORD]```

   (_Optional_, _Functional_) Password to generate hash from. If none supplied, this script will ask you for one.
   Examples:
   - Hash a manually provided password with automatically generated salt and with ```md5``` hashing algorithm
      ```
      $ python fradius_mkpasswd.py -s -a md5 hunter2000
      Password-With-Header := {smd5}dXzp17kYJg7QnIqEb4JvbGSaq2Ho/PnU
      ```
   - Hash a requested password with no salt and with ```sha1``` hashing algorithm.
      ```
      $ python fradius_mkpasswd.py -a sha1
      Password [at least 8 characters]: ((type `hunter2000' here))
      Password-With-Header := {sha1}AbRaUK+unRDAO5F/zUq5sIMNR70=
      ```
### Module Interface
If imported as a module, this script exports:
- exception ```fradius_mkpasswd.AlgorithmError```

   A subclass of default ```Exception``` class, raised whenever an unknown or bad hash algorithm is specified.
   ```Exception.message``` attribute can be used to extract exception message.
- warning ```fradius_mkpasswd.SaltWarning```

   This warning is raised whenever a bad salt is supplied for hash. You can filter this warning if required
   ([example](fradius-mkpasswd.py#L268)), but no exception is raised; the script will automatically fix the salt.
- ```fradius_mkpasswd.ATTRIBUTE_KEY```

   Attribute key for generated salt. By default this variable is set as ```Password-With-Header``` for
   FreeRADIUS<sup>4</sup>, but if you want to use this script for OpenLDAP<sup>5</sup>, change it to ```userPassword```
- ```fradius_mkpasswd.ATTRIBUTE_OP```

   Attribute operator for generated salt. By default this variable is set as ```:=```, but if you want to use this
   script for OpenLDAP, change it to ```:```
- ```fradius_mkpasswd.AVAILABLE_ALG```

   List of available hash algorithms in this script, sans unsupported algorithms (e.g. if you're using Win32 platform,
   you won't find unsupported ```crypt```<sup>6</sup> algorithm in this list.)   
- ```fradius_mkpasswd.generate_random(length[, character_set])```

   Generates a random byte string with specified _length_. If a _character_set_ string is supplied, then a random string
   with random characters specified in _character_set_ is generated.
   
   Example: 
   ```python
   import fradius_mkpasswd
   import string
 
   print "Random 8 character alphanumeric string: ",
   print fradius_mkpasswd.generate_random(character_set=string.uppercase + string.lowercase + string.digits)
   print "Random 16 byte string: ",
   print fradius_mkpasswd.generate_random(length=16)
   ``` 
- ```fradius_mkpasswd.check_algorithm(algorithm)```

   Check if supplied _algorithm_ is supported. Returns a tuple of ```(result, message)``` representing a check _result_
   (```True``` on success, ```False``` on failure), and error _message_, if exists.
   
   Note that this method is used in ```fradius_mkpasswd.generate_hash()```, but this method still exposed in case you
   need to check your hashing algorithm beforehand.
- ```fradius_mkpasswd.check_salt(salt, algorithm)```

   Checks given _salt_ for given _algorithm_. If supplied salt is invalid or insufficient, this method will try to fix
   it for you. Returns a tuple of ```(result, message, salt)``` representing a check _result_ (```True``` on success,
   ```False``` on failure), error _message_ if exists, and final _salt_ string to be supplied to hash method.
   
   Note that this method is used in ```fradius_mkpasswd.generate_hash()```, but this method still exposed in case you
   need to check your salt string beforehand.
- ```fradius_mkpasswd.generate_hash(password, salt, algorithm[, bare])```

   Generates a hash of given _password_ string and _salt_ string, with given hashing _algorithm_.
   
   If _salt_ is set to ```True```, a random salt is generated; but if _salt_ is set to ```None```, no salt will applied
   to the password.
   
   If _bare_ is set to ```True```, generated hash is returned without attribute prefix.
   
   Raises ```fradius_mkpasswd.AlgorithmError``` if invalid or unsupported _algorithm_ is supplied; and raises
   ```fradius_mkpasswd.SaltWarning``` if supplied salt is insufficient or invalid.
   
   Example:
   ```python
   from fradius_mkpasswd import generate_hash, check_algorithm, check_salt, AlgorithmError
   import sys
 
   print "MD5 Hash for password {{hunter2000}} with automatically generated salt to be used in FreeRADIUS' `users.conf': ",
   print generate_hash("hunter2000", True, "md5")
   
   print "Reads password and salt from CLI arguments, validate them, and spit the hash."
   password = sys.argv[1]
   salt = sys.argv[2]
   algorithm = sys.argv[3]
   
   print "Validating algorithm..."
   algorithm_result, algorithm_message = check_algorithm(algorithm)
   
   if algorithm_result is False:
       raise AlgorithmError(algorithm_message)
   
   print "Validating salt..."
   salt_result, salt_message, salt = check_salt(salt, algorithm)
   
   if salt_result is False:
       raise AlgorithmError(salt_message)
   elif salt_message is not None:
       print "** Warning: " + salt_message
   else:
       print "Calculating hash..."
   
   print generate_hash(password, salt, algorithm)
   
   ```

## License
This project is licensed under the terms of the MIT license. Full text of the license can be read under
[LICENSE file](LICENSE) in project root directory. 

## Copyrights and Trademarks
All trademarks, copyrights, product names and logos mentioned are property of their respective owners. All rights
reserved. 

## Footnotes
1. [FreeRADIUS GitHub](https://github.com/FreeRADIUS/freeradius-server)
2. [Security documentation for OpenLDAP 2.4](https://www.openldap.org/doc/admin24/security.html)
3. This script requires ```argparse``` to parse CLI arguments, in which only
[supported on Python 2.7+](https://docs.python.org/2.7/library/argparse.html)
4. [FreeRADIUS rlm_pap](https://freeradius.org/radiusd/man/rlm_pap.txt)
5. [Password Storage on OpenLDAP](https://www.openldap.org/doc/admin24/security.html#Password%20Storage)
6. [Python ```crypt``` module](https://docs.python.org/2/library/crypt.html)