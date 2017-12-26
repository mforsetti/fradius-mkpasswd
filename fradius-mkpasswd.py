# vim: fileencoding=utf-8
import sys
import os
import base64
import re
import warnings      # at least Python 2.1
import hashlib       # at least Python 2.5
import string        # str.format() requires at least Python 2.6

try:
    import argparse  # at least Python 2.7
except ImportError:
    argparse = None

try:
    import crypt     # not available in Windows
except ImportError:
    crypt = None

if argparse is not None:
    import getpass   # not available if no argparse.

__version__ = "0.1-devel"

######################################################################################################
#     ____                     ______            _____                        __  _                  #
#    / __ )____ _________     / ____/___  ____  / __(_)___ ___  ___________ _/ /_(_)___  ____  _____ #
#   / __  / __ `/ ___/ _ \   / /   / __ \/ __ \/ /_/ / __ `/ / / / ___/ __ `/ __/ / __ \/ __ \/ ___/ #
#  / /_/ / /_/ (__  )  __/  / /___/ /_/ / / / / __/ / /_/ / /_/ / /  / /_/ / /_/ / /_/ / / / (__  )  #
# /_____/\__,_/____/\___/   \____/\____/_/ /_/_/ /_/\__, /\__,_/_/   \__,_/\__/_/\____/_/ /_/____/   #
#                                                  /____/                                            #
######################################################################################################

ATTRIBUTE_KEY = "Password-With-Header"
MIN_SALT_LENGTH = 8
MIN_PASSWD_LENGTH = 8

########################################################################
#                                                                      #
#   ____________  ______  / /_      _________  ___  _____(_) __(_)____ #
#  / ___/ ___/ / / / __ \/ __/_____/ ___/ __ \/ _ \/ ___/ / /_/ / ___/ #
# / /__/ /  / /_/ / /_/ / /_/_____(__  ) /_/ /  __/ /__/ / __/ / /__   #
# \___/_/   \__, / .___/\__/     /____/ .___/\___/\___/_/_/ /_/\___/   #
#          /____/_/                  /_/                               #
########################################################################

CRYPT_ALG = ["crypt"] if crypt is not None else []
CRYPT_SALT_CHARSET = string.ascii_uppercase + string.ascii_lowercase + string.digits + "./"
CRYPT_SALT_LENGTH = 8
CRYPT_SALT_RE = r"[0-9a-zA-Z\./]+"

#######################################################################################################
#     __  __           __       ______            _____                        __  _                  #
#    / / / /___ ______/ /_     / ____/___  ____  / __(_)___ ___  ___________ _/ /_(_)___  ____  _____ #
#   / /_/ / __ `/ ___/ __ \   / /   / __ \/ __ \/ /_/ / __ `/ / / / ___/ __ `/ __/ / __ \/ __ \/ ___/ #
#  / __  / /_/ (__  ) / / /  / /___/ /_/ / / / / __/ / /_/ / /_/ / /  / /_/ / /_/ / /_/ / / / (__  )  #
# /_/ /_/\__,_/____/_/ /_/   \____/\____/_/ /_/_/ /_/\__, /\__,_/_/   \__,_/\__/_/\____/_/ /_/____/   #
#                                                   /____/                                            #
#######################################################################################################

CLEARTEXT = ["cleartext"]
OPENSSL_ALG = ["md5", "sha1", "sha224", "sha256", "sha384", "sha512"]
AVAILABLE_ALG = CLEARTEXT + CRYPT_ALG + [x for x in OPENSSL_ALG if x in hashlib.algorithms_available]

#############################################################################
#    ______                   ______                 __  _                  #
#   / ____/___  ________     / ____/_  ______  _____/ /_(_)___  ____  _____ #
#  / /   / __ \/ ___/ _ \   / /_  / / / / __ \/ ___/ __/ / __ \/ __ \/ ___/ #
# / /___/ /_/ / /  /  __/  / __/ / /_/ / / / / /__/ /_/ / /_/ / / / (__  )  #
# \____/\____/_/   \___/  /_/    \__,_/_/ /_/\___/\__/_/\____/_/ /_/____/   #
#                                                                           #
#############################################################################


def generate_hash(password, salt, algorithm, bare=False):
    """
    Cleans up and generate hash from given password, salt, and algorithm.
    :param str password: Password string to generate hash from.
    :param str | bool | None salt: Salt string to use when generate hash. If True, generate a hash automatically, if
                                   None, do not use salt string.
    :param str algorithm: Algorithm to use when generating hash.
    :param bool bare: Include FreeRADIUS' control attribute string if False.
    :return str: Hashed password, and control attribute string if `bare' is False
    :raise AlgorithmError:
    :raise SaltWarning:
    """
    alg_ret, alg_msg = check_algorithm(algorithm)
    if not alg_ret:
        raise AlgorithmError(alg_msg)

    salt_ret, salt_msg, salt = check_salt(salt, algorithm)
    if not salt_ret:
        raise AlgorithmError(salt_msg)
    if salt_msg is not None:
        warnings.warn(salt_msg, SaltWarning)

    if algorithm in CLEARTEXT:
        ret = "{{cleartext}}{0}".format(password)
    elif algorithm in CRYPT_ALG:
        ret = "{{crypt}}{0}".format(crypt.crypt(password, salt))
    elif algorithm in OPENSSL_ALG:
        h = getattr(hashlib, algorithm)(password)
        ret = "{"
        if salt is not None:
            h.update(salt)
            ret += "s"
        ret += "{0}}}".format(algorithm)
        ret += base64.b64encode("{0}{1}".format(h.digest(), "" if salt is None else salt))
    else:
        raise AlgorithmError("No algorithm specified or algorithm is not supported.")
    if not bare:
        ret = "{0} := {1}".format(ATTRIBUTE_KEY, ret)

    return ret


def check_algorithm(algo_str):
    """
    Check given hashing algorithm.
    :param str algo_str: Hashing algorithm name.
    :return tuple(bool, None|str): A tuple of check result (True if OK, False if invalid) and error message if check
                                   failed or None if check success.
    """
    return (True, None) if algo_str in AVAILABLE_ALG \
        else (False, "Invalid or unsupported algorithm.")


def check_salt(salt_str, algo_str):
    """
    Check and fix salt depending of the hashing algorithm and salt string given.
    :param str | bool salt_str: Salt string to check and fix.
    :param str algo_str: Hash algorithm to check the salt against.
    :return tuple(bool, str | None, str | None): A tuple of salt status.
                                                 First element is True if salt string is okay and False if salt string
                                                     has problems.
                                                 Second element is error message if first element is False, warning
                                                     message if first element is True, or None if there is nothing to
                                                     say.
                                                 Third element is fixed salt string.
    """
    if algo_str in CLEARTEXT:
        return True, None if algo_str is None else "`cleartext' algorithm does not support salt string.", None
    elif algo_str in CRYPT_ALG:
        if salt_str is True or salt_str is None:
            return True, None, generate_random(CRYPT_SALT_LENGTH, CRYPT_SALT_CHARSET)
        else:
            temp = re.match(CRYPT_SALT_RE, salt_str)
            if temp is None or not temp.group(0) == salt_str:
                return True, "Invalid salt character found. Generated new salt string.",\
                       generate_random(CRYPT_SALT_LENGTH, CRYPT_SALT_CHARSET)
            else:
                msg = None
                if len(salt_str) < CRYPT_SALT_LENGTH:
                    salt_str += generate_random(CRYPT_SALT_LENGTH, CRYPT_SALT_CHARSET)
                    msg = "Salt too short. Appended random salt string."
                return True, msg, salt_str[:8]
    elif algo_str in OPENSSL_ALG:
        if salt_str is None or salt_str is True:
            return True, None, None if salt_str is None else generate_random(MIN_SALT_LENGTH, None)
        else:
            msg = None
            if len(salt_str) < MIN_SALT_LENGTH:
                salt_str += generate_random(MIN_SALT_LENGTH - len(salt_str))
                msg = "Salt too short. Appended random salt string."
            return True, msg, salt_str
    else:
        return False, "Invalid or unsupported algorithm.", None


class AlgorithmError(Exception):
    """
    Exception class for hashing algorithm errors.
    """
    pass


class SaltWarning(Warning):
    """
    Warning class for salt checking or generation errors.
    """
    pass

######################################
#    __  ____  _ ___ __  _           #
#   / / / / /_(_) (_) /_(_)__  _____ #
#  / / / / __/ / / / __/ / _ \/ ___/ #
# / /_/ / /_/ / / / /_/ /  __(__  )  #
# \____/\__/_/_/_/\__/_/\___/____/   #
######################################


def generate_random(length=MIN_SALT_LENGTH, character_set=None):
    """
    Generate a random string from specified character set, with specified length. If no character set is given, a plain
    random byte string will be returned.
    :param int length: Length of random string to generate. Default is MIN_SALT_LENGTH (= 8)
    :param str | None character_set: String of characters to be used as character sets in the generated random string.
                                     If this parameter set to None, a random byte string with specified length is
                                     generated.
    :return:
    """
    return os.urandom(length) if character_set is None \
        else "".join([character_set[ord(z) % len(character_set)] for z in os.urandom(length)])

#######################################################################
#    ________    ____   ______                 __  _                  #
#   / ____/ /   /  _/  / ____/_  ______  _____/ /_(_)___  ____  _____ #
#  / /   / /    / /   / /_  / / / / __ \/ ___/ __/ / __ \/ __ \/ ___/ #
# / /___/ /____/ /   / __/ / /_/ / / / / /__/ /_/ / /_/ / / / (__  )  #
# \____/_____/___/  /_/    \__,_/_/ /_/\___/\__/_/\____/_/ /_/____/   #
#######################################################################


def console_version(prog):
    """
    Console-only: Show current library name and version.
    :param str prog: Application name.
    :return str: Application name and version.
    """
    return "{0} v{1}".format(prog, __version__)


def console_get_arguments():
    """
    Console-only: Fetch and return CLI arguments.
    :return Namespace: CLI arguments.
    """
    argument_parser = argparse.ArgumentParser(description="FreeRADIUS PAP authentication password generator.",
                                              epilog="PS: Probably compatible with OpenLDAP.")
    argument_parser.add_argument("password", metavar="PASSWORD", nargs="?", help="Password to generate hash from.")
    argument_parser.add_argument("-a", "--algorithm", default="cleartext",
                                 help="Hashing algorithm to use. Available hashing algorithms on this system are: "
                                      "[{0}]".format(", ".join([y for y in AVAILABLE_ALG])))
    argument_parser.add_argument("-b", "--bare", action="store_true",
                                 help="Provide hash without `{0}' control attribute string.".format(ATTRIBUTE_KEY))
    argument_parser.add_argument("-s", "--salt", nargs="?", const=True,
                                 help="Add salt to password string. If no salt string is given, it will automatically "
                                      "generated {0}-byte salt. Supported on these algorithms: "
                                      "[{1}]".format(MIN_SALT_LENGTH, ", ".join([y for y in CRYPT_ALG + OPENSSL_ALG])))
    argument_parser.add_argument("-v", "--version", action="version", version=console_version(argument_parser.prog))

    return argument_parser.parse_args()


def console_main():
    """
    Console-only: Main functions, called from CLI entry point.
    :return int: 0 on success, 1 on failure.
    """
    if argparse is None:
        print >> sys.stderr, "`argparse' module is not available. CLI functions are disabled."

    arguments = console_get_arguments()
    password = arguments.password

    alg_ret, alg_msg = check_algorithm(arguments.algorithm)
    if not alg_ret:
        print >> sys.stderr, "*** E: {0}".format(alg_msg)
        return 1

    if password is not None and len(password) < MIN_PASSWD_LENGTH:
        print >> sys.stderr, "*** E: Password too short. Please specify longer password (at least {0} " \
                             "characters).".format(MIN_PASSWD_LENGTH)
    while password is None or len(password) < MIN_PASSWD_LENGTH:
        password = getpass.getpass("Password [at least {0} characters]: ".format(MIN_PASSWD_LENGTH))

    try:
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            h = generate_hash(password, arguments.salt, arguments.algorithm, arguments.bare)
            if len(w) > 0:
                print >> sys.stdout, "*** W: {0}: {1}".format(w[-1].category.__name__, w[-1].message)
    except (AlgorithmError,) as e:
        print >> sys.stderr, "*** E: {0}: {1}".format(e.__class__.__name__, e.message)
        return 1

    print >> sys.stdout, h
    return 0


if __name__ == "__main__":
    sys.exit(console_main())
