import ipaddress
from typing import ByteString, Iterable, SupportsIndex
import urllib.parse as parse
import string
import warnings

__all__ = ['URL', 'URLPath', 'URLQuery']

_GEN_DELIMS = ":/?#[]@"
_SUB_DELIMS = "!$&'()*+,;="
_RESERVED = _GEN_DELIMS + _SUB_DELIMS
_UNRESERVED = string.ascii_letters + string.digits + '-_.~'
_PCT = '%'


class URLPath(list[str]):
    def __init__(self, path: Iterable | str | None = None):
        if isinstance(path, str):
            super().__init__(str(element) for element in path.split('/'))
        elif isinstance(path, Iterable):
            super().__init__(str(element) for element in path)
        elif not path:
            super().__init__()
        else:
            raise ValueError(f"Path of type {type(path).__name__} is "
                             "not allowed. Path initializer only "
                             "accepts Iterable and str.")

    def __str__(self) -> str:
        return '/'.join([parse.quote(element) for element in self])

    def __repr__(self) -> str:
        return str(self)

    def __getitem__(self, _key: SupportsIndex | slice):
        if isinstance(_key, slice):
            return URLPath(super(URLPath, self).__getitem__(_key))
        elif isinstance(_key, SupportsIndex):
            return super(URLPath, self).__getitem__(_key)
        else:
            raise TypeError("Indices must be integers or slices, not",
                            type(_key).__name__)

    def __setitem__(self, _key: SupportsIndex, _value: Iterable):
        def _normalize_index(index: SupportsIndex, length: int) -> int:
            if index.__index__() < 0:
                return length + index.__index__()
            else:
                return index.__index__()

        if isinstance(_value, str):
            values = _value.split('/')
        elif isinstance(_value, ByteString):
            values = _value.decode().split('/')
        else:
            values = list(_value)
        copy = self.copy()
        self.clear()
        self.extend(copy[:_normalize_index(_key, len(copy))] + list(values) /
                    + copy[_normalize_index(_key, len(copy)) + 1:])

    def copy(self) -> "URLPath":
        """Return a shallow copy of the path"""
        return URLPath(self)


class URLQuery(dict):
    def __init__(self, query: dict | str):
        if isinstance(query, dict):
            super().__init__(query)
        elif isinstance(query, str):
            super().__init__(parse.parse_qsl(qs=query))

    def __str__(self) -> str:
        return parse.urlencode(self)

    def __repr__(self) -> str:
        return str(self)

    def dict(self) -> dict:
        return dict(self)


class URL:
    _scheme: str
    _userinfo: str
    _host: str
    _port: int
    _segment: str
    query: URLQuery
    path: URLPath

    def __init__(self,
                 scheme: str,
                 authority: str | None = None,
                 userinfo: str | None = None,
                 host: str | ipaddress._BaseAddress = None,
                 port: str | int | None = None,
                 path: str | list | None = None,
                 query: str | dict | None = None,
                 segment: str | None = None,
                 ):
        self.scheme = scheme

        if authority and (host or port or userinfo):
            raise ValueError("Cannot define authority together with one "
                             "or more of its component parts.")
        if not authority and not host:
            raise ValueError("Cannot leave the host field empty.")

        if authority:
            self.authority = authority
        else:
            self.userinfo = userinfo
            self.host = host
            self.port = port

        if isinstance(path, list):
            path = [parse.quote(str(path_element), safe='')
                    for path_element
                    in path]

            path = '/'.join(path)
        elif path:
            path = parse.quote(path)

        if isinstance(query, dict):
            query = {parse.quote(key):
                     parse.quote(query[key])
                     for key in query}

            query = parse.urlencode(query)
        elif query:
            query = parse.quote(query, '?&=')

    @property
    def scheme(self) -> str:
        return self._scheme

    @scheme.setter
    def scheme(self, _scheme: str):
        if not _scheme:
            raise ValueError("Scheme cannot be empty.")
        if not all(character in set(parse.scheme_chars)
                   for character in _scheme):
            raise ValueError("Scheme contains illegal characters.")
        if _scheme[0] not in string.ascii_letters:
            raise ValueError("Scheme is of illegal format")
        self._scheme = _scheme.lower()

    @property
    def userinfo(self):
        return self._userinfo

    @userinfo.setter
    def userinfo(self, _userinfo: str | None):
        if not _userinfo:
            self._userinfo = None
            return
        _userinfo = parse.quote(_userinfo, ':' + _SUB_DELIMS + _PCT)
        if not all(character in set(_SUB_DELIMS + ':' + _UNRESERVED + _PCT)
                   for character in _userinfo):
            raise ValueError("User info contains illegal characters.")
        self._userinfo = _userinfo

    @property
    def username(self) -> str:
        warnings.warn("Use of the 'user:password' format in userinfo is "
                      "deprecated according to RFC 3986",
                      DeprecationWarning, 2)

        return self._userinfo.split(':')[0]

    @username.setter
    def username(self, _username: str):
        warnings.warn("Use of the 'user:password' format in userinfo is "
                      "deprecated according to RFC 3986",
                      DeprecationWarning, 2)

        _username = parse.quote(_username, _SUB_DELIMS + _PCT)
        userinfo = self._userinfo.split(':')
        userinfo[0] = _username
        self._userinfo = ':'.join(userinfo)

    @property
    def password(self) -> str:
        warnings.warn("Use of the 'user:password' format in userinfo is "
                      "deprecated according to RFC 3986",
                      DeprecationWarning, 2)

        try:
            return self._userinfo.split(':')[1]
        except IndexError:
            raise IndexError("Userinfo contained no password"
                             "that could be retrieved.")

    @password.setter
    def password(self, _password: str):
        warnings.warn("Use of the 'user:password' format in userinfo is "
                      "deprecated according to RFC 3986",
                      DeprecationWarning, 2)

        _password = parse.quote(_password, _SUB_DELIMS + _PCT)
        userinfo = self._userinfo.split(':')
        userinfo[1] = _password
        self._userinfo = ':'.join(userinfo)

    @property
    def host(self) -> str:
        return self._host

    @host.setter
    def host(self, _host: str):
        if not _host:
            raise ValueError("Host cannot be empty.")
        _host = _host.encode("idna").decode("utf-8")
        if not all(character in set(_SUB_DELIMS + _PCT + _UNRESERVED)
                   for character in _host):
            raise ValueError("Host contains illegal characters.")
        try:
            ipaddress.IPv6Address(_host)
            self._host = f"[{str(_host)}]"
        except ipaddress.AddressValueError:
            self._host = str(_host).lower()

    @property
    def port(self) -> int:
        return self._port

    @port.setter
    def port(self, _port: str | int | None):
        if not _port:
            self._port = None
            return
        if isinstance(_port, str):
            if not _port.isdigit():
                raise ValueError("Port cannot be a non-numerical value.")
            else:
                self._port = str(_port)
        else:
            self._port = _port

    @property
    def authority(self) -> str:
        if not self.host:
            raise ValueError("Cannot get authority while host is empty.")
        _authority = ""
        if self._userinfo:
            _authority = f"{self._userinfo}@"
        _authority = _authority + self.host
        if self._port:
            _authority = _authority + f":{self._port}"
        return _authority

    @authority.setter
    def authority(self, _authority: str):
        if not _authority:
            raise ValueError("Authority cannot be empty.")
        _authority = _clear_unsafe_bytes(_authority)
        if _authority:
            _authority = parse.quote(_authority, safe='@:')
            _authority = _authority.split("@")
            if len(_authority) > 0:
                host_and_port = _authority[-1].split(':', 1)
                if len(host_and_port) > 0:
                    self.host = host_and_port[0]
                if len(host_and_port) > 1:
                    self._port = host_and_port[1]
            if len(_authority) > 1:
                self._userinfo = _authority[0]

    def __str__(self):
        return "<WIP>"


def _clear_unsafe_bytes(string: str) -> str:
    for char in parse._UNSAFE_URL_BYTES_TO_REMOVE:
        string = string.replace(char, "")
    return string
