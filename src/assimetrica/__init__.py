import base64
import binascii
import json
import math
import secrets
import textwrap
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Self, Union

import sympy


class TipoChave(Enum):
    PUBLICA = 0
    PRIVADA = 1


@dataclass
class Chave:
    issued_at: datetime = None
    issued_to: str = None
    serial: str = None
    size: int = None
    n: int = None

    def __eq__(self, other):
        return all([self.issued_at == other.issued_at,
                    self.issued_to == other.issued_to,
                    self.serial == other.serial,
                    self.size == other.size,
                    self.n == other.n])


@dataclass
class ChavePublica(Chave):
    e: int = None

    def __eq__(self, other):
        return self.e == other.e and super.__eq__(self, other)


@dataclass
class ChavePrivada(Chave):
    d: int = None

    def __eq__(self, other):
        return self.d == other.d and super.__eq__(self, other)


class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)


class Ferramentas:
    @staticmethod
    def melhor_e(phi_n) -> Optional[int]:
        valores_comuns_para_e = [65537, 17, 3]
        for e in valores_comuns_para_e:
            if e < phi_n and math.gcd(e, phi_n) == 1:
                return e
        e = 65539
        while e < phi_n:
            if e < phi_n and math.gcd(e, phi_n) == 1:
                return e
            e += 2
            while not sympy.is_prime(e):
                e += 2
        return None

    @staticmethod
    def gerar_primo(bits: int = 8) -> int:
        while True:
            num = secrets.randbits(bits) | 1
            if sympy.isprime(num):
                return num

    @staticmethod
    def armored(base_str: str = None,
                start_banner: str = '--- BEGIN ---',
                end_banner: str = '--- END ---',
                width: int = 72) -> str:
        wrapped = textwrap.fill(base_str, width)
        return f"{start_banner}\n{wrapped}\n{end_banner}"

    @staticmethod
    def safe_fromisoformat(value) -> Optional[datetime]:
        try:
            return datetime.fromisoformat(value) if isinstance(value, str) else value
        except ValueError:
            return None


class ParDeChaves:
    def __init__(self):
        self._n = None
        self._phi_n = None
        self._e = None
        self._d = None

        self._size = None
        self._issued_at = None
        self._issued_to = None
        self._serial = None
        self._has_private = False
        self._has_public = False

    def __eq__(self, other: Self):
        return all([self.n == other.n,
                    self.phi_n == other.phi_n,
                    self.e == other.e,
                    self.d == other.d,
                    self.size == other.size,
                    self.issued_at == other.issued_at,
                    self.issued_to == other.issued_to,
                    self.serial == other.serial,
                    self.has_private == other.has_private,
                    self.has_public == other.has_public])

    def __str__(self):
        data = {
            'phi_n'      : self.phi_n,
            'size'       : self.size,
            'issued_at'  : self.issued_at.strftime('%Y-%m-%d %H:%M:%S %Z'),
            'issued_to'  : self.issued_to,
            'serial'     : self.serial,
            'has_private': self.has_private,
            'has_public' : self.has_public,
        }
        if self.has_private:
            data.update({'private': {'n': self.n, 'd': self.d}})
        if self.has_public:
            data.update({'public': {'n': self.n, 'e': self.e}})
        return json.dumps(data, indent=2)

    @property
    def n(self):
        return self._n

    @property
    def e(self):
        return self._e

    @property
    def d(self):
        return self._d

    @property
    def phi_n(self):
        return self._phi_n

    @property
    def size(self):
        return self._size

    @property
    def issued_at(self):
        return self._issued_at

    @property
    def issued_to(self):
        return self._issued_to

    @property
    def serial(self):
        return self._serial

    @property
    def has_private(self):
        return self._has_private

    @property
    def has_public(self):
        return self._has_public

    def generate(self,
                 bits: int = 16,
                 p: int = None,
                 q: int = None,
                 issued_to: str = None,
                 issued_at: datetime = None) -> bool:

        if self.has_private or self.has_public:
            return False

        if bits < 5:  # Muito curto não dá certo
            return False

        self._size = bits
        if p is None or not sympy.is_prime(p):
            p = Ferramentas.gerar_primo(self.size)
        if q is None or not sympy.is_prime(q):
            q = Ferramentas.gerar_primo(self.size)
        while True:
            while p == q:
                q = Ferramentas.gerar_primo(self.size)

            self._phi_n = (p - 1) * (q - 1)

            self._e = Ferramentas.melhor_e(self.phi_n)
            if self.e is not None:
                break
            q = None

        self._n = p * q
        self._d = sympy.mod_inverse(self.e, self.phi_n)
        self._issued_to = issued_to
        if issued_at is None or not isinstance(issued_at, datetime):
            self._issued_at = datetime.now(timezone.utc).replace(microsecond=0)
        else:
            self._issued_at = issued_at
        self._serial = str(uuid.uuid4())
        self._has_private = True
        self._has_public = True
        return True

    def public(self, armored: bool = False) -> Union[ChavePublica, str]:
        chave = ChavePublica(issued_at=self.issued_at,
                             issued_to=self.issued_to,
                             serial=self.serial,
                             size=self.size,
                             n=self.n,
                             e=self.e)
        if not armored:
            return chave
        chave = json.dumps(chave.__dict__, cls=CustomJSONEncoder)
        return Ferramentas.armored(
            base_str=base64.b64encode(chave.encode('utf-8')).decode('utf-8'),
            start_banner='--- INICIO DE CHAVE PUBLICA ---',
            end_banner='--- FINAL DE CHAVE PUBLICA ---',
            width=72
        )

    def private(self, armored: bool = False) -> Union[ChavePrivada, str]:
        chave = ChavePrivada(issued_at=self.issued_at,
                             issued_to=self.issued_to,
                             serial=self.serial,
                             size=self.size,
                             n=self.n,
                             d=self.d)
        if not armored:
            return chave
        chave = json.dumps(chave.__dict__, cls=CustomJSONEncoder)
        return Ferramentas.armored(
            base_str=base64.b64encode(chave.encode('utf-8')).decode('utf-8'),
            start_banner='--- INICIO DE CHAVE PRIVADA ---',
            end_banner='--- FINAL DE CHAVE PRIVADA ---',
            width=72
        )

    def _same_base_metadata(self, other: Chave) -> bool:
        return all([
            self.issued_at is None or self.issued_at == other.issued_at,
            self.issued_to is None or self.issued_to == other.issued_to,
            self.serial is None or self.serial == other.serial,
            self.size is None or self.size == other.size,
            self.n is None or self.n == other.n
        ])

    def load_key(self,
                 chave: Union[Chave, str] = None,
                 tipo: TipoChave = None) -> bool:
        if chave is None:
            return False
        if isinstance(chave, Chave):  # Carregar dados comuns aos dois tipos de chave
            if not self._same_base_metadata(chave):
                return False
            self._issued_at = chave.issued_at
            self._issued_to = chave.issued_to
            self._serial = chave.serial
            self._size = chave.size
            self._n = chave.n
        if isinstance(chave, ChavePrivada):  # Carregar chave privada
            self._d = chave.d
            self._has_private = True
            return True
        if isinstance(chave, ChavePublica):  # Carregar chave publica
            self._e = chave.e
            self._has_public = True
            return True
        if isinstance(chave, str) and tipo is None:  # Se for str, tem que dizer o tipo
            return False
        match tipo:
            case TipoChave.PUBLICA:
                start_banner = '--- INICIO DE CHAVE PUBLICA ---'
                end_banner = '--- FINAL DE CHAVE PUBLICA ---'
            case TipoChave.PRIVADA:
                start_banner = '--- INICIO DE CHAVE PRIVADA ---'
                end_banner = '--- FINAL DE CHAVE PRIVADA ---'
            case _:
                return False
        if isinstance(chave, str):
            lines = chave.splitlines()
        else:
            return False
        try:
            start_idx = lines.index(start_banner)
            end_idx = lines.index(end_banner)
        except ValueError:
            return False
        base_str = ''.join(lines[start_idx + 1:end_idx])
        del lines
        try:
            chave = json.loads(base64.b64decode(base_str.encode('utf-8')).decode('utf-8'))
        except (binascii.Error, ValueError):
            return False
        self._issued_to = chave.get('issued_to')
        self._issued_at = Ferramentas.safe_fromisoformat(chave.get('issued_at'))
        self._serial = chave.get('serial')
        self._size = chave.get('bits')
        self._n = chave.get('n')
        if self.n is None:
            return False  # Faltando N não tem chave
        if tipo == TipoChave.PRIVADA:
            self._d = chave.get('d')
            if self.d is None:  # Faltando D não tem chave privada
                return False
            self._has_private = True
        else:
            self._e = chave.get('e')
            if self.e is None:  # Faltando E não tem chave pública
                return False
            self._has_public = True
        return True


if __name__ == '__main__':
    chaves = ParDeChaves()
    chaves.generate(bits=7, issued_to="daniel@lobato.org")
    print(chaves)
