import base64
import json
import math
import secrets
import textwrap
import time
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Union
from datetime import datetime
import sympy


class TipoChave(Enum):
    PUBLICA = 1
    PRIVADA = 2


@dataclass
class Chave:
    issued_at: int = None
    issued_to: str = None
    serial: str = None
    bits: int = None
    n: int = None


@dataclass
class ChavePublica(Chave):
    e: int = None


@dataclass
class ChavePrivada(Chave):
    d: int = None


class ParDeChaves:
    def __init__(self):
        self.p = None
        self.q = None
        self.e = None
        self.d = None
        self.serial = None
        self._n = None
        self.bits = None
        self.issued_at = None
        self.issued_to = None
        self._has_private = False
        self._has_public = False

    @property
    def cabecalho(self) -> str:
        return (f"Gerado para...........: {self.issued_to}\n"
                f"Gerado em.............: {datetime.fromtimestamp(self.issued_at).strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"Serial................: {self.serial}\n"
                f"Tamanho da chave......: {self.bits} bits\n"
                f"Inclui chave privada..: {self._has_private}\n"
                f"Inclui chave publica..: {self._has_public}")

    @property
    def n(self):
        return self.p * self.q if self.p is not None and self.q is not None else self._n

    @property
    def phi_n(self):
        return (self.p - 1) * (self.q - 1) if self.p is not None and self.q is not None else None

    @staticmethod
    def _melhor_e(phi_n) -> Optional[int]:
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
    def _gerar_primo(bits: int = 8) -> int:
        while True:
            num = secrets.randbits(bits) | 1
            if sympy.isprime(num):
                return num

    @staticmethod
    def _armored(base_str: str = None,
                 start_banner: str = '--- BEGIN ---',
                 end_banner: str = '--- END ---',
                 width: int = 72) -> str:
        wrapped = textwrap.fill(base_str, width)
        return f"{start_banner}\n{wrapped}\n{end_banner}"

    def generate(self,
                 bits: int = 16,
                 issued_to: str = None,
                 issued_at: int = None) -> bool:

        if self._has_private or self._has_public:
            return False

        self.bits = bits
        self.p = ParDeChaves._gerar_primo(self.bits)
        self.q = ParDeChaves._gerar_primo(self.bits)
        while self.p == self.q:
            self.q = ParDeChaves._gerar_primo(self.bits)

        self.e = ParDeChaves._melhor_e(self.phi_n)
        if self.e is None:
            raise ValueError(f"Não foi possível encontrar um e para phi_n = {self.phi_n}")

        self.d = sympy.mod_inverse(self.e, self.phi_n)
        self.issued_to = issued_to
        self.issued_at = int(time.time()) if issued_at is None else issued_at
        self.serial = str(uuid.uuid4())
        self._has_private = self._has_public = True
        return True

    def public(self, armored: bool = False) -> Union[ChavePublica, str]:
        chave = ChavePublica(issued_at=self.issued_at,
                             issued_to=self.issued_to,
                             serial=self.serial,
                             bits=self.bits,
                             n=self.n,
                             e=self.e)
        if not armored:
            return chave
        return self._armored(
            base_str=base64.b64encode(json.dumps(chave.__dict__).encode('utf-8')).decode('utf-8'),
            start_banner='--- INICIO DE CHAVE PUBLICA ---',
            end_banner='--- FINAL DE CHAVE PUBLICA ---',
            width=72
        )

    def private(self, armored: bool = False) -> Union[ChavePrivada, str]:
        chave = ChavePrivada(issued_at=self.issued_at,
                             issued_to=self.issued_to,
                             serial=self.serial,
                             bits=self.bits,
                             n=self.n,
                             d=self.d)
        if not armored:
            return chave
        return self._armored(
            base_str=base64.b64encode(json.dumps(chave.__dict__).encode('utf-8')).decode('utf-8'),
            start_banner='--- INICIO DE CHAVE PRIVADA ---',
            end_banner='--- FINAL DE CHAVE PRIVADA ---',
            width=72
        )

    def load_key(self,
                 chave: Union[Chave, str] = None,
                 tipo: TipoChave = None) -> bool:
        if chave is None:
            return False
        if isinstance(chave, Chave):
            self.issued_at = chave.issued_at
            self.issued_to = chave.issued_to
            self.serial = chave.serial
            self.bits = chave.bits
            self._n = chave.n
        if isinstance(chave, ChavePrivada):  # Carregar chave privada
            self.d = chave.d
            self._has_private = True
            return True
        if isinstance(chave, ChavePublica):  # Carregar chave publica
            self.e = chave.e
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
        assert isinstance(chave, str)
        lines = chave.splitlines()
        start_idx = lines.index(start_banner)
        end_idx = lines.index(end_banner)
        base_str = ''.join(lines[start_idx + 1:end_idx])
        chave = json.loads(base64.b64decode(base_str.encode('utf-8')).decode('utf-8'))
        self.issued_to = chave.get('issued_to')
        self.issued_at = chave.get('issued_at')
        self.serial = chave.get('serial')
        self.bits = chave.get('bits')
        self._n = chave.get('n')
        if tipo == TipoChave.PRIVADA:
            self._has_private = True
            self.d = chave.get('d')
        else:
            self._has_public = True
            self.e = chave.get('e')
        return True


if __name__ == '__main__':
    chaves = ParDeChaves()
    chaves.generate(bits=8, issued_to="daniel@lobato.org")
    print(chaves.cabecalho)
    print(chaves.public(armored=True))
    print(chaves.private(armored=True))
