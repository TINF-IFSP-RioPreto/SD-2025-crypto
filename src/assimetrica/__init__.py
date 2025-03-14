import base64
import binascii
import hashlib
import json
import math
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Self, Union

import sympy
from sympy.codegen.ast import Raise

from src.ferramental import Ferramental


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
        if isinstance(obj, bytes):
            return base64.b64encode(obj).decode('utf-8')
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
            while not sympy.isprime(e):
                e += 2
        return None

    @staticmethod
    def gerar_primo(bits: int = 16) -> int:
        while True:
            num = secrets.randbits(bits) | 1
            if sympy.isprime(num):
                return num


class Mensagem:
    """
    Classe para manipulação de mensagens, permitindo operações como cifrar,
     decifrar, assinar e verificar assinaturas.

    Atributos:
        _conteudo (bytes): O conteúdo da mensagem em bytes.
        _size (int): O tamanho do conteúdo da mensagem.
    """

    def __init__(self, conteudo: Union[str, bytes] = None):
        if conteudo is None:
            self._conteudo = None
            self._size = None
            return
        elif isinstance(conteudo, str):
            self._conteudo = conteudo.encode('utf-8')
        elif isinstance(conteudo, bytes):
            self._conteudo = conteudo
        else:
            Raise(ValueError("Tipo incorreto"))
        self._size = len(self._conteudo)

    def __str__(self) -> str:
        return self._conteudo.decode('utf-8')

    @property
    def conteudo(self) -> bytes:
        return self._conteudo

    @conteudo.setter
    def conteudo(self, value: Union[str, bytes]):
        if value is None:
            self._conteudo = None
        elif isinstance(value, str):
            self._conteudo = value.encode('utf-8')
        elif isinstance(value, bytes):
            self._conteudo = value
        else:
            Raise(ValueError("Tipo incorreto"))
        self._size = len(self._conteudo)

    @property
    def size(self) -> int:
        return self._size

    @property
    def as_int(self) -> int:
        return int.from_bytes(self._conteudo, byteorder='big')

    @property
    def get_hash(self):
        return hashlib.sha256(self._conteudo).hexdigest()

    def append(self, chunk: Union[str, bytes, int]) -> bool:
        """
        Adiciona um chunk ao conteúdo da mensagem.

        Args:
            chunk (Union[str, bytes, int]): O chunk a ser adicionado, que pode
                                            ser uma string, bytes ou um inteiro.

        Returns:
            bool: True se o chunk foi adicionado com sucesso
                  False caso contrário.
            """
        if isinstance(chunk, str):
            self._conteudo += chunk.encode('utf-8')
        elif isinstance(chunk, bytes):
            self._conteudo += chunk
        elif isinstance(chunk, int):
            self._conteudo += chunk.to_bytes((chunk.bit_length() + 7) // 8, byteorder='big')
        else:
            Raise(ValueError("Tipo incorreto"))
        self._size = len(self._conteudo)
        return True

    def loads(self, chunks: List[Union[bytes, int]],
              has_padding: bool = True,
              padding: bytes = b'\x9F',
              has_crc=True) -> bool:
        """
        Carrega e decodifica uma lista de chunks em bytes ou inteiros.

        Args:
            chunks (List[Union[bytes, int]]): Lista de chunks a serem decodificados.
            has_padding (bool): Indica se os chunks têm padding. Padrão é True.
            padding (bytes): Byte de padding a ser verificado. Padrão é b'\\x9F'.
            has_crc (bool): Indica se os chunks têm CRC. Padrão é True.

        Returns:
            bool: True se a carga e decodificação forem bem-sucedidas
                  False caso contrário.
        """
        if len(chunks) < 1:
            return False
        if has_padding and len(padding) != 1:
            return False
        content = b''
        inicio = 1 if has_crc else 0
        for chunk in chunks:
            if isinstance(chunk, int):
                data = chunk.to_bytes((chunk.bit_length() + 7) // 8, byteorder='big')
            elif isinstance(chunk, bytes):
                data = chunk
            else:
                return False
            if has_padding and data[-1:] != padding:
                return False
            if has_crc and data[0:1] != Ferramental.crc8(data[1:]):
                return False
            content += data[inicio:-1] if has_padding else data[1:]
        self.conteudo = content
        return True

    def dumps(self, size: int = 2,
              as_bytes: bool = True,
              add_padding: bool = True,
              padding: bytes = b'\x9F',
              add_crc=True) -> Union[List[Union[bytes, int]], None]:
        """
        Serializa o conteúdo em uma lista de chunks de bytes ou inteiros.

        Args:
            size (int): O tamanho de cada chunk. Padrão é 2.
            as_bytes (bool): Indica se os chunks devem ser retornados como bytes. Padrão é True.
            add_padding (bool): Indica se deve adicionar padding aos chunks. Padrão é True.
            padding (bytes): O byte de padding a ser adicionado. Padrão é b'\\x9F'.
            add_crc (bool): Indica se deve adicionar CRC aos chunks. Padrão é True.

        Returns:
            Union[List[Union[bytes, int]], None]: Uma lista de chunks serializados ou None se
            ocorrer um erro.
        """
        if size < 2:
            return None
        actual_size = size - 1 if add_crc else 0
        if add_padding and len(padding) != 1:
            return None
        actual_size = actual_size - (1 if add_padding else 0)
        if actual_size < 1:
            return None
        chunks = list()
        for i in range(0, len(self._conteudo), actual_size):
            content = self._conteudo[i:i + actual_size] + (padding if add_padding else b'')
            if add_crc:
                content = Ferramental.crc8(content) + content
            if as_bytes:
                chunks.append(content)
            else:
                chunks.append(int.from_bytes(content, byteorder='big'))
        return chunks

    def cifrar(self,
               chave: ChavePublica,
               add_padding: bool = True,
               padding: bytes = b'\x9F',
               add_crc=True,
               size: int = None,
               armored: bool = False) -> Optional[Union[str, Dict[str, Any]]]:
        """
        Cifra o conteúdo da mensagem usando uma chave pública.

        Args:
            chave (ChavePublica): A chave pública usada para cifrar a mensagem.
            add_padding (bool): Indica se deve adicionar padding aos chunks. Padrão é True.
            padding (bytes): O byte de padding a ser adicionado. Padrão é b'\\x9F'.
            add_crc (bool): Indica se deve adicionar CRC aos chunks. Padrão é True.
            size (int): O tamanho de cada chunk. Se None, será calculado automaticamente.
            armored (bool): Indica se a mensagem cifrada deve ser retornada em formato armored.
            Padrão é False.

        Returns:
            Optional[Union[str, Dict[str, Any]]]: A mensagem cifrada em formato dict ou string se
            armored for True, ou None se ocorrer um erro.
        """
        if chave.e is None or chave.n is None:
            return None
        if size is None:
            size = chave.size + 7 // 8
        chunks = self.dumps(size=size,
                            as_bytes=False,
                            add_padding=add_padding,
                            padding=padding,
                            add_crc=add_crc)
        if chunks is None:
            return None
        cifrado = {
            'key_serial'  : chave.serial,
            'has_crc'     : add_crc,
            'has_padding' : add_padding,
            'generated_at': datetime.now(timezone.utc).replace(microsecond=0),
            'chunks'      : [],
        }
        if add_padding:
            cifrado['padding'] = padding
        for chunk in chunks:
            cifrado['chunks'].append(pow(chunk, chave.e, chave.n))
        if not armored:
            return cifrado
        return Ferramental.armored(json.dumps(cifrado, cls=CustomJSONEncoder).encode('utf-8'),
                                   '--- INICIO DE MENSAGEM CIFRADA ---',
                                   '--- FINAL DE MENSAGEM CIFRADA ---',
                                   72)

    def decifrar(self,
                 chave: ChavePrivada,
                 msg: Union[str, Dict[str, Any]]) -> bool:
        """
        Decifra o conteúdo da mensagem usando uma chave privada.

        Args:
            chave (ChavePrivada): A chave privada usada para decifrar a mensagem.
            msg (Union[str, Dict[str, Any]]): A mensagem cifrada, que pode ser uma string ou um
            dicionário.

        Returns:
            bool: True se a decifração for bem-sucedida, False caso contrário.
        """
        if chave.d is None or chave.n is None:
            return False
        if isinstance(msg, str):
            content = Ferramental.unarmor(msg,
                                          '--- INICIO DE MENSAGEM CIFRADA ---',
                                          '--- FINAL DE MENSAGEM CIFRADA ---')
            if content is None:
                return False
            content = json.loads(content)
        elif isinstance(msg, dict):
            content = msg
        else:
            return False
        if content.get('key_serial') != chave.serial:
            return False
        padding = b'\x9F'
        if content.get('padding', None) is not None:
            padding = base64.b64decode(content.get('padding'))
        chunks = content.get('chunks')
        if chunks is None:
            return False
        decifrado = list()
        for chunk in chunks:
            decifrado.append(pow(chunk, chave.d, chave.n))
        return self.loads(decifrado,
                          has_padding=content.get('has_padding', True),
                          padding=padding,
                          has_crc=content.get('has_crc', True))

    def assinar(self,
                chave: ChavePrivada,
                armored: bool = True) -> Optional[Union[str, Dict[str, Any]]]:
        """
        Assina o conteúdo da mensagem usando uma chave privada.

        Args:
            chave (ChavePrivada): A chave privada usada para assinar a mensagem.
            armored (bool): Indica se a assinatura deve ser retornada em formato armored. Padrão
            é True.

        Returns:
            Optional[Union[str, Dict[str, Any]]]: A assinatura em formato dict ou string se
            armored for True, ou None se ocorrer um erro.
        """
        if chave.d is None or chave.n is None:
            return None
        resumo = Mensagem(self.get_hash)
        chunks = resumo.dumps(size=10,
                              as_bytes=False,
                              add_padding=False,
                              add_crc=True)
        del resumo
        if chunks is None:
            return None
        assinatura = {
            'key_serial'  : chave.serial,
            'issued_to'   : chave.issued_to,
            'has_crc'     : True,
            'has_padding' : False,
            'generated_at': datetime.now(timezone.utc).replace(microsecond=0),
            'chunks'      : [],
        }
        for chunk in chunks:
            assinatura['chunks'].append(pow(chunk, chave.d, chave.n))
        if not armored:
            return assinatura
        return Ferramental.armored(json.dumps(assinatura, cls=CustomJSONEncoder).encode('utf-8'),
                                   '--- INICIO DE ASSINATURA ---',
                                   '--- FINAL DE ASSINATURA ---',
                                   72)

    def verificar_assinatura(self,
                             chave: ChavePublica,
                             assinatura: Union[str, Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Verifica a assinatura de uma mensagem usando uma chave pública.

        Args:
            chave (ChavePublica): A chave pública usada para verificar a assinatura.
            assinatura (Union[str, Dict[str, Any]]): A assinatura a ser verificada, que pode ser
            uma string ou um dicionário.

        Returns:
            Optional[Dict[str, Any]]: Um dicionário contendo informações sobre a verificação da
            assinatura, incluindo:
                - 'valid' (bool): Indica se a assinatura é válida.
                - 'key_serial' (str): O serial da chave usada para assinar.
                - 'issued_to' (str): O destinatário da chave.
                - 'generated_at' (datetime): A data e hora em que a assinatura foi gerada.
                - 'expected' (str): O hash esperado da mensagem.
        """
        retorno = {
            'valid': False
        }
        if chave.e is None or chave.n is None:
            return retorno
        if isinstance(assinatura, str):
            content = Ferramental.unarmor(assinatura,
                                          '--- INICIO DE ASSINATURA ---',
                                          '--- FINAL DE ASSINATURA ---')
            if content is None:
                return retorno
            content = json.loads(content)
        elif isinstance(assinatura, dict):
            content = assinatura
        else:
            return retorno
        if content.get('key_serial') != chave.serial:
            return retorno
        chunks = content.get('chunks')
        if chunks is None:
            return retorno
        decifrado = list()
        for chunk in chunks:
            decifrado.append(pow(chunk, chave.e, chave.n))
        msg = Mensagem()
        if not msg.loads(decifrado,
                         has_padding=False,
                         has_crc=True):
            return retorno
        retorno['key_serial'] = chave.serial
        retorno['issued_to'] = content.get('issued_to', None)
        if content.get('generated_at', None) is not None:
            retorno['generated_at'] = Ferramental.safe_fromisoformat(content.get('generated_at'))
        retorno['expected'] = str(msg)
        retorno['received'] = self.get_hash
        # https://docs.python.org/3.13/library/secrets.html#secrets.compare_digest
        retorno['valid'] = secrets.compare_digest(self.get_hash, str(msg))
        return retorno


class ParDeChaves:
    """
    Classe para geração e manipulação de pares de chaves RSA.

    Atributos:
        _n (int): O módulo n da chave RSA.
        _phi_n (int): O valor de phi(n) (função totiente de Euler).
        _e (int): O expoente público e da chave RSA.
        _d (int): O expoente privado d da chave RSA.
        _size (int): O tamanho da chave em bits.
        _issued_at (datetime): A data e hora de emissão da chave.
        _issued_to (str): O proprietário da chave.
        _serial (str): O número de série da chave.
        _has_private (bool): Indica se a chave privada está presente.
        _has_public (bool): Indica se a chave pública está presente.
    """

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

    def _same_base_metadata(self, other: Chave) -> bool:
        return all([
            self.issued_at is None or self.issued_at == other.issued_at,
            self.issued_to is None or self.issued_to == other.issued_to,
            self.serial is None or self.serial == other.serial,
            self.size is None or self.size == other.size,
            self.n is None or self.n == other.n
        ])

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
        """
        Gera um par de chaves RSA.

        Args:
            bits (int): O tamanho em bits das chaves a serem geradas. Padrão é 16.
            p (int): Um número primo opcional para ser usado na geração da chave. Se None,
            um primo será gerado automaticamente.
            q (int): Um segundo número primo opcional para ser usado na geração da chave. Se
            None, um primo será gerado automaticamente.
            issued_to (str): O proprietário da chave.
            issued_at (datetime): A data e hora de emissão da chave. Se None, a data e hora
            atuais serão usadas.

        Returns:
            bool: True se a geração das chaves for bem-sucedida, False caso contrário.
        """
        if self.has_private or self.has_public:
            return False

        if bits < 16:  # Muito curto não dá certo
            return False

        self._size = bits
        if p is None or not sympy.isprime(p):
            p = Ferramentas.gerar_primo(self.size)
        if q is None or not sympy.isprime(q):
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
        """
        Retorna a chave pública.

        Args:
            armored (bool): Indica se a chave deve ser retornada em formato armored. Padrão é False.

        Returns:
            Union[ChavePublica, str]: A chave pública em formato ChavePublica ou string se
            armored for True.
        """
        chave = ChavePublica(issued_at=self.issued_at,
                             issued_to=self.issued_to,
                             serial=self.serial,
                             size=self.size,
                             n=self.n,
                             e=self.e)
        if not armored:
            return chave
        chave = json.dumps(chave.__dict__, cls=CustomJSONEncoder)
        return Ferramental.armored(
                base_bytes=chave.encode('utf-8'),
                start_banner='--- INICIO DE CHAVE PUBLICA ---',
                end_banner='--- FINAL DE CHAVE PUBLICA ---',
                width=72
        )

    def private(self, armored: bool = False) -> Union[ChavePrivada, str]:
        """
        Retorna a chave privada.

        Args:
            armored (bool): Indica se a chave deve ser retornada em formato armored. Padrão é False.

        Returns:
            Union[ChavePrivada, str]: A chave privada em formato ChavePrivada ou string se
            armored for True.
        """
        chave = ChavePrivada(issued_at=self.issued_at,
                             issued_to=self.issued_to,
                             serial=self.serial,
                             size=self.size,
                             n=self.n,
                             d=self.d)
        if not armored:
            return chave
        chave = json.dumps(chave.__dict__, cls=CustomJSONEncoder)
        return Ferramental.armored(
                base_bytes=chave.encode('utf-8'),
                start_banner='--- INICIO DE CHAVE PRIVADA ---',
                end_banner='--- FINAL DE CHAVE PRIVADA ---',
                width=72
        )

    def load_key(self,
                 chave: Union[Chave, str] = None,
                 tipo: TipoChave = None) -> bool:
        """
        Carrega uma chave pública ou privada.

        Args:
            chave (Union[Chave, str]): A chave a ser carregada, que pode ser um objeto Chave ou
            uma string.
            tipo (TipoChave): O tipo da chave (PUBLICA ou PRIVADA) se a chave for uma string.

        Returns:
            bool: True se a chave for carregada com sucesso, False caso contrário.
        """
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
        self._issued_at = Ferramental.safe_fromisoformat(chave.get('issued_at'))
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
    chaves.generate(bits=512, issued_to="daniel@lobato.org")

    msg = Mensagem("Olá, mundo!")
    cifrado = msg.cifrar(chaves.public(), armored=True, size=4)
    print(cifrado)
    decifrado = Mensagem()
    if decifrado.decifrar(chaves.private(), cifrado):
        print(decifrado)
    else:
        print("Erro")

    msg = Mensagem("O rato roeu a roupa do rei de Roma")
    assinatura = msg.assinar(chaves.private(), armored=False)
    print(json.dumps(assinatura, indent=2))

    resultado = msg.verificar_assinatura(chaves.public(), assinatura)
    print(json.dumps(resultado, cls=CustomJSONEncoder, indent=2))

    msg = Mensagem("O rato roeu a roupa do rei de Milão")
    resultado = msg.verificar_assinatura(chaves.public(), assinatura)
    print(json.dumps(resultado, cls=CustomJSONEncoder, indent=2))
