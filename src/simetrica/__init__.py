import base64
from typing import List, Optional, Tuple, Union

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from src.ferramental import Ferramental


def gerar_chave(password: bytes = None,
                salt: bytes = None) -> Optional[bytes]:
    """
    Gera uma chave de criptografia para Fernet a partir de uma senha.

    Se `password` for None, gera uma chave aleatória usando Fernet.
    Se `password` for fornecido, `salt` também deve ser fornecido para
        derivar a chave usando PBKDF2HMAC.

    Args:
        password (bytes, opcional): A senha para derivar a chave.
        salt (bytes, opcional): O sal para derivar a chave.

    Returns:
        Optional[bytes]: A chave gerada ou None se `password` for fornecido
                         sem `salt`.
    """
    if password is None:
        return Fernet.generate_key()

    if salt is None:
        return None

    kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=1_200_000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key


def cifrar(chave: bytes,
           mensagem: bytes,
           armored: bool = False) -> Optional[Union[bytes, str]]:
    """
    Cifra uma mensagem usando a chave fornecida.

    Args:
        chave (bytes): A chave de criptografia.
        mensagem (bytes): A mensagem a ser cifrada.
        armored (bool): Indica se a mensagem cifrada deve ser retornada em
                        formato armored. Padrão é False.

    Returns:
        Optional[bytes]: A mensagem cifrada ou None se a chave ou a mensagem
                         forem inválidas.

    """
    if chave is None or mensagem is None:
        return None

    if len(chave) != 44 or not isinstance(chave, bytes):
        return None

    if not isinstance(mensagem, bytes):
        return None

    f = Fernet(chave)
    cifrado = f.encrypt(mensagem)

    if not armored:
        return cifrado
    return Ferramental.armored(cifrado)


def decifrar(chave: bytes,
             criptotexto: Union[bytes, str],
             ttl: int = None) -> Optional[bytes]:
    """
    Decifra um criptotexto usando a chave fornecida.

    Args:
        chave (bytes): A chave de criptografia.
        criptotexto (bytes): O texto cifrado a ser decifrado.
        ttl (int, opcional): Tempo de vida em segundos para o criptotexto. Se
                             fornecido, a decifração falhará se o criptotexto
                             for mais antigo que o TTL.

    Returns:
        Optional[bytes]: O texto decifrado ou None se a chave ou criptotexto
                         forem inválidos, ou se o TTL expirar.
    """
    if chave is None or criptotexto is None:
        return None

    if len(chave) != 44 or not isinstance(chave, bytes):
        return None

    if isinstance(criptotexto, str):
        criptotexto = Ferramental.unarmor(criptotexto)
    elif not isinstance(criptotexto, bytes):
        return None

    f = Fernet(chave)

    try:
        return f.decrypt(criptotexto, ttl=ttl)
    except InvalidToken:
        return None


def _criar_matriz(chave, mensagem) -> Tuple[List[List[str]], int, int]:
    # Calcula o número de colunas e linhas
    num_colunas = len(chave)
    num_linhas = (len(mensagem) + num_colunas - 1) // num_colunas

    # Cria a grade de transposição
    grade = [['-' for _ in range(num_colunas)] for _ in range(num_linhas)]

    return grade, num_linhas, num_colunas


def cifrar_transposicao_colunar(mensagem: str = None,
                                chave: str = None) -> Optional[str]:
    if chave is None or mensagem is None:
        return None

    chave = ''.join(dict.fromkeys(chave.upper()))
    mensagem = mensagem.upper().replace(" ", "")  # Remove espaços

    grade, num_linhas, num_colunas = _criar_matriz(chave, mensagem)
    indice_mensagem = 0

    # Cria uma lista de tuplas (letra da chave, índice)
    chave_ordenada = sorted((letra, i) for i, letra in enumerate(chave))

    # Preenche a grade com a mensagem
    for linha in range(num_linhas):
        for coluna in range(num_colunas):
            if indice_mensagem < len(mensagem):
                grade[linha][coluna] = mensagem[indice_mensagem]
                indice_mensagem += 1

    # Lê a grade coluna por coluna, na ordem da chave
    texto_cifrado = ''
    for letra, indice_coluna in chave_ordenada:
        for linha in range(num_linhas):
            texto_cifrado += grade[linha][indice_coluna]

    return texto_cifrado


def decifrar_transposicao_colunar(texto_cifrado: str = None,
                                  chave: str = None) -> Optional[str]:
    if chave is None or texto_cifrado is None:
        return None

    chave = ''.join(dict.fromkeys(chave.upper()))

    grade, num_linhas, num_colunas = _criar_matriz(chave, texto_cifrado)
    indice_cifrado = 0

    # Cria uma lista de tuplas (letra da chave, índice)
    chave_ordenada = sorted((letra, i) for i, letra in enumerate(chave))

    # Preenche a grade com o texto cifrado, na ordem da chave
    for letra, indice_coluna in chave_ordenada:
        for linha in range(num_linhas):
            if indice_cifrado < len(texto_cifrado):
                grade[linha][indice_coluna] = texto_cifrado[indice_cifrado]
                indice_cifrado += 1

    # Lê a grade linha por linha
    mensagem_decifrada = ''
    for linha in range(num_linhas):
        for coluna in range(num_colunas):
            mensagem_decifrada += grade[linha][coluna]

    return mensagem_decifrada.replace("-",
                                      "")


def cifrar_cesar(texto: str = None,
                 chave: int = None) -> Optional[str]:
    if texto is None or chave is None:
        return None

    texto_cifrado = ""
    texto = texto.upper()
    for caractere in texto:
        if caractere.isalpha():
            codigo_base = ord('A')
            codigo_cifrado = (ord(caractere) - codigo_base + chave) % 26 + codigo_base
            texto_cifrado += chr(codigo_cifrado)
        else:
            texto_cifrado += caractere  # Mantém caracteres não alfabéticos
    return texto_cifrado


def decifrar_cesar(texto_cifrado: str = None,
                   chave: int = None) -> Optional[str]:
    if texto_cifrado is None or chave is None:
        return None

    return cifrar_cesar(texto_cifrado, -chave)
