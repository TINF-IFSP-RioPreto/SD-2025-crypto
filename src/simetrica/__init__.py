from typing import List, Optional, Tuple

from cryptography.fernet import Fernet, InvalidToken


def gerar_chave() -> bytes:
    return Fernet.generate_key()


def cifrar(chave: bytes,
           mensagem: bytes) -> Optional[bytes]:
    if chave is None or mensagem is None:
        return None

    if len(chave) != 44 or not isinstance(chave, bytes):
        return None

    if not isinstance(mensagem, bytes):
        return None

    f = Fernet(chave)

    return f.encrypt(mensagem)


def decifrar(chave: bytes,
             criptotexto: bytes,
             ttl: int = None) -> Optional[bytes]:
    if chave is None or criptotexto is None:
        return None

    if len(chave) != 44 or not isinstance(chave, bytes):
        return None

    if not isinstance(criptotexto, bytes):
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
                                      "")  # Remove os -, caso eles tenham sido adicionados para completar a grade.


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

    return cifrar_cesar(texto_cifrado, -chave)  # Decifrar é cifrar com a chave negativa
