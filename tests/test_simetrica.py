from time import sleep

import pytest
from cryptography.fernet import Fernet

from src.simetrica import cifrar, cifrar_cesar, cifrar_transposicao_colunar, decifrar, \
    decifrar_cesar, decifrar_transposicao_colunar, gerar_chave


@pytest.fixture
def nova_chave():
    return Fernet.generate_key()


@pytest.fixture
def chave_invalida_menor():
    return b'hkh7Pqw3JJcuZeWlAP3wnxrXhvLTfF165A='


@pytest.fixture
def chave_invalida_tipo():
    return 'hkh7Pqw3JJcuZeWlAP3wnaXUkLxs8sxrXhvLTfF165A='


@pytest.fixture
def chave_errada():
    return b'hkh7Pqw3JJcuZeWlAP3wnaXUkLxs8sxrXhvLTfF165A='


@pytest.fixture
def mensagem_padrao():
    return 'Ola mundo!'


def test_gerar_chave():
    key = gerar_chave()
    assert isinstance(key, bytes)
    assert len(key) == 44


def test_cifrar_com_chave(nova_chave, mensagem_padrao):
    cripto = cifrar(nova_chave, mensagem_padrao.encode())
    assert cripto is not None


def test_cifrar_mensagem_tipo_invalido(nova_chave, mensagem_padrao):
    cripto = cifrar(nova_chave, mensagem_padrao)
    assert cripto is None


def test_cifrar_chave_invalida_menor(chave_invalida_menor, mensagem_padrao):
    cripto = cifrar(chave_invalida_menor, mensagem_padrao.encode())
    assert cripto is None


def test_cifrar_chave_invalida_tipo(chave_invalida_tipo, mensagem_padrao):
    cripto = cifrar(chave_invalida_tipo, mensagem_padrao.encode())
    assert cripto is None


def test_cifrar_sem_chave(mensagem_padrao):
    cripto = cifrar(None, mensagem_padrao.encode())
    assert cripto is None


def test_cifrar_sem_mensagem(nova_chave):
    cripto = cifrar(nova_chave, None)
    assert cripto is None


def test_decifrar_com_chave(nova_chave, mensagem_padrao):
    cripto = cifrar(nova_chave, mensagem_padrao.encode())
    assert mensagem_padrao.encode() == decifrar(nova_chave, cripto)


def test_decifrar_com_chave_errada(chave_errada, nova_chave, mensagem_padrao):
    cripto = cifrar(nova_chave, mensagem_padrao.encode())
    assert decifrar(chave_errada, cripto) is None


def test_decifrar_sem_chave(nova_chave, mensagem_padrao):
    cripto = cifrar(nova_chave, mensagem_padrao.encode())
    assert decifrar(None, cripto) is None


def test_decifrar_sem_mensagem(nova_chave, mensagem_padrao):
    cripto = cifrar(nova_chave, mensagem_padrao.encode())
    assert decifrar(nova_chave, None) is None


def test_rejeitar_mensagem_antiga(nova_chave, mensagem_padrao):
    cripto = cifrar(nova_chave, mensagem_padrao.encode())
    sleep(2)
    assert decifrar(nova_chave, cripto, 1) is None


def test_decifrar_mensagem_tipo_invalido(nova_chave, mensagem_padrao):
    cripto = cifrar(nova_chave, mensagem_padrao.encode())
    assert decifrar(nova_chave, cripto.decode()) is None


def test_decifrar_chave_invalida_menor(nova_chave, chave_invalida_menor, mensagem_padrao):
    cripto = cifrar(nova_chave, mensagem_padrao.encode())
    assert decifrar(chave_invalida_menor, cripto) is None


def test_decifrar_chave_invalida_tipo(nova_chave, chave_invalida_tipo, mensagem_padrao):
    cripto = cifrar(nova_chave, mensagem_padrao.encode())
    assert decifrar(chave_invalida_tipo, cripto) is None


def test_cifrar_colunar():
    cifrado = cifrar_transposicao_colunar('pode atacar amanha de manha', 'cachorro')
    assert cifrado == 'OAMDHPTAANDCAEAEANM-ARHA-'


def test_cifrar_colunar_sem_chave():
    cifrado = cifrar_transposicao_colunar('pode atacar amanha de manha')
    assert cifrado is None


def test_cifrar_colunar_sem_mensagem():
    cifrado = cifrar_transposicao_colunar(chave='cachorro')
    assert cifrado is None


def test_decifrar_colunar():
    decifrado = decifrar_transposicao_colunar('OAMDHPTAANDCAEAEANM-ARHA-', 'cachorro')
    assert decifrado == 'PODEATACARAMANHADEMANHA'


def test_decifrar_colunar_sem_chave():
    decifrado = decifrar_transposicao_colunar('pode atacar amanha de manha')
    assert decifrado is None


def test_decifrar_colunar_sem_mensagem():
    decifrado = decifrar_transposicao_colunar(chave='cachorro')
    assert decifrado is None


def test_cifrar_cesar():
    cifrado = cifrar_cesar('pode atacar amanha de manha', 3)
    assert cifrado == 'SRGH DWDFDU DPDQKD GH PDQKD'


def test_cifrar_cesar_sem_chave():
    cifrado = cifrar_cesar('pode atacar amanha de manha')
    assert cifrado is None


def test_cifrar_cesar_sem_mensagem():
    cifrado = cifrar_cesar(chave=3)
    assert cifrado is None


def test_decifrar_cesar():
    decifrado = decifrar_cesar('SRGH DWDFDU DPDQKD GH PDQKD', 3)
    assert decifrado == 'PODE ATACAR AMANHA DE MANHA'


def test_decifrar_cesar_sem_chave():
    decifrado = decifrar_cesar('pode atacar amanha de manha')
    assert decifrado is None


def test_decifrar_cesar_sem_mensagem():
    decifrado = decifrar_cesar(chave=3)
    assert decifrado is None
