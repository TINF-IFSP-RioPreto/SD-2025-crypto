

import pytest

from src.assimetrica import ChavePrivada, ChavePublica, ParDeChaves, TipoChave


@pytest.fixture
def par_de_chaves():
    chaves = ParDeChaves()
    chaves.generate(bits=512, issued_to="test@example.com")
    return chaves


def test_public_key(par_de_chaves):
    public_key = par_de_chaves.public()
    assert par_de_chaves.has_public
    assert isinstance(public_key, ChavePublica)
    assert public_key.issued_to == "test@example.com"


def test_public_key_armored(par_de_chaves):
    public_key = par_de_chaves.public(armored=True)
    assert isinstance(public_key, str)
    assert "--- INICIO DE CHAVE PUBLICA ---" in public_key
    assert "--- FINAL DE CHAVE PUBLICA ---" in public_key


def test_private_key(par_de_chaves):
    private_key = par_de_chaves.private()
    assert par_de_chaves.has_private
    assert isinstance(private_key, ChavePrivada)
    assert private_key.issued_to == "test@example.com"


def test_private_key_armored(par_de_chaves):
    private_key = par_de_chaves.private(armored=True)
    assert isinstance(private_key, str)
    assert "--- INICIO DE CHAVE PRIVADA ---" in private_key
    assert "--- FINAL DE CHAVE PRIVADA ---" in private_key


def test_load_public_key(par_de_chaves):
    public_key_str = par_de_chaves.public(armored=True)
    new_chaves = ParDeChaves()
    assert new_chaves.load_key(public_key_str, TipoChave.PUBLICA)
    assert new_chaves.has_public
    assert new_chaves.issued_to == "test@example.com"
    assert par_de_chaves.serial == new_chaves.serial


def test_load_private_key(par_de_chaves):
    private_key_str = par_de_chaves.private(armored=True)
    new_chaves = ParDeChaves()
    assert new_chaves.load_key(private_key_str, TipoChave.PRIVADA)
    assert new_chaves.has_private
    assert new_chaves.issued_to == "test@example.com"
    assert par_de_chaves.serial == new_chaves.serial
