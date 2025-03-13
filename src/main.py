import json

from simetrica import gerar_chave, cifrar, decifrar
from assimetrica import Chave
from src.assimetrica import ParDeChaves
from tests.test_simetrica import nova_chave

chaves_do_usuario = ParDeChaves()
chavesimetrica = gerar_chave()
print(chavesimetrica)
chaves_do_usuario.generate(bits=256)
privada = chaves_do_usuario.private()
privada_cifrada = cifrar(chavesimetrica, str(privada).encode('utf-8'))
print(privada_cifrada)

registro = {'id': 1,
            'nome': 'Alice',
            'email': 'alice@gmail.com'
            }
registro_serializado = json.dumps(registro)

print(registro_serializado)

senha = input("Digite a senha de assinatura: ")

chave_privada_para_assinar = decifrar(senha.encode('utf-8'), privada_cifrada).decode('utf-8')

print(chave_privada_para_assinar)

nova_chave = ParDeChaves()
nova_chave.load_key(chave_privada_para_assinar)

nova_chave.assinar(registro_serializado.encode('utf-8'), arm)
