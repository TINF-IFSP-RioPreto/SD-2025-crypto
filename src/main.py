import json
import os

from simetrica import cifrar, decifrar, gerar_chave
from src.assimetrica import Mensagem, ParDeChaves, TipoChave

# Armazenamento das chaves do usuário no banco #################################
# Esse salt precisa estar no banco, e deve ser gerado na hora em que o
# usuário for adicionado ao banco. Se for modificado, precisa novamente
# cifrar e armazenar a senha de assinatura do usuário
salt = os.urandom(16)

chaves_do_usuario = ParDeChaves()
chaves_do_usuario.generate(bits=256)
privada = chaves_do_usuario.private(armored=True)
publica = chaves_do_usuario.public(armored=True)
senha = input("Digite a senha de assinatura: ")

chavesimetrica = gerar_chave(password=senha.encode('utf-8'), salt=salt)

# Isso é que vai pro banco #####################################################
# O que estamos fazendo com a chave privada é Key Wrapping
# https://cryptography.io/en/latest/hazmat/primitives/keywrap/#key-wrapping
privada_cifrada = cifrar(chavesimetrica, str(privada).encode('utf-8'), armored=True)
publica_aberta = publica



# Assinar o registro ###########################################################
registro = {'id': 1,
            'nome': 'Alice',
            'email': 'alice@gmail.com'
            }
# Transforma em uma Mensagem para ser assinada
registro_serializado = Mensagem(json.dumps(registro))
print(registro_serializado)

# Carrega a chave privada cifrada do banco e decifra ela com a senha de assinatura
chave_privada_para_assinar = decifrar(chavesimetrica, privada_cifrada).decode('utf-8')

# Criar um par de chaves para extrair a chave privada e assinar
nova = ParDeChaves()
nova.load_key(chave_privada_para_assinar, TipoChave.PRIVADA)

# É essa assinatura que vai pro registro no banco
assinatura = registro_serializado.assinar(nova.private(), armored=True)
print(assinatura)





# Verificar assinatura do registro #############################################
# Obter do banco a chave publica do usuario, para verificar a assinatura
chave_publica_para_verificar = publica_aberta
nova = ParDeChaves()
nova.load_key(chave_publica_para_verificar, TipoChave.PUBLICA)

# Verificar o registro sem mudanças
resultado = registro_serializado.verificar_assinatura(chave=nova.public(),
                                          assinatura=assinatura)
print(resultado)

# Verificar o registro com mudanças
registro = {'id'   : 1,
            'nome' : 'Bob',
            'email': 'bob@gmail.com'
            }
registro_serializado = Mensagem(json.dumps(registro))
resultado = registro_serializado.verificar_assinatura(chave=nova.public(),
                                                      assinatura=assinatura)
print(resultado)
