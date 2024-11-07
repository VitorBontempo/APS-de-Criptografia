from Crypto.Cipher import AES #Implementação de algoritmo para a criptografia
from Crypto.Util.Padding import pad, unpad #Para auxílio do algoritmo implementado, evitar erros
import os #Auxílio na complexificação da criptografia
import binascii  # Para converter para hexadecimal
import rich

#Função de criptografagem
def criptografar(mensagem, key):
    iv = os.urandom(16) #Gerar IV
    cripto = AES.new(key, AES.MODE_GCM, nonce=iv) #Modo da criptografia AES com o IV gerado
    mensagemPad = pad(mensagem.encode(), AES.block_size)  # Adiciona padding para evitar erros
    criptoMensagem, tag = cripto.encrypt_and_digest(mensagemPad) #Além de criptografar o código, gera uma 'tag' para verificar se foi alterado o código.
    return iv+criptoMensagem+tag

rich.print("=================[red]Sistema de Segurança Cibernética[/red]=================")
rich.print("[blue]Modo de ENCRIPTAÇÃO[/blue]")

senha = os.urandom(16)
    
mensagemOriginal = input("Mensagem para ser enviada: ") #Mensagem para ser criptografada

mensagemCifrada = criptografar(mensagemOriginal, senha) #Criptografando a mensagem
print(f"Mensagem criptografada: {binascii.hexlify(mensagemCifrada).decode('utf-8')}\nSenha: {binascii.hexlify(senha).decode('utf-8')}")
