from Crypto.Cipher import AES #Implementação de algoritmo para a criptografia
from Crypto.Util.Padding import pad, unpad #Para auxílio do algoritmo implementado, evitar erros
import binascii
import rich

#Função de decriptografagem
def descriptografar(mensagem, key):
    iv = mensagem[:16] #Identificar o IV
    cripto = AES.new(key, AES.MODE_GCM, nonce=iv) #Modo da criptografia AES
    criptoMensagem = mensagem[16:-16] #Mensagem em si à ser decodificada
    tag = mensagem[-16:] #Identificar a tag
    try:
        descriptMensagem = cripto.decrypt_and_verify(criptoMensagem, tag)
        return unpad(descriptMensagem, AES.block_size).decode() #Remove o padding e retorna a mensagem original
    except ValueError:
        
        return "Erro de autentificação." #Aviso de falha na autentificação caso a tag seja alterada

rich.print("=================[red]Sistema de Segurança Cibernética[/red]=================")
rich.print("[blue]Modo de DECIFRAGEM[/blue]")

mensagemCifrada = binascii.unhexlify(input("Mensagem cifrada: "))
senha = binascii.unhexlify(input("Senha: "))

mensagemDecifrada = descriptografar(mensagemCifrada, senha) #Removendo a criptografia
print(f"Mensagem descriptografada: {mensagemDecifrada}")