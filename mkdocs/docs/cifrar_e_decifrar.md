### Como cifrar e decifrar um mensagem?

#### Cifrar
Tendo a chave pública \((e, n)\), cifrar uma mensagem é efetuar um única
operação, a saber:

$$c=m^e \mod(n) $$

Onde \(e\) e \(n\) fazem parte da chave pública, \(m\) é a mensagem a
ser cifrada, e \(c\) é a mensagem cifrada com a chave pública \((e, n)\).

#### Decifrar
Para decifrar uma mensagem é necessário possuir a chave privada \((d, n)\). Ela 
é a única chave capaz de garantir a propriedade \(D_{(d, n)}(C_{(e, n)}(M)) = M\).
A operação necessária é:

$$m=c^d \mod(n)$$

Onde \(d\) e \(n\) fazem parte da chave privada, \(c\) é a mensagem cifrada com a
chave pública \((e, n)\), e \(m\) é a mensagem decifrada

#### O que são \(m\) e \(c\)?

Como \(m\) e \(c\) são utilizados no processo de cifrar e decifrar, 
e o processo é uma operação de potenciação, tanto \(m\) quanto \(c\) precisam 
ser números inteiros.

Mas como eu vou cifrar a mensagem "ABC", por exemplo?

Vamos precisar converter essa mensagem para um número inteiro, e a forma de
fazer isso vai ser detalhada na [implementação](cifrar_decifrar_python.md).
