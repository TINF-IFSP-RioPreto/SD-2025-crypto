### Como gerar as chaves?

O processo de geração das chaves começa com a escolha de
dois números primos, arbitrariamente grandes, que chamaremos
de \(p\) e \(q\). Em 2025, números com menos de 2048 bits são 
considerados inadequados do ponto de vista da segurança.

De posse dos números \(p\) e \(q\), o passo seguinte é encontrar 
o produto \(n\), tal que \(n = p \times q\). O valor de \(n\) será 
parte das **chaves pública e privada**.

Agora, precisamos encontrar \(\varphi(n)\), que é a **função Totiente**, 
também chamada de *Função \(\varphi\) de Euler*. Ela é definida para um
número inteiro positivo \(n\) como sendo igual à quantidade de números
inteiros positivos que são relativamente primos com \(n\) não 
excedendo \(n\), que denotaremos por \(\varphi(n)\). Para o nosso
algoritmo, \(\varphi(n) = (p-1)\times(q-1)\).

Sabendo o valor de \(\varphi(n)\), precisamos escolher um expoente \(e\), tal
que \(1 < e < \varphi(n)\) e e seja coprimo com \(\varphi(n)\).

O último passo é escolher o expoente \(d\), que deve ser o inverso
modular de \(e\) módulo \(\varphi(n)\); ou seja: \(e \times d \equiv 1 \mod(\varphi(n))\).

Pronto!  Agora temos as chaves:

- Chave pública = \((e, n)\), e;
- Chave privada = \((d, n)\).

Esse par de chaves pertence ao usuário *Alberto*. A **chave 
pública** deve ser distribuída, e a **chave privada** deve
ser mantida em segredo pelo dono do par de chavesm, ou seja, por 
*Alberto*.

Quando, por exemplo, o usuário *Benedito* quiser enviar uma 
mensagem para *Alberto*, ele deve utilizar a **chave pública de *Alberto***
para cifrar a mensagem (\(C_{(e, n)}\)).  Ao receber a mensagem cifrada, *Alberto* deve
utilizar a sua **chave privada** que está em segredo e só ele 
conhece, para decifrar a mensagem (\(D_{(d, n)}\)).

As chaves possuem uma propriedade, tal que:

$$D_{(d, n)}(C_{(e, n)}(M)) = D_{(e, n)}(C_{(d, n)}(M)) = M$$

Ou seja: apesar de serem chamadas de **chave pública** e **chave privada**,
elas podem ser trocadas, e utilizadas em papéis diferentes.  O importante é
escolher uma delas para se tornar pública, e amplamente conhecida, e 
outra deve ser mantida em segredo pelo proprietário do par de chaves.

A segurança do algoritmo repousa no fato que, dado \(n\), encontrar os
valores de \(p\) e \(q\) -- ou seja, *fatorar \(n\)* -- é computacionalmente
caro para números suficientemente grandes (por isso, pelo menos 2048 bits). 
Mesmo sabendo o valor de \(e\), calcular o valor de \(d\) sem fatorar \(n\)
é inviável.