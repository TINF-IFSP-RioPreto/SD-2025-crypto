## A prática, agora com números...

### Passo 1: a escolha dos primos

Para efeitos didáticos, vamos escolher dois números primos pequenos
para \(p\) e \(q\), a saber:

$$p=61\\
q=53$$

Agora, podemos calcular o valor de \(n\) e de \(\varphi(n)\):

$$n = p \times q = 61 \times 53 = 3233\\
\varphi(n) = (p-1) \times (q-1) = (61-1) \times (53-1) = 60 \times 52 = 3120$$

### Passo 2: a escolha do expoente \(e\)

De acordo com o algoritmo, precisamos garantir que:

- \(1 < e < \varphi(n)\), e;
- \(e\) seja coprimo de \(\varphi(n)\), ou seja, \(\text{MDC} (e, 3120) = 1\)

Uma escolha comum é:

$$e \in \{17, 257, 65537\}$$

A escolha do valor de \(e\) é importante, tanto para a segturança
quanto para o desempenho do algoritmo.

#### Por que escolher \(e \in \{17, 257\}\)?

O processo de cifrar a mensagem envolve calcular \(m^e\). Quanto
maior o valor de \(e\), mas poder computacional é necessário. Logo,
valores pequenos para \(e\) podem ser calculados mais rapidamente. Assim,
seria melhor (olhando apenas para o desempenho), escolher \(e=17\) e não
\(e=257\).

Olhando para a segurança, qualquer valor para \(e\) que seja válido,
ou seja, \(1 < e < \varphi(n)\) e coprimo de \(\varphi(n)\), fornece o mesmo nível de segurança
**se \(d\) for grande o bastante**. Apenas valores muito pequenos
(por exemplo, 3) poderiam deixar o algoritmo suscetível a ataque em
determinadas condições.

Em resumo: na prática, \(e \in \{17, 257, 65537\}\) fornece um bom
balanço entre segurança e desempenho.  Em implementações comerciais,
normalmente o valor 65537 (`0x10001`) é escolhido por ser pequeno
o bastante para garantir um tempo pequeno no cálculo de \(m^e\),
ao mesmo tempo que é grande o bastante para evitar algumas
vulnerabilidades conhecidas.

No nosso exemplo, vamos adotar \(e=17\), para facilitar as contas.

### Passo 3: calcular o expoente privado \(d\)

O valor de \(d\) deve ser o inverso modular de \(e\) \(\mod \varphi(n)\),
ou seja:

$$d \times e \equiv 1 \mod \varphi(n)$$

ou, numericamente:

$$d \times 17 \equiv 1 \mod 3120$$

Utilizando o [Algoritmo de Euclides estendido](https://pt.wikipedia.org/wiki/Algoritmo_de_Euclides_estendido), 
temos \(d = 2753\), pois:

$$(17 \times 2753) \mod 3120 = 1$$

### Passo 4: construir as chaves pública e privada

Agora, tendo os valores para \(n\), \(d\) e \(e\), podemos chegar em:

- Chave pública = \((e, n) = (17, 3233)\), e;
- Chave privada = \((d, n) = (2753, 3233)\).

### Passo 5: cifrar a mensagem

Agora podemos cifrar uma mensagem!

*Benedito* possui a chave pública de *Abelardo*, que é `(17, 3233)`.
Com ela, vamos cifrar a mensagem `A`, que podemos converter para o
valor inteiro da letra `A` na tabela ASCII: `65`.

Logo, para cifrar a mensagem `65` temos:

$$c = m^e \mod n$$
$$c = 65^{17} \mod 3233$$
$$c = 6.599.743.590.836.592.050.933.837.890.625 \mod 3233$$
$$c = 2790$$

Ou seja:

$$(C_{(17, 3233)}(65)=2790)$$

A mensagem `65`, quando cifrada com a chave `(17, 3233)`,
resulta em `2790`.

### Passo 6: decifrar a mensagem

Ao receber a mensagem enviada por *Benedito*, *Abelardo* encontra
a sua chave privada (no caso `(2753, 3233)`).  Com a chave e a mensagem
cifrada recebida `2790`, podemos iniciar o processo de decifrar a mensagem.

$$m = c^d \mod n$$
$$m = 2790^{2753} \mod 3233$$
$$m = 56023\ldots000000 \mod 3233$$
$$m = 65$$
