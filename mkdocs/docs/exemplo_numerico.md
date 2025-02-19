### A prática, agora com números...

#### Passo 1: a escolha dos primos

Para efeitos didáticos, vamos escolher dois números primos pequenos
para \(p\) e \(q\), a saber:

$$p=61\\
q=53$$

Agora, podemos calcular o valor de \(n\) e de \(\varphi(n)\):

$$n = p \times q = 61 \times 53 = 3233\\
\varphi(n) = (p-1) \times (q-1) = (61-1) \times (53-1) = 60 \times 52 = 3120$$

#### Passo 2: a escolha do expoente \(e\)

De acordo com o algoritmo, precisamos garantir que:

- \(1 < e < \varphi(n)\), e;
- \(e\) seja coprimo de \(\varphi(n)\), ou seja, \(\text{MDC} (e, 3120) = 1\)

Uma escolha comum é \(e \in \{17, 257, 65537\}\). Por que?

Great question! The choice of
𝑒
e is important for both security and performance. Let's break it down.

Why Choose 17 Over 257?
Efficiency (Computation Speed)

Encryption involves computing:
𝐶
=
𝑀
𝑒
m
o
d
 
 
𝑛
C=M
e
modn
The larger
𝑒
e, the more computational power is needed.
𝑒
=
17
e=17 is small and can be computed faster than
𝑒
=
257
e=257.
In real-world applications, common choices for
𝑒
e are small Fermat primes like:
𝑒
=
3
,
17
,
65537
e=3,17,65537
These numbers allow for faster exponentiation while still being secure.
Security Considerations

Any valid
𝑒
e (coprime with
𝜑
(
𝑛
)
φ(n)) provides the same level of security if
𝑑
d is large enough.
However, very small
𝑒
e (like
𝑒
=
3
e=3) can make attacks easier under certain conditions.
𝑒
=
17
e=17 or
𝑒
=
65537
e=65537 are preferred because they strike a balance between security and efficiency.
Common Best Practice:
𝑒
=
65537
e=65537

In real cryptographic implementations,
𝑒
=
65537
e=65537 (0x10001) is the most commonly used value.
It’s still small enough for efficient computation, but large enough to avoid some vulnerabilities.
Should You Choose 257 Instead of 17?
Mathematically, both work fine as long as they satisfy
gcd
⁡
(
𝑒
,
𝜑
(
𝑛
)
)
=
1
gcd(e,φ(n))=1.
Practically,
𝑒
=
17
e=17 is much faster.
In real-world applications, use
𝑒
=
65537
e=65537 because it's a well-tested industry standard.