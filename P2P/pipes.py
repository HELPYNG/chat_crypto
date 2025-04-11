def somar(valor):
    return lambda x: x + valor

def subtrair(valor):
    return lambda x: x - valor

def calcular(valor_inicial, *operacoes):
    resultado = valor_inicial
    for operacao in operacoes:
        resultado = operacao(resultado)
    return resultado

if __name__ == "__main__":
    operacao = calcular(
        10,
        somar(5),
        somar(7),
        somar(8),
        subtrair(7)
    )

    print("Resultado final:", operacao)
