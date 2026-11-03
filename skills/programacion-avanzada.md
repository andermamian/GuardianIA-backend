---
name: programacion-avanzada
description: Método de ingeniería de software para escribir, revisar y depurar código de nivel profesional en cualquier lenguaje.
triggers: codigo, programa, programar, script, funcion, clase, api, bug, error, depurar, refactor, test, prueba unitaria, python, javascript, typescript, java, kotlin, flutter, dart, sql, php, c++, c#, rust, go, android
siempre: no
tipos: codigo
---
# Programación avanzada

Antes de escribir código:
1. Reformula el problema en una frase y lista supuestos y casos límite (entradas vacías, nulos, Unicode, zonas horarias, concurrencia, archivos grandes).
2. Elige la solución más simple que cumpla los requisitos; justifica en una línea por qué esa y no otra.

Al escribir:
- Entrega programas COMPLETOS y ejecutables: imports, manejo de errores explícito, tipos o anotaciones, constantes con nombre, sin números mágicos ni funciones a medio hacer.
- Una responsabilidad por función; nombres que se lean como prosa; comentarios que expliquen el POR QUÉ, no el qué.
- Valida toda entrada externa. Parametriza consultas SQL. No pongas secretos en el código: variables de entorno.
- Complejidad: indica la de tiempo y memoria cuando importe y evita trabajo repetido.
- Concurrencia y E/S: cierra recursos (with / try-finally), define tiempos de espera y reintentos con retroceso exponencial.

Al depurar: reproduce → aísla → formula una hipótesis → comprueba con evidencia (logs, prueba mínima) → corrige la CAUSA, no el síntoma → añade una prueba que habría detectado el fallo.

Siempre cierra con: (a) cómo ejecutarlo y qué instalar, (b) al menos 3 pruebas (normal, límite, error), (c) riesgos conocidos y mejoras siguientes.
Para Flutter/Dart: separa UI, estado y datos; usa sqflite/drift con migraciones versionadas; maneja `async` con try/catch y estados de carga/error/vacío.
Para Python: PEP 8, `pathlib`, `dataclasses`, `logging` en vez de `print`, `pytest` para pruebas.
