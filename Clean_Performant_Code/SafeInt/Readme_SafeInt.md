# *SafeInt*: Eine Bibliothek zum Schutz vor Integer-Überläufen


[Zurück](../Secure_Programming/Readme_Secure_Programming.md)

---

## Inhalt

  * [Überlauf ganzzahliger Variablen](#link1)
  * [*SafeInt*-Bibliothek](#link2)
  * [Literatur](#link3)

---

#### Quellcode

[*SafeInt.cpp*](SafeInt.cpp)<br />

---

## Überlauf ganzzahliger Variablen <a name="link1"></a>

Der Wertebereich von ganzzahligen Variablen ist nicht unendlich.
Was die Sache noch ein klein wenig in C++ erschwert, ist der Umstand,
dass C++ Programme auf unterschiedlichen Rechnersystemen mit unterschiedlicher Hardware ablaufen können.
Oder etwas anders formuliert: Der Wertebereich einer `int`-Variablen
ist leider von Rechner zu Rechner unterschiedlich!

Man hat es in C/C++ versäumt, den Datentyp `int` rechnerunabhängig zu definieren.
Okay, wir sollten an dieser Stelle hinzufügen, das dies nie das Ziel in der Konzeption
von C/C++ gewesen ist, sondern ganz im Gegenteil: Auf vielen Rechnersystem sollte &ndash; historisch betrachtet &ndash; 
die Bitbreite einer  `int`-Variablen mit der Bitbreite des Akkumulators  zusammenpassen.
Der Akkumulator ist das zentrale Register innerhalb einer CPU,
in dem Ergebnisse der Recheneinheit gespeichert werden.

In Sprachen wie C# oder Java hat man hier einen anderen Weg eingeschlagen:
`int`-Variablen in einem C#-Programm nehmen in jedem Programm 4 Byte in Anspruch,
egal, auf welchem Zielsystem das Programm ausgeführt wird.

Zur Wahrheit gehört auch, dass es in C# den `int`-Datentyp so nicht wirklich gibt:
Der Bezeichner  `int` wird auf den Strukturtyp `System.Int32` abgebildet, 
und dieser definiert eben eine 32-Bit-Ganzzahl mit Vorzeichen

Zurück zu C++:

Betrachten Sie folgendes Beispielprogramm:

```cpp
01: int16_t sum(const std::vector<int16_t>& values)
02: {
03:     int16_t result{};
04: 
05:     for (auto num : values)
06:     {
07:         result += num;
08:     }
09: 
10:     return result;
11: }
12: 
13: void test()
14: {
15:     std::vector<int16_t> vec{ 30'000, 2'000, 700, 60, 7, 0 };
16:     auto result{ sum(vec) };
17:     std::println("Sum: {}", result);
18: }
```

*Ausgabe*:

```
Sum: 32767
```

Ändern wir den letzen Wert des Vektors `vec` in Zeile 15 in 1 ab,
so hingegen erhalten wir das Ergebnis

```
Sum: -32768
```

Hmm, dies ist offentlich falsch, wir haben es mit einem Überlauf in der Arithmetik
einer 16-Bit-Ganzzahl mit Vorzeichen zu tun.

Natürlich könnten wir dieses Problem lösen, indem wir von 16-Bit-Ganzzahlen zu 32-Bit-Ganzzahlen
wechseln. Aber auch hier könnten wir ein ähnlich gelagertes Problem bekommen.

Welche Lösungen bieten sich an:

  * Möchte man die standardmäßig in C/C++ eingebauten arithmetischen Operationen verwenden,
   dann gibt es nur eine Vorgehensweise: Man muss die Wertebereiche überprüfen.
  * Einsatz einer Spezialbibliothek für &bdquo;*Big Integer*&rdquo; Arithmetik.


## *SafeInt*-Bibliothek <a name="link2"></a>


*SafeInt* ist eine portable Bibliothek, die mit MSVC, GCC oder Clang verwendet werden kann,
um Ganzzahlüberläufe zu verhindern, die möglicherweise aus von der Anwendung durchgeführten
mathematischen Operationen resultieren könnten.

Die neueste Version dieser Bibliothek befindet sich unter [https://github.com/dcleblanc/SafeInt](https://github.com/dcleblanc/SafeInt).

*Beispiel*:

```cpp
01: int16_t sum_safe(const std::vector<int16_t>& values)
02: {
03:     // use SafeInt to check against integer overflow
04:     SafeInt<int16_t> sum{};    // = 0;   <-- automatically initialized to 0
05:     for (auto num : values)
06:     {
07:         sum += num;   // <-- *automatically* checked against integer overflow!!
08:     }
09: 
10:     return sum;
11: }
```

Und noch ein zweites Beispiel:

```cpp
01: size_t factorial(size_t x) {
02: 
03:     size_t ret{ 1 };
04: 
05:     for (size_t i{ 1 }; i <= x; ++i) {
06:         ret *= i;
07:     }
08: 
09:     return ret;
10: }
11: 
12: size_t factorial_safe(size_t x) {
13: 
14:     SafeInt<size_t> ret{ 1 };
15: 
16:     for (size_t i{ 1 }; i <= x; ++i) {
17:         ret *= i;
18:     }
19: 
20:     return ret;
21: }
```

*Ausgabe*:

```
Factorial of  1: 1
Factorial of  2: 2
Factorial of  3: 6
Factorial of  4: 24
Factorial of  5: 120
Factorial of  6: 720
Factorial of  7: 5040
Factorial of  8: 40320
Factorial of  9: 362880
Factorial of 10: 3628800
Factorial of 11: 39916800
Factorial of 12: 479001600
Factorial of 13: 6227020800
Factorial of 14: 87178291200
Factorial of 15: 1307674368000
Factorial of 16: 20922789888000
Factorial of 17: 355687428096000
Factorial of 18: 6402373705728000
Factorial of 19: 121645100408832000
Factorial of 20: 2432902008176640000
Factorial of 21: 14197454024290336768
Factorial of 22: 17196083355034583040
Factorial of 23: 8128291617894825984
Factorial of 24: 10611558092380307456
Factorial of 25: 7034535277573963776
Factorial of 26: 16877220553537093632
Factorial of 27: 12963097176472289280
Factorial of 28: 12478583540742619136
Factorial of 29: 11390785281054474240
```

und

```
Factorial of  1: 1
Factorial of  2: 2
Factorial of  3: 6
Factorial of  4: 24
Factorial of  5: 120
Factorial of  6: 720
Factorial of  7: 5040
Factorial of  8: 40320
Factorial of  9: 362880
Factorial of 10: 3628800
Factorial of 11: 39916800
Factorial of 12: 479001600
Factorial of 13: 6227020800
Factorial of 14: 87178291200
Factorial of 15: 1307674368000
Factorial of 16: 20922789888000
Factorial of 17: 355687428096000
Factorial of 18: 6402373705728000
Factorial of 19: 121645100408832000
Factorial of 20: 2432902008176640000
No more correct Factorial values available!
```

---

## Literatur <a name="link3"></a>

[SafeInt-Bibliothek](https://learn.microsoft.com/de-de/cpp/safeint/safeint-library?view=msvc-170)

---

[Zurück](../Secure_Programming/Readme_Secure_Programming.md)

---
