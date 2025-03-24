# Besserer Code mit der `std::ranges`-Bibliothek

[Zurück](../Clean_Code/Readme_Clean_Code.md)

---

## Inhalt

  * [Allgemeines](#link1)
  * [Was ist ein *Range*](#link2)
  * [*Ranges* versus traditionelle Iteratoren im Vergleich](#link3)
  * [Ranges und Concepts (Konzepte)](#link4)
  * [*Views* (Ansichten)](#link5)
  * [*Range Adaptors* (Bereichsadapter)](#link6)
  * [*Function Composition, Pipelines* (Komposition von Funktionen)](#link7)
  * [*Lazy Evaluation* (*Lazy* Auswertung)](#link8)
  * [*Eager Evaluation* (*Gierige* Auswertung)](#link9)
  * [Begrenzte vs. unbegrenzte (unendliche) Ranges](#link10)
  * [*Lazy* Auswertung, Beispiel für Primzahlen](#link11)
  * [Projektionen (*Projections*)](#link12)
  * [Sentinels](#link13)
  * [*Dangling Iterators* / *Borrowed Iterators* ](#link14)
  * [`std::map`: Views für Schlüssel und Werte von Assoziativ-Containern](#link15)
  * [`std::views::common`](#link16)
  * [Das Trio `std::all_of`, `std::any_of` und `std::none_of`](#link17)
  * [Zwei Beispiele zum Abschluss: `std::variant` und `std::variant`](#link18)
  * [Literatur](#link19)

---

#### Quellcode

[*Ranges.cpp*](Ranges.cpp)<br />

---

## Allgemeines <a name="link1"></a>

Wir geben in diesem Tutorial keinen vollständigen Überblick über die `std::ranges` Bibliothek:
Es sollen vielmehr einige erste Beispiele für einen Neueinsteiger in *Modern C++ 20* gegeben werden.

Erfahren Sie, wie Sie `std::ranges` für besser lesbaren und effizienteren Code nutzen können,
also für *Clean Code*.

---

## Was ist ein *Range* <a name="link2"></a>

  * Ein *Range* (*Bereich*) ist ein Konzept, das die Anforderungen an einen Typ definiert,
  der eine Iteration über seine Elemente zulässt.

  * Ein gültiger Bereich sollte zwei Methoden bereitstellen: `begin()` und `end()`.

  * Im Gegensatz zur Definition des Iteratoren-Konzepts in C++ müssen die Rückgabetypen
  dieser beiden Methoden nicht identisch sein, dazu aber später mehr.

  * *Beispiele*:<br />
  `std::array`, `std::vector`, `std::string_view`, `std::span`, Array im C-Stil usw.

  * Vorraussetzungen zum Gebrauch der Bibliothek:
 
```cpp
#include <ranges>
```

  * Die Datentypen der `std::ranges`-Bibliothek liegen im Namensraum `std::ranges`.

---

## *Ranges* versus traditionelle Iteratoren im Vergleich <a name="link3"></a>

  * Traditionelle STL-Algorithmen verwenden Iteratorenpaare zur Bezeichnung von Bereichen.

  * Dies kann fehleranfällig sein und ist darüber hinaus etwas &bdquo;*geschwätzig*&rdquo; (&bdquo;*verbose*&rdquo;).

*Beispiel*:

```cpp
01: std::vector<int> numbers{ 1, 4, 2, 7, 9, 3, 5 };
02: 
03: std::sort(
04:     numbers.begin(), 
05:     numbers.end()
06: );
```

*Beispiel*:

```cpp
01: std::vector<int> numbers{ 1, 4, 2, 7, 9, 3, 5 };
02: std::ranges::sort(numbers);
```

---

## Ranges und Concepts (Konzepte) <a name="link4"></a>

  * Der Gebrauch von *Range Concepts* trägt dazu bei, bessere und verständlichere Fehlermeldungen zu generieren.
  Die Fehlermeldungen, die bei klassischem C++ und der STL erscheinen,
  sind manchmal absolut unverständlich und sie treten vor allem in Dateien in Erscheinung,
  die korrekt sind. Der Fehler wäre im Regelfall in der Nähe der Template Instanziierung zu suchen,
  was für einen C++ Compiler zunächst einmal nicht die Fehlerursache ist.
  Das **reagierde** Verhalten im Falle von Fehlern tritt an anderen Stellen zu Tage.

  * Bei Gebrauch von *Range Concepts* haben wir es mit einem **proaktiven** Verhalten zu tun:
  Es wird die Stelle der Template Instanziierung in Übereinstimmung mit dem Concept analysiert,
  im Fehlerfall erfolgt die Fehlermeldung an der Stelle des Fehlers.

*Beispiel*:

```cpp
01: std::list<int> numbers{ 5, 6, 1, 3, 7 };
02: 
03: std::sort(
04:     numbers.begin(),
05:     numbers.end()
06: );
```

Die Fehlermeldung lautet

```
binary '-':
'const std::_List_unchecked_iterator<std::_List_val<std::_List_simple_types<_Ty>>>'
does not define this operator or a conversion to a type acceptable to the predefined operator
```

und sie wird aus der Datei *algorithm.h* in Zeile 8244 gemeldet!

*Beispiel*:

```cpp
01: std::list<int> numbers{ 5, 6, 1, 3, 7 };
02: std::ranges::sort(numbers);
```

Die Fehlermeldung lautet nun

```
   20 |         std::ranges::sort(numbers);
      |         ~~~~~~~~~~~~~~~~~^~~~~~~~~
      |     note:   'std::random_access_iterator_tag' is not a base of 'std::bidirectional_iterator_tag'
      |     concept derived_from = __is_base_of(_Base, _Derived)
      | 
```

Dieses Mal finden wir die Zeilennummer 20 und die korrekte Zuordnung zur Quelldatei vor.

---

## *Views* (Ansichten) <a name="link5"></a>

  * Views sind so genannte *Lightweight Ranges* (*leichtgewichtige Bereiche*).

  * Views besitzen *non-owning* (nicht besitzende) Referenzen der Daten.

  * Views können über die Elemente eines Bereichs iterieren
   und dabei die Daten transformieren oder filtern.

  * Views benötigen eine konstante Zeitkomplexität zum Kopieren, Verschieben oder Zuweisen von Ansichten.


*Syntax*:

```cpp
std::ranges::operation_view { range, arguments... }
```


*Beispiel*:

```cpp
01: std::vector<int> numbers = { 1, 2, 3, 4, 5, 6 };
02: 
03: auto view{ std::ranges::take_view{ numbers, 3 } };
04: 
05: std::ranges::for_each(
06:     view,
07:     [] (auto n) { std::print("{} ", n); }
08: );
```

*Ausgabe*:

```
1 2 3
```

Normalerweise werden Ansichten nicht mit ihren Konstruktoren,
sondern mit *Range Adaptors* (Bereichsadapter) erstellt.

---

## *Range Adaptors* (Bereichsadapter) <a name="link6"></a>

  * Bereichsadapter sind Hilfsfunktionen, die Views erstellen,
  wie beispielsweise `views::filter` , `views::transform` 
  und `views::take`.

  * Es ist vorzuziehen, Adapter zum Erstellen von Ansichten zu verwenden, da sie Optimierungen ermöglichen:
```
range | std::ranges::views::operation(arguments...)
```

  * Bereichsadapter können zusammengesetzt werden (*Composition*),
  um komplexe *Data Processing Pipelines* (Datenverarbeitungspipelines) effizient aufzubauen.


*Beispiel*:

```cpp
01: std::vector<int> numbers = { 1, 2, 3, 4, 5, 6 };
02: 
03: auto result = numbers 
04:     | std::views::filter([](auto n) { return n % 2 == 0; })
05:     | std::views::transform([](auto n) { return n * 2; });
06: 
07: for (auto n : result) {
08:     std::print("{} ", n);
09: }
```

*Ausgabe*:

```
4 8 12
```

---

## *Function Composition, Pipelines* (Komposition von Funktionen) <a name="link7"></a>

  * Da es sich bei einer View (Ansicht) um einen Range (Bereich) handelt,
  kann man eine Ansicht als Argument für eine andere Ansicht verwenden,
  um eine Verkettung zu ermöglichen:

*Beispiel*:

```cpp
01: std::vector<int> numbers = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
02: 
03: auto result {
04:     std::views::reverse(
05:         std::views::take(
06:             std::views::transform(
07:                 std::views::filter(numbers, [](auto n) { return n % 2 == 0; }),
08:                 [](auto n) { return n * n; }
09:             ),
10:             4
11:         )
12:     ) 
13: };
14: 
15: std::ranges::for_each(
16:     result,
17:     [](auto n) { std::print("{} ", n); }
18: );
```

*Ausgabe*:

```
64 36 16 4
```

  * Übermäßige Verschachtelung kann zu Lesbarkeits- und Wartungsproblemen führen.

  * Es gibt eine weitere Möglichkeit, Bereiche und Ansichten zu kombinieren,
  indem Sie den Pipe-Operator `|` verwenden:

*Beispiel*:

```cpp
01: std::vector<int> numbers = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
02: 
03: auto result = numbers | std::views::filter([](auto n) { return n % 2 == 0; })
04:     | std::views::transform([](auto n) { return n * n; })
05:     | std::views::take(4)
06:     | std::views::reverse;
07: 
08: for (auto n : result) {
09:     std::print("{} ", n);
10: }
```

---

## *Lazy Evaluation* (*Lazy* Auswertung) <a name="link8"></a>

  * Eine Ansicht ist lediglich die Beschreibung einer Verarbeitung.

  * Die Verarbeitung findet nicht statt, wenn man die Ansicht definiert.

  * Die eigentliche Verarbeitung wird Element für Element ausgeführt, wenn der nächste Wert *angefordert* wird.

*Beispiel*:

```cpp
01: auto lazySquares = 
02:     std::views::iota(1, 10) | std::views::transform([](auto i) { return i * i; });
03: 
04: for (auto n : lazySquares) {
05:     std::print("{} ", n);             // squares are calculated here
06: }
```

*Ausgabe*:

```
1 4 9 16 25 36 49 64 81
```

---

## *Eager Evaluation* (*Gierige* Auswertung) <a name="link9"></a>

  * Ab C++ 23 gibt es mit `std::ranges::to` ein einfache `Möglichkeit`,
  dass eine View *gierig* ausgewertet wird und das Ergebnis in einem Container gespeichert wird.

  * `std::ranges::to` ist ein Klassentemplate, der Elementtyp kann infolgedessen weggelassen werden
  und wird dann mithilfe von CTAD (*Class Template Argument Deduction*) entsprechend dem Elementtyp der View abgeleitet.


*Beispiel*:

```cpp
01: auto squares = std::views::iota(1, 10)
02:     | std::views::transform([](auto i) { return i * i; })
03:     | std::ranges::to<std::vector>();
04: 
05: for (auto n : squares) {
06:     std::print("{} ", n);
07: }
```


*Ausgabe*:

```
1 4 9 16 25 36 49 64 81
```

  
---

## Begrenzte vs. unbegrenzte (unendliche) Ranges <a name="link10"></a>

  * `std::views::iota` kann als eine *Range-Factory* angesehen werden,
  die eine Sequenz von Elementen generiert, indem sie einen Anfangswert wiederholt inkrementiert.

  * Die Sequenz kann entweder begrenzt oder unbegrenzt (unendlich) sein.

  * `std::views::iota(10)` ist eine *lazy* View. Sie erzeugt nur dann einen neuen Wert,
  wenn dieser angefordert wird.


*Beispiel*:

```cpp
01: // use bounded std::views::iota with begin and end value
02: for (int n : std::views::iota(0, 10)) {
03:     std::print("{} ", n);
04: }
05: std::println();
06:         
07: // use infinite std::views::iota in combination with std::views::take
08: for (int n : std::views::iota(0) | std::views::take(10)) { 
09:     std::print("{} ", n);
10: }
11: std::println();
12:         
13: // use infinite std::views::iota in combination with std::views::take_while
14: for (int n : std::views::iota(0) | std::views::take_while([] (int y) { return y < 10; })) {
15:     std::print("{} ", n);
16: }
17: std::println();
```

*Ausgabe*:

```
0 1 2 3 4 5 6 7 8 9
0 1 2 3 4 5 6 7 8 9
0 1 2 3 4 5 6 7 8 9
```

---

## *Lazy* Auswertung, Beispiel für Primzahlen <a name="link11"></a>

Wir betrachten ein Beispiel zur Berechnung von Primzahlen:

*Beispiel*:

```cpp
01: bool isPrime(int num)
02: {
03:     if (num <= 1) return false;
04:     if (num % 2 == 0) return false;
05: 
06:     for (int i = 2; i * i <= num; ++i) {
07:         if (num % i == 0) return false;
08:     }
09: 
10:     return true;
11: }
12: 
13: void test()
14: {
15:     // generate an infinite range starting from 2
16:     auto numbers = std::ranges::iota_view{ 2 };
17: 
18:     // filter the numbers to keep only prime numbers and take the first 20 ones
19:     auto primeNumbers = numbers
20:         | std::views::filter(isPrime)
21:         | std::views::take(20);
22: 
23:     // print the first 20 prime numbers
24:     for (int prime : primeNumbers) {
25:         std::cout << prime << " ";
26:     }
27: }
```

*Ausgabe*:

```
3 5 7 11 13 17 19 23 29 31 37 41 43 47 53 59 61 67 71 73
```

---

## Projektionen (*Projections*) <a name="link12"></a>

  * Viele bereichsbasierte Algorithmen haben einen so genannten *Projektionsparameter*,
  einen Rückruf, der jedes Element vor der Verarbeitung transformiert.

  * Beispiel: Projektionsparameter der Funktion `std::ranges::sort()`<br />
  (entnommen aus [https://en.cppreference.com/w/cpp/algorithm/ranges/sort](https://en.cppreference.com/w/cpp/algorithm/ranges/sort)):

```cpp

template<ranges::random_access_range R,
         class Comp = ranges::less,
         class Proj = std::identity>
    requires std::sortable<ranges::iterator_t<R>, Comp, Proj>
constexpr ranges::borrowed_iterator_t<R>
sort( R&& r, Comp comp = {}, Proj proj = {} );
```


*Beispiel*:

```cpp
01: std::vector<int> numbers = { -8, 4, -6, -3, 2, -5, 10, 7, 1, -9 };
02: 
03: // using projection
04: std::ranges::sort(
05:     numbers,
06:     std::ranges::less{},                  // comparison
07:     [](auto n) { return std::abs(n); }    // identity
08: );
09: 
10: for (auto elem : numbers) {
11:     std::print("{} ", elem);
12: }
13: std::println();
```


*Ausgabe*:

```
1 2 -3 4 -5 -6 7 -8 -9 10
```

*Beispiel*:

```cpp
01: std::vector<int> numbers = { -8, 4, -6, -3, 2, -5, 10, 7, 1, -9 };
02: 
03: // using defaulted projection and original value
04: std::ranges::sort(
05:     numbers,
06:     {},
07:     {}
08: );
09: 
10: for (auto elem : numbers) {
11:     std::print("{} ", elem);
12: }
```

*Ausgabe*:

```
-9 -8 -6 -5 -3 1 2 4 7 10
```

---

## Sentinels <a name="link13"></a>

  * *Sentinels* stellen das Ende eines Bereichs dar:

  * Beispiele für Sentinels in der Programmierung:

    * EOF als Ende eines Dateistreams
    * Der Nullterminator `\0` als Ende einer Zeichenfolge im C-Stil
    * `nullptr` als Ende einer verknüpften Liste
    * `-1` als Ende einer Liste mit nicht-negativen Ganzzahlen
    * `\n` als Ende einer Zeile

  * Im Gegensatz zum traditionellen iteratorenbasierten STL-Ansatz,
  bei dem Anfang und Ende einer Sequenz (STL-Container) durch Iteratoren desselben Typs gekennzeichnet sind,
  können der Typ des Sentinels und der des Anfangsiterators unterschiedlich sein.

  * Dieses Feature kann nützlich sein,
  wenn das Ende der Sequenz ungewiss ist, bis es während der Iteration erreicht wird.


*Beispiel*:

```cpp
01: struct NegativeNumber
02: {
03:     bool operator== (std::input_iterator auto iter) const {
04:         return *iter < 0;
05:     }
06: };
07: 
08: static void ranges_sentinels_01()
09: {
10:     std::vector<int> numbers{ 1, 2, 3, -4, 5, 6 };
11: 
12:     std::ranges::transform(
13:         numbers.begin(),
14:         NegativeNumber{},   // <== sentinel
15:         numbers.begin(),
16:         [](const auto& n) { return n * n; }
17:     );
18: 
19:     for (auto elem : numbers) {
20:         std::print("{} ", elem);
21:     }
22: }
```

*Ausgabe*:

```
1 4 9 -4 5 6
```

*Beispiel*:

```cpp
01: std::vector<int> numbers{ 1, 2, 3, -4, 5, 6 };
02: 
03: std::ranges::for_each(
04:     numbers.begin(),
05:     NegativeNumber{},     // <== sentinel
06:     [] (auto n) { std::print("{} ", n); }
07: );
```

*Ausgabe*:

```
1 2 3
```

*Beispiel*:

```cpp
01: std::vector<int> numbers{ 1, 2, 3, -4, 5, 6 };
02: 
03: auto range{ 
04:     std::ranges::subrange{
05:         numbers.begin(),
06:         NegativeNumber{}    // <== sentinel
07:     }
08: };
09: 
10: for (auto elem : range) {
11:     std::print("{} ", elem);
12: }
```

*Ausgabe*:

```
1 2 3
```


*Beispiel*:

```cpp
01: const char* str = "Hello, World!";
02: 
03: std::ranges::for_each(
04:     str,
05:     TerminatingZero{},
06:     [] (char c) { std::print("{} ", c); }
07: );
```


*Ausgabe*:

```
H e l l o ,   W o r l d !
```

---

## *Dangling Iterators* / *Borrowed Iterators*  <a name="link14"></a>

  * Wenn man einen temporären Bereich an einen Algorithmus übergibt, der einen Iterator zurückgibt,
  ist der zurückgegebene Iterator am Ende der Anweisung ungültig, da der Bereich zerstört wird.

  * Dieses Problem würde nicht auftreten, wenn man einen Bereich mit zwei Argumenten definiert (Anfang und Ende).

  * Die *Ranges* Bibliothek führt zu diesem Zweck das Konzept so genannter *Borrowed Iterators* ein.

  * Wenn der an einen Algorithmus übergebene Range ein temporäres Objekt ist,
  dann ist der Rückgabewert ein Objekt vom Typ `std::ranges::dangling`.

*Beispiel*:

```cpp
01: std::vector<int> getData()
02: {
03:     return std::vector<int> { 1, 2, 3, 4, 5 };
04: }
05: 
06: void test()
07: {
08:     auto pos = std::ranges::find( getData(), 123); 
09: 
10:     std::println("{} ", *pos);
11: }
```

Dieses Beispiel ist *nicht* übersetzungsfähig! Die Fehlermeldung lautet in etwa

```
Error: You cannot dereference an operand of type 'std::ranges::dangling'
```

  * Der Typ `std::ranges::dangling` stellt keinerlei Operationen bereit,
  man kann ihn in einem Programm nicht verwenden!
  Er dient ausschließlich dem Zweck,
  eine praktische Fehlermeldung zu erzeugen,
  um darauf hinzuweisen, was schiefgelaufen ist.

  * Die Lösung des Problems besteht darin, dass man dem temporären Bereich
  einen Namen geben muss:

*Beispiel*:

```cpp
01: const auto& values = getData();               // declare const lvalue reference
02: 
03: auto value{ 3 };
04: 
05: auto pos = std::ranges::find(values, value);
06: 
07: if (pos == values.end()) {
08:     std::println("Value {} not found!", value);
09: }
10: else {
11:     std::println("Value {} found!", *pos);
12: }
```

*Ausgabe*:

```
Value 3 found!
```


---

## `std::map`: Views für Schlüssel und Werte von Assoziativ-Containern <a name="link15"></a>

  * Mit *Ranges* ist es erheblich leichter, auf die Schlüssel und Werte von
  Assoziativ-Containern wie `std::map`, `unordered_map`, etc. zugreifen zu können. 

  * Es gibt sogar gleich mehrere Möglichkeiten bzw. Schreibweisen,
  wir werden einen Blick auf die Ermittlung der Schlüssel.

  * Klassische Vorgehensweise &ndash; auschließlich Verwendung der STL:

*Beispiel*:

```cpp
01: std::map<std::string, int> map{ 
02:     { "one",   1 }, 
03:     { "two",   2 },
04:     { "three", 3 }, 
05:     { "four",  4 }, 
06:     { "five",  5 } 
07: };
08: 
09: std::vector<std::string> keys{};
10: 
11: std::transform(
12:     map.begin(),
13:     map.end(),
14:     std::back_inserter(keys),
15:     [] (const auto& elem) { return elem.first; }
16: );
17: 
18: for (const auto& key : keys) {
19:     std::print("{} ", key);
20: }
```

*Ausgabe*:

```
five four one three two
```

  * Moderne Vorgehensweise &ndash; Verwendung der *Ranges* Bibliothek:


*Beispiel*:

```cpp
01: std::map<std::string, int> map{
02:     { "one",   1 },
03:     { "two",   2 },
04:     { "three", 3 },
05:     { "four",  4 },
06:     { "five",  5 }
07: };
08: 
09: auto strings{ std::views::keys(map) };
10: 
11: for (const auto& s : strings) { std::print("{} ", s); }
12: std::println();
13:         
14: for (const auto& s : std::views::keys(map)) { std::print("{} ", s); }
15: std::println();
16: 
17: auto keysView = map | std::views::keys;
18: 
19: for (const auto& s : keysView) { 
20:     std::print("{} ", s);
21: }
```

Das Beispiel produziert diesselbe Ausgabe wie das Beispiel zuvor.

---

## `std::views::common` <a name="link16"></a>

Der Gebrauch von `std::views::common` ermöglicht:

  * Kombination von `std::ranges::views` und `std::accumulate` (kein bereichsbasierter Algorithmus)

  * `std::views::common` erstellt eine View mit konsistenten Typen von Anfangs- und Enditeratoren.


*Beispiel*:

```cpp
01: auto numbers = std::views::iota(1) | std::views::take(10);
02:         
03: auto evenNumbers = numbers
04:     | std::views::filter([](int n) { return n % 2 == 0; })
05:     | std::views::common;
06:         
07: int sum{ std::accumulate(evenNumbers.begin(), evenNumbers.end(), 0) };
08:         
09: std::print("Sum: {} ", sum);
```


*Ausgabe*:

```
Sum: 30
```

---

## Das Trio `std::all_of`, `std::any_of` und `std::none_of` <a name="link17"></a>

  * Das Trio der booleschen Algorithmen `std::all_of`, `std::any_of` und `std::none_of`
  liefert die entsprechenden booleschen Reduktionen auf der Grundlage eines unären Prädikats.

  * Während `std::all_of` und `std::none_of` für leere Bereiche *true* zurückgeben,
  erfordert `std::any_of` mindestens ein Argument und gibt für einen leeren Bereich *false* zurück.


*Beispiel*:

```cpp
01: std::vector<int> numbers = { 2, 4, 6, 8, 10 };
02: 
03: bool anyNegative = std::ranges::any_of(numbers, [](int x) { return x < 0; });    // false
04: std::println("any_of:  {} ", anyNegative);
05:         
06: bool noneNegative = std::ranges::none_of(numbers, [](int x) { return x < 0; });  // true
07: std::println("none_of: {} ", noneNegative);
08:         
09: bool allEven = std::ranges::all_of(numbers, [](int x) { return x % 2 == 0; });   //true
10: std::println("all_of:  {} ", allEven);
```

*Ausgabe*:

```
any_of:  false
none_of: true
all_of:  true
```


---

## Zwei Beispiele zum Abschluss: `std::variant` und `std::variant` <a name="link18"></a>

Wir beenden unsere *Ranges*-Betrachtungen mit zwei Beispielen:

#### Beispiel mit der Klasse `std::variant`

  * Erstellung eines Vektors mit Zahlen und Zeichenfolgen.
  * Die Zeichenfolgen werden mit `std::views::filter` herausgefiltert.


*Beispiel*:

```cpp
01: std::vector<std::variant<int, std::string>> mixedData = { 1, 2, "three", 4, "five", "six" };
02: 
03: auto stringValues = mixedData 
04:     | std::views::filter([](const auto& var) { return std::holds_alternative<std::string>(var); }
05: );
06:         
07: for (const auto& str : stringValues) {
08:     std::cout << std::get<std::string>(str) << " ";
09: }
```

*Ausgabe*:

```
three five six
```

#### Beispiel mit der Klasse `std::unordered_map`

  * Das Transformieren von Elementen eines Bereichs erfordert nicht unbedint, dass der resultierende Bereich Elemente desselben Typs enthält..
  * Man kann Elemente Elementen eines anderen Typs zuordnen.

*Beispiel*:

```cpp
01: std::vector<int> numbers{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
02: 
03: std::unordered_map<int, std::string> map {
04:     { 1, "one"   },
05:     { 2, "two"   },
06:     { 3, "three" },
07:     { 4, "four"  },
08:     { 5, "five"  }
09: };
10:         
11: auto result = numbers
12:     | std::views::filter([](const auto& n) { return n <= 5; })
13:     | std::views::transform([&](const auto& n) { return map[n]; });
14:         
15: for (const auto& str : result) {
16:     std::cout << str << " ";
17: }
```

*Ausgabe*:

```
one two three four five
```

---

## Literatur <a name="link19"></a>

Die Beispiele und Anregungen dieses Abschnitts wurden sehr stark inspiriert von dem Aufsatz
[&bdquo;C++ 20 Ranges. Practical examples&rdquo;](https://indico.gsi.de/event/19561/contributions/78837/attachments/46921/67160/cpp_ranges.pdf)
von *Semen Lebedev*.

---

[Zurück](../Clean_Code/Readme_Clean_Code.md)

---
