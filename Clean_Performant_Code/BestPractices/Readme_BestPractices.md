# C++ Performance Optimierung: Best Practices

[Zurück](../Performance_Optimization/Readme_Performance_Optimization.md)

---

## Inhalt

  * [Vermeiden Sie unnötiges Kopieren](#link1)
  * [Bevorzuge Stack Allokation](#link2)
  * [Schleifen optimieren](#link3)
  * [Vermeiden Sie *Raw*-Schleifen](#link4)
  * [Reduzieren Sie Funktionsaufrufe](#link5)
  * [Literatur](#link6)

---

#### Quellcode

[*BestPractices.cpp*](BestPractices.cpp)<br />

---

## Vermeiden Sie unnötiges Kopieren <a name="link1"></a>

Das Kopieren von Objekten kann teuer sein.

Verwenden Sie beim Übergeben von Objekten Referenzen oder Verschiebesemantik (`std::move`),
um unnötiges Kopieren zu minimieren.

Hat man bei Parametern die Wahl zwischen `const std::string&` und `std::string_view`,
so sollte man `std::string_view` verwenden. Nicht immer,
aber häufig kann in diesem Fall die Performance besser sein.

---

## Bevorzuge Stack Allokation <a name="link2"></a>

Legen Sie Objekte nach Möglichkeit auf dem Stapel an,
da die Stack Allokation schneller ist als eine dynamische
Speicherplatzreservierung auf der Halde (*Heap*).

Verwenden Sie die dynamische Speicherplatzreservierung (`new` and `delete`) nur dann,
wenn die Lebensdauer des Objekts über den aktuellen Scope hinausgehen soll.

Es ist jedoch wichtig zu beachten, dass die Stack Allokation Einschränkungen hat:

  * Feste Größe:<br />
    Die Größe des Stapelspeichers ist fest und begrenzt.
    Das bedeutet, dass man keine sehr großen Objekte oder eine dynamische Anzahl von Objekten auf dem Stapel ablegen kann.

  * Das Risiko eines *Stack Overflows*:<br />
    Übermäßiger Stapelspeicherverbrauch kann zu einem Stapelüberlauf (*Stack Overflow*) führen,
    wenn der verfügbare Stapelspeicherplatz erschöpft ist.
    Der Heap-Speicher kennt diese Einschränkung nicht.

---

## Schleifen optimieren <a name="link3"></a>

Schleifen bilden oft den Kern von Algorithmen.

Optimieren Sie Schleifen, indem Sie den Overhead von Schleifen,
unnötige Berechnungen reduzieren und die richtigen Schleifenkonstrukte verwenden
(z. B. bereichsbasierte Schleifen / *range-based for loop*).

---

## Vermeiden Sie *Raw*-Wiederholungschleifen <a name="link4"></a>

*Raw*-Wiederholungschleifen drücken keine Absicht aus &ndash; vor allem in Bezug auf die Lesbarkeit des Quellcodes &ndash;,
Algorithmen jedoch schon.

*Beispiel*: *Violating the Rule*

```cpp
01: void processMoreData(const std::vector<int>& data) {}
02: 
03: void processData(const std::vector<int>& data)
04: {
05:     bool inRange{ true };
06: 
07:     for (const auto& elem : data) {
08:         if (elem < 5 || elem > 100) {
09:             inRange = false;
10:             break;
11:         }
12:     }
13: 
14:     if (inRange) {
15:         processMoreData(data);
16:     }
17: }
```

*Beispiel*: *Respecting the Rule*

```cpp
01: void processMoreData(const std::vector<int>& data) {}
02: 
03: void processData(const std::vector<int>& data)
04: {
05:     auto inRange = [](int value) { 
06:         return value < 5 || value > 100;
07:     };
08: 
09:     const bool allInRange = std::all_of(data.begin(), data.end(), inRange);
10: 
11:     if (allInRange) {
12:         processMoreData(data);
13:     }
14: }
```

---

## Reduzieren Sie Funktionsaufrufe <a name="link5"></a>

Minimieren Sie Funktionsaufrufe innerhalb enger Schleifen.

Durch *Inline*-Funktionen (z. B. mit Hilfe von `inline`- oder Compileroptimierungen)
kann der Funktionsaufruf-Overhead eliminiert werden.

---

## Literatur <a name="link6"></a>

Die Anregungen zum konzeptionellen Beispiel finden Sie unter

[C++ Performance Optimization: Best Practices](https://hackernoon.com/c-performance-optimization-best-practices)

---

[Zurück](../Performance_Optimization/Readme_Performance_Optimization.md)

---
