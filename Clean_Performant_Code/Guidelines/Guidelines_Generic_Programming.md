# Guidelines Generische Programmierung

[Zurück](./Readme_Guidelines.md)

---

## Inhalt

  * [Allgemeines](#link1)
  * [Literatur](#link19)


---

## Allgemeines <a name="link1"></a>

---

## Wozu dienen Tempates?

Man kann den Abstraktionslevel des Quellcodes steigern.

*Beispiel*:

```cpp
01: bool isGreaterThanFifty(int n) {
02: 
03:     return n > 50;
04: }
05: 
06: template <typename T>
07: bool isGreaterThanFifty(T n) {
08: 
09:     return n > T{ 50 };
10: }
11: 
12: bool isGreaterThanFifty(auto n) {
13: 
14:     return n > decltype(n) { 50 };
15: }
```

---

## Templates und Algorithmen

Nutzen Sie Templates zur Beschreibung von Algorithmen,
die sich auf viele Argumente anwenden lassen.

---

## Templates und Container (*Ranges*)

Nutzen Sie Templates zur Beschreibung von Containern und Bereichen.

---


## Literatur <a name="link19"></a>


Die Beispiele und Anregungen dieses Abschnitts wurden sehr stark inspiriert von dem Aufsatz
[&bdquo;C++ 20 Ranges. Practical examples&brquo;](https://indico.gsi.de/event/19561/contributions/78837/attachments/46921/67160/cpp_ranges.pdf)
von *Semen Lebedev*.

---

[Zurück](./Readme_Guidelines.md)

---
