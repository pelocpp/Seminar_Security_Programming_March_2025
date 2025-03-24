# Compile-Time Programming

[Zurück](../Performance_Optimization/Readme_Performance_Optimization.md)

---

## Inhalt

  * [Allgemeines](#link1)
  * [Metaprogrammierung mit Templates](#link2)
  * [Verwendung von ganzen Zahlen als Template Parameter](#link3)
  * [Spezialisierung eines Templates](#link4)
  * [Abgekürzte Funktionstemplates &ndash; *Abbreviated Function Templates*](#link5)
  * [Programmieren mit konstanten Ausdrücken und Funktionen](#link6)
  * [Literatur](#link7)

---

#### Quellcode

[*CompileTimeProgramming.cpp*](CompileTimeProgramming.cpp)<br />

---

## Allgemeines <a name="link1"></a>

---

## Metaprogrammierung mit Templates <a name="link2"></a>

*Beispiel*:

```cpp
01: template <typename T>
02: auto powerN(const T& v, size_t n) {
03:     auto product = T{ 1 };
04:     for (size_t i{}; i != n; ++i) {
05:         product *= v;
06:     }
07:     return product;
08: }
09: 
10: void test()
11: {
12:     auto x{ powerN<float>(1.5f, 3) };   // x is a float
13:     auto y{ powerN<int>(3, 4) };        // y is an int
14: 
15:     std::println("powerN: {}", x);
16:     std::println("powerN: {}", y);
17: }
```

---

## Verwendung von ganzen Zahlen als Template Parameter <a name="link3"></a>

*Beispiel*:

```cpp
01: template <int N, typename T>
02: auto morePowerN(const T& v) {
03:     auto product = T{ 1 };
04:     for (size_t i{}; i != N; ++i) {
05:         product *= v;
06:     }
07:     return product;
08: }
09: 
10: void test()
11: {
12:     auto x1{ morePowerN<2>(4) };
13:     auto x2{ morePowerN<3>(4) };
14: }
```


---

## Spezialisierung eines Templates <a name="link4"></a>

*Beispiel*:

```cpp
01: template<>
02: auto morePowerN<2, int>(const int& v) {
03:     return v * v;
04: }
05: 
06: void test()
07: {
08:     auto x{ morePowerN<2>(4) };
09: }
```


---

## Abgekürzte Funktionstemplates &ndash; *Abbreviated Function Templates* <a name="link5"></a>

*Beispiel*:

```cpp
01: auto anotherPowerN(const auto& v, int n) {
02:     auto product = decltype(v){ 1 };
03:     for (size_t i{}; i != n; ++i) {
04:         product *= v;
05:     }
06:     return product;
07: }
08: 
09: void test()
10: {
11:     auto x{ anotherPowerN<float>(1.5f, 3) };
12:     auto y{ anotherPowerN<int>(3, 4) };
13: }
```

---

## Literatur <a name="link6"></a>

Die Anregungen zum konzeptionellen Beispiel finden Sie unter

[https://refactoring.guru/design-patterns](https://refactoring.guru/design-patterns/memento/cpp/example#example-0)

und 

[https://www.codeproject.com](https://www.codeproject.com/Articles/455228/Design-Patterns-3-of-3-Behavioral-Design-Patterns#Memento)

vor.

Das *Real*-*World*-Beispiel kann [hier](https://vishalchovatiya.com/posts//memento-design-pattern-in-modern-cpp/) im Original nachgelesen werden.

---

[Zurück](../Performance_Optimization/Readme_Performance_Optimization.md)

---
