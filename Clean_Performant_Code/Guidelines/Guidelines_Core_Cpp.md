# Guidelines Core C++

[Zurück](./Readme_Guidelines.md)

---

## Inhalt

  * [Zum Ersten: Klasse (`class`) oder Struktur (`struct`)?](#link1)
  * [Zum Zweiten: Klasse (`class`) oder Struktur (`struct`)?](#link2)
  * [Zum Dritten: Klasse (`class`) oder Struktur (`struct`)?](#link3)
  * [Interfaces (Schnittstellen): Wozu?](#link4)
  * [Minimieren Sie die Sichtbarkeit von Mitgliedern einer Klasse](#link5)
  * [Lebenszyklus eines Objekts: Spezielle Member-Funktionen](#link6)
  * [Automatische Erzeugung der speziellen Member-Funktionen: Wann?](#link7)
  * [Automatische Erzeugung der speziellen Member-Funktionen: Wie?](#link8)
  * [*Explicitly defaulted* Standardkonstruktor](#link9)
  * [*Explicitly deleted* Standardkonstruktor](#link10)
  * [Automatische Erzeugung spezieller Member-Funktionen: Fazit](#link11)
  * [Literatur](#link)


  * [Schreiben Sie kleine, fokussierte Funktionen (Methoden)](#link)
  * [Verwenden Sie `const` großzügig](#link)
  * [Ausnahmen (*Exceptions*) sind Fehlercodes (*Error Codes*) vorzuziehen](#link)
  * [Rückgabetyp einer Methode](#link)
  * [Bevorzuge Komposition der Vererbung](#link)
  * [Implizite Konvertierungen vermeiden](#link)
  * [Schlüsselwort `auto` verwenden oder nicht?](#link)

---

#### Zum Ersten: Klasse (`class`) oder Struktur (`struct`)? <a name="link1"></a>

  * Verwenden Sie Strukturen (`struct`), wenn der zu konzipierende Datentyp
   hauptsächlich ein Halter von Daten ist.
  * Verwenden Sie Klassen (`class`), wenn für den zu konzipierenden Datentyp
   die Daten eher als Implementierungsdetails anzusehen sind
   und es das Verhalten (Methoden) ist, was man nach außen zeigen möchte.

#### Zum Zweiten: Klasse (`class`) oder Struktur (`struct`)? <a name="link2"></a>

Eine Richtlinie stammt von Bjarne Stroustrup *himself*:

  * Verwenden Sie Klasse (`class`), wenn es *Invarianten* gibt.
  * Verwenden Sie Strukturen (`struct`), wenn alle Datenelemente sich unabhängig voneinander verändern können.

Es bleibt nur noch zu klären, was man unter einer *Invarianten* versteht?

#### Zum Dritten: Klasse (`class`) oder Struktur (`struct`)? <a name="link3"></a>

Wenn ein (oder mehrere Elemente) mit `private` zu kennzeichnen sind, sollte man `class` verwenden.

#### Interfaces (Schnittstellen): Wozu? <a name="link4"></a>

*Interfaces* stellen nicht nur eine Beschreibung von Methoden dar, sie bewirken damit
auch eine *Hervorhebung*:

  * Zur Implementierung in einer Klasse wird ein Bezug zur Schnittstelle gegeben.
  * In einer Klasse lassen sich Daten kapseln, die relevanten Methoden der Schnittstell sind hervorgehoben.

#### Minimieren Sie die Sichtbarkeit von Mitgliedern einer Klasse <a name="link5"></a>

Ohne Worte :)

#### Lebenszyklus eines Objekts: Spezielle Member-Funktionen <a name="link6"></a>

C++ definiert für den Lebenszyklus eines Objekts eine Reihe von Methoden/Operatoren,
die eine besondere Rolle einnehmen.

Die Schnittstellen dieser Operationen sehen so aus:

| Beschreibung | Schnittstelle |
| :-------- | :------- |
| Standardkonstruktor (Default Constructor) | `X()` |
| Kopierkonstruktor (Copy Constructor) | `X(const X&)` |
| Kopierende Zuweisung (Assignment Operator) | `X& operator=(const X&)` |
| Verschiebekonstruktor (Move Constructor) | `X(X&&) noexcept` |
| Verschiebende Zuweisung (Move Assignment) | `X& operator=(X&&) noexcept` |
| Destruktor (Destructor) | `~X()` |

*Tabelle* 1: Spezielle Member-Funktionen eines C++ Objekts.

#### Automatische Erzeugung der speziellen Member-Funktionen: Wann? <a name="link7"></a>

In manchen Situationen nimmt der Compiler einem Entwickler die Arbeit ab und 
erzeugt für eine oder mehrere der speziellen Member-Funktionen eine Realisierung.

Das gesamte Regelwerk in diesem Umfeld ist nicht ganz trivial,
einen Überblick versucht das folgende Bild zu geben ([hier](https://howardhinnant.github.io/classdecl.html) vorgefunden):

<img src="cpp_special_member_functions.svg" width="700">

*Abbildung* 1: Überblick über die automatische Erzeugung spezieller Member-Funktionen.

Aus *Abbildung* 1 kann man einige wesentliche Aussagen ableiten:

  * Standardkonstruktor:<br/>Der Standardkonstruktor wird automatisch generiert, wenn Sie in der betroffenen Klasse selbst *überhaupt keinen* Konstruktor implementiert haben.
  * Kopierkonstruktor:<br/>Der Kopierkonstruktor wird automatisch generiert, wenn Sie keine der beiden Verschiebeoperationen implementieren.
  * Kopierende Zuweisung:<br/>Die Kopierzuweisung wird automatisch generiert, wenn Sie keine der beiden Verschiebeoperationen implementieren.
  * Verschiebekonstruktor:<br/>Der Verschiebekonstruktor wird automatisch generiert, wenn Sie keine der beiden Kopieroperationen implementieren und alle Elemente verschoben werden können.
  * Verschiebende Zuweisung:<br/>Die verschiebende Zuweisung wird automatisch generiert, wenn Sie keine der beiden Kopieroperationen implementieren und alle Elemente verschoben werden können.
  * Destruktor:<br/>Der Destruktor wird automatisch generiert, wenn Sie keinen Destruktor implementiert haben.

Was erkennen wir an diesen Aussagen?

  * Die beiden *Kopieroperationen* sind unabhängig voneinander:
  Wenn in einer Klasse eine der beiden Kopieroperationen definiert ist,
  könnte der Übersetzer immer noch die andere Operation automatisch erzeugen.

  * Für die beiden *Verschiebeoperationen* gilt das Gegenteil:
  Wird vom Entwickler eine der beiden Operationen implementiert,
  stellt der Compiler *keine* Realisierung der anderen Operation bereit.

#### Automatische Erzeugung der speziellen Member-Funktionen: Wie? <a name="link8"></a>

Natürlich wäre es interessant zu wissen, wie der Quellcode von automatisch erzeugten Member-Funktionen aussieht.
Das ist keine triviale Frage, dennoch kann man ein paar Richtlinien erkennen:

  * Standardkonstruktor:<br/>
    * Für alle Instanzvariablen, die Objekte sind, wird deren Standardkonstruktor aufgerufen.
    * Für alle Instanzvariablen, die elementar sind (`int`, `double`), erfolgt **keine** Initialisierung, also auch keine Vorbelegung mit einem datentypspezifischen Null-Wert!

  * Kopierende Operationen:<br/>
    * Das Objekt wird elementweise kopiert.<br/>
    * Darunter ist zu verstehen, dass für jedes Element, das selbst wieder ein Objekt
    oder eine Variable elementaren Datentyps ist, der zugehörige Zuweisungsoperator aufgerufen wird.
    Für Variablen elementaren Datentyps (und dazu zählen auch Zeigervariablen) bewirkt dies eine bitweise Kopie.
    * Falls Konstanten oder Referenzen vorhanden sind, geschieht dies jedoch nicht, weil sie
    nur initialisiert, aber nicht durch Zuweisung verändert werden können.
    Der Zuweisungsoperator wird vom System in diesem Fall *nicht* erzeugt.
    * *Hinweis*:<br/>Im Falle  von (klassischen) Zeigervariablen entstehen in diesem Fall Probleme (Stichwort: flache versus tiefe Kopie).

  * Verschiebende Operationen:<br/>
    * Für alle Instanzvariablen, die Objekte sind, wird deren entsprechende Verschiebeoperation aufgerufen, falls vorhanden. Anderenfalls erfolgt eine Kopie.
    * Für alle Instanzvariablen, die elementar sind (`int`, `double`), erfolgt eine bitweise Kopie.


#### *Explicitly defaulted* Standardkonstruktor <a name="link9"></a>

Um das manuelle Schreiben leerer Standardkonstruktoren zu vermeiden,
unterstützt C++ das Konzept von *explicitly defaulted* Standardkonstruktoren (*Explicitly defaulted Default Constructors*).

Dadurch können Sie die Klassendefinition wie folgt schreiben,
ohne eine leere Implementierung für den Standardkonstruktor bereitstellen zu müssen:

```cpp
class X
{
public:
    X() = default;
    X(double initialValue);
    X(std::string initialValue);
    // ...
};
```

Klasse `X` definiert zwei benutzerdefinierte Konstruktoren.

Der Compiler generiert jedoch weiterhin einen vom Standardcompiler generierten Standardkonstruktor,
da dieses mithilfe des Schlüsselworts `default` explizit festgelegt wird.

Sie können das `= default` direkt in die Klassendefinition einfügen,
damit kann man sich in der Klassenimplementierung eine leere Implementierung für den Standardkonstruktor sparen.

Zur Vermeidung von Missverständnissen:

Die Implementierung des automatisch erzeugten Standardkonstruktors ist so,
als hätte man `= default` in der Klassendefinition geschrieben.
Diese Aussage gilt für alle speziellen Member-Funktionen.


#### *Explicitly deleted* Standardkonstruktor <a name="link10"></a>

Auch das Gegenteil von *explicitly defaulted Default Constructors* ist möglich
und wird als *Explicitly deleted Default Constructor* bezeichnet.

Sie können beispielsweise eine Klasse mit nur statischen Memberfunktionen definieren
für die Sie keine Konstruktoren schreiben möchten und für die Sie auch nicht möchten,
dass der Compiler den Standardkonstruktor automatisch generiert.

In diesem Fall müssen Sie den Standardkonstruktor explizit löschen:

```cpp
class X
{
public:
    X() = delete;
};
```

#### Automatische Erzeugung spezieller Member-Funktionen: Fazit <a name="link11"></a>

Was sieht die einfachste Strategie aus:

**Rule-of-Zero**

  * Alles sechs speziellen Member-Funktionen dürfen weder implementiert noch mit `= delete` gelöscht werden.
  * Der Compiler generiert alle Member-Funktionen so, wie es benötigt wird.
  * Das funktioniert natürlich nur dann, wenn die automatisch erzeugten Operationen das tun, was sie müssen:
    Korrekt initialisieren, kopieren und verschieben &ndash; und keine Ressourcen übrig lassen.
  * Wann funktioniert das? Wenn man sich auf folgenden Member-Variablen einschränkt:
    * Standard Datentypen
    * Aggregate (Strukturen)
    * STL Standard Container
    * Smart Pointer
 * Was geht nicht:
    * Wenn in den Instanzvariablen klassische Zeiger, die auf mit `new` allokierte Daten zeigen, vorhanden sind.
    * Wenn Referenzen in den Instanzvariablen vorhanden sind.

Wenn keine der fünf speziellen Member-Funktionen selbst geschrieben werden (*Rule-of-Zero*),
weil Sie geschickt auf `new` usw. verzichten, werden diese sämtlich vom Compiler erzeugt,
einschließlich des verschiebenden Konstruktors und des verschiebenden Zuweisungsoperators.

Damit wird Ihr Programmcode performant, einfacher und wartbarer &ndash; und es spart Schreibarbeit.

---

#### Schreiben Sie kleine, fokussierte Funktionen (Methoden) <a name="link"></a>

Funktionen (Methoden) sind die Bausteine der *Clean Code* Programmierung.
Eine gute Funktion sollte klein und fokussiert sein und genau eine Sache tun.
Kleine Funktionen sind leichter zu verstehen, zu testen und wiederzuverwenden.

Einige Richtlinien zum Schreiben sauberer Funktionen:

  * Halten Sie Funktionen kurz, normalerweise unter 50 Zeilen Code.
  * Geben Sie Funktionen beschreibende Namen, die klar vermitteln, was sie tun.
  * Vermeiden Sie Nebeneffekte &ndash; eine Funktion sollte entweder einen Wert berechnen oder eine Aktion ausführen, nicht beides.
  * Bevorzugen Sie &bdquo;reine&rdquo; (*pure*) Funktionen, die bei denselben Eingaben immer das gleiche Ergebnis liefern.
  * Verwenden Sie Parameter für die Eingabe und Rückgabewerte für die Ausgabe zurück, anstatt sich auf den globalen Status zu verlassen.
  * Halten Sie die Anzahl der Parameter niedrig, normalerweise unter 5.


Stellen Sie sich beispielsweise eine Funktion `isValidUsername` vor,
die einen Benutzernamen validiert. Eine saubere Version könnte so aussehen:

```cpp
01: bool isValidUsername(const std::string& username) {
02: 
03:     const auto MinLength{ 8 };
04:     const auto MaxLength{ 30 };
05:         
06:     const std::string ValidCharacters {
07:         "abcdefghijklmnopqrstuvwxyz0123456789_-."
08:     };
09: 
10:     if (username.length() < MinLength || username.length() > MaxLength) {
11:         return false;
12:     }
13: 
14:     for (char ch : username) {
15:         if (ValidCharacters.find(ch) == std::string::npos) {
16:             return false;
17:         }
18:     }
19: 
20:     return true;
21: }
```

Diese Funktion ist kurz (weniger als 20 Zeilen), hat einen eindeutigen Namen, nimmt einen einzigen Eingabeparameter an,
gibt ein boolesches Ergebnis zurück und hat keine Nebenwirkungen. Sie ist leicht zu verstehen und kann ausführlichen Unit-Tests unterzogen werden.

---

#### Verwenden Sie `const` großzügig <a name="link"></a>

`const` ist ein leistungsstarkes Sprachfeature in C++, um Absichten auszudrücken und potenzielle Fehler zur Kompilierzeit abzufangen:

    * Wird es auf eine Variable angewendet, zeigt es an, dass der Wert nicht geändert wird.
    * Wird es auf eine Methode angewendet, zeigt es an, dass die Methode das aufgerufene Objekt nicht ändert.

Einige Richtlinien zur Verwendung von `const`:

  * Deklarieren Sie Funktionsparameter mit `const`, wenn diese von der Funktion nicht geändert werden.
  * Deklarieren Sie Methoden mit `const`, wenn sie den Zustand des gerufenen Objekts nicht ändern.
  * Deklarieren Sie Variablen mit `const`, wenn sich ihre Werte nach der Initialisierung nicht ändern sollen.
  * Verwenden Sie `const`-Referenzen, um unnötiges Kopieren großer Objekte zu vermeiden.

*Beispiel*:

```cpp
01: class Rectangle
02: {
03: private:
04:     double m_width;
05:     double m_height;
06: 
07: public:
08:     Rectangle(double width, double height) 
09:         : m_width(width), m_height(height) 
10:     {}
11: 
12:     double area() const {
13:         return  m_width * m_height;
14:     }
15: 
16:     void scale(double factor) {
17:         m_width *= factor;
18:         m_height *= factor;
19:     }
20: };
21: 
22: static void printArea(const Rectangle& rect) {
23:     std::println("Area: {}", rect.area());
24: }
```

In diesem Beispiel wird die Methode `area()` als `const` deklariert, da sie den Zustand des Rechtecks ​​nicht ändert.

Die Funktion `printArea` nimmt ihren Parameter per `const`-Referenz, was bedeutet,
dass sie das Rechteck nicht ändert und ein unnötiges Kopieren vermeidet.

Die konsequente Verwendung von `const` macht Ihren Code selbstdokumentierender und hilft,
potenzielle Fehler zu erkennen, wie z. B. versehentliche Änderungen an Werten, die konstant sein sollten.

#### Ausnahmen (*Exceptions*) sind Fehlercodes (*Error Codes*) vorzuziehen <a name="link"></a>

Ausnahmen (*Exceptions*) sind die bevorzugte Methode zum Melden und Behandeln von Fehlern in Modern C++.
Sie haben mehrere Vorteile gegenüber herkömmlichen Fehlercodes:

  * Ausnahmen können nicht ignoriert werden, Fehlercodes hingegen schon.
  * Ausnahmen werden automatisch an rufende Methoden weitergegeben, während Fehlercodes an jeder Aufrufstelle manuell überprüft und manuell weitergegeben werden müssen.
  * Ausnahmen trennen den Fehlerbehandlungscode vom normalen Kontrollfluss und machen den Code übersichtlicher

Einige Richtlinien zur Verwendung von Ausnahmen:

  * Verwenden Sie Ausnahmen für außergewöhnliche Bedingungen, nicht für den normalen Kontrollfluss.
  * Werfen Sie Ausnahmen *by value* aus und fangen Sie sie *by reference*.
  * Verwenden Sie nach Möglichkeit Standardausnahmetypen wie `std::runtime_error`, `std::out_of_range` usw.
  * Definieren Sie Ihre eigenen Ausnahmetypen für domänenspezifische Fehler.
  * Vermeiden Sie das Auslösen von Ausnahmen in Destruktoren.
  * Verwenden Sie RAII, um sicherzustellen, dass Ressourcen bei Ausnahmen aufgeräumt werden.

So könnten Sie beispielsweise einen Dateifehler mit Ausnahmen behandeln:

```cpp
01: try {
02:     std::ifstream file("data.txt");
03:             
04:     if (!file.is_open()) {
05:         throw std::runtime_error("Could not open file");
06:     }
07:             
08:     // process the file
09: }
10: catch (const std::exception& e) {
11:     std::cerr << "Error: " << e.what() << std::endl;
12: }
```

Vergleichen Sie dies mit einer Version, die Fehler Codes hantiert:

```cpp
01: std::ifstream file("data.txt");
02: 
03: if (!file.is_open()) {
04:     // handle the error, maybe return an error code  
05: }
06: 
07: // process the file
```

Die Version mit *Exception Handling* trennt die Fehlerbehandlung vom normalen Ablauf
und der Fehler kann nicht ignoriert werden.


#### Rückgabetyp einer Methode <a name="link"></a>

Wir betrachten folgendes Beispiel:

```cpp
01: class Person
02: {
03: private:
04:     std::string   m_name;
05:     size_t        m_age;
06: 
07: public:
08:     Person() = default;
09:     Person(const std::string& name, size_t age)
10:         : m_name{ name }, m_age{ age }
11:     {}
12: 
13:     std::string getName() const { return m_name; }
14:     size_t getAge() const { return m_age; }
15: };
```

*Vorgehensweise*: &bdquo;*Copied to Caller*&rdquo;

Es gibt auch eine zweite Möglichkeit:

```cpp
01: class Person
02: {
03: private:
04:     std::string   m_name;
05:     size_t        m_age;
06: 
07: public:
08:     Person() = default;
09:     Person(const std::string& name, size_t age)
10:         : m_name{ name }, m_age{ age }
11:     {}
12: 
13:     const std::string& getName() const { return m_name; }
14:     size_t getAge() const { return m_age; }
15: };
```

*Vorgehensweise*: &bdquo;*Lifetime by Voucher*&rdquo;

---

#### Bevorzuge Komposition der Vererbung <a name="link"></a>

  * Vererbung ist ein leistungsstarkes Feature der objektorientierten Programmierung,
  wird aber oft überstrapaziert.

  * Vererbung koppelt die abgeleitete Klasse eng an die Basisklasse
  (Stichwort &bdquo;*Strong Coupling*&rdquo; versus &bdquo;*Lose Coupling*&rdquo;),
  wodurch der Code starrer und schwerer zu ändern wird.

  * Sie führt außerdem tendenziell zu tiefen und komplexen Vererbungshierarchien,
  die schwer zu verstehen sind.

  * Komposition hingegen ist eine Technik, bei der eine Klasse Instanzen anderer Klassen enthält,
  anstatt von ihnen zu erben.

  * Dies führt zu einem flexibleren und modulareren Design.

*Beispiel*:

Wenn beispielsweise viele unterschiedliche Klassen in einem 3D-Szenario
ein *Transformations*-Eigenschaft (also eine Position, eine Rotation und eine Skalierung) benötigen,
könnten Sie alle Ihre Klassen von einer Klasse `Transform` ableiten,
Sie könnten eine Transform-Eigenschaft aber auch als Attribut den Klassen hinzufügen:

```cpp
01: class Vector3D{};
02: 
03: class Transform {
04:     Vector3D m_position;
05:     Vector3D m_rotation;
06:     Vector3D m_scale;
07: };
08: 
09: class Character
10: {
11: public:
12:     // functions that might use *m_transform* if they need it
13: 
14: private:
15:     Transform m_transform;
16: };
17: 
18: class Obstacle
19: {
20: public:
21:     // functions that might use *m_transform* if they need it
22: 
23: private:
24:     Transform m_transform;
25: };
```

  * Dadurch haben Sie mehr Kontrolle über die Schnittstelle der &bdquo;untergeordneten&rdquo; Klassen.

  * Denn wenn Sie eine übergeordnete Klasse ändern, wird die Änderung zwangsläufig in allen untergeordneten Klassen widergespiegelt, was oft nicht erwünscht ist.

  * Aber oft müssen Sie der übergeordneten Klasse etwas hinzufügen, weil eine bestimmte untergeordnete Klasse es braucht, und indem Sie dies tun, zwingen Sie es allen anderen untergeordneten Klassen auf, die es nicht unbedingt brauchen oder wollen.

  * Mit Komposition haben Sie mehr Kontrolle darüber.

  * Und Komposition ermutigt Sie natürlich auch, kleinere Klassen zu schreiben, anstatt von einer großen übergeordneten Klasse zu erben.

---

#### Implizite Konvertierungen vermeiden <a name="link"></a>

In der Sprache C++ gibt es des Feature so genannter &bdquo;impliziter Typkonvertierungen&rdquo;.

Hierunter versteht man Konvertierungen, die der Übersetzer automatisch durchführt:

  * Sie werden immer dann durchgeführt, wenn ein Ausdruck eines Typs `T1` in einem Kontext verwendet wird,
  der diesen Typ nicht akzeptiert, aber einen anderen Typ `T2`.

  * Obwohl diese nützlich sein können, können sie auch zu unerwarteten Ergebnissen und Fehlern führen.

Daher ist es manchmal wünschenswert, implizite Konvertierungen zu vermeiden.

*Beispiel*:

```cpp
01: class Distance
02: {
03: private:
04:     int m_meters;
05: 
06: public:
07:     Distance(int meters) : m_meters{ meters } {}
08: 
09:     void display() const {
10:         std::println("Distance: {}", m_meters);
11:     }
12: };
13: 
14: void printDistance(const Distance& d) {
15:     d.display();
16: }
17: 
18: void test() {
19:     auto meters{ 10 };
20:     printDistance(meters);
21: }
```

In diesem Beispiel gibt es neben der Klasse `Distance` eine Funktion `printDistance`,
die ein Objekt vom Typ `Distance` als Argument annimmt.

In der rufenden Funktion haben wir jedoch eine `int`-Variable an die Funktion übergeben
und dennoch wird der Quellcode fehlerfrei übersetzt und korrekt ausgeführt:

Der Compiler hat eine implizite Konvertierung von `int` nach `Distance` durchgeführt!

Um implizite Konvertierungen in C++ zu vermeiden, können wir das Schlüsselwort `explicit` verwenden.

Wenn das Schlüsselwort `explicit` mit einem Konstruktor oder einer Konvertierungsfunktion verwendet wird,
verhindert es implizite Konvertierungen, die automatisch vom Compiler durchgeführt werden.

*Hinweis*:
Mit einer expliziten Typwandlung könnte man die Konvertierung wieder aktivieren,
aber dieses Mal eben nicht versteckt, sondern sichtbar für den Entwickler!

---

#### Schlüsselwort `auto` verwenden oder nicht? <a name="link"></a>

Empfielt sich der Einsatz des Schlüsselworts `auto` oder nicht?

`auto`: **You totally know what you’re doing, or you totally don’t**

*Frage*:

Warum ist dieses Code-Fragment nicht übersetzungsfähig?

```cpp
01: void test()
02: {
03:     std::map<int, std::string> aMap{ { 1, "Hello"  } };
04: 
05:     std::map<int, std::string>::iterator it{ aMap.begin() };
06: 
07:     std::pair<int, std::string>& entry1{ *it };  // Why this line DOES NOT compile ???
08: 
09:     auto& entry2{ *it };                         // This line compiles :)
10: }
```

#### Zwei Empfehlungen:

  * Verwenden Sie es prinzipiell großzügig. Es kann die Lesbarkeit verbessern.
    Der Compiler kann Typen für uns besser ableiten (*Type Deduction*) als wir selbst.

  * Ist der Typ einer Variablen von entscheidender Natur, dann sollte man diesen auch explizit hinschreiben.

*Achtung*:

Verlust von `const` und `&` bei Verwendung von `auto`:

```cpp
01: class Person
02: {
03: private:
04:     std::string   m_name;
05: 
06: public:
07:     Person() = default;
08:     Person(const std::string& name) : m_name{ name } {}
09: 
10:     const std::string& getName() const { return m_name; }
11: };
12: 
13: static void guidelines_keyword_auto_02()
14: {
15:     Person jack{ "Jack", 50 };
16:     auto name = jack.getName();
17: }
```

Es gibt  hier nur eine Warnung:<br />
*auto does not deduce references a possibly unintended copy is being made*.

---

[Zurück](./Readme_Guidelines.md)

---
