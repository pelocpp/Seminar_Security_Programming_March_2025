# Klassische Prinzipien der Clean Code Programmierung

[Zurück](../Clean_Code/Readme_Clean_Code.md)

---

## Inhalt

  * [KISS](#link1)
  * [YAGNI](#link2)
  * [DRY](#link3)
  * [POLS](#link4)
  * [*Kohäsion* und *Kopplung*](#link5)
  * [RAII](#link6)
  * [Literatur](#link7)

---

#### Quellcode

[*Principles.cpp*](Principles.cpp)<br />

---

## KISS <a name="link1"></a>

KISS ist ein Akronym für &bdquo;*Keep it simple and stupid*&bdquo;.

Das KISS-Prinzip besagt, dass Einfachheit ein Hauptziel bei der Softwareentwicklung sein sollte
und dass unnötige Komplexität vermieden werden sollte.

KISS ist eines der Prinzipien ist, die Entwickler bei der Softwareentwicklung oft vergessen.

Es ist ratsam, nicht jedes ausgefallene Feature einer Programmiersprache oder coole Designmuster zu verwenden,
nur weil Sie es können.

Halten Sie Ihren Code so einfach wie möglich! Wenn hohe Qualitätsanforderungen an Flexibilität und Erweiterbarkeit gestellt werden,
müssen Sie natürlich Komplexität hinzufügen, um diese Anforderungen zu erfüllen.

Sie können beispielsweise das bekannte &bdquo;Strategie Entwurfsmuster&rdquo; verwenden,
um einen flexiblen Variationspunkt in Ihren Code einzuführen, wenn die Anforderungen dies erfordern.

Aber seien Sie vorsichtig und fügen Sie nur so viel Komplexität hinzu, dass solche Dinge einfacher werden.

---

## YAGNI <a name="link2"></a>

YAGNI ist ein Akronym für &bdquo;You ain’t gonna need it!&rdquo;.

Das Prinzip besagt, dass Sie keinen Code schreiben sollten, der im Moment nicht erforderlich ist, aber in Zukunft erforderlich sein könnte.

Viele Entwickler denken bei der Programmierung eines Programms gerne ein paar Schritte voraus
und programmieren einige zusätzliche Funktionen, &bdquo;nur für den Fall, dass wir sie brauchen&rdquo;
oder zumindest &bdquo;irgendwann einmal brauchen werden&rdquo;.

Nur 5 Wörter: „You Aren’t Gonna Need It“.

Halten Sie sich an YAGNI: Schreiben Sie Qellcode erst, wenn Sie wissen, dass sie ihn wirklich benötigen, nicht vorher.

#### Dem Yagni-Prinzip folgen: Ein Selbsttest

Folgen Sie dem Yagni-Prinzip? Wenn ja, wie genau machen Sie das?
Hier ist ein einfacher Test, der Ihnen dabei helfen kann, das zu beurteilen.
Nehmen Sie ihn aber nicht zu ernst.

*Aufgabe*: Erstellen Sie eine Funktion, die die Summe von 2 und 3 berechnet. Wie würden Sie diese Funktion implementieren?

*Erste Antwort*:

So würden die meisten Entwickler vorgehen:

```cpp
01: static int sum(int x, int y)
02: {
03:     return x + y;
04: }
```

Sehen Sie hier ein Problem? In diesem Code gibt es eine voreilige Verallgemeinerung:
Statt einer Methode, die die Summe von 2 und 3 berechnet, wie es in der Problemdefinition gefordert wurde,
haben wir eine Funktion implementiert, die die Summe zweier beliebiger Zahlen zurückgibt.

Hier ist die Version, die dem Yagni-Prinzip folgt:

```cpp
01: static int sumTwoAndThree()
02: {
03:     return 2 + 3;
04: }
```

Natürlich ist das nur ein Spielzeugbeispiel, aber es zeigt, wie tief in unserem Geist die Gewohnheit verankert ist,
Verallgemeinerungen vorzunehmen.

---

## DRY <a name="link3"></a>

Wie oft entdeckt man ähnlichen Quellcode in verschiedenen Teilen innerhalb eines Programms?

Genau hier kommt DRY ins Spiel, was im Deutschen so viel bedeutet wie &bdquo;Wiederhole Dich nicht&rdquo; (&bdquo; Don’t Repeat Yourself&rdquo;).

Das DRY-Prinzip, formuliert von Andrew Hunt und David Thomas, besagt, das Code-Wiederholungen zu vermeiden sind.

Also Finger weg von Copy&Paste.

Die DRY-Programmierung kann besonders in großen Anwendungen nützlich sein, in denen Code ständig von vielen Programmierern gepflegt, geändert und erweitert wird.

---

## POLS <a name="link4"></a>

Das &bdquo;Principle of Least Surprise&rdquo; (&bdquo;Prinzip der geringsten Überraschung&rdquo;),
auch unter der Abkürzung POLS bekannt, ist eine goldene Regel in der Software-Ergonomie, der Mensch-Computer-Interaktion und dem Interfacedesign.

Diese Regel wurde z. B. 1987 von *Geoffrey James* in seinem Buch *The Tao of Programming* als &bdquo;Law of Least Astonishment&rdquo; formuliert.
Sie besagt, dass eine Benutzerschnittstelle so ausgelegt werden sollte, dass der Benutzer möglichst wenige Überraschungen erlebt.

Das &bdquo;Principle of Least Surprise&rdquo; wird auch auf den Quellcode von Anwendungen erweitert.
Hierbei sollen Objekte wie Variablen, Funktionen, Methoden, Klassen und dergleichen derart benannt werden,
dass deren Funktion und mögliche Nebenwirkungen klar erkenntlich sind.

*Beispiel*:

```cpp
std::shared_ptr<Customer> getCustomer(int customerId);
```

Gibt einen Kunden anhand einer eindeutigen Identifikationsnummer zurück.
Sollte der Kunde nicht gefunden werden, tritt eine Ausnahme auf. Die Methode besitzt keine Nebenwirkungen.

```cpp
std::shared_ptr<Customer> getCustomerOrEmpty(int customerId);
```

Gibt einen Kunden anhand einer eindeutigen Identifikationsnummer zurück.
Sollte der Kunde nicht gefunden werden, wird ein leeres std::shared_ptr<Customer>-Objekt zurückgeliefert.
Die Methode besitzt keine Nebenwirkungen.

---

## *Kohäsion* und *Kopplung* (*Cohesion* and *Coupling*) <a name="link5"></a>

Wir wenden uns zunächst einer Erklärung der beiden Begrifflichkeiten zu:

Während *Kopplung* ein ziemlich intuitives Konzept ist, das heißt, dass fast niemand Schwierigkeiten hat, es zu verstehen,
ist der Begriff der *Kohäsion* schwieriger zu begreifen.

Darüber hinaus scheinen die Unterschiede zwischen den beiden Begriffen oft unklar zu sein.
Das ist nicht überraschend: Die Ideen hinter diesen Begriffen sind tatsächlich ähnlich.

Dennoch unterscheiden sie sich:

#### *Kohäsion*

  * *Kohäsion* stellt den Grad dar, in dem ein Teil einer Codebasis eine logisch einzelne, atomare Einheit bildet.

  * Sie kann auch als Anzahl der Verbindungen innerhalb einer Codeeinheit ausgedrückt werden.

  * Wenn die Anzahl niedrig ist, sind die Grenzen für die Einheit wahrscheinlich schlecht gewählt,
  der Code innerhalb der Einheit ist nicht logisch verbunden.

  * Eine Einheit ist hier nicht unbedingt eine Klasse.
  Es könnte eine Methode, eine Klasse, eine Gruppe von Klassen oder sogar ein Modul oder eine Baugruppe sein:


Der Begriff der Kohäsion (sowie der Kopplung) ist auf verschiedenen Ebenen anwendbar,
wir führen unsere Betrachtungen des Begriffs der *Kohäsion*
mit Klassen fort:

  * Klassen sollten eine kleine Anzahl von Instanzvariablen haben.
  * Jede Methode einer Klasse sollte eine oder mehrere dieser Variablen verändern.
  * Im Allgemeinen gilt: Je mehr Variablen eine Methode verändert, desto kohäsiver ist diese Methode für ihre Klasse.
  * Eine Klasse, in der jede Variable von jeder Methode verwendet wird, ist maximal kohäsiv.
  * Im Allgemeinen ist es weder ratsam noch möglich, solche maximal kohäsiven Klassen zu erstellen.
  * Andererseits kann eine eine starke Kohäsion auch von Vorteil sein:
   Eine starke Kohäsion hat zur Folge,
   dass die Methoden und Variablen der Klasse voneinander abhängig sind und als logisches Ganzes zusammenhängen.

#### *Kopplung*

  * Die *Kopplung* hingegen stellt den Grad dar, in dem eine einzelne Einheit von anderen unabhängig ist.

  * Mit anderen Worten handelt es sich um die Anzahl der Verbindungen zwischen zwei oder mehr Einheiten.

  * Je geringer die Anzahl, desto geringer die Kopplung.

#### Richtlinie für starke Kohäsion, geringe Kopplung

  * starke Kohäsion bedeutet im Wesentlichen, dass Teile einer Codebasis, die miteinander in Beziehung stehen,
  an einem einzigen Ort aufbewahrt werden.

  * Geringe Kopplung bedeutet gleichzeitig, nicht miteinander in Beziehung stehende Teile der Codebasis
  so weit wie möglich voneinander zu trennen.

---

## RAII <a name="link6"></a>

Siehe Repository *Entwurfsmuster*.

---

## Literatur <a name="link6"></a>

Eine gute Beschreibung der Begriffe *Kohäsion* und *Kopplung*  
wird in [Cohesion and Coupling: the difference](https://enterprisecraftsmanship.com/posts/cohesion-coupling-difference/) gegeben.

---

[Zurück](../Clean_Code/Readme_Clean_Code.md)

---
