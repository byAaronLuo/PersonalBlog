## 反射

### 何为反射

反射就是Reflection，**Java的反射是指程序在运行期可以拿到一个对象的所有信息**。即Java反射机制是在运行状态时，对于任意一个类，都能够获取到这个类的所有属性和方法，对于任意一个对象，都能够调用它的任意一个方法和属性(包括私有的方法和属性)，这种动态获取的信息以及动态调用对象的方法的功能就称为java语言的反射机制。

`class`（包括`interface`）的本质是数据类型（`Type`）

**而**`**class**`**是由JVM在执行过程中动态加载的。JVM在第一次读取到一种**`**class**`**类型时，将其加载进内存。**

每加载一种`class`，JVM就为其创建一个`Class`类型的实例，并关联起来。注意：这里的`Class`类型是一个名叫`Class`的`class`。它长这样：

```java
public final class Class {
    private Class() {}
}
```

以`String`类为例，当JVM加载`String`类时，它首先读取`String.class`文件到内存，然后，为`String`类创建一个`Class`实例并关联起来：

```java
Class cls = new Class(String);
```

这个`Class`实例是JVM内部创建的，如果我们查看JDK源码，可以发现`Class`类的构造方法是`private`，只有JVM能创建`Class`实例，我们自己的Java程序是无法创建`Class`实例的。

所以，JVM持有的每个`Class`实例都指向一个数据类型（`class`或`interface`）

**由于JVM为每个加载的**`**class**`**创建了对应的**`**Class**`**实例，并在实例中保存了该**`**class**`**的所有信息，包括类名、包名、父类、实现的接口、所有方法、字段等，因此，如果获取了某个**`**Class**`**实例，我们就可以通过这个**`**Class**`**实例获取到该实例对应的**`**class**`**的所有信息。**

**这种通过**`**Class**`**实例获取**`**class**`**信息的方法称为反射（Reflection）。**

### 获取class的Class实例

> 获取一个`class`的`Class`实例，有4个方法：


#### 方法一

直接通过一个`class`的静态变量`class`获取：

```java
Class cls = String.class;
```

#### 方法二

如果我们有一个实例变量，可以通过该实例变量提供的`getClass()`方法获取：

```java
String s = "Hello";
Class cls = s.getClass();
```

#### 方法三

如果知道一个`class`的完整类名，可以通过静态方法`Class.forName()`获取：

```java
Class cls = Class.forName("java.lang.String");
```

#### 方法四

利用`classLoader`

```java
Class cls = ClassLoader.getSystemClassLoader().loadClass("java.lang.Runtime")
```

---

#### 比较

因为`Class`实例在JVM中是唯一的，所以，上述方法获取的`Class`实例是同一个实例。可以用`==`比较两个`Class`实例：

```java
Class cls1 = String.class;

String s = "Hello";
Class cls2 = s.getClass();

boolean sameClass = cls1 == cls2; // true
```

#### 获取基本信息

获取class的基本信息

```java
package org.example;

import java.util.ArrayList;

public class App{
    public static void main(String[] args) {
        Class<String> cls1 = String.class;

        ArrayList a = new ArrayList();
        Class cls2 = a.getClass();

        printInfo(cls1);
        printInfo(cls2);
    }

    static void printInfo(Class cls){
        System.out.println("Class name : " + cls.getName());
        System.out.println("Simple name: " + cls.getSimpleName());
        if (cls.getPackage() != null) {
            System.out.println("Package name: " + cls.getPackage().getName());
        }
        System.out.println("is interface: " + cls.isInterface());
        System.out.println("is enum: " + cls.isEnum());
        System.out.println("is array: " + cls.isArray());
        System.out.println("is primitive: " + cls.isPrimitive());
    } }
```

### 小结

1. JVM为每个加载的`class`及`interface`创建了对应的`Class`实例来保存`class`及`interface`的所有信息；
2. 获取一个`class`对应的`Class`实例后，就可以获取该`class`的所有信息；
3. 通过Class实例获取`class`信息的方法称为反射（Reflection）；
4. JVM总是动态加载`class`，可以在运行期根据条件来控制加载class。

## 访问字段

对任意的一个`Object`实例，只要我们获取了它的`Class`，就可以获取它的一切信息。

我们先看看如何通过`Class`实例获取字段信息。

### 获取字段的一些信息

```java
import java.util.Arrays;

public class Test{
    public static void main(String[] args) throws NoSuchFieldException, IllegalAccessException {
        Class ot = OtherTest.class;
        System.out.println(Arrays.toString(ot.getFields()));    // 获取所有public的field（包括父类）
        System.out.println(Arrays.toString(ot.getDeclaredFields()));    // 获取当前类的所有field（不包括父类）
        System.out.println(ot.getField("a"));   // 根据字段名获取某个 public 的field（包括父类）
        System.out.println(ot.getDeclaredField("b")); // 根据字段名获取当前类的某个field（不包括父类）

        System.out.println(ot.getField("a").getName()); // 字段名称
        System.out.println(ot.getField("a").getType()); // 字段类型，也是一个Class实例
        System.out.println(ot.getField("a").getModifiers()); // 修饰符
    }
}

class OtherTest extends emmTest{
    public int a = 5;
    private int b;
}

class emmTest {
    public float cc;
}
```

```
[public int OtherTest.a, public float emmTest.cc]
[public int OtherTest.a, private int OtherTest.b]
public int OtherTest.a
private int OtherTest.b
a
int
1
```

### 获取字段的值

先获取`Class`实例，再获取`Field`实例，然后，用`Field.get(Object)`获取指定实例的指定字段的值。

```java
package org.example;


import java.lang.reflect.Field;

public class App {
    public static void main(String[] args) throws NoSuchFieldException, IllegalAccessException {
        OtherTest ot = new OtherTest("haha");

        Class cls = ot.getClass();
        Field f = cls.getDeclaredField("name");
        f.setAccessible(true);  // 设置访问权限，一律为true，不然不能访问 private 的
        Object value = f.get(ot);   // 从对象ot中获取值，因为所有的同类型class共用一个Class，所以获取内容要选定对象
        System.out.println(value);
    }
}

class OtherTest {
    private String name;

    public OtherTest(String name) {
        this.name = name;
    }
}

// 输出 haha
```

反射是一种非常规的用法，使用反射，首先代码非常繁琐，其次，它更多地是给工具或者底层框架来使用，目的是在不知道目标实例任何信息的情况下，获取特定字段的值。

此外，`setAccessible(true)`可能会失败。如果JVM运行期存在`SecurityManager`，那么它会根据规则进行检查，有可能阻止`setAccessible(true)`。例如，某个`SecurityManager`可能不允许对`java`和`javax`开头的`package`的类调用`setAccessible(true)`，这样可以保证JVM核心库的安全。
### 获取所有的字段
```java
public class APP {
    public static void main(String[] args) throws IllegalAccessException {
        OtherTest ot = new OtherTest("haha");
        Class cls = ot.getClass();
        Field[] f = cls.getDeclaredFields(); //取所有的字段
        for (Field field : f) {
            field.setAccessible(true);// 设置访问权限，一律为true，不然不能访问 private 的
            System.out.println(field.getName() + " " + field.getType()); // 获取field 的Name，Type
            System.out.println(field.get(ot));
        }
    }
}

class OtherTest {
    private String name;

    public OtherTest(String name) {
        this.name = name;
    }
}
// 输出
// name class java.lang.String
// haha
```
### 修改字段的值

```java
package org.example;


import java.lang.reflect.Field;

public class App {
    public static void main(String[] args) throws NoSuchFieldException, IllegalAccessException {
        OtherTest ot = new OtherTest("haha");

        Class cls = ot.getClass();
        Field f = cls.getDeclaredField("name");
        f.setAccessible(true);  // 设置访问权限，一律为true，不然不能访问 private 的
        f.set(ot, "modify");    // 反射修改值

        System.out.println(ot.getName());
    }
}

class OtherTest {
    private String name;

    public OtherTest(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }
}
```

### 小结

Java的反射API提供的`Field`类封装了字段的所有信息：

1. 通过`Class`实例的方法可以获取`Field`实例：`getField()`，`getFields()`，`getDeclaredField()`，`getDeclaredFields()`；
2. 通过Field实例可以获取字段信息：`getName()`，`getType()`，`getModifiers()`；
3. 通过Field实例可以读取或设置某个对象的字段，如果存在访问限制，要首先调用`setAccessible(true)`来访问非`public`字段。
4. 通过反射读写字段是一种非常规方法，它会破坏对象的封装。

## 调用方法（‼️）

### 获取方法

通过`Class`实例获取所有`Method`信息。`Class`类提供了以下几个方法来获取`Method`

```java
import java.util.Arrays;

public class Test{
    public static void main(String[] args) throws NoSuchMethodException {
        Class<OtherTest> cls = OtherTest.class; // Class cls = ot.getClass();
        System.out.println(Arrays.toString(cls.getMethods()));  // 获取所有public的Method（包括父类）
        System.out.println(Arrays.toString(cls.getDeclaredMethods()));  // 获取当前类的所有Method（不包括父类）
        System.out.println(cls.getMethod("echoEver", String.class));    // 获取某个public的Method（包括父类） //.getMethod(方法名，这个方法的参数类型)
        System.out.println(cls.getDeclaredMethod("echoEver", String.class));    // 获取当前类的某个Method（不包括父类）
    }
}

class OtherTest{
    public void echoEver(String thing){
        System.out.println(thing);
    }
}

// =====

/*
[public void org.example.OtherTest.echoEver(java.lang.String), public final void java.lang.Object.wait(long,int) throws java.lang.InterruptedException, public final native void java.lang.Object.wait(long) throws java.lang.InterruptedException, public final void java.lang.Object.wait() throws java.lang.InterruptedException, public boolean java.lang.Object.equals(java.lang.Object), public java.lang.String java.lang.Object.toString(), public native int java.lang.Object.hashCode(), public final native java.lang.Class java.lang.Object.getClass(), public final native void java.lang.Object.notify(), public final native void java.lang.Object.notifyAll()]

[public void org.example.OtherTest.echoEver(java.lang.String)]

public void org.example.OtherTest.echoEver(java.lang.String)

public void org.example.OtherTest.echoEver(java.lang.String)
*/
```

### 调用方法

- 获取Class实例
- 反射获取方法
- invoke调用方法



```java
package org.example;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

public class App {
    public static void main(String[] args) throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        OtherTest ot = new OtherTest();
        Class cls = ot.getClass();
        Method echoEver = cls.getDeclaredMethod("echoEver", String.class);
        echoEver.setAccessible(true);
        echoEver.invoke(ot,"test");	// 第一个参数是调用该方法的对象，第二个参数是一个可变长参数，是这个方法的需要传入的参数

    }
}

class OtherTest{
    private void echoEver(String thing){
        System.out.println(thing);
    }
}
```
### 示例
这里再以Java中使用反射调取Runtime来执行命令注入
```java
// 传统使用Java 来执行Runtime进行命令执行代码
package org.example;

import java.io.*;

public class App {
    public static void main(String[] args) throws IOException{
		Process s = Runtime.getRuntime().exec("whoami");
        InputStream inputStream = s.getInputStream();
        InputStreamReader inputStreamReader = new InputStreamReader(inputStream);
        BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
        String line;
        while ((line = bufferedReader.readLine()) != null) {
            System.out.println(line);
        }
    }
}
```
使用反射
```java
package com.ReflectTest;


import java.io.*;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

public class Reflect {
    public static void main(String[] args) throws IOException, ClassNotFoundException, NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        Class clazz = Class.forName("java.lang.Runtime");
        Method method = clazz.getDeclaredMethod("exec", String.class);
        Process process = (Process) method.invoke(Class.forName("java.lang.Runtime").getDeclaredMethod("getRuntime").invoke(Class.forName("java.lang.Runtime")), "whoami");
        // 这里细看Class.forName("java.lang.Runtime").getDeclaredMethod("getRuntime").invoke(Class.forName("java.lang.Runtime"))
        // 在这里，method.invoke 第一个参数是实例化的对象，从不使用反射的代码中看，应该是Runtime.getRuntime() 这个实例化对象
        // 然后要调用 getRuntime()的实例化对象则是Runtime，所以整合起来如下：
        // Class.forName("java.lang.Runtime").getDeclaredMethod("getRuntime").invoke(Class.forName("java.lang.Runtime"))
        // 这个就是上述调用exec方法的实例化对象RunTime.getRuntime()
        // 反射调用方法，就是从后往前依次寻找调用方法的实例化对象，加上参数
        InputStream inputStream = process.getInputStream();
        InputStreamReader inputStreamReader = new InputStreamReader(inputStream);
        BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
        String line;
        while ((line = bufferedReader.readLine()) != null) {
            System.out.println(line);
        }
    }
}

class OtherTest {
    private void echoEver(String thing) {
        System.out.println(thing);
    }
}

```
### 小结

Java的反射API提供的Method对象封装了方法的所有信息：

1. 通过`Class`实例的方法可以获取`Method`实例：`getMethod()`，`getMethods()`，`getDeclaredMethod()`，`getDeclaredMethods()`；
2. 通过`Method`实例可以获取方法信息：`getName()`，`getReturnType()`，`getParameterTypes()`，`getModifiers()`；
3. 通过`Method`实例可以调用某个对象的方法：`Object invoke(Object instance, Object... parameters)`；
4. 通过设置`setAccessible(true)`来访问非`public`方法；
5. 通过反射调用方法时，仍然遵循多态原则。

## 调用构造方法

### 举例

我们通常使用`new`操作符创建新的实例：

```java
Person p = new Person();
```

如果通过反射来创建新的实例，可以调用Class提供的`newInstance()`方法：

```java
Person p = Person.class.newInstance();
```

**调用**`**Class.newInstance()**`**的局限是，它只能调用该类的public无参数构造方法。如果构造方法带有参数，或者不是public，就无法直接通过**`**Class.newInstance()**`**来调用。**

---

为了调用任意的构造方法，Java的反射API提供了`Constructor`对象，它包含一个构造方法的所有信息，可以创建一个实例。**Constructor对象和Method非常类似**，**不同之处仅在于它是一个构造方法**，并且，**调用结果总是返回实例**：

```java
package org.example;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.Arrays;

public class App {
    public static void main(String[] args) throws NoSuchMethodException, IllegalAccessException, InvocationTargetException, InstantiationException {
        Class<Integer> cls = Integer.class;
        System.out.println(cls.getName());
        System.out.println(Arrays.toString(cls.getConstructors()));
        
        // Integer.class.getConstructor(int.class);
        Constructor<Integer> cons1 = cls.getConstructor(int.class);
        Integer int1 = cons1.newInstance(123);
        System.out.println(int1);

        Constructor<Integer> cons2 = cls.getConstructor(String.class);
        System.out.println(cons2.newInstance("456"));
    }
}


/*
java.lang.Integer
[public java.lang.Integer(int), public java.lang.Integer(java.lang.String) throws java.lang.NumberFormatException]
123
456
*/
```

通过Class实例获取Constructor的方法如下：

- `getConstructor(Class...)`：获取某个`public`的`Constructor`；
- `getDeclaredConstructor(Class...)`：获取某个`Constructor`；
- `getConstructors()`：获取所有`public`的`Constructor`；
- `getDeclaredConstructors()`：获取所有`Constructor`。

注意`Constructor`总是当前类定义的构造方法，和父类无关，因此不存在多态的问题。

调用非`public`的`Constructor`时，必须首先通过`setAccessible(true)`设置允许访问。`setAccessible(true)`可能会失败。
### 示例
调用方法示例使用invoke方法反射调用Runtime.getRuntime.exec(String.class)方法，那么由Construct改写如下：
```java
package com.ReflectTest;


import java.io.*;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

public class App {
    public static void main(String[] args) throws IOException, ClassNotFoundException, NoSuchMethodException, InvocationTargetException, IllegalAccessException, InstantiationException {
        Class clazz = Class.forName("java.lang.Runtime");
        Method method = clazz.getDeclaredMethod("exec", String.class);
        Constructor constructor = clazz.getDeclaredConstructor();
        constructor.setAccessible(true);
        // 实例化
        Runtime runtime = (Runtime) constructor.newInstance();
        // 使用exec调用
        Process process = (Process) method.invoke(runtime.getRuntime(), "whoami");
        InputStream inputStream = process.getInputStream();
        InputStreamReader inputStreamReader = new InputStreamReader(inputStream);
        BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
        String line;
        while ((line = bufferedReader.readLine()) != null) {
            System.out.println(line);
        }
    }
}


```

### 小结

`Constructor`对象封装了构造方法的所有信息；

1.  通过`Class`实例的方法可以获取`Constructor`实例：`getConstructor()`，`getConstructors()`，`getDeclaredConstructor()`，`getDeclaredConstructors()`； 
2.  通过`Constructor`实例可以创建一个实例对象：`newInstance(Object... parameters)`； 通过设置`setAccessible(true)`来访问非`public`构造方法。 

## 获取继承关系

### 获取父类class和interface

```java
import java.util.Arrays;

public class Test{
    public static void main(String[] args) {
        OtherTest ot = new OtherTest("emm");
        Class cls = ot.getClass();
        System.out.println(cls.getSuperclass());    // 获取父类class
        System.out.println(Arrays.toString(cls.getInterfaces()));   // 获取接口

        System.out.println("".getClass().getSuperclass());  // 获取 String 的父类
    }
}

class OtherTest extends Emmm implements Aaa{
    private String name;
    public OtherTest(String name){
        this.name = name;
    }

    @Override
    public void echo() {
        System.out.println("666");
    }
}

class Emmm {
    private int aa;
}

interface Aaa{
    public void echo();
}


/*
class org.example.Emmm
[interface org.example.Aaa]
class java.lang.Object
*/
```

### 小结

通过`Class`对象可以获取继承关系：

- `Class getSuperclass()`：获取父类类型；
- `Class[] getInterfaces()`：获取当前类实现的所有接口。

- 通过`Class`对象的`isAssignableFrom()`方法可以判断一个向上转型是否可以实现。

## 动态代理

**有没有可能不编写实现类，直接在运行期创建某个**`**interface**`**的实例呢？**

这是可能的，因为Java标准库提供了一种动态代理（Dynamic Proxy）的机制：可以在运行期动态创建某个`interface`的实例。

所谓动态代理，是和静态相对应的。我们来看静态代码怎么写：

```java
// 创建接口
public interface Hello {
    void morning(String name);
}

// 实现接口Hello
public class HelloWorld implements Hello {
    public void morning(String name) {
        System.out.println("Good morning, " + name);
    }
}

// 创建实例，调用
public static void main(String[] args) {
    Hello hello = new HelloWorld();
    hello.morning("Bob");
}
```

动态如下 过程 ，不需要单独实现接口，而是动态实现接口。

### 过程

在运行期动态创建一个`interface`实例的方法如下：

1. 定义一个`InvocationHandler`实例，**它负责实现接口的方法调用**；
2. 通过`Proxy.newProxyInstance()`创建`interface`实例，它需要3个参数： 
   1. 使用的`ClassLoader`，通常就是接口类的`ClassLoader`；
   2. 需要实现的接口数组，至少需要传入一个接口进去；
   3. 用来处理接口方法调用的`InvocationHandler`实例。
3. 将返回的`Object`强制转型为接口。

```java
package org.example;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

public class App{
    public static void main(String[] args) {
        InvocationHandler handler = new InvocationHandler() {
            @Override
            public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
                System.out.println(method);
                System.out.println(args.length);
				// 实现对应的方法
                if (method.getName().equals("echo")){
                    System.out.println(args[0]);
                }
                return null;
            }
        };

        Hello hello = (Hello) Proxy.newProxyInstance(Hello.class.getClassLoader(), new Class[]{Hello.class}, handler);
        hello.echo("9999");
    }
}


interface Hello{
    public void echo(String s);
}

/*
1
9999
*/
```

### 小结

Java标准库提供了动态代理功能，允许在运行期动态创建一个接口的实例；

动态代理是通过`Proxy`创建代理对象，然后将接口方法“代理”给`InvocationHandler`完成的。
