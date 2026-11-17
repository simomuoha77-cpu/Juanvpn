#!/bin/sh
# Compiles HJ01.java and runs the security regression suite on a plain JVM.
# Needs a JDK and bcprov-jdk18on (or bcprov-jdk15on) on the classpath: BCJAR=/path/to/bcprov.jar ./run.sh
cd "$(dirname "$0")"
BCJAR="${BCJAR:-/usr/share/java/bcprov-1.77.jar}"
OUT="$(mktemp -d)"
JAVAC="javac"; command -v javac >/dev/null 2>&1 || JAVAC="java -m jdk.compiler/com.sun.tools.javac.Main"
$JAVAC -cp "$BCJAR" -d "$OUT" ../app/src/main/java/com/juanvpn/app/HJ01.java HJ01SelfTest.java || exit 1
java -cp "$BCJAR:$OUT" com.juanvpn.app.HJ01SelfTest
