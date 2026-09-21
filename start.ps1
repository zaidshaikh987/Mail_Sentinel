$env:JAVA_HOME = "$PWD\jdk-17.0.10+7"
$env:PATH = "$env:JAVA_HOME\bin;$PWD\apache-maven-3.9.6\bin;" + $env:PATH
$env:SMS_PYTHON = "$PWD\.venv\Scripts\python.exe"
mvn -f backend/pom.xml -DskipTests package
java -jar backend/target/mailsentinel-1.0.0.jar
