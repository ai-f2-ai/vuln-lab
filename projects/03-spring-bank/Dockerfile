FROM openjdk:8-jdk
COPY target/spring-bank-vuln-1.0.0.jar /app.jar
USER root
EXPOSE 8080
ENTRYPOINT ["java","-jar","/app.jar"]
