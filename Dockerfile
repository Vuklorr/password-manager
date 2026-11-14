FROM maven:3.9.9-eclipse-temurin-21 AS build
WORKDIR /build
COPY pom.xml .
RUN mvn -B dependency:go-offline
COPY src src
RUN mvn -B package

FROM eclipse-temurin:21-jre-alpine
RUN addgroup -S vault && adduser -S vault -G vault
WORKDIR /app
COPY --from=build --chown=vault:vault /build/target/password-manager-1.0.0.jar app.jar
USER vault
EXPOSE 8080
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75", "-jar", "app.jar"]
