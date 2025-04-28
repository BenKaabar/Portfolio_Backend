# Build Stage
FROM maven:3.9.9-eclipse-temurin-24-alpine AS build

# Set working directory
WORKDIR /app

# Copy all files to the container
COPY . .

# Package the application, skipping tests
RUN mvn clean package -DskipTests

# Runtime Stage
FROM eclipse-temurin:21-jdk-jammy

# Set working directory
WORKDIR /app

# Copy the built jar from the build stage
COPY --from=build /app/target/portfolio-1.0.0.jar portfolio.jar

# Expose port 8080
EXPOSE 8080

# Command to run the application
ENTRYPOINT ["java", "-jar", "portfolio.jar"]
