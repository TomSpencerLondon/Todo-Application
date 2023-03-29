# Todo Application for Stratospheric

The purpose of this todo application is to serve as an example for the various use cases covered by the book.

## Getting Started

### Prerequisites

* [Java 17 or higher](https://adoptium.net/)
* [Gradle](https://gradle.org/) (Optional as this project ships with the Gradle wrapper)

### Running the Application on Your Local Machine

* Make sure you have Docker up- and running (`docker info`) and Docker Compose installed (`docker-compose -v`)
* Start the required infrastructure with `docker-compose up`
* Run `./gradlew bootRun` to start the application
* Access http://localhost:8080 in your browser

You can now log in with the following users: `duke`, `tom`, `bjoern`, `philip`. They all have the same password `stratospheric`.

### Application Profiles

- `dev` running the application locally for development. You don't need any AWS account or running AWS services for this. All infrastructure components are started within `docker-compose.yml`.
- `aws` running the application inside AWS. This requires the whole infrastructure setup inside your AWS account.

### Running the Tests

Run `./gradlew build` from the command line.

### Deployment

You can deploy the application by using the standard Spring Boot deployment mechanism (see these three articles for more
information on Spring Boot deployment techniques and alternatives:
[Deploying Spring Boot Applications](https://spring.io/blog/2014/03/07/deploying-spring-boot-applications),
[Running your application](https://docs.spring.io/spring-boot/docs/current/reference/html/using-boot-running-your-application.html),
[Installing Spring Boot applications](https://docs.spring.io/spring-boot/docs/current/reference/html/deployment-install.html)):

## Architecture

### Model

#### Class structure
![alt text][class-diagram]

#### Entity-relationship
![alt text][entity-relationship-diagram]

#### Database schema
![alt text][database-schema-diagram]

[class-diagram]:https://github.com/stratospheric-dev/stratospheric/raw/main/application/docs/Todo%20App%20-%20Class%20Diagram.png "class diagram"
[entity-relationship-diagram]:https://github.com/stratospheric-dev/stratospheric/raw/main/application/docs/Todo%20App%20-%20ER%20diagram.png "entity-relationship diagram"
[database-schema-diagram]:https://github.com/stratospheric-dev/stratospheric/raw/main/application/docs/Todo%20App%20-%20ER%20diagram%20from%20database%20schema.png "database schema diagram"

## Built with

* [Spring Boot](https://projects.spring.io/spring-boot/) and the following starters: Spring Web MVC, Spring Data JPA, Spring Cloud AWS, Spring WebFlux, Spring WebSocket, Thymeleaf, Spring Mail, Spring Validation, Spring Security, Actuator, OAuth2 Client
* [Gradle](https://gradle.org/)

## License

[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0)

## Authors

* **[Tom Hombergs](https://reflectoring.io)**
* **[Philip Riecks](https://rieckpil.de)**
* **[Björn Wilmsmann](https://bjoernkw.com)**

### Local Development
We will learn about the challenges of local cloud development.
We will also learn about LocalStack and Drop-in replacements for Amazon RDS and Amazon Cognito.
The goal is to make local development as easy as possible. LocalStack is a fully functional
AWS Cloud stack:
https://localstack.cloud/

We will use the localstack docker image:
```bash
docker run -p 4566:4566 -e SERVICES=s3 localstack/localstack
```
To use localstack we can use the following command:
```bash
aws s3api create-bucket --bucket toms-s3-bucket --endpoint-url http://localhost:4566 --create-bucket-configuration LocationConstraint=eu-west-1
{
    "Location": "http://toms-s3-bucket.s3.localhost.localstack.cloud:4566/"
}

```

With local development, we now need to connect to the LocalStack instance:
```yaml
  cloud:
    aws:
      rds:
        enabled: false
      sqs:
        endpoint: http://localhost:4566
        region: eu-central-1
      mail:
        endpoint: http://localhost:4566
        region: eu-central-1
      credentials:
        secret-key: foo
        access-key: bar
```
We also hard code our credentials above. We then create our resources on LocalStack. We will use docker-compose.yml for this.
We use local-aws-infrastructure.sh to create our services:
```bash
awslocal sqs create-queue --queue-name stratospheric-todo-sharing
```

We use a local docker image for postgres to replace AWS RDS. We will also use KeyCloak to replace Amazon Cognito:
```yaml
  keycloak:
    image: quay.io/keycloak/keycloak:18.0.0-legacy
    ports:
      - 8888:8080
    environment:
      - KEYCLOAK_USER=keycloak
      - KEYCLOAK_PASSWORD=keycloak
      - DB_VENDOR=h2
      - JAVA_OPTS=-Dkeycloak.migration.action=import -Dkeycloak.migration.provider=singleFile -Dkeycloak.migration.file=/tmp/stratospheric-realm.json
    volumes:
      - ./src/test/resources/keycloak/stratospheric-realm.json:/tmp/stratospheric-realm.json
```

We will use docker compose before starting our application:
```bash
docker-compose up
```

We now have two properties application-dev and application-aws for local development.
We have learnt about the approaches for local cloud development, using the LocalStack and Docker and we have replaced
RDS and Cognito with a local postgres instance and KeyCloak.

### Building User Registration and Login with Amazon Cognito
We will now learn how to add User Registration and Login using AWS Cognito. We will first learn about Amazon Cognito.
We will then look at OAuth 2.0 and OpenID Connect and look at the OAuth Authorization Code Grant Flow.
