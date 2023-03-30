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

### Todo App Design
![image](https://user-images.githubusercontent.com/27693622/228904750-5a3fe117-0e2b-4324-b33b-3165c86225f2.png)


### Building User Registration and Login with Amazon Cognito
We will now learn how to add User Registration and Login using AWS Cognito. We will first learn about Amazon Cognito.
We will then look at OAuth 2.0 and OpenID Connect and look at the OAuth Authorization Code Grant Flow.
Amazon Cognito is a managed service that provides authentication, authorization and user management for applications.
This allows us to delegate user management to AWS.

#### OAuth 2.0
Open Authorization is the industry standard for authentication and authorization. It provides a protocol for login for applications.
When we sign up we are asked to grant access to the site for specific tasks. We are redirected to another site to grant permissions.
Once we have granted permission the application has access to data shared by our identifying website. We will now learn about
Resource Owners (end users who own resources in a third party application), Resource Sever (provides protected resources),
Client for accessing resources and Authorization Server (a server dedicated to authorization). There are different Grant Types which
might be Authorization Codes, Client Codes and Refresh Tokens. 

#### OpenID Connect 1.0
OpenID connect is a protocol for identity authentication. With OpenID Connect the end user entity becomes the protected resource.
This authentication mechanism is most commonly used with the Authorization Code grant type. When we see login with Google
the application is most commonly using OpenID Connect.

#### OAuth Authorization Code Grant Flow
![image](https://user-images.githubusercontent.com/27693622/228911198-bf7f9126-a966-4803-aafa-8c8edc32ad4b.png)

Above we describe user management with OAuth2. Here the resource owner asks to access the application.
The application requests authorization for Github repos from the user. The user authenticates at Github and grants authorization.
The Authorization server then sends an authorization code. The application then exchanges the authorization code for an access token
which is then returned by the authorization server. The application then requests the protected resources (in this case Github repos) with
the access token. If the access token is correct then the resource server returns information about the resource.

Here we have learnt about OAuth and OpenID Connect and the Authentication and Authorization Flows. We will now learn about
Amazon Cognito.

#### Amazon Cognito
We will now learn about creating AWS Cognito resources with CDK. We will now look at some of the terms that Amazon Cognito uses.
A User Pool stores and manages User information. The User Pool App Client runs operations on a User Pool.
The Identity Pool works with IAM roles. For our application, we will create a single user pool to store all our users. 
In the User Pool we will configure our password policy, define required and optional user attributes, enable password recovery and customize email notifications.
We will register our application as a User Pool app client to enable user login with OIDC and OAuth 2.0.
This is the setup for the CognitoApp:
```java
public class CognitoApp {

  public static void main(final String[] args) {
    App app = new App();

    String environmentName = (String) app.getNode().tryGetContext("environmentName");
    Validations.requireNonEmpty(environmentName, "context variable 'environmentName' must not be null");

    String applicationName = (String) app.getNode().tryGetContext("applicationName");
    Validations.requireNonEmpty(applicationName, "context variable 'applicationName' must not be null");

    String accountId = (String) app.getNode().tryGetContext("accountId");
    Validations.requireNonEmpty(accountId, "context variable 'accountId' must not be null");

    String region = (String) app.getNode().tryGetContext("region");
    Validations.requireNonEmpty(region, "context variable 'region' must not be null");

    String applicationUrl = (String) app.getNode().tryGetContext("applicationUrl");
    Validations.requireNonEmpty(applicationUrl, "context variable 'applicationUrl' must not be null");

    String loginPageDomainPrefix = (String) app.getNode().tryGetContext("loginPageDomainPrefix");
    Validations.requireNonEmpty(loginPageDomainPrefix, "context variable 'loginPageDomainPrefix' must not be null");

    Environment awsEnvironment = makeEnv(accountId, region);

    ApplicationEnvironment applicationEnvironment = new ApplicationEnvironment(
      applicationName,
      environmentName
    );

    new CognitoStack(app, "cognito", awsEnvironment, applicationEnvironment, new CognitoStack.CognitoInputParameters(
      applicationName,
      applicationUrl,
      loginPageDomainPrefix));

    app.synth();
  }

  static Environment makeEnv(String account, String region) {
    return Environment.builder()
      .account(account)
      .region(region)
      .build();
  }

}

```
Here we add the domain name of our application with the following:
```java

public class CognitoApp {

    public static void main(final String[] args) {
        App app = new App();
        // ...
        String applicationUrl = (String) app.getNode().tryGetContext("applicationUrl");
        Validations.requireNonEmpty(applicationUrl, "context variable 'applicationUrl' must not be null");
        
        String loginPageDomainPrefix = (String) app.getNode().tryGetContext("loginPageDomainPrefix");
        Validations.requireNonEmpty(loginPageDomainPrefix, "context variable 'loginPageDomainPrefix' must not be null");
    }
}
```
The application url parameter is the final url of our application. Stack sets up the application:
```java
class CognitoStack extends Stack {

    private final ApplicationEnvironment applicationEnvironment;

    private final UserPool userPool;
    private final UserPoolClient userPoolClient;
    private final UserPoolDomain userPoolDomain;
    private String userPoolClientSecret;
    private final String logoutUrl;

    public CognitoStack(
            final Construct scope,
            final String id,
            final Environment awsEnvironment,
            final ApplicationEnvironment applicationEnvironment,
            final CognitoInputParameters inputParameters) {
        super(scope, id, StackProps.builder()
                .stackName(applicationEnvironment.prefix("Cognito"))
                .env(awsEnvironment).build());

        this.applicationEnvironment = applicationEnvironment;
        this.logoutUrl = String.format("https://%s.auth.%s.amazoncognito.com/logout", inputParameters.loginPageDomainPrefix, awsEnvironment.getRegion());

        this.userPool = UserPool.Builder.create(this, "userPool")
                .userPoolName(inputParameters.applicationName + "-user-pool")
                .selfSignUpEnabled(false)
                .accountRecovery(AccountRecovery.EMAIL_ONLY)
                .autoVerify(AutoVerifiedAttrs.builder().email(true).build())
                .signInAliases(SignInAliases.builder().username(true).email(true).build())
                .signInCaseSensitive(true)
                .standardAttributes(StandardAttributes.builder()
                        .email(StandardAttribute.builder().required(true).mutable(false).build())
                        .build())
                .mfa(Mfa.OFF)
                .passwordPolicy(PasswordPolicy.builder()
                        .requireLowercase(true)
                        .requireDigits(true)
                        .requireSymbols(true)
                        .requireUppercase(true)
                        .minLength(12)
                        .tempPasswordValidity(Duration.days(7))
                        .build())
                .build();

        this.userPoolClient = UserPoolClient.Builder.create(this, "userPoolClient")
                .userPoolClientName(inputParameters.applicationName + "-client")
                .generateSecret(true)
                .userPool(this.userPool)
                .oAuth(OAuthSettings.builder()
                        .callbackUrls(Arrays.asList(
                                String.format("%s/login/oauth2/code/cognito", inputParameters.applicationUrl),
                                "http://localhost:8080/login/oauth2/code/cognito"
                        ))
                        .logoutUrls(Arrays.asList(inputParameters.applicationUrl, "http://localhost:8080"))
                        .flows(OAuthFlows.builder()
                                .authorizationCodeGrant(true)
                                .build())
                        .scopes(Arrays.asList(OAuthScope.EMAIL, OAuthScope.OPENID, OAuthScope.PROFILE))
                        .build())
                .supportedIdentityProviders(Collections.singletonList(UserPoolClientIdentityProvider.COGNITO))
                .build();

        this.userPoolDomain = UserPoolDomain.Builder.create(this, "userPoolDomain")
                .userPool(this.userPool)
                .cognitoDomain(CognitoDomainOptions.builder()
                        .domainPrefix(inputParameters.loginPageDomainPrefix)
                        .build())
                .build();

        createOutputParameters();

        applicationEnvironment.tag(this);
    }
}
```
Here we have avoided using MFA and set a password policy for the user. We also set the configuration for the User Pool Client.
We also add a list of UserPoolClientIdentityProviders. We also create output parameters for the Spring application.

We have learnt about Cognito Resources and Infrastructure. This is a useful link for Amazon Cognito:
https://aws.amazon.com/cognito/
This is a useful link for more information about OAuth:
https://oauth.net/2/

#### Connecting to Database with Amazon RDS
In this section we will learn how to work with AWS RDS.
We will learn about RDS and also develop the infrastructure we will deploy.
AWS RDS offers supports PostgreSQL, MySQL, MariaDB, Oracle, Microsoft and Aurora.
It allows us to manage relational databases with tools such as AWS CLI, IAM, CloudFormation and CDK.

![image](https://user-images.githubusercontent.com/27693622/228945157-2b1a86e9-a467-4f64-82f3-414277c535d7.png)

Above is a diagram of the database setup. We put a database instance into a private subnet. The application in our 
Service stack would connect to the RDS database. The ECS Task represents a Docker image and the ECS Service wraps
several Docker images into a Service. The overall infrastructure runs on a VPC. We will use an Application Load Balancer
and Internet Gateway to enable access for the internet.

Here we have learnt about working with relational databases on AWS. In the next section we will learn about configuring IAM permissions
for RDS access. We will deploy a database related infrastructure and use the RDS database from our SpringBoot application.

#### Connecting to the Database with AWS RDS

Here we will look at setting up the required IAM permissions. We will then deploy RDS with CDK and then configure the RDS
databaes with our SpringBoot application.

#### Setting up the requisite IAM permissions

We need to add the RDSFullAccess policy for our developer user account:
![image](https://user-images.githubusercontent.com/27693622/228948472-55654f36-5c05-4ac1-a97f-1a5818c9be8e.png)

The application will have access to the database through the CDK app. We will deploy a database infrastructure with CDK and use the
Postgres Database Construct. The 

```java
public class PostgresDatabase extends Construct {
    public PostgresDatabase(
            final Construct scope,
            final String id,
            final Environment awsEnvironment,
            final ApplicationEnvironment applicationEnvironment,
            final DatabaseInputParameters databaseInputParameters) {

        super(scope, id);

        this.applicationEnvironment = applicationEnvironment;

        // Sadly, we cannot use VPC.fromLookup() to resolve a VPC object from this VpcId, because it's broken
        // (https://github.com/aws/aws-cdk/issues/3600). So, we have to resolve all properties we need from the VPC
        // via SSM parameter store.
        Network.NetworkOutputParameters networkOutputParameters = Network.getOutputParametersFromParameterStore(this, applicationEnvironment.getEnvironmentName());

        String username = sanitizeDbParameterName(applicationEnvironment.prefix("dbUser"));

        databaseSecurityGroup = CfnSecurityGroup.Builder.create(this, "databaseSecurityGroup")
                .vpcId(networkOutputParameters.getVpcId())
                .groupDescription("Security Group for the database instance")
                .groupName(applicationEnvironment.prefix("dbSecurityGroup"))
                .build();

        // This will generate a JSON object with the keys "username" and "password".
        databaseSecret = Secret.Builder.create(this, "databaseSecret")
                .secretName(applicationEnvironment.prefix("DatabaseSecret"))
                .description("Credentials to the RDS instance")
                .generateSecretString(SecretStringGenerator.builder()
                        .secretStringTemplate(String.format("{\"username\": \"%s\"}", username))
                        .generateStringKey("password")
                        .passwordLength(32)
                        .excludeCharacters("@/\\\" ")
                        .build())
                .build();

        CfnDBSubnetGroup subnetGroup = CfnDBSubnetGroup.Builder.create(this, "dbSubnetGroup")
                .dbSubnetGroupDescription("Subnet group for the RDS instance")
                .dbSubnetGroupName(applicationEnvironment.prefix("dbSubnetGroup"))
                .subnetIds(networkOutputParameters.getIsolatedSubnets())
                .build();

        dbInstance = CfnDBInstance.Builder.create(this, "postgresInstance")
                .dbInstanceIdentifier(applicationEnvironment.prefix("database"))
                .allocatedStorage(String.valueOf(databaseInputParameters.storageInGb))
                .availabilityZone(networkOutputParameters.getAvailabilityZones().get(0))
                .dbInstanceClass(databaseInputParameters.instanceClass)
                .dbName(sanitizeDbParameterName(applicationEnvironment.prefix("database")))
                .dbSubnetGroupName(subnetGroup.getDbSubnetGroupName())
                .engine("postgres")
                .engineVersion(databaseInputParameters.postgresVersion)
                .masterUsername(username)
                .masterUserPassword(databaseSecret.secretValueFromJson("password").toString())
                .publiclyAccessible(false)
                .vpcSecurityGroups(Collections.singletonList(databaseSecurityGroup.getAttrGroupId()))
                .build();

        CfnSecretTargetAttachment.Builder.create(this, "secretTargetAttachment")
                .secretId(databaseSecret.getSecretArn())
                .targetId(dbInstance.getRef())
                .targetType("AWS::RDS::DBInstance")
                .build();

        createOutputParameters();

        applicationEnvironment.tag(this);

    }
}

```
First the construct creates a database security group. We also define subnets which will be used by the database instance. We also create a database secret
and then create the Postgres Database. We can then deploy and destroy the application with our package.json script:
```json
{
  "scripts": {
    "database:deploy": "cdk deploy --app \"./mvnw -e -q compile exec:java -Dexec.mainClass=dev.stratospheric.todoapp.cdk.DatabaseApp\" --require-approval never",
    "database:destroy": "cdk destroy --app \"./mvnw -e -q compile exec:java -Dexec.mainClass=dev.stratospheric.todoapp.cdk.DatabaseApp\" --force --require-approval never"
  }
}
```

We run the command and create and instantiate the database and server that we will use.

```bash
npm run database:deploy
```

AWS will instantiate the Postgres server and the other resources we need. The above command runs the cdk deploy.
If we want to use a different profile we can use:
```bash
npm run database:deploy -- --profile stratospheric
```
Here the double dash tells npm not to evaluate what is after it so the --profile is sent on to the aws script. 

We now have a database running so we can now setup our SpringBoot application. We do this with the ServiceApp inside the CDK folder:
```java

public class ServiceApp {
    public static void main(final String[] args) {
        App app = new App();

        String environmentName = (String) app.getNode().tryGetContext("environmentName");
        Validations.requireNonEmpty(environmentName, "context variable 'environmentName' must not be null");

        String applicationName = (String) app.getNode().tryGetContext("applicationName");
        Validations.requireNonEmpty(applicationName, "context variable 'applicationName' must not be null");

        String accountId = (String) app.getNode().tryGetContext("accountId");
        Validations.requireNonEmpty(accountId, "context variable 'accountId' must not be null");

        String springProfile = (String) app.getNode().tryGetContext("springProfile");
        Validations.requireNonEmpty(springProfile, "context variable 'springProfile' must not be null");

        String dockerRepositoryName = (String) app.getNode().tryGetContext("dockerRepositoryName");
        Validations.requireNonEmpty(dockerRepositoryName, "context variable 'dockerRepositoryName' must not be null");

        String dockerImageTag = (String) app.getNode().tryGetContext("dockerImageTag");
        Validations.requireNonEmpty(dockerImageTag, "context variable 'dockerImageTag' must not be null");

        String region = (String) app.getNode().tryGetContext("region");
        Validations.requireNonEmpty(region, "context variable 'region' must not be null");

        Environment awsEnvironment = makeEnv(accountId, region);

        ApplicationEnvironment applicationEnvironment = new ApplicationEnvironment(
                applicationName,
                environmentName
        );

        // This stack is just a container for the parameters below, because they need a Stack as a scope.
        // We're making this parameters stack unique with each deployment by adding a timestamp, because updating an existing
        // parameters stack will fail because the parameters may be used by an old service stack.
        // This means that each update will generate a new parameters stack that needs to be cleaned up manually!
        long timestamp = System.currentTimeMillis();
        Stack parametersStack = new Stack(app, "ServiceParameters-" + timestamp, StackProps.builder()
                .stackName(applicationEnvironment.prefix("Service-Parameters-" + timestamp))
                .env(awsEnvironment)
                .build());

        Stack serviceStack = new Stack(app, "ServiceStack", StackProps.builder()
                .stackName(applicationEnvironment.prefix("Service"))
                .env(awsEnvironment)
                .build());

        PostgresDatabase.DatabaseOutputParameters databaseOutputParameters =
                PostgresDatabase.getOutputParametersFromParameterStore(parametersStack, applicationEnvironment);

        CognitoStack.CognitoOutputParameters cognitoOutputParameters =
                CognitoStack.getOutputParametersFromParameterStore(parametersStack, applicationEnvironment);

        MessagingStack.MessagingOutputParameters messagingOutputParameters =
                MessagingStack.getOutputParametersFromParameterStore(parametersStack, applicationEnvironment);

        ActiveMqStack.ActiveMqOutputParameters activeMqOutputParameters =
                ActiveMqStack.getOutputParametersFromParameterStore(parametersStack, applicationEnvironment);

        List<String> securityGroupIdsToGrantIngressFromEcs = Arrays.asList(
                databaseOutputParameters.getDatabaseSecurityGroupId(),
                activeMqOutputParameters.getActiveMqSecurityGroupId()
        );

        new Service(
                serviceStack,
                "Service",
                awsEnvironment,
                applicationEnvironment,
                new Service.ServiceInputParameters(
                        new Service.DockerImageSource(dockerRepositoryName, dockerImageTag),
                        securityGroupIdsToGrantIngressFromEcs,
                        environmentVariables(
                                serviceStack,
                                databaseOutputParameters,
                                cognitoOutputParameters,
                                messagingOutputParameters,
                                activeMqOutputParameters,
                                springProfile,
                                environmentName))
                        .withTaskRolePolicyStatements(List.of(
                                PolicyStatement.Builder.create()
                                        .sid("AllowSQSAccess")
                                        .effect(Effect.ALLOW)
                                        .resources(List.of(
                                                String.format("arn:aws:sqs:%s:%s:%s", region, accountId, messagingOutputParameters.getTodoSharingQueueName())
                                        ))
                                        .actions(Arrays.asList(
                                                "sqs:DeleteMessage",
                                                "sqs:GetQueueUrl",
                                                "sqs:ListDeadLetterSourceQueues",
                                                "sqs:ListQueues",
                                                "sqs:ListQueueTags",
                                                "sqs:ReceiveMessage",
                                                "sqs:SendMessage",
                                                "sqs:ChangeMessageVisibility",
                                                "sqs:GetQueueAttributes"))
                                        .build(),
                                PolicyStatement.Builder.create()
                                        .sid("AllowCreatingUsers")
                                        .effect(Effect.ALLOW)
                                        .resources(
                                                List.of(String.format("arn:aws:cognito-idp:%s:%s:userpool/%s", region, accountId, cognitoOutputParameters.getUserPoolId()))
                                        )
                                        .actions(List.of(
                                                "cognito-idp:AdminCreateUser"
                                        ))
                                        .build(),
                                PolicyStatement.Builder.create()
                                        .sid("AllowSendingEmails")
                                        .effect(Effect.ALLOW)
                                        .resources(
                                                List.of(String.format("arn:aws:ses:%s:%s:identity/stratospheric.dev", region, accountId))
                                        )
                                        .actions(List.of(
                                                "ses:SendEmail",
                                                "ses:SendRawEmail"
                                        ))
                                        .build(),
                                PolicyStatement.Builder.create()
                                        .sid("AllowDynamoTableAccess")
                                        .effect(Effect.ALLOW)
                                        .resources(
                                                List.of(String.format("arn:aws:dynamodb:%s:%s:table/%s", region, accountId, applicationEnvironment.prefix("breadcrumb")))
                                        )
                                        .actions(List.of(
                                                "dynamodb:Scan",
                                                "dynamodb:Query",
                                                "dynamodb:PutItem",
                                                "dynamodb:GetItem",
                                                "dynamodb:BatchWriteItem",
                                                "dynamodb:BatchWriteGet"
                                        ))
                                        .build(),
                                PolicyStatement.Builder.create()
                                        .sid("AllowSendingMetricsToCloudWatch")
                                        .effect(Effect.ALLOW)
                                        .resources(singletonList("*")) // CloudWatch does not have any resource-level permissions, see https://stackoverflow.com/a/38055068/9085273
                                        .actions(singletonList("cloudwatch:PutMetricData"))
                                        .build()
                        ))
                        .withStickySessionsEnabled(true)
                        .withHealthCheckPath("/actuator/health")
                        .withAwsLogsDateTimeFormat("%Y-%m-%dT%H:%M:%S.%f%z")
                        .withHealthCheckIntervalSeconds(30), // needs to be long enough to allow for slow start up with low-end computing instances

                Network.getOutputParametersFromParameterStore(serviceStack, applicationEnvironment.getEnvironmentName()));

        app.synth();
    }
    
    static Map<String, String> environmentVariables(
            Construct scope,
            PostgresDatabase.DatabaseOutputParameters databaseOutputParameters,
            CognitoStack.CognitoOutputParameters cognitoOutputParameters,
            MessagingStack.MessagingOutputParameters messagingOutputParameters,
            ActiveMqStack.ActiveMqOutputParameters activeMqOutputParameters,
            String springProfile,
            String environmentName
    ) {
        Map<String, String> vars = new HashMap<>();

        String databaseSecretArn = databaseOutputParameters.getDatabaseSecretArn();
        ISecret databaseSecret = Secret.fromSecretCompleteArn(scope, "databaseSecret", databaseSecretArn);

        vars.put("SPRING_PROFILES_ACTIVE", springProfile);
        vars.put("SPRING_DATASOURCE_URL",
                String.format("jdbc:postgresql://%s:%s/%s",
                        databaseOutputParameters.getEndpointAddress(),
                        databaseOutputParameters.getEndpointPort(),
                        databaseOutputParameters.getDbName()));
        vars.put("SPRING_DATASOURCE_USERNAME",
                databaseSecret.secretValueFromJson("username").toString());
        vars.put("SPRING_DATASOURCE_PASSWORD",
                databaseSecret.secretValueFromJson("password").toString());
        vars.put("COGNITO_CLIENT_ID", cognitoOutputParameters.getUserPoolClientId());
        vars.put("COGNITO_CLIENT_SECRET", cognitoOutputParameters.getUserPoolClientSecret());
        vars.put("COGNITO_USER_POOL_ID", cognitoOutputParameters.getUserPoolId());
        vars.put("COGNITO_LOGOUT_URL", cognitoOutputParameters.getLogoutUrl());
        vars.put("COGNITO_PROVIDER_URL", cognitoOutputParameters.getProviderUrl());
        vars.put("TODO_SHARING_QUEUE_NAME", messagingOutputParameters.getTodoSharingQueueName());
        vars.put("WEB_SOCKET_RELAY_ENDPOINT", activeMqOutputParameters.getStompEndpoint());
        vars.put("WEB_SOCKET_RELAY_USERNAME", activeMqOutputParameters.getActiveMqUsername());
        vars.put("WEB_SOCKET_RELAY_PASSWORD", activeMqOutputParameters.getActiveMqPassword());
        vars.put("ENVIRONMENT_NAME", environmentName);

        return vars;
    }

}

```

Here we create the SpringBoot Service with the correct environment variables for configuring the database connection.
The AWS specific database stack can then be used with the Spring application. Spring uses the environment variables to 
configure the database connection on SpringBoot start. 

We have seen how to configure IAM permissions for RDS access. We have deployed the database and are now using the RDS database from
our Spring application.

### Sharing Todos with Amazon SQS and Amazon SES
Here we will integrate two new AWS services, AWS Simple Queue Service ([SQS](https://aws.amazon.com/sqs/)) and 
AWS Simple Email Service ([SES](https://aws.amazon.com/ses/)) so that we can share Todos with other users so that they
can collaborate. Users accept collaboration by email and then collaborate. When users share their todos we put the request
into an SQS queue and then send out emails to the requested other user. 

#### Introduction to Amazon SQS
Amazon SQS is a fully managed messaging service for queueing messages to different parts of our application. SQS can
also decouple components in a microservices distributed architecture. We interact with SQS via an https API.
SQS can persist our messages for up to 14 days. The standard queue type delivers on a best effort ordering. FIFO SQS
guarantees messages are sent in the same order as they are sent. Each message remains on the queue until the consumer 
acknowledges its delivery by deleting the message. We set up our messaging queue with the MessagingStack:
```java
class MessagingStack extends Stack {

  private final ApplicationEnvironment applicationEnvironment;
  private final IQueue todoSharingQueue;
  private final IQueue todoSharingDlq;

  public MessagingStack(
    final Construct scope,
    final String id,
    final Environment awsEnvironment,
    final ApplicationEnvironment applicationEnvironment) {
    super(scope, id, StackProps.builder()
      .stackName(applicationEnvironment.prefix("Messaging"))
      .env(awsEnvironment).build());

    this.applicationEnvironment = applicationEnvironment;

    this.todoSharingDlq = Queue.Builder.create(this, "todoSharingDlq")
      .queueName(applicationEnvironment.prefix("todo-sharing-dead-letter-queue"))
      .retentionPeriod(Duration.days(14))
      .build();

    this.todoSharingQueue = Queue.Builder.create(this, "todoSharingQueue")
      .queueName(applicationEnvironment.prefix("todo-sharing-queue"))
      .visibilityTimeout(Duration.seconds(30))
      .retentionPeriod(Duration.days(14))
      .deadLetterQueue(DeadLetterQueue.builder()
        .queue(todoSharingDlq)
        .maxReceiveCount(3)
        .build())
      .build();

    createOutputParameters();

    applicationEnvironment.tag(this);
  }

  private static final String PARAMETER_TODO_SHARING_QUEUE_NAME = "todoSharingQueueName";

  private void createOutputParameters() {
    StringParameter.Builder.create(this, PARAMETER_TODO_SHARING_QUEUE_NAME)
      .parameterName(createParameterName(applicationEnvironment, PARAMETER_TODO_SHARING_QUEUE_NAME))
      .stringValue(this.todoSharingQueue.getQueueName())
      .build();
  }

  private static String createParameterName(ApplicationEnvironment applicationEnvironment, String parameterName) {
    return applicationEnvironment.getEnvironmentName() + "-" + applicationEnvironment.getApplicationName() + "-Messaging-" + parameterName;
  }

  public static String getTodoSharingQueueName(Construct scope, ApplicationEnvironment applicationEnvironment) {
    return StringParameter.fromStringParameterName(scope, PARAMETER_TODO_SHARING_QUEUE_NAME, createParameterName(applicationEnvironment, PARAMETER_TODO_SHARING_QUEUE_NAME))
      .getStringValue();
  }

  public static MessagingOutputParameters getOutputParametersFromParameterStore(Construct scope, ApplicationEnvironment applicationEnvironment) {
    return new MessagingOutputParameters(
      getTodoSharingQueueName(scope, applicationEnvironment)
    );
  }

  public static class MessagingOutputParameters {
    private final String todoSharingQueueName;

    public MessagingOutputParameters(String todoSharingQueueName) {
      this.todoSharingQueueName = todoSharingQueueName;
    }

    public String getTodoSharingQueueName() {
      return todoSharingQueueName;
    }
  }

}

```
Here we set up the queue and set the Deadletter queue to accept messages after four attempts. We also need to set up
SQS as a dependency in our build.gradle:
```gradle
  implementation 'io.awspring.cloud:spring-cloud-aws-starter-sqs'
```
We then send the todo with a form on our dashboard:
```html

<div class="dropdown-menu" aria-labelledby="dropdownMenuLink">
              <span class="dropdown-item" th:if="${collaborators.isEmpty()}">
                No collaborator available
              </span>
    <form th:method="POST"
          th:each="collaborator : ${collaborators}"
          th:action="@{/todo/{todoId}/collaborations/{collaboratorId}(todoId=${todo.id}, collaboratorId=${collaborator.id})}">
        <button
                th:text="${collaborator.name}"
                type="submit"
                name="submit"
                class="dropdown-item">
        </button>
    </form>
</div>
```

We also have a post endpoint on our controller to share todos:

```java
@Controller
@RequestMapping("/todo")
public class TodoCollaborationController {

    private final TodoCollaborationService todoCollaborationService;

    public TodoCollaborationController(TodoCollaborationService todoCollaborationService) {
        this.todoCollaborationService = todoCollaborationService;
    }

    @Timed(
            value = "stratospheric.collaboration.sharing",
            description = "Measure the time how long it takes to share a todo"
    )
    @PostMapping("/{todoId}/collaborations/{collaboratorId}")
    public String shareTodoWithCollaborator(
            @PathVariable("todoId") Long todoId,
            @PathVariable("collaboratorId") Long collaboratorId,
            @AuthenticationPrincipal OidcUser user,
            RedirectAttributes redirectAttributes
    ) throws JsonProcessingException {
        String collaboratorName = todoCollaborationService.shareWithCollaborator(user.getEmail(), todoId, collaboratorId);

        redirectAttributes.addFlashAttribute("message",
                String.format("You successfully shared your todo with the user %s. " +
                        "Once the user accepts the invite, you'll see them as a collaborator on your todo.", collaboratorName));
        redirectAttributes.addFlashAttribute("messageType", "success");

        return "redirect:/dashboard";
    }
}
```
The TodoCollaboration controller takes collaboration requests and sharings them using the todoCollaborationService.
The Service then shares the request:
```java
@Service
@Transactional
public class TodoCollaborationService {

    private final TodoRepository todoRepository;
    private final PersonRepository personRepository;
    private final TodoCollaborationRequestRepository todoCollaborationRequestRepository;

    private final SqsTemplate sqsTemplate;
    private final String todoSharingQueueName;

    private final SimpMessagingTemplate simpMessagingTemplate;

    private static final Logger LOG = LoggerFactory.getLogger(TodoCollaborationService.class.getName());

    private static final String INVALID_TODO_ID = "Invalid todo ID: ";
    private static final String INVALID_PERSON_ID = "Invalid person ID: ";
    private static final String INVALID_PERSON_EMAIL = "Invalid person Email: ";

    public TodoCollaborationService(
            @Value("${custom.sharing-queue}") String todoSharingQueueName,
            TodoRepository todoRepository,
            PersonRepository personRepository,
            TodoCollaborationRequestRepository todoCollaborationRequestRepository,
            SqsTemplate sqsTemplate,
            SimpMessagingTemplate simpMessagingTemplate) {
        this.todoRepository = todoRepository;
        this.personRepository = personRepository;
        this.todoCollaborationRequestRepository = todoCollaborationRequestRepository;
        this.sqsTemplate = sqsTemplate;
        this.todoSharingQueueName = todoSharingQueueName;
        this.simpMessagingTemplate = simpMessagingTemplate;
    }

    public String shareWithCollaborator(String todoOwnerEmail, Long todoId, Long collaboratorId) {

        Todo todo = todoRepository
                .findByIdAndOwnerEmail(todoId, todoOwnerEmail)
                .orElseThrow(() -> new IllegalArgumentException(INVALID_TODO_ID + todoId));

        Person collaborator = personRepository
                .findById(collaboratorId)
                .orElseThrow(() -> new IllegalArgumentException(INVALID_PERSON_ID + collaboratorId));

        if (todoCollaborationRequestRepository.findByTodoAndCollaborator(todo, collaborator) != null) {
            LOG.info("Collaboration request for todo {} with collaborator {} already exists", todoId, collaboratorId);
            return collaborator.getName();
        }

        LOG.info("About to share todo with id {} with collaborator {}", todoId, collaboratorId);

        TodoCollaborationRequest collaboration = new TodoCollaborationRequest();
        String token = UUID.randomUUID().toString();
        collaboration.setToken(token);
        collaboration.setCollaborator(collaborator);
        collaboration.setTodo(todo);
        todo.getCollaborationRequests().add(collaboration);

        todoCollaborationRequestRepository.save(collaboration);

        sqsTemplate.send(todoSharingQueueName, new TodoCollaborationNotification(collaboration));

        return collaborator.getName();
    }
}
```

We then listen for the request with our TodoSharingListener:
```java

@Component
public class TodoSharingListener {

  private final MailSender mailSender;
  private final TodoCollaborationService todoCollaborationService;
  private final boolean autoConfirmCollaborations;
  private final String confirmEmailFromAddress;
  private final String externalUrl;

  private static final Logger LOG = LoggerFactory.getLogger(TodoSharingListener.class.getName());

  public TodoSharingListener(
    MailSender mailSender,
    TodoCollaborationService todoCollaborationService,
    @Value("${custom.auto-confirm-collaborations}") boolean autoConfirmCollaborations,
    @Value("${custom.confirm-email-from-address}") String confirmEmailFromAddress,
    @Value("${custom.external-url}") String externalUrl) {
    this.mailSender = mailSender;
    this.todoCollaborationService = todoCollaborationService;
    this.autoConfirmCollaborations = autoConfirmCollaborations;
    this.confirmEmailFromAddress = confirmEmailFromAddress;
    this.externalUrl = externalUrl;
  }

  @SqsListener(value = "${custom.sharing-queue}")
  public void listenToSharingMessages(TodoCollaborationNotification payload) throws InterruptedException {
    LOG.info("Incoming todo sharing payload: {}", payload);

    SimpleMailMessage message = new SimpleMailMessage();
    message.setFrom(confirmEmailFromAddress);
    message.setTo(payload.getCollaboratorEmail());
    message.setSubject("A todo was shared with you");
    message.setText(
      String.format(
        """
          Hi %s,\s

          someone shared a Todo from %s with you.

          Information about the shared Todo item:\s

          Title: %s\s
          Description: %s\s
          Priority: %s\s

          You can accept the collaboration by clicking this link: %s/todo/%s/collaborations/%s/confirm?token=%s\s

          Kind regards,\s
          Stratospheric""",
        payload.getCollaboratorEmail(),
        externalUrl,
        payload.getTodoTitle(),
        payload.getTodoDescription(),
        payload.getTodoPriority(),
        externalUrl,
        payload.getTodoId(),
        payload.getCollaboratorId(),
        payload.getToken()
      )
    );
    mailSender.send(message);

    LOG.info("Successfully informed collaborator about shared todo.");

    if (autoConfirmCollaborations) {
      LOG.info("Auto-confirmed collaboration request for todo: {}", payload.getTodoId());
      Thread.sleep(2_500);
      todoCollaborationService.confirmCollaboration(payload.getCollaboratorEmail(), payload.getTodoId(), payload.getCollaboratorId(), payload.getToken());
    }
  }
}

```

Here we have learnt about implementing collaboration features with SQS for decoupling events from behaviour.

### Sharing Todos with Amazon SQS and Amazon SES

Here, we will use Amazon SES for sending emails to collaborators. Amazon SES is an easy to set up email service.
We interact with the SES service with CDK or an API. We could use this service for marketing, sign up or email news services.
Amazon SES is available in several regions. We allow sending emails with the following configuration:
```java
public class ServiceApp {

    public static void main(final String[] args) {
        // ...
        PolicyStatement.Builder.create()
                .sid("AllowSendingEmails")
                .effect(Effect.ALLOW)
                .resources(
                        List.of(String.format("arn:aws:ses:%s:%s:identity/stratospheric.dev", region, accountId))
                )
                .actions(List.of(
                        "ses:SendEmail",
                        "ses:SendRawEmail"
                ))
                .build();
        // ...
    }
}
```
Spring defines two interfaces for sending emails: MailSender and JavaMailSender. We also add the ses dependency to our
build.gradle file:
```gradle
  implementation 'io.awspring.cloud:spring-cloud-aws-starter-ses'
```

We send the email from our TodoSharingListener:
```java
@Component
public class TodoSharingListener {
    // ...
  @SqsListener(value = "${custom.sharing-queue}")
  public void listenToSharingMessages(TodoCollaborationNotification payload) throws InterruptedException {
    LOG.info("Incoming todo sharing payload: {}", payload);

    SimpleMailMessage message = new SimpleMailMessage();
    message.setFrom(confirmEmailFromAddress);
    message.setTo(payload.getCollaboratorEmail());
    message.setSubject("A todo was shared with you");
    message.setText(
      String.format(
        """
          Hi %s,\s

          someone shared a Todo from %s with you.

          Information about the shared Todo item:\s

          Title: %s\s
          Description: %s\s
          Priority: %s\s

          You can accept the collaboration by clicking this link: %s/todo/%s/collaborations/%s/confirm?token=%s\s

          Kind regards,\s
          Stratospheric""",
        payload.getCollaboratorEmail(),
        externalUrl,
        payload.getTodoTitle(),
        payload.getTodoDescription(),
        payload.getTodoPriority(),
        externalUrl,
        payload.getTodoId(),
        payload.getCollaboratorId(),
        payload.getToken()
      )
    );
    mailSender.send(message);

    LOG.info("Successfully informed collaborator about shared todo.");

    if (autoConfirmCollaborations) {
      LOG.info("Auto-confirmed collaboration request for todo: {}", payload.getTodoId());
      Thread.sleep(2_500);
      todoCollaborationService.confirmCollaboration(payload.getCollaboratorEmail(), payload.getTodoId(), payload.getCollaboratorId(), payload.getToken());
    }
  }
}

```
The mailSender#send function hands the delivery of the email to Amazon SES. We handle the user's response to the email in 
the TodoCollaborationController:
```java
@Controller
@RequestMapping("/todo")
public class TodoCollaborationController {
    //...
  @GetMapping("/{todoId}/collaborations/{collaboratorId}/confirm")
  public String confirmCollaboration(
    @PathVariable("todoId") Long todoId,
    @PathVariable("collaboratorId") Long collaboratorId,
    @RequestParam("token") String token,
    @AuthenticationPrincipal OidcUser user,
    RedirectAttributes redirectAttributes
  ) {
    if (todoCollaborationService.confirmCollaboration(user.getEmail(), todoId, collaboratorId, token)) {
      redirectAttributes.addFlashAttribute("message", "You've confirmed that you'd like to collaborate on this todo.");
      redirectAttributes.addFlashAttribute("messageType", "success");
    } else {
      redirectAttributes.addFlashAttribute("message", "Invalid collaboration request.");
      redirectAttributes.addFlashAttribute("messageType", "danger");
    }

    return "redirect:/dashboard";
  }
}

```
We confirm the collaboration with the TodoCollaborationService:
```java
@Service
@Transactional
public class TodoCollaborationService {
    // ...
  public boolean confirmCollaboration(String authenticatedUserEmail, Long todoId, Long collaboratorId, String token) {

    Person collaborator = personRepository
      .findByEmail(authenticatedUserEmail)
      .orElseThrow(() -> new IllegalArgumentException(INVALID_PERSON_EMAIL + authenticatedUserEmail));

    if (!collaborator.getId().equals(collaboratorId)) {
      return false;
    }

    TodoCollaborationRequest collaborationRequest = todoCollaborationRequestRepository
      .findByTodoIdAndCollaboratorId(todoId, collaboratorId);

    LOG.info("Collaboration request: {}", collaborationRequest);

    if (collaborationRequest == null || !collaborationRequest.getToken().equals(token)) {
      return false;
    }

    LOG.info("Original collaboration token: {}", collaborationRequest.getToken());
    LOG.info("Request token: {}", token);

    Todo todo = todoRepository
      .findById(todoId)
      .orElseThrow(() -> new IllegalArgumentException(INVALID_TODO_ID + todoId));

    todo.addCollaborator(collaborator);

    todoCollaborationRequestRepository.delete(collaborationRequest);

    String name = collaborationRequest.getCollaborator().getName();
    String subject = "Collaboration confirmed.";
    String message = "User "
      + name
      + " has accepted your collaboration request for todo #"
      + collaborationRequest.getTodo().getId()
      + ".";
    String ownerEmail = collaborationRequest.getTodo().getOwner().getEmail();

    simpMessagingTemplate.convertAndSend("/topic/todoUpdates/" + ownerEmail, subject + " " + message);

    LOG.info("Successfully informed owner about accepted request.");

    return true;
  }
}

```
For local testing with LocalStack we use the following definition in our docker-compose.yml:
```yaml
  localstack:
    image: localstack/localstack:0.14.4
    ports:
      - 4566:4566
    environment:
      - SERVICES=sqs,ses,dynamodb
      - DEFAULT_REGION=eu-central-1
      - USE_SINGLE_REGION=true
    volumes:
      - ./src/test/resources/localstack/local-aws-infrastructure.sh:/docker-entrypoint-initaws.d/init.sh
```
To set up our local environment we use the following script in local-aws-infrastructure.sh:
```bash
#!/bin/sh

awslocal sqs create-queue --queue-name stratospheric-todo-sharing

awslocal ses verify-email-identity --email-address noreply@stratospheric.dev
awslocal ses verify-email-identity --email-address info@stratospheric.dev
awslocal ses verify-email-identity --email-address tom@stratospheric.dev
awslocal ses verify-email-identity --email-address bjoern@stratospheric.dev
awslocal ses verify-email-identity --email-address philip@stratospheric.dev

awslocal dynamodb create-table \
    --table-name local-todo-app-breadcrumb \
    --attribute-definitions AttributeName=id,AttributeType=S \
    --key-schema AttributeName=id,KeyType=HASH \
    --provisioned-throughput ReadCapacityUnits=10,WriteCapacityUnits=10 \

echo "Initialized."
```
For local development we override the url endpoint with our application-dev.yml:
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
We set auto-confirm-collaborations to true to enable email success:
```yaml
  auto-confirm-collaborations: true
```
This is then used in the autoConfirmCollaborations parameter in our TodoSharingListener:
```java
public class TodoSharingListener {

    private final MailSender mailSender;
    private final TodoCollaborationService todoCollaborationService;
    private final boolean autoConfirmCollaborations;
    private final String confirmEmailFromAddress;
    private final String externalUrl;

    private static final Logger LOG = LoggerFactory.getLogger(TodoSharingListener.class.getName());

    public TodoSharingListener(
            MailSender mailSender,
            TodoCollaborationService todoCollaborationService,
            @Value("${custom.auto-confirm-collaborations}") boolean autoConfirmCollaborations,
            @Value("${custom.confirm-email-from-address}") String confirmEmailFromAddress,
            @Value("${custom.external-url}") String externalUrl) {
        this.mailSender = mailSender;
        this.todoCollaborationService = todoCollaborationService;
        this.autoConfirmCollaborations = autoConfirmCollaborations;
        this.confirmEmailFromAddress = confirmEmailFromAddress;
        this.externalUrl = externalUrl;
    }
}
```

Here we have learnt about sending and receiving emails with AWS SES and we have looked at implementing email functionality
in a Spring Boot application.

### Production Readiness with AWS
We will now look at Amazon CloudWatch and send log data to this service. We will set up metrics for CloudWatch and alarms if
thresholds are breached. We will also make the application production-ready by securing it with HTTPS and hosting it on a custom
domain.

We will use Spring Boot Logback for logging:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <include resource="org/springframework/boot/logging/logback/defaults.xml"/>
  <include resource="org/springframework/boot/logging/logback/console-appender.xml"/>

  <appender name="JSON" class="ch.qos.logback.core.ConsoleAppender">
    <encoder class="de.siegmar.logbackawslogsjsonencoder.AwsJsonLogEncoder"/>
  </appender>
  
  <root level="INFO">
    <appender-ref ref="CONSOLE"/>
  </root>
</configuration>
```
Here we will use centralized logging. We will use CloudWatch logging and learn how to send logs from ECS Fargate
to Amazon CloudWatch.


