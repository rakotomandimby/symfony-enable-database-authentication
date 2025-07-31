# Enable Symfony authentication against database

**Note**: Database here is a PostgreSQL database.

Setup the database and create a user in the database.

```sql
CREATE TABLE public.users (
    id SERIAL NOT NULL,
    email CHARACTER VARYING(255) NOT NULL,
    password CHARACTER VARYING(255) NOT NULL,
    first_name CHARACTER VARYING(512),
    last_name CHARACTER VARYING(512),
    roles CHARACTER VARYING(1024)
);
```

Create the user:
```sql
INSERT INTO public.users (
    email, 
    password, 
    first_name, 
    last_name, 
    roles) 
VALUES (
    'mr@rktmb.org', 
    '$2a$12$AbZtZJCEB8qnu2ZCAcQIE.4wOlO1RM4H7eec8y4Fmaehtvrwu9SaW', 
    'Miha', 
    'RKTMB', 
    'ROLE_ADMIN,ROLE_USER');
```

The password is `mihamina` hashed with any [online bcrypt generator](https://www.google.com/search?client=firefox-b-d&q=bcrypt+online)

Create a Symfony project:

```bash
symfony new my_project_name --no-git
```

Install the security and JWT bundles:

```bash
composer require symfony/security-bundle lexik/jwt-authentication-bundle
```


Define `User` entity in `src/Entity/User.php`:

```php
<?php
namespace App\Entity;


use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class User implements UserInterface, PasswordAuthenticatedUserInterface
{
  private ?int $id;
  private ?string $email;
  private ?string $password;
  private ?string $firstName;
  private ?string $lastName;
  // roles
  private ?string $roles;

  public function __construct(
    ?int $id = null, 
    ?string $email = null, 
    ?string $password = null,
    ?string $firstName = null,
    ?string $lastName = null,
    ?string $roles = null
  )
  {
    $this->id = $id;
    $this->email = $email;
    $this->password = $password;
    $this->firstName = $firstName;
    $this->lastName = $lastName;
    $this->roles = $roles; 
  }

  public function getRoles(): array
  {
    // Roles are coma separated in the database
    // we need to explode them
    return explode(',', $this->roles);
  }

  public function setRoles(?array $roles): self
  {
    $this->roles = implode(',', $roles);
    return $this;
  }

  public function eraseCredentials():void
  {
  }

  public function getUserIdentifier(): string
  {
    return $this->email;
  }

  public function getId(): ?int
  {
    return $this->id;
  }

  public function getEmail(): ?string
  {
    return $this->email;
  }

  public function setEmail(?string $email): self
  {
    $this->email = $email;
    return $this;
  }
  
  public function getUsername(): ?string
  {
    return $this->email;
  }

  public function setUsername(?string $email): self
  {
    $this->email = $email;
    return $this;
  }

  public function getPassword(): ?string
  {
    return $this->password;
  }

  public function setPassword(?string $password): self
  {
    $this->password = $password;
    return $this;
  }

  public function getFirstName(): ?string
  {
    return $this->firstName;
  }

  public function setFirstName(?string $firstName): self
  {
    $this->firstName = $firstName;
    return $this;
  }

  public function getLastName(): ?string
  {
    return $this->lastName;
  }

  public function setLastName(?string $lastName): self
  {
    $this->lastName = $lastName;
    return $this;
  }
}
```

Define the `UserProvider` in `src/Security/UserProvider.php`:

```php
<?php

namespace App\Security;

use App\Repository\UserRepository;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class UserProvider implements UserProviderInterface
{
  private UserRepository $userRepository;

  public function __construct(UserRepository $userRepository)
  {
    $this->userRepository = $userRepository;
  }

  public function loadUserByIdentifier(string $identifier): UserInterface
  {
    $user = $this->userRepository->findOneByEmail($identifier);

    if (!$user) {
      throw new UserNotFoundException();
    }

    return $user;
  }

  public function refreshUser(UserInterface $user): UserInterface
  {
    /** @var App\Entity\User|null $user */
    return $this->loadUserByIdentifier($user->getEmail());
  }

  public function supportsClass(string $class): bool
  {
    return $class === 'App\Entity\User';
  }
}
```
Define the `UserRepository` in `src/Repository/UserRepository.php`:

```php
<?php

namespace App\Repository;

use App\Entity\User;

class UserRepository
{
  private \PDO $conn;

  /**
   * Maps standard URL schemes to PHP's PDO driver names.
   */
  private const SCHEME_TO_DRIVER_MAP = [
      'postgresql' => 'pgsql',
      'mysql' => 'mysql',
  ];

  public function __construct()
  {
      $dbUrl = getenv('DATABASE_URL');
      if ($dbUrl === false) {
          throw new \RuntimeException('DATABASE_URL environment variable is not set.');
      }

      $db = parse_url($dbUrl);
      if ($db === false || !isset($db['scheme'])) {
          throw new \RuntimeException('Could not parse DATABASE_URL.');
      }

      $driver = self::SCHEME_TO_DRIVER_MAP[$db['scheme']] ?? null;
      if ($driver === null) {
          throw new \RuntimeException("Unsupported database driver: {$db['scheme']}");
      }

      $host = $db['host'];
      $port = $db['port'];
      $user = $db['user'];
      $pass = $db['pass'];
      $dbname = ltrim($db['path'], '/');

      $dsn = "{$driver}:host={$host};port={$port};dbname={$dbname}";

      $this->conn = new \PDO($dsn, $user, $pass);
      $this->conn->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
  }

  public function findOneByEmail(string $email): ?User
  {
    $stmt = $this->conn->prepare('SELECT id, email, password, first_name, last_name, roles FROM users WHERE email = :email');
    $stmt->execute([':email' => $email]);

    if ($row = $stmt->fetch(\PDO::FETCH_ASSOC)) {
      return new User(
        $row['id'],
        $row['email'],
        $row['password'],
        $row['first_name'],
        $row['last_name'],
        $row['roles']
      );
    }

    return null;
  }

  // findOneByUsername(), which is the same as findOneByEmail(), so just wrap it
  public function findOneByUsername(string $username): ?User
  {
    return $this->findOneByEmail($username);
  }
}
```

Configure dependency injection for `UserRepository` in `config/services.yaml`:

**Note** : Here, we just append the new content to the existing `services.yaml` file.

```yaml
### existing services.yaml content ###
services:
    ### existing service definitions ###
    App\Repository\UserRepository:
        arguments: ['%env(DATABASE_URL)%']
```

Configure the security in `config/packages/security.yaml`:

**Note** : Here, we replace the whole file with the following content.

```yaml
security:
    password_hashers:
        Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface: 'auto'
    providers:
        database:
            id: App\Security\UserProvider
    firewalls:
        dev:
            pattern: ^/(_(profiler|wdt)|css|images|js)/
            security: false
        api:
            pattern: ^/api
            stateless: true
            provider: database
            jwt: ~
            json_login:
                check_path: /api/login
                success_handler: lexik_jwt_authentication.handler.authentication_success
                failure_handler: lexik_jwt_authentication.handler.authentication_failure
                username_path: email 
                password_path: password   

    access_control:
        - { path: ^/api/login, roles: IS_AUTHENTICATED_ANONYMOUSLY }
        - { path: ^/api,       roles: IS_AUTHENTICATED_FULLY }   # Easy way to control access for large sections of your site

when@test:
    security:
        password_hashers:
            # By default, password hashers are resource intensive and take time. This is
            # important to generate secure password hashes. In tests however, secure hashes
            # are not important, waste resources and increase test times. The following
            # reduces the work factor to the lowest possible values.
            Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface:
                algorithm: auto
                cost: 4 # Lowest possible value for bcrypt
                time_cost: 3 # Lowest possible value for argon
                memory_cost: 10 # Lowest possible value for argon
```

Declare the `/api/login` route in `config/routes/security.yaml`:

**Note** : Here, we append the new content to the existing `security.yaml` file.

```yaml
### ... other routes ###
api_login:
    path: /api/login
    methods: [POST]
```

Generate JWT keys:

```bash
mkdir config/jwt; cd config/jwt
openssl genrsa -out private.pem 4096
openssl rsa -pubout -in private.pem -out public.pem
```

Create a controller to check the authentication in `src/Controller/TestAuthController.php`:

```php
<?php
namespace App\Controller;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;

class TestAuthController extends AbstractController
{
  #[Route('/api/test/auth', name: 'api_test_auth')]
  public function testAuth(): Response
  {
    /** @var App\Entity\User|null $user */
    $user = $this->getUser();
    
    if ($user) {
      return $this->json(
        [
          'id' => $user->getId(), 
          'username' => $user->getUserIdentifier(),
          'name' => $user->getFirstName() . ' ' . $user->getLastName(),
          'roles' => $user->getRoles()
        ]);
    }
    return $this->json(['message' => 'Not authenticated'], 401);
  }
}
```

## Testing the API

When making a `POST` request to the `/api/login` endpoint to authenticate, you **must** include the `Content-Type: application/json` header.

If this header is omitted, Symfony's `json_login` listener will not be triggered to handle the credentials. The request will fall through to the next security layer, the JWT authenticator, which will fail because no token is present. This results in a `401 Unauthorized` response with a "JWT Token not found" error message.

Here is an example of a correct login request using `curl`:

```bash
curl -X POST http://127.0.0.1:8000/api/login \
  -H "Content-Type: application/json" \
  -d '{"email": "mr@rktmb.org", "password": "mihamina"}'
