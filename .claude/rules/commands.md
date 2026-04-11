# Repository Commands

## Build & Run
```bash
./mvnw clean package              # Build
./mvnw spring-boot:run            # Run locally (port-forward cluster DB first)
./mvnw clean package -DskipTests  # Skip tests during build
./mvnw test                       # Run all tests
./mvnw test -Dtest=ClassName      # Run a single test class
./mvnw verify                     # Full build + tests
docker build -t auth-service .    # Build Docker image
```

## Cluster access (local dev)
```bash
kubectl port-forward -n apps svc/postgres 5432:5432    # PostgreSQL
kubectl get nodes -o wide                              # Check cluster status
kubectl get pods -n apps                               # List pods
```
